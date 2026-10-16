// ONE definition of what `/v1/verify` is allowed to have said.
//
// Extracted so the attestation path and the tool surface cannot drift apart.
// The last review found three different `.viz` equality rules living in three
// modules while the commit message claimed there was one; a second copy of the verdict contract would be the same mistake with
// higher stakes, since this is the rule that decides whether a claim exists.

import type { VerifyResponse } from "./types.js";
import { canonicalVizDomain } from "./viz-domain.js";
import {
  projectProducerReputation,
  tickMatchesReputation,
  type ProducerReputation,
} from "./producer-reputation.js";

/**
 * The WHOLE producer contract for a successful `/v1/verify` body — not the two
 * fields we happen to read.
 *
 * An earlier change bound `identity` and killed version-as-proof, and stopped there. That
 * left the body field-picked, which is the same defect an earlier review spent four rounds
 * removing from `/v1/blue-tick`: a response was trusted because it parsed.
 * Reproduced on that branch, all four bodies
 * the Worker cannot emit:
 *
 *   {verified:true, identity:R, signing_version:99}            => verified, version 99 echoed
 *   {verified:true, identity:R, blue_tick:true, reputation:null} => TICK, with no measurement
 *   {verified:true, identity:R, blue_tick:false}                 => a fabricated NEGATIVE
 *   {verified:true, identity:R, code:"E_SIG_MISMATCH"}           => success carrying a failure code
 *
 * The second is the serious one and it is the same review's second P1 on the neighbouring
 * endpoint: a tick minted from a body carrying no reputation. It is reachable
 * only while the registry lookup below returns nothing — an outage, or an
 * unmeasured agent — which is precisely when we decided to say `unknown`.
 *
 * PRODUCER, read before tightening (the registry's POST /v1/verify success
 * response):
 *
 *   { verified: true, identity: from, signing_version: 0|1,
 *     freshness_checked: true, reputation: null|{...}, blue_tick: null|boolean }
 *
 * `signing_version` and `freshness_checked` arrived in the same commit, so a build that emits one emits the other — requiring both costs
 * nothing against any deployed Worker. `blue_tick`/`reputation` came later
 * and are ABSENT on a pre-fanout build, which production may still be,
 * so their absence is a legal success shape rather than a violation. Getting
 * that wrong would fail every attestation network-wide.
 *
 * The two are COUPLED at the producer: both are set inside the behaviour fetch
 * or neither is. That coupling is what makes `blue_tick` without `reputation`
 * a body no Worker can emit.
 *
 * Reputation VALUES go through `projectProducerReputation`: a closed
 * calibration-stage vocabulary, bounded scores, coupled unseen/measured
 * forms, and a typed projection of the four reputation fields. The
 * tick is then bound with `tickMatchesReputation`. Invalid or contradictory
 * copied enrichment degrades to tick unknown without undoing cryptographic
 * verification. This distinction matters because the Worker authors the
 * verdict fields but copies all five reputation/tick values from the behavior service
 * without validation.
 */
export type RemoteSuccess =
  | {
      ok: true;
      identity: string;
      version: 0 | 1;
      tick: boolean | "unknown";
      reputation?: ProducerReputation;
    }
  | { ok: false };

/** Consumer-supported remote versions; version 2 remains local-receipt only. */
export const REMOTE_VERIFY_SIGNING_VERSIONS = [0, 1] as const;

function isRemoteVerifySigningVersion(
  value: unknown
): value is (typeof REMOTE_VERIFY_SIGNING_VERSIONS)[number] {
  return REMOTE_VERIFY_SIGNING_VERSIONS.includes(
    value as (typeof REMOTE_VERIFY_SIGNING_VERSIONS)[number]
  );
}

export function validateRemoteSuccess(input: unknown): RemoteSuccess {
  // `unknown` in, because every caller is holding a body it did not build.
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false };
  }
  const vr = input as VerifyResponse;
  if (!Object.prototype.hasOwnProperty.call(vr, "verified") || vr.verified !== true) {
    return { ok: false };
  }
  // A success body never carries either failure-only field. Contradiction is
  // not a partial success; it is a body we cannot attribute to this producer.
  if ("code" in vr || "error" in vr) return { ok: false };

  // Deliberate compatibility posture: fail closed on a new remote signing
  // version until this consumer understands that version's canonical payload
  // and proof semantics. In particular, version 2 is reserved for the local
  // capability-bearing receipt path; accepting arbitrary integers here would
  // turn a roadmap deployment into an unreviewed trust-boundary expansion.
  if (!isRemoteVerifySigningVersion(vr.signing_version)) {
    return { ok: false };
  }
  if (vr.freshness_checked !== true) return { ok: false };
  const identity = canonicalVizDomain(vr.identity);
  if (!identity) return { ok: false };

  const hasTick = "blue_tick" in vr && vr.blue_tick !== undefined;
  const hasRep = "reputation" in vr && vr.reputation !== undefined;

  // Legacy pre-fanout build: neither key present. Verified, tick unknown.
  if (!hasTick && !hasRep) {
    return { ok: true, identity, version: vr.signing_version, tick: "unknown" };
  }
  // Half a pair is a shape the producer cannot produce.
  if (hasTick !== hasRep) return { ok: false };

  // Unmeasured: the Worker says so with both explicitly null.
  if (vr.blue_tick === null && vr.reputation === null) {
    return { ok: true, identity, version: vr.signing_version, tick: "unknown" };
  }

  // Measured: a boolean tick, and the complete companion object behind it.
  // `blue_tick_status` is NOT consulted, here or anywhere on this path. It
  // exists only on the agent card, never on the
  // verify response, so treating `"verified"` as a tick trusted a field outside
  // this endpoint's contract — a claim asserted from a string, with no
  // reputation behind it. It now falls through as one more
  // unknown extra field, which is what it always was.
  if (typeof vr.blue_tick !== "boolean") return { ok: false };
  if (
    typeof vr.reputation !== "object" ||
    vr.reputation === null ||
    Array.isArray(vr.reputation)
  ) {
    return { ok: false };
  }
  const reputation = projectProducerReputation(vr.reputation);
  // The Worker authors the cryptographic verdict, but copies these enrichment
  // fields from the behavior service without validating them. Missing or newly-null
  // fields can therefore produce `{ reputation: {} }` beside a valid signature
  // verdict. Preserve the authenticated identity while refusing to mint either
  // a positive or negative tick from enrichment we cannot project.
  if (!reputation) {
    return { ok: true, identity, version: vr.signing_version, tick: "unknown" };
  }
  // All five enrichment values are copied from the behavior service. A contradiction
  // among them says nothing about the signature verdict the Worker authored;
  // discard the whole enrichment rather than demoting authenticated identity.
  if (!tickMatchesReputation(vr.blue_tick, reputation)) {
    return { ok: true, identity, version: vr.signing_version, tick: "unknown" };
  }
  return { ok: true, identity, version: vr.signing_version, tick: vr.blue_tick, reputation };
}

/**
 * The producer status/code matrix for a FAILED POST `/v1/verify`. Exact pairs, no regex, no “looks like a
 * code”:
 *
 *   200  E_SIG_MISMATCH
 *   400  E_MISSING_FIELDS | E_TIMESTAMP_FORMAT | E_STALE | E_SIG_FORMAT
 *   404  E_AGENT_NOT_FOUND
 *   500  E_STORED_KEY | E_VERIFY
 *
 * `E_STALE` is raised from the timestamp window check, before registry lookup,
 * key import, base64 parsing, or Ed25519 verify. It does not prove the
 * signature is genuine.
 *
 * A 503, an invented code, a mismatched pair, a success-only field on a
 * failure body, or a malformed object is not a verdict — it is unknown.
 * Additive diagnostic fields are ignored and never projected.
 */
export const VERIFY_FAILURE_CODES_BY_STATUS: Readonly<Record<number, readonly string[]>> = {
  200: ["E_SIG_MISMATCH"],
  400: ["E_MISSING_FIELDS", "E_TIMESTAMP_FORMAT", "E_STALE", "E_SIG_FORMAT"],
  404: ["E_AGENT_NOT_FOUND"],
  500: ["E_STORED_KEY", "E_VERIFY"],
};

const FAILURE_SUCCESS_ONLY_KEYS = [
  "identity",
  "signing_version",
  "freshness_checked",
  "blue_tick",
  "reputation",
] as const;

export type RemoteFailure = { ok: true; code: string } | { ok: false };

export function validateRemoteFailure(status: number, input: unknown): RemoteFailure {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false };
  }
  const body = input as Record<string, unknown>;
  for (const key of ["verified", "error", "code"]) {
    if (!Object.prototype.hasOwnProperty.call(body, key)) return { ok: false };
  }
  if (body.verified !== false) return { ok: false };
  if (typeof body.error !== "string" || typeof body.code !== "string") return { ok: false };

  const allowed = VERIFY_FAILURE_CODES_BY_STATUS[status];
  if (!allowed || !allowed.includes(body.code)) return { ok: false };

  // Permit additive diagnostics such as `request_id`, but never accept a
  // failure body carrying fields that assert or enrich a success.
  if (FAILURE_SUCCESS_ONLY_KEYS.some((key) => key in body)) return { ok: false };
  return { ok: true, code: body.code };
}
