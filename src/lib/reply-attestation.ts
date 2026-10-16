import { type A2AResponse, type VerifyResponse } from "./types.js";
import { extractReplyMetadata, type VerifyFn, type VerifyRequest } from "./a2a-reply.js";
import { provenReceipt } from "../core/receipts.js";
import { canonicalVizDomain, sameVizIdentity } from "./viz-domain.js";
import { boundModelText } from "./model-text.js";
import { readJsonBounded } from "./bounded-json.js";
import { validateRemoteFailure, validateRemoteSuccess, VERIFY_FAILURE_CODES_BY_STATUS } from "./verify-contract.js";

// Re-exported so existing importers keep one entry point. `RECEIPT_PROOF` is
// deliberately NOT among them any more: the symbol is private to the module
// that verifies receipts, and `provenReceipt` is the only way to read it.
export { extractReplyMetadata } from "./a2a-reply.js";
export type { VerifyFn, VerifyRequest } from "./a2a-reply.js";
import {
  BehaviourLookup,
  sharedBehaviourLookup,
  type BehaviourClaim,
} from "../core/behaviour.js";

// Preserve and VERIFY the recipient's signed reply.
//
// zipviz_send previously extracted the recipient's reply text and discarded the
// signature the recipient already attached. This module consumes that existing
// `metadata.zipviz` block and verifies it through the SAME api.zipviz.ai
// /v1/verify path zipviz_verify and the recipient relays use, so the caller can
// authenticate the reply's provenance/integrity.
//
// Hard rules baked in here:
//  * FAIL CLOSED — malformed, stale, invalid, or identity-mismatched metadata
//    never yields reply_verified:true. Any exception degrades to
//    "verify_unavailable", never a throw that crashes the send.
//  * Cryptographic verification proves PROVENANCE, not that the remote text is
//    safe to act on. The caller keeps wrapping the reply text as untrusted.
//  * The model-facing attestation never echoes the raw signature bytes or any
//    private material — only a compact, bounded verdict.

// Machine-readable, bounded failure codes. A verified reply carries none.
export type ReplyFailureReason =
  | "missing_metadata"
  | "malformed_metadata"
  | "identity_mismatch"
  | "signature_invalid"
  | "verdict_off_contract"
  | "verify_unavailable"
  | "reply_text_unsigned";

export interface ReplyAttestation {
  reply_verified: boolean;
  reply_from: string | null;
  reply_blue_tick: boolean | "unknown";
  /**
   * The same behavioural record the receiver's verification block carries — stage,
   * entropy, z-score, drift and the plain-language summary. Present whenever the
   * registry returned a measurement.
   *
   * `reply_blue_tick` alone is a yes/no with nothing behind it, which reads as
   * an assertion rather than a reading. This is the evidence for it.
   *
   * When present, this record DETERMINES `reply_blue_tick` — it does not merely
   * accompany it. The two cannot contradict each other because one is derived
   * from the other, rather than because two sources happen to agree.
   */
  reply_behaviour?: BehaviourClaim;
  reply_signing_version: number | null;
  // Present iff reply_verified === false. Bounded, machine-readable.
  reply_failure_reason?: string;
  // Present only when a v2 ACCEPTED receipt verified. Never on the v1 path.
  // A receipt proves the recipient accepted THIS message; it signs no reply
  // text, so an attestation carrying one always has reply_verified: false
  // with reason "reply_text_unsigned".
  receipt?: {
    status: "ACCEPTED";
    msg_id: string;
    received_at: string;
  };
}


const VERIFY_URL = "https://api.zipviz.ai/v1/verify";

// The verify hop runs AFTER send.ts has already cleared its own A2A abort
// controller, so without an explicit bound a verifier connection that never
// settles would hang zipviz_send indefinitely instead of failing closed. Bound
// every default verification request; a timeout aborts the fetch, which
// surfaces upstream as verify_unavailable.
export const VERIFY_TIMEOUT_MS = 10_000;

// The signed reply's verification is a network hop to our own trusted API.
//
// OPERATOR DECISION: reply_verified:true may originate
// ONLY from a successful 2xx /v1/verify response. This is the fail-closed
// invariant at the HTTP trust boundary — a gateway/proxy/error response must
// never be able to assert verified:true, no matter what its body claims.
//
// Failures are accepted only when HTTP status and `code` match the producer
// matrix in verify-contract.ts. A 503, an invented code, a mismatched pair,
// or a body that is not exactly the failure shape is verify_unavailable.
async function defaultVerify(
  body: VerifyRequest,
  timeoutMs: number = VERIFY_TIMEOUT_MS
): Promise<VerifyResponse | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(VERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    let parsed: unknown;
    try {
      parsed = await readJsonBounded(res);
    } catch {
      return null;
    }
    const status =
      typeof res.status === "number" && res.status > 0 ? res.status : res.ok ? 200 : 0;
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) && (parsed as Record<string, unknown>).verified === true) {
      if (status !== 200) return null;
      return parsed as VerifyResponse;
    }
    const failure = validateRemoteFailure(status, parsed);
    if (!failure.ok) return null;
    return { verified: false, code: failure.code };
  } finally {
    clearTimeout(timer);
  }
}

function isNonEmptyString(x: unknown): x is string {
  return typeof x === "string" && x.length > 0;
}

// We surface a recognized code VERBATIM as the attestation's failure reason —
// it's already bounded and machine-readable, and unlike a free-text
// `reason`/`error` it's a stable contract the caller can branch on.
// `verify_unavailable` is reserved for transport/availability failures and is
// NEVER produced here.
const PRODUCER_FAILURE_CODES = new Set(
  Object.values(VERIFY_FAILURE_CODES_BY_STATUS).flat()
);
// Local receipt verifier only. Not a /v1/verify HTTP code — must not be
// collapsed by the producer matrix, and must not be accepted from the wire.
const LOCAL_FAILURE_CODES = new Set(["E_RECEIPT_MISMATCH"]);

function verdictFailureReason(vr: VerifyResponse): string {
  if (typeof vr.code === "string" && (PRODUCER_FAILURE_CODES.has(vr.code) || LOCAL_FAILURE_CODES.has(vr.code))) {
    return vr.code;
  }
  return boundReason(vr.reason ?? vr.error, "signature_invalid");
}

// api.zipviz.ai is trusted, but the reason still flows into a model-facing
// result — bound it defensively: single line, no control chars, capped length.
function boundReason(raw: unknown, fallback: ReplyFailureReason): string {
  const cleaned = boundModelText(raw, 120, true);
  if (cleaned.length === 0) return fallback;
  return cleaned;
}

function boundedReplyFrom(value: unknown): string | null {
  return canonicalVizDomain(value);
}

// A non-verified attestation carries NO signing version: the only trustworthy
// version is the one the verifier authenticated on the success path, so every
// failure reports reply_signing_version: null rather than echoing an unverified
// (possibly attacker-supplied) metadata claim.
function fail(
  reason: ReplyFailureReason,
  from: string | null
): ReplyAttestation {
  return {
    reply_verified: false,
    reply_from: from,
    reply_blue_tick: "unknown",
    reply_signing_version: null,
    reply_failure_reason: reason,
  };
}

/**
 * Verify the recipient's signed reply and return a compact attestation.
 *
 * `replyText` MUST be the exact reply text the recipient signed (the joined
 * text parts, before any untrusted-content wrapping) — /v1/verify reconstructs
 * the canonical `{v:1, from, message, timestamp}` payload from it.
 *
 * `recipientDomain` is the domain the caller addressed; the reply's claimed
 * `from` must equal it or we fail closed on identity mismatch.
 */
export async function attestReply(params: {
  recipientDomain: string;
  replyText: string;
  response: A2AResponse;
  verifyFn?: VerifyFn;
  timeoutMs?: number;
  /**
   * Fetch used for the behavioural fallback below. Injectable for the same
   * reason the admin handlers thread one: without it this reaches the live
   * registry on every verified reply, and unit tests that only stub `verifyFn`
   * silently make real outbound requests.
   *
   * Pass `null` to skip the lookup entirely — the fully-offline receipt path
   * has no business touching the network.
   */
  behaviourFetchFn?: ((url: string, init?: RequestInit) => Promise<Response>) | null;
}): Promise<ReplyAttestation> {
  const { recipientDomain, replyText, response } = params;
  // A caller-supplied verifyFn is used verbatim; the default one is bound with
  // an explicit timeout so the verify hop can never hang the send.
  const verify: VerifyFn =
    params.verifyFn ?? ((body) => defaultVerify(body, params.timeoutMs));

  const meta = extractReplyMetadata(response);

  // No signed metadata at all → an unsigned / non-ZipViz compatibility reply.
  // Never claim verification; say plainly it's missing.
  if (!meta) return fail("missing_metadata", null);

  // Early failure paths run before identity binding. Never echo arbitrary
  // metadata into the unwrapped model-facing attestation: retain only a
  // bounded, syntactically valid `.viz` name.
  const claimedFrom = boundedReplyFrom(meta.from);

  // Shape must be complete: from + timestamp + signature, all non-empty strings.
  if (
    !isNonEmptyString(meta.from) ||
    !isNonEmptyString(meta.timestamp) ||
    !isNonEmptyString(meta.signature)
  ) {
    return fail("malformed_metadata", claimedFrom);
  }

  // The reply must be signed AS the domain we addressed. A reply claiming a
  // different identity is never presented as authenticated.
  // Through `sameVizIdentity` — the same rule the verdict binding and the
  // behaviour binding use. This was a strict `!==`, which was *safe* (strict
  // fails closed) but made three comparison rules for one kind of name, while
  // an earlier commit message claimed there was now one. Review caught the
  // claim; this is the claim being made true.
  if (!sameVizIdentity(meta.from, recipientDomain)) {
    return fail("identity_mismatch", claimedFrom);
  }

  let vr: VerifyResponse | null;
  try {
    vr = await verify({
      from: meta.from,
      message: replyText,
      timestamp: meta.timestamp,
      signature: meta.signature,
    });
  } catch {
    // Any transport/timeout/parse failure → fail closed, do not crash the send.
    vr = null;
  }

  // Null means the endpoint gave us no parseable verdict (unreachable, timed
  // out, or a non-verdict body). That is an availability failure, distinct from
  // a real "signature invalid" verdict below.
  if (!vr) return fail("verify_unavailable", claimedFrom);

  // Stale / tampered / wrong-key / unknown-agent all come back verified:false
  // from /v1/verify with a stable machine `code` (the endpoint enforces the
  // ≤5-min freshness window server-side). Surface that code, not a guess.
  if (vr.verified !== true) {
    return {
      reply_verified: false,
      reply_from: claimedFrom,
      reply_blue_tick: "unknown",
      reply_signing_version: null,
      reply_failure_reason: verdictFailureReason(vr),
    };
  }

  // TWO SUCCESS FORMS, and they are not interchangeable.
  //
  // The LOCAL form is produced by `localV2ReceiptVerifyFn`, which has already
  // verified a signature and bound `msg_id`/`to` to this send. It is identified
  // by the proof it carries — a value a remote body cannot produce and, since
  // this review, no other module can either. It reports version 2 and carries no
  // behavioural fields, so validating it against the remote contract would
  // reject the one verdict we trust most.
  //
  // The REMOTE form is a body off the network, and it is checked whole.
  // Anything that is not one of the producer's success shapes yields NO claim:
  // not a pass, and not a failure either — `verdict_off_contract` says we could
  // not attribute the body to the producer, which is different from the producer
  // telling us the signature was bad.
  const proven = provenReceipt(vr);
  let verifiedVersion: number | null;
  let contractTick: boolean | "unknown";
  if (proven) {
    // The local capability does not pass through the remote body validator, so
    // bind its echoed identity explicitly.
    if (!sameVizIdentity(vr.identity, meta.from)) {
      return fail("identity_mismatch", claimedFrom);
    }
    // The receipt is genuine, but its signature covers the receipt fields
    // (from, to, msg_id, status, nonce, timestamps) and nothing else. The
    // reply text beside it is unsigned, so the same receipt would verify next
    // to any text at all. Report the proven receipt and say plainly that the
    // text is not verified, rather than letting the receipt stand in for it.
    //
    // A receipt is attached ONLY when the verifier hands us one it proved.
    //
    // This used to gate on `verifiedVersion === 2` and then rebuild the receipt
    // from the metadata block. Both halves were wrong. A scalar cannot stand in
    // for a signature check performed in another module, so a remote verdict
    // claiming version 2 produced an ACCEPTED receipt with an attacker-chosen
    // `msg_id`; and re-deriving the fields from unverified metadata meant the
    // values attached were never the values checked.
    //
    // Now the proof and the receipt travel together, under a symbol key a JSON
    // body cannot carry, set only by `localV2ReceiptVerifyFn` after it has
    // verified the signature and bound `msg_id`/`to` to this send. `provenReceipt`
    // is the only way to read it and there is no exported way to write it — the
    // symbol used to be exported from `types.ts`, so any in-process caller could
    // import it and attach any receipt it liked.
    return { ...fail("reply_text_unsigned", claimedFrom), receipt: proven };
  } else {
    const contract = validateRemoteSuccess(vr);
    if (!contract.ok) return fail("verdict_off_contract", claimedFrom);
    // RemoteSuccess cannot exist without a canonical producer identity. Compare
    // the validated projection, not a second field-pick from the raw body.
    if (!sameVizIdentity(contract.identity, meta.from)) {
      return fail("identity_mismatch", claimedFrom);
    }
    verifiedVersion = contract.version;
    contractTick = contract.tick;
  }

  // /v1/verify only carries blue_tick on a build with the trust-status fanout, and
  // production currently predates it — so mapBlueTick(vr) collapses a real tick
  // to "unknown". Fall back to the dedicated /v1/blue-tick endpoint: the same
  // source the receiver's verification block reads, and live on the deployed build.
  // The verify verdict still wins when it has an opinion; this only fills the
  // gap, and a failed lookup leaves "unknown" rather than inventing a value.
  // Note this fires on EVERY envelope_v=2 send, not occasionally: v2 receipts
  // verify locally (localV2ReceiptVerifyFn) and a local verdict never carries
  // blue_tick, so `unknown` always holds. Explicit `null` opts out.
  // ONE precedence rule, applied here and in zipviz_status: the registry record
  // wins. behaviour.ts names /v1/blue-tick as the source of truth, so a verdict
  // that disagrees with it is the stale one.
  //
  // This was the other way round and it was wrong. `tick` took the /v1/verify
  // verdict when it had one, while `reply_behaviour` was attached
  // unconditionally from the registry — so the day production ships the trust-status
  // fanout, an attestation could read `reply_blue_tick: true` with
  // `reply_behaviour.blue_tick: false` sitting underneath it, and a reader would
  // have no way to know which to believe. status.ts already resolved the same
  // conflict in the opposite direction.
  // The tick the CONTRACT allows, not a field read off the body. `mapBlueTick`
  // is gone: reading `blue_tick` on its own is what let a body with no
  // reputation mint one.
  let tick: boolean | "unknown" = contractTick;
  let behaviour: BehaviourClaim | undefined;
  if (params.behaviourFetchFn !== null) {
    // With an injected fetchFn, build a throwaway lookup: a caller supplying
    // its own transport must not have its responses recorded in — or served
    // from — an outage memory shared with every other caller in the process.
    // Otherwise use the shared one, so a burst of sends coalesces.
    const lookup = params.behaviourFetchFn
      ? new BehaviourLookup({ fetchFn: params.behaviourFetchFn })
      : sharedBehaviourLookup();
    const b = await lookup.get(meta.from);
    if (b) {
      behaviour = b;
      tick = b.blue_tick;
    }
  }

  const attestation: ReplyAttestation = {
    reply_verified: true,
    // Use the same bounded canonical identity on success and failure. At this
    // point it is non-null because the identity-binding check above passed.
    reply_from: claimedFrom,
    reply_blue_tick: tick,
    reply_signing_version: verifiedVersion,
    ...(behaviour ? { reply_behaviour: behaviour } : {}),
  };
  return attestation;
}

// `receiptFromMeta` was deleted after review. Rebuilding a receipt
// from the metadata block could only ever produce fields nobody had verified;
// the proven receipt now arrives from the verifier that checked them.
