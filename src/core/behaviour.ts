import { sameVizIdentity } from "../lib/viz-domain.js";
import {
  projectProducerReputation,
  tickMatchesReputation,
  type CalibrationStage,
} from "../lib/producer-reputation.js";

/**
 * Behavioural trust lookup for the claim verification block.
 *
 * When an agent claims a message it is told whether the sender's signature
 * verified. That answers "is this really them?" — Layer 1. It does not answer
 * "have they been behaving like themselves?", which is Layer 2 and the reason
 * anyone would choose this registry over a bare keypair. This adds the second
 * answer to the same block, so the agent can report both to its human without
 * anyone running a separate command.
 *
 * Source of truth is the public `/v1/blue-tick/:domain` endpoint — deliberately
 * the same contract a third party would use, rather than a private side channel.
 * If it ever disagrees with what an agent reports, the agent is wrong.
 *
 * Fails soft, always. A behaviour lookup that is slow, unreachable, or returns
 * anything unexpected must never delay or block a claim: identity verification
 * already succeeded, and the message is deliverable regardless. On any failure
 * the block simply carries no behavioural claim — the same posture the Worker
 * takes when the behaviour service is absent, and the same reason: an outage
 * must read as "unknown", never as a pass and never as an outage of the receiver.
 */

const DEFAULT_API_BASE = "https://api.zipviz.ai";

/** Short by design: this sits inside a claim, which agents wait on. */
const LOOKUP_TIMEOUT_MS = 2500;

/**
 * How long an UNAVAILABLE verdict is remembered — and simultaneously the
 * CEILING on that window. A caller may ask for less; asking for more is clamped
 * to this rather than honoured, so no config and no caller can widen a
 * stale-unknown window.
 *
 * This was briefly a 10 s default under a separate 30 s ceiling, which meant a
 * caller could in fact widen the window threefold — the exact thing the rule
 * forbids, undone by having two numbers instead of one. A stale "unknown" is cheap for ten seconds and dishonest for
 * thirty: it would let a receiver go on reporting "we could not ask" long after
 * it could, across the window in which a drift event is worth seeing.
 */
export const BEHAVIOUR_UNAVAILABLE_TTL_MS = 10_000;

/** Bound on remembered domains, so a flood of unique names cannot grow the map. */
export const BEHAVIOUR_CACHE_MAX_ENTRIES = 512;

/** Bound on simultaneous upstream requests. Exceeding it degrades to `unknown`. */
export const BEHAVIOUR_MAX_CONCURRENT = 8;

type FetchFn = (url: string, init?: RequestInit) => Promise<Response>;

/**
 * The ONLY thing this module ever stores.
 *
 * The origin sets `Cache-Control: no-store` on /v1/blue-tick on purpose, so
 * that no cache can mask a live drift moment. A positive cache would overclaim
 * — it could report a tick that has since been withdrawn. This one cannot: it
 * records that we failed to ask, and nothing else, so its worst possible output
 * is `unknown`, which is already the honest answer for a measurement we do not
 * have.
 *
 * That is a property of the TYPE, not of anyone's discipline — see the
 * compile-time assertion below.
 */
export type BehaviourUnavailableEntry = {
  unavailable: true;
  until: number;
};

// Compile-time guarantee, emitting no runtime code: the entry type is exactly
// the unavailability marker. Add a field to it -- `blue_tick`, `claim`, a
// cached score, anything -- and `npm run typecheck` fails here rather than a
// stale positive tick reaching a human through a cache hit.
type Assert<T extends true> = T;
type KeysAreExactly<T, K extends string> = [Exclude<keyof T, K>] extends [never]
  ? [Exclude<K, keyof T>] extends [never]
    ? true
    : false
  : false;
export type _BehaviourEntryCannotHoldAClaim = Assert<
  KeysAreExactly<BehaviourUnavailableEntry, "unavailable" | "until">
>;

/**
 * Why a lookup could not be answered. A real ABSENCE of measurement is not
 * here: a 404 and a 200 with no reputation are answers about the agent, and
 * neither is an outage.
 *
 * `client_error` is split out from `http_status` deliberately. A 429 or a 5xx
 * is the endpoint having a bad moment; a 400/401/403 is OUR request being
 * wrong, and it will still be wrong in ten seconds. Both are cached — hammering
 * a rejecting endpoint helps nobody — but only one of them is an operator's
 * problem right now, so they are named apart and audited at different levels.
 *
 * `capacity` is not cached: it means we declined to ask, not that asking
 * failed, and the very next call may have a free slot.
 */
export type BehaviourUnavailableReason =
  | "http_status"
  | "client_error"
  | "network"
  | "timeout"
  | "malformed"
  | "capacity";

export type BehaviourUnavailableInfo = {
  domain: string;
  reason: BehaviourUnavailableReason;
  status?: number;
  /** 0 when the outcome was deliberately not remembered. */
  cached_for_ms: number;
};

/**
 * How loudly an operator should hear about it. A misconfigured request that
 * will keep failing is an error; a throttled or flaky endpoint is a warning.
 */
export function behaviourUnavailableLevel(
  reason: BehaviourUnavailableReason
): "warn" | "error" {
  return reason === "client_error" ? "error" : "warn";
}

export type BehaviourClaim = {
  /** True only when the registry says the agent has earned it. Never inferred. */
  blue_tick: boolean;
  /** Ladder rung, closed: the measured stages plus `unseen`. */
  calibration_stage: CalibrationStage | null;
  /** Composite behavioural entropy for the most recent scored session. */
  entropy_score: number | null;
  /** Deviation from the expected baseline, in standard deviations. */
  z_score: number | null;
  /** Whether the latest session read as anomalous for this agent. */
  drift_detected: boolean | null;
  /**
   * A plain-language line the agent can repeat to its human verbatim. The
   * numbers above mean nothing to a person reading a message; this does.
   */
  summary: string;
};

/**
 * The sentence a human actually reads. Deliberately never claims more than the
 * gate does: an un-ticked agent is described as measured-and-not-yet-qualified,
 * never as "pending approval" or any other phrasing that implies it is on track.
 */
export function summarise(b: Omit<BehaviourClaim, "summary">): string {
  if (b.blue_tick) {
    return "Trust status: earned. Behavior matches this agent's established baseline.";
  }
  if (b.calibration_stage === null || b.calibration_stage === "unseen") {
    return "Trust status: not held. No behavioral measurement exists for this agent yet.";
  }
  const stage =
    b.calibration_stage === "cohort"
      ? "still building its own history, so it is measured against agents doing similar work"
      : `at the '${b.calibration_stage}' stage of calibration`;
  const drift =
    b.drift_detected === true
      ? " Its latest session reads as out of pattern for it."
      : b.drift_detected === false
        ? " Its latest session reads as normal for it."
        : "";
  return `Trust status: not held. This agent is ${stage}.${drift}`;
}

/**
 * The outcome of one upstream request, classified.
 *
 * `answered` covers both a real reading and a real absence — a 404, or a 200
 * with no reputation object. Both are statements ABOUT THE AGENT, so neither is
 * cached and neither is audited as an outage.
 *
 * `unavailable` means we failed to ask: throttled, erroring, timed out, or
 * handed something unparseable. Only these are remembered, and only briefly.
 */
type BehaviourFetchOutcome =
  | { kind: "answered"; claim: BehaviourClaim | null }
  | { kind: "unavailable"; reason: BehaviourUnavailableReason; status?: number };

function apiBaseFrom(apiBase?: string): string {
  return (apiBase ?? process.env.ZIPVIZ_API_BASE_URL ?? DEFAULT_API_BASE).replace(/\/+$/, "");
}

async function fetchBehaviour(
  domain: string,
  opts: { fetchFn?: FetchFn; apiBase?: string }
): Promise<BehaviourFetchOutcome> {
  const fetchFn = opts.fetchFn ?? fetch;
  const base = apiBaseFrom(opts.apiBase);
  let res: Response;
  try {
    res = await fetchFn(`${base}/v1/blue-tick/${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
    });
  } catch (err) {
    // A timeout is worth naming separately from a refused connection: they
    // point at different things when someone reads the audit log later.
    const name = err instanceof Error ? err.name : "";
    const timedOut = name === "TimeoutError" || name === "AbortError";
    return { kind: "unavailable", reason: timedOut ? "timeout" : "network" };
  }

  if (!res.ok) {
    // 404/410 is the registry saying it has no such agent. That is an answer,
    // and caching it would keep a freshly registered agent invisible for the
    // whole window.
    if (res.status === 404 || res.status === 410) return { kind: "answered", claim: null };
    // 408 and 429 are the endpoint asking us to come back; 5xx is it failing.
    // Both are moments. Any other 4xx is OUR request being wrong — a bad base
    // URL, a blocked origin — and it will be just as wrong on the next call, so
    // it is named apart and audited louder rather than smoothed over as flake.
    const transient = res.status === 408 || res.status === 429 || res.status >= 500;
    return {
      kind: "unavailable",
      reason: transient ? "http_status" : "client_error",
      status: res.status,
    };
  }

  type Body = {
    identity?: unknown;
    blue_tick?: unknown;
    reputation?: {
      entropy_score?: unknown;
      z_score?: unknown;
      drift_detected?: unknown;
      calibration_stage?: unknown;
    } | null;
  };
  let parsed: unknown;
  try {
    parsed = await res.json();
  } catch {
    // A 200 carrying something unparseable is a proxy interstitial or a
    // truncated body, not a statement about the agent.
    return { kind: "unavailable", reason: "malformed" };
  }

  // Parsing successfully is not the same as getting the right shape.
  // `JSON.parse("null")` succeeds, and reading `.reputation` off it then threw
  // OUTSIDE the guard above — breaking lookupBehaviour's "resolves to null on
  // any failure" contract outright, and misfiling the throw as a network
  // failure inside BehaviourLookup.
  // Arrays are excluded too: an array has no `reputation`, so it would
  // otherwise pass as a legitimate "measured nothing yet".
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { kind: "unavailable", reason: "malformed" };
  }
  const data = parsed as Body;

  // BIND THE ANSWER TO THE QUESTION, before reading anything else out of it.
  //
  // The endpoint echoes `identity`, and nothing checked it — so a misrouted,
  // stale, or wrongly keyed response handed one agent's earned tick to another
  // agent entirely, under the caller's domain. The receiver already refuses a
  // message that does not name it as recipient; a trust claim about an identity
  // deserves the same binding and did not have it.
  //
  // A response we cannot bind is `malformed` rather than an absence: we do not
  // know anything about the agent we asked about, including that it is
  // unmeasured.
  //
  // Through `sameVizIdentity`, which is the ONE equality rule for `.viz` names.
  // This line used to do its own `trim().toLowerCase()` while promising, in this
  // comment, "no unicode folding, nothing that could let two different names
  // compare equal" — and `toLowerCase()` is Unicode-aware, so it folded U+212A
  // KELVIN SIGN onto `k` and the promise was false here exactly as it was in the
  // helper. Sharing the rule is the point: an earlier change
  // claimed both boundaries already shared it, and they did not.
  if (!sameVizIdentity(data.identity, domain)) {
    return { kind: "unavailable", reason: "malformed" };
  }

  // THE PRODUCER EMITS TWO SHAPES AND ONLY TWO. Validate against both in full,
  // rather than picking fields out of whatever arrives.
  //
  // An earlier cut accepted any reputation object carrying "at least one usable
  // field", on the theory that a stage without scores was a legitimate early
  // ladder rung. It is not: the registry copies all four measurement fields
  // verbatim, so a body missing three of them is one the service would never
  // send — and it minted an earned tick, with the missing companions silently
  // nulled.
  //
  // Shape one, unmeasured: `blue_tick: null` beside `reputation: null`. That is
  // a real answer about the agent, so it is neither cached nor audited.
  const repRaw = data.reputation;
  if (repRaw === null) {
    // The pairing is the check. A tick asserted beside no measurement at all is
    // a contradiction the producer cannot produce, and treating it as an
    // absence would let it pass unaudited.
    if (data.blue_tick !== null) return { kind: "unavailable", reason: "malformed" };
    return { kind: "answered", claim: null };
  }

  // Shape two: a boolean tick bound to a reputation the producer can emit.
  // Extra keys are stripped by the projector; unknown stages, mixed
  // unseen/measured fields, a tick on an unseen record, and a tick while
  // drifting fail closed. Anything we cannot project is `malformed`.
  if (typeof data.blue_tick !== "boolean") {
    return { kind: "unavailable", reason: "malformed" };
  }
  const reputation = projectProducerReputation(repRaw);
  if (!reputation) return { kind: "unavailable", reason: "malformed" };
  if (!tickMatchesReputation(data.blue_tick, reputation)) {
    return { kind: "unavailable", reason: "malformed" };
  }
  const core = { blue_tick: data.blue_tick, ...reputation };
  return { kind: "answered", claim: { ...core, summary: summarise(core) } };
}

/**
 * Look up one agent's behavioural standing, with no caching and no coalescing.
 * Resolves to `null` on any failure, which callers must treat as "no claim
 * available" rather than as a negative.
 *
 * Prefer `BehaviourLookup` on any path that runs more than once: this is the
 * single-shot primitive it is built from.
 */
export async function lookupBehaviour(
  domain: string,
  opts: { fetchFn?: FetchFn; apiBase?: string } = {}
): Promise<BehaviourClaim | null> {
  try {
    const outcome = await fetchBehaviour(domain, opts);
    return outcome.kind === "answered" ? outcome.claim : null;
  } catch {
    // Swallowed on purpose — see the module docstring. A claim must not fail
    // because a trust *enrichment* did. `fetchBehaviour` is written not to
    // throw, but this function's contract is "resolves to null on any failure"
    // and that promise should not depend on another function keeping its own.
    return null;
  }
}

/**
 * A shared lookup: one upstream request per domain per burst, and a short
 * memory of outages.
 *
 * Two things it does, and one it very deliberately does not.
 *
 * It COALESCES: concurrent misses for one domain share a single request, so a
 * claim and a send attestation firing together cost one call rather than two.
 * The shared promise is discarded the moment it settles — it is a concurrency
 * optimisation, never storage.
 *
 * It REMEMBERS OUTAGES: a throttled or erroring endpoint answers `unknown`
 * immediately instead of costing every caller a 2.5 s wait and another request
 * against a budget that is already exhausted.
 *
 * It never caches a pass. See {@link BehaviourUnavailableEntry}.
 */
export class BehaviourLookup {
  private readonly unavailable = new Map<string, BehaviourUnavailableEntry>();
  private readonly inFlight = new Map<string, Promise<BehaviourClaim | null>>();
  private readonly fetchFn: FetchFn | undefined;
  private readonly apiBase: string | undefined;
  private readonly nowFn: () => number;
  private readonly unavailableTtlMs: number;
  private readonly maxEntries: number;
  private readonly maxConcurrent: number;
  private readonly onUnavailable: ((info: BehaviourUnavailableInfo) => void) | undefined;

  constructor(
    opts: {
      fetchFn?: FetchFn;
      apiBase?: string;
      nowFn?: () => number;
      unavailableTtlMs?: number;
      maxEntries?: number;
      maxConcurrent?: number;
      /**
       * Called once per outage, not once per suppressed lookup. Wired to the
       * host's audit log so an unreachable endpoint is visible,
       * rather than being indistinguishable from an agent that simply has no
       * measurement yet.
       */
      onUnavailable?: (info: BehaviourUnavailableInfo) => void;
    } = {}
  ) {
    this.fetchFn = opts.fetchFn;
    this.apiBase = opts.apiBase;
    this.nowFn = opts.nowFn ?? Date.now;
    // Clamped, not validated: config may only ever SHORTEN this window. A
    // caller asking for an hour gets ten seconds.
    this.unavailableTtlMs = Math.min(
      opts.unavailableTtlMs ?? BEHAVIOUR_UNAVAILABLE_TTL_MS,
      BEHAVIOUR_UNAVAILABLE_TTL_MS
    );
    this.maxEntries = opts.maxEntries ?? BEHAVIOUR_CACHE_MAX_ENTRIES;
    this.maxConcurrent = opts.maxConcurrent ?? BEHAVIOUR_MAX_CONCURRENT;
    this.onUnavailable = opts.onUnavailable;
  }

  // LRU: Map iteration order is insertion order, so re-inserting moves an
  // entry to the back and the front is always the least recently TOUCHED.
  // Touched, not written — a read has to refresh the order too, or this is
  // FIFO wearing an LRU label and a hot domain gets evicted ahead of a cold
  // one.
  private touch(domain: string, entry: BehaviourUnavailableEntry): void {
    this.unavailable.delete(domain);
    this.unavailable.set(domain, entry);
    while (this.unavailable.size > this.maxEntries) {
      const coldest = this.unavailable.keys().next().value as string | undefined;
      if (coldest === undefined) break;
      this.unavailable.delete(coldest);
    }
  }

  /**
   * Tell the operator, and never let telling them break the caller.
   *
   * `onUnavailable` reaches the host's audit log, which may write to a database
   * and can therefore throw — a locked or full database. Unguarded, that rejection
   * propagates out of `get()` and turns an optional trust enrichment into a 500
   * on the claim it sits inside, which is the precise failure this whole module
   * exists to avoid.
   */
  private report(info: BehaviourUnavailableInfo): void {
    try {
      this.onUnavailable?.(info);
    } catch {
      // Deliberately swallowed. A claim must not fail because we could not
      // write down that a lookup failed.
    }
  }

  async get(domain: string): Promise<BehaviourClaim | null> {
    const now = this.nowFn();
    const marked = this.unavailable.get(domain);
    if (marked && now < marked.until) {
      // A hit refreshes eviction order but NOT `until`, which is absolute: an
      // agent being asked about repeatedly must not have its stale-unknown
      // window extended by the asking.
      this.touch(domain, marked);
      return null;
    }
    if (marked) this.unavailable.delete(domain);

    const pending = this.inFlight.get(domain);
    if (pending) return pending;
    if (this.inFlight.size >= this.maxConcurrent) {
      // Unlike the pubkey cache, which throws E_REGISTRY_BUSY because a message
      // cannot be verified without a key, this degrades quietly: a behaviour
      // lookup is an enrichment, and under pressure it reports `unknown` while
      // the claim it sits inside proceeds untouched.
      //
      // Quietly to the CALLER, not to the operator. Shedding load without
      // saying so makes saturation invisible exactly when someone needs to see
      // it, so it is audited — and deliberately not cached, because we declined
      // to ask rather than failed to, and the next call may have a free slot.
      this.report({ domain, reason: "capacity", cached_for_ms: 0 });
      return null;
    }

    const run = this.run(domain).finally(() => {
      this.inFlight.delete(domain);
    });
    this.inFlight.set(domain, run);
    return run;
  }

  private async run(domain: string): Promise<BehaviourClaim | null> {
    let outcome: BehaviourFetchOutcome;
    try {
      outcome = await fetchBehaviour(domain, {
        ...(this.fetchFn ? { fetchFn: this.fetchFn } : {}),
        ...(this.apiBase !== undefined ? { apiBase: this.apiBase } : {}),
      });
    } catch {
      // fetchBehaviour is written not to throw; this is the belt to its braces,
      // because a throw here would propagate into a claim.
      outcome = { kind: "unavailable", reason: "network" };
    }
    if (outcome.kind === "answered") return outcome.claim;

    this.touch(domain, { unavailable: true, until: this.nowFn() + this.unavailableTtlMs });
    this.report({
      domain,
      reason: outcome.reason,
      ...(outcome.status !== undefined ? { status: outcome.status } : {}),
      cached_for_ms: this.unavailableTtlMs,
    });
    return null;
  }
}

let shared: BehaviourLookup | undefined;

/**
 * The process-wide lookup used by the MCP tool surfaces (`zipviz_status` and
 * the send attestation), which run inside a long-lived server and would
 * otherwise each pay full price for an endpoint that is already throttling.
 *
 * ONE PER PROCESS. Separate processes each hold their own instance, which
 * cannot be the same object however they are wired.
 * Two outage memories is the ceiling, not an oversight.
 *
 * Collapsing them would mean a shared store, which puts a network hop and a new
 * failure mode in front of an enrichment whose entire contract is that it must
 * never delay or fail a claim. The rate ceiling is per-IP and both processes sit
 * behind one address, so the halves do share a budget — if that budget ever
 * proves too tight, the answer is a raised ceiling or a longer-lived reading at
 * the origin, not a cache in front of `no-store`.
 *
 * Callers that inject their own `fetchFn` must NOT use this — they build their
 * own instance, so one caller's scripted responses cannot leak into another
 * through a shared outage memory.
 */
export function sharedBehaviourLookup(): BehaviourLookup {
  if (!shared) shared = new BehaviourLookup({ onUnavailable: reportToStderr });
  return shared;
}

/**
 * The MCP process has no audit table of its own, so
 * its outages went nowhere at all: a saturated or throttled lookup in
 * `zipviz_status` or a send attestation produced neither a row nor a line, and
 * the only symptom was a behaviour section quietly missing.
 *
 * stderr, never stdout: a stdio MCP server speaks JSON-RPC on stdout, and a log
 * line written there corrupts the protocol stream.
 *
 * One line per outage, carrying the agent's public `.viz` name and the reason —
 * no message content, no bodies, nothing an operator should not already be able
 * to read off the public registry.
 */
function reportToStderr(info: BehaviourUnavailableInfo): void {
  const status = info.status !== undefined ? ` status=${info.status}` : "";
  process.stderr.write(
    `[zipviz] behaviour lookup unavailable for ${info.domain}: ` +
      `${info.reason}${status} (cached_for_ms=${info.cached_for_ms})\n`
  );
}

/** Test seam: drop the shared instance's outage memory between cases. */
export function resetSharedBehaviourLookup(): void {
  shared = undefined;
}
