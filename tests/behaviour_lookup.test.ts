// One behaviour lookup, and never cache a pass.
//
// Several surfaces hit /v1/blue-tick, including zipviz_status and the send
// attestation, against a 30/min/IP ceiling, uncached. At the rate limit the lookup returns null, so the behaviour section
// silently disappears exactly when traffic is highest.
//
// The fix is deliberately asymmetric, and that asymmetry is the whole design.
// The origin sets `Cache-Control: no-store` so a cache cannot mask a live drift
// moment. A POSITIVE cache would therefore overclaim — it could report a tick
// that has since been withdrawn. A NEGATIVE cache cannot: its worst output is
// `unknown`, which is already the honest answer for a measurement we could not
// obtain. So: coalescing plus a failure-only cache, and no positive cache at
// all. The type of a cache entry cannot hold a tick, which is asserted at
// compile time in behaviour.ts rather than by convention here.
import { describe, expect, it, vi } from "vitest";

import {
  BEHAVIOUR_UNAVAILABLE_TTL_MS,
  BehaviourLookup,
  behaviourUnavailableLevel,
  type BehaviourUnavailableInfo,
} from "../src/core/behaviour.js";

const TICKED = {
  identity: "gary.yc.viz",
  blue_tick: true,
  reputation: {
    entropy_score: 0.0405,
    drift_detected: false,
    z_score: 3.066,
    calibration_stage: "full",
  },
};

const DRIFTED = {
  identity: "gary.yc.viz",
  blue_tick: false,
  reputation: {
    entropy_score: 0.09,
    drift_detected: true,
    z_score: 4.2,
    calibration_stage: "full",
  },
};

function ok(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

/** A fetch that answers from a script, counting every call it receives. */
function scripted(...responses: Array<() => Promise<Response>>) {
  let n = 0;
  const fn = vi.fn(async () => {
    const step = responses[Math.min(n, responses.length - 1)];
    n += 1;
    return step();
  });
  return fn;
}

const always = (body: unknown, status = 200) => async () => ok(body, status);
const throws = (name = "Error") => async () => {
  throw Object.assign(new Error("boom"), { name });
};

function makeClock(start = 1_000_000) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

describe("BehaviourLookup — coalescing", () => {
  it("collapses concurrent lookups for one domain into a single request", async () => {
    const fetchFn = scripted(always(TICKED));
    const lookup = new BehaviourLookup({ fetchFn });

    const [a, b, c] = await Promise.all([
      lookup.get("gary.yc.viz"),
      lookup.get("gary.yc.viz"),
      lookup.get("gary.yc.viz"),
    ]);

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(a!.blue_tick).toBe(true);
    expect(b!.blue_tick).toBe(true);
    expect(c!.blue_tick).toBe(true);
  });

  it("does not persist the coalesced success — a later lookup asks again", async () => {
    // Coalescing is a concurrency optimisation, never a cache. If the shared
    // promise leaked into storage it would be a positive cache by the back
    // door, which is the one thing this milestone must not build.
    const fetchFn = scripted(always(TICKED));
    const lookup = new BehaviourLookup({ fetchFn });

    await Promise.all([lookup.get("gary.yc.viz"), lookup.get("gary.yc.viz")]);
    expect(fetchFn).toHaveBeenCalledTimes(1);

    await lookup.get("gary.yc.viz");
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("does not coalesce across different domains", async () => {
    const fetchFn = scripted(always(TICKED));
    const lookup = new BehaviourLookup({ fetchFn });

    await Promise.all([lookup.get("gary.yc.viz"), lookup.get("stuart.yc.viz")]);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("fails soft rather than throwing when concurrency capacity is exceeded", async () => {
    // The pubkey cache throws E_REGISTRY_BUSY here because a message cannot be
    // verified without a key. A behaviour lookup is an enrichment: under
    // pressure it must report `unknown`, never fail the claim it sits inside.
    let release: (() => void) | undefined;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const fetchFn = vi.fn(async () => {
      await gate;
      return ok(TICKED);
    });
    const lookup = new BehaviourLookup({ fetchFn, maxConcurrent: 2 });

    const pending = [
      lookup.get("a.yc.viz"),
      lookup.get("b.yc.viz"),
      lookup.get("c.yc.viz"),
    ];
    // The third had no slot: it resolves to null immediately, without a request.
    await expect(pending[2]).resolves.toBeNull();
    expect(fetchFn).toHaveBeenCalledTimes(2);
    release!();
    await Promise.all(pending);
  });
});

describe("BehaviourLookup — a success is never cached", () => {
  it("asks again on every sequential lookup", async () => {
    const fetchFn = scripted(always(TICKED));
    const lookup = new BehaviourLookup({ fetchFn });

    await lookup.get("gary.yc.viz");
    await lookup.get("gary.yc.viz");
    await lookup.get("gary.yc.viz");

    expect(fetchFn).toHaveBeenCalledTimes(3);
  });

  it("shows a drift flip on the very next lookup", async () => {
    // The headline test. The origin refuses to let anyone cache this precisely
    // so that a tick withdrawn mid-conversation is visible on the next turn.
    const fetchFn = scripted(always(TICKED), always(DRIFTED));
    const lookup = new BehaviourLookup({ fetchFn });

    const before = await lookup.get("gary.yc.viz");
    const after = await lookup.get("gary.yc.viz");

    expect(before!.blue_tick).toBe(true);
    expect(before!.drift_detected).toBe(false);
    expect(after!.blue_tick).toBe(false);
    expect(after!.drift_detected).toBe(true);
  });

  it("cannot serve a tick out of the cache when the registry goes away", async () => {
    // A stale positive is unreachable by construction: the cache stores an
    // unavailability marker whose TYPE has no field for a claim. The observable
    // consequence is that a tick, followed by a 429, reports the block as
    // ABSENT — not as the previous tick, and not as `blue_tick: false`.
    const fetchFn = scripted(always(TICKED), always({}, 429));
    const lookup = new BehaviourLookup({ fetchFn });

    const first = await lookup.get("gary.yc.viz");
    expect(first!.blue_tick).toBe(true);

    const second = await lookup.get("gary.yc.viz");
    expect(second).toBeNull();
  });
});

describe("BehaviourLookup — only transient outcomes are cached", () => {
  it.each([
    ["a 429 from the rate limiter", always({}, 429)],
    ["a 500 from the origin", always({}, 500)],
    ["a 503 from the origin", always({}, 503)],
    ["a network failure", throws()],
    ["a timeout", throws("TimeoutError")],
    ["a malformed body on a 200", async () => new Response("<html>nope</html>", { status: 200 })],
  ])("remembers %s and answers the next lookup without a request", async (_label, step) => {
    const fetchFn = scripted(step as () => Promise<Response>);
    const lookup = new BehaviourLookup({ fetchFn });

    await expect(lookup.get("gary.yc.viz")).resolves.toBeNull();
    expect(fetchFn).toHaveBeenCalledTimes(1);

    await expect(lookup.get("gary.yc.viz")).resolves.toBeNull();
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it.each([
    [400],
    [401],
    [403],
  ])("caches a persistent %i but names it apart from a flaky endpoint", async (status) => {
    // Caching stays: hammering an endpoint
    // that is rejecting us helps nobody. What changes is that it is no longer
    // filed as the same kind of event as a 429 — this one will still be broken
    // in ten seconds, and an operator should hear it as an error.
    const seen: BehaviourUnavailableInfo[] = [];
    const fetchFn = scripted(always({}, status));
    const lookup = new BehaviourLookup({ fetchFn, onUnavailable: (i) => seen.push(i) });

    await expect(lookup.get("gary.yc.viz")).resolves.toBeNull();
    await expect(lookup.get("gary.yc.viz")).resolves.toBeNull();

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(seen[0].reason).toBe("client_error");
    expect(seen[0].status).toBe(status);
    expect(behaviourUnavailableLevel(seen[0].reason)).toBe("error");
  });

  it.each([
    [408],
    [429],
    [500],
    [503],
  ])("files a %i as a passing moment, not a misconfiguration", async (status) => {
    const seen: BehaviourUnavailableInfo[] = [];
    const lookup = new BehaviourLookup({
      fetchFn: scripted(always({}, status)),
      onUnavailable: (i) => seen.push(i),
    });

    await lookup.get("gary.yc.viz");

    expect(seen[0].reason).toBe("http_status");
    expect(behaviourUnavailableLevel(seen[0].reason)).toBe("warn");
  });

  it("does not cache a 404 — registration state can change under us", async () => {
    // A 404 is an answer about the agent, not a failure to ask. Caching it
    // would keep a freshly registered agent invisible for the whole window.
    const fetchFn = scripted(always({}, 404));
    const lookup = new BehaviourLookup({ fetchFn });

    await expect(lookup.get("new.yc.viz")).resolves.toBeNull();
    await expect(lookup.get("new.yc.viz")).resolves.toBeNull();

    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("does not cache a measured-nothing-yet response", async () => {
    // A 200 with no reputation object is also a real answer, and re-asking is
    // cheap and correct: it is exactly the case that flips to a first reading.
    const body = { identity: "new.yc.viz", blue_tick: null, reputation: null };
    const fetchFn = scripted(always(body));
    const lookup = new BehaviourLookup({ fetchFn });

    await expect(lookup.get("new.yc.viz")).resolves.toBeNull();
    await expect(lookup.get("new.yc.viz")).resolves.toBeNull();

    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("re-asks once the unavailability window has passed", async () => {
    const clock = makeClock();
    const fetchFn = scripted(always({}, 503), always(TICKED));
    const lookup = new BehaviourLookup({ fetchFn, nowFn: clock.now, unavailableTtlMs: 10_000 });

    await expect(lookup.get("gary.yc.viz")).resolves.toBeNull();
    clock.advance(9_999);
    await expect(lookup.get("gary.yc.viz")).resolves.toBeNull();
    expect(fetchFn).toHaveBeenCalledTimes(1);

    clock.advance(2);
    await expect(lookup.get("gary.yc.viz")).resolves.not.toBeNull();
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("lets config shorten the window but never widen it", async () => {
    // This previously clamped to a SEPARATE
    // 30 s ceiling, which meant a caller could widen the 10 s window threefold
    // — the exact thing the rule forbids, undone by having two numbers instead
    // of one. Asking for an hour now gets ten seconds.
    const clock = makeClock();
    const fetchFn = scripted(always({}, 503), always(TICKED));
    const lookup = new BehaviourLookup({
      fetchFn,
      nowFn: clock.now,
      unavailableTtlMs: 60 * 60 * 1000,
    });

    await expect(lookup.get("gary.yc.viz")).resolves.toBeNull();
    clock.advance(BEHAVIOUR_UNAVAILABLE_TTL_MS + 1);

    await expect(lookup.get("gary.yc.viz")).resolves.not.toBeNull();
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("shortens on request, because a caller may always be more cautious", async () => {
    const clock = makeClock();
    const fetchFn = scripted(always({}, 503), always(TICKED));
    const lookup = new BehaviourLookup({ fetchFn, nowFn: clock.now, unavailableTtlMs: 1_000 });

    await expect(lookup.get("gary.yc.viz")).resolves.toBeNull();
    clock.advance(1_001);
    await expect(lookup.get("gary.yc.viz")).resolves.not.toBeNull();
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("reports the window it actually used, not the one it was asked for", async () => {
    const seen: BehaviourUnavailableInfo[] = [];
    const lookup = new BehaviourLookup({
      fetchFn: scripted(always({}, 503)),
      unavailableTtlMs: 60 * 60 * 1000,
      onUnavailable: (i) => seen.push(i),
    });

    await lookup.get("gary.yc.viz");

    expect(seen[0].cached_for_ms).toBe(BEHAVIOUR_UNAVAILABLE_TTL_MS);
  });

  it("bounds the cache so a flood of unique names cannot grow it without limit", async () => {
    const fetchFn = scripted(always({}, 503));
    const lookup = new BehaviourLookup({ fetchFn, maxEntries: 2 });

    await lookup.get("a.yc.viz");
    await lookup.get("b.yc.viz");
    await lookup.get("c.yc.viz");
    expect(fetchFn).toHaveBeenCalledTimes(3);

    // `a` was evicted as the coldest, so it costs a request again; `c` is still
    // remembered and costs nothing.
    await lookup.get("a.yc.viz");
    expect(fetchFn).toHaveBeenCalledTimes(4);
    await lookup.get("c.yc.viz");
    expect(fetchFn).toHaveBeenCalledTimes(4);
  });

  it("evicts the least recently READ, not merely the least recently written", async () => {
    // A cache hit used to return without
    // refreshing insertion order, which made this FIFO wearing an LRU label: a
    // domain being asked about constantly was evicted ahead of one nobody had
    // touched since it was written.
    const clock = makeClock();
    const fetchFn = scripted(always({}, 503));
    const lookup = new BehaviourLookup({ fetchFn, nowFn: clock.now, maxEntries: 2 });

    await lookup.get("a.yc.viz");
    await lookup.get("b.yc.viz");
    expect(fetchFn).toHaveBeenCalledTimes(2);

    // Read `a` — it is now the hottest entry, and `b` the coldest.
    await lookup.get("a.yc.viz");
    expect(fetchFn).toHaveBeenCalledTimes(2);

    // Inserting `c` must evict `b`, not `a`.
    await lookup.get("c.yc.viz");
    expect(fetchFn).toHaveBeenCalledTimes(3);

    await lookup.get("a.yc.viz");
    expect(fetchFn).toHaveBeenCalledTimes(3); // still remembered
    await lookup.get("b.yc.viz");
    expect(fetchFn).toHaveBeenCalledTimes(4); // evicted
  });

  it("does not extend the window just because the domain keeps being asked about", async () => {
    // `until` is absolute. If a hit refreshed it, a busy receiver could hold a
    // stale `unknown` open indefinitely — a slow-motion version of the stale
    // positive this module exists to prevent.
    const clock = makeClock();
    const fetchFn = scripted(always({}, 503), always(TICKED));
    const lookup = new BehaviourLookup({ fetchFn, nowFn: clock.now });

    await lookup.get("gary.yc.viz");
    for (let i = 0; i < 9; i += 1) {
      clock.advance(1_000);
      await lookup.get("gary.yc.viz");
    }
    expect(fetchFn).toHaveBeenCalledTimes(1);

    clock.advance(1_001);
    await expect(lookup.get("gary.yc.viz")).resolves.not.toBeNull();
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });
});

describe("valid JSON that is not the expected shape", () => {
  // Finding 3. `JSON.parse("null")` succeeds, so the
  // parse guard let it through and `data.reputation` then threw OUTSIDE it.
  // That broke `lookupBehaviour`'s documented "resolves to null on any failure"
  // contract outright — a regression introduced by refactoring the original
  // whole-body try/catch into a narrower one — and `BehaviourLookup` caught the
  // throw but filed it as `network`, blaming the transport for a body problem.
  const shapes: Array<[string, string]> = [
    ["null", "null"],
    ["a bare true", "true"],
    ["a number", "123"],
    ["a string", '"nope"'],
    ["an array", "[]"],
  ];

  it.each(shapes)("makes %s fail soft rather than throw", async (_label, raw) => {
    const { lookupBehaviour } = await import("../src/core/behaviour.js");
    await expect(
      lookupBehaviour("gary.yc.viz", {
        fetchFn: async () => new Response(raw, { status: 200 }),
      })
    ).resolves.toBeNull();
  });

  it.each(shapes)("classifies %s as malformed, not as a network failure", async (_label, raw) => {
    const seen: BehaviourUnavailableInfo[] = [];
    const lookup = new BehaviourLookup({
      fetchFn: async () => new Response(raw, { status: 200 }),
      onUnavailable: (i) => seen.push(i),
    });

    await expect(lookup.get("gary.yc.viz")).resolves.toBeNull();
    expect(seen).toHaveLength(1);
    expect(seen[0].reason).toBe("malformed");
  });

  // The nested half of the same bug, and far worse than the top-level one:
  // reading a field off a primitive does NOT throw in JS, it silently yields
  // undefined. So `{"blue_tick":true,"reputation":true}` walked straight past
  // the truthiness check and produced "Trust status: earned. Behavior matches
  // this agent's established baseline." from a body containing no measurement
  // whatsoever — the exact fabrication this milestone exists to prevent.
  // Pre-existing on main, not
  // introduced by M0, which means it is live today.
  const nested: Array<[string, string]> = [
    ["a boolean", '{"blue_tick":true,"reputation":true}'],
    ["a number", '{"blue_tick":true,"reputation":123}'],
    ["a string", '{"blue_tick":true,"reputation":"full"}'],
    ["an array", '{"blue_tick":true,"reputation":[]}'],
    ["an empty object", '{"blue_tick":true,"reputation":{}}'],
  ];

  it.each(nested)("refuses to mint a tick from %s reputation", async (_label, raw) => {
    const { lookupBehaviour } = await import("../src/core/behaviour.js");
    const claim = await lookupBehaviour("gary.yc.viz", {
      fetchFn: async () => new Response(raw, { status: 200 }),
    });
    // Absent, not `blue_tick: false`. We do not know that they lack a tick; we
    // know we were handed something we cannot read.
    expect(claim).toBeNull();
  });

  it.each(nested)("classifies %s reputation as malformed", async (_label, raw) => {
    const seen: BehaviourUnavailableInfo[] = [];
    const lookup = new BehaviourLookup({
      fetchFn: async () => new Response(raw, { status: 200 }),
      onUnavailable: (i) => seen.push(i),
    });

    await expect(lookup.get("gary.yc.viz")).resolves.toBeNull();
    expect(seen).toHaveLength(1);
    expect(seen[0].reason).toBe("malformed");
  });

  it("rejects a partial reputation, however plausible it looks", async () => {
    // SUPERSEDED, deliberately. This used to assert that a stage-only
    // reputation was accepted, on the theory that "one usable field" was a
    // reasonable bar and a full-schema check would be a lock-in. A later fifth
    // review compared the consumer against BOTH producers and showed the bar
    // was too low: the producer always emits all four measurement fields, so a
    // body missing three of them is not an early ladder rung, it is a body the
    // service would never send — and it minted an earned tick.
    const { lookupBehaviour } = await import("../src/core/behaviour.js");
    const claim = await lookupBehaviour("new.yc.viz", {
      fetchFn: async () =>
        new Response(
          '{"identity":"new.yc.viz","blue_tick":false,"reputation":{"calibration_stage":"cohort"}}',
          { status: 200 }
        ),
    });
    expect(claim).toBeNull();
  });

  it("still treats a well-shaped body with no reputation as a real absence", async () => {
    // The guard must reject non-objects without also swallowing the legitimate
    // "measured nothing yet" answer, which is an object and must stay uncached.
    const seen: BehaviourUnavailableInfo[] = [];
    const fetchFn = scripted(always({ identity: "n.yc.viz", blue_tick: null, reputation: null }));
    const lookup = new BehaviourLookup({ fetchFn, onUnavailable: (i) => seen.push(i) });

    await expect(lookup.get("n.yc.viz")).resolves.toBeNull();
    await expect(lookup.get("n.yc.viz")).resolves.toBeNull();

    expect(seen).toHaveLength(0);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });
});

describe("the response must be about the agent we asked about", () => {
  // The endpoint's contract echoes
  // `identity`, and nothing checked it — so a misrouted, stale, or wrongly
  // keyed response transferred one agent's earned tick onto another. The
  // receiver already binds a message to its recipient for exactly this reason;
  // a trust claim deserves the same, and did not have it.
  //
  // Pre-existing on main, not introduced by M0.
  const VICTIM = "victim.yc.viz";
  const rep =
    '"reputation":{"calibration_stage":"full","z_score":3.1,"entropy_score":0.04,"drift_detected":false}';

  it("refuses a claim whose identity names a different agent", async () => {
    const { lookupBehaviour } = await import("../src/core/behaviour.js");
    const claim = await lookupBehaviour(VICTIM, {
      fetchFn: async () =>
        new Response(`{"identity":"attacker.yc.viz","blue_tick":true,${rep}}`, { status: 200 }),
    });
    // The security property in one line: another agent's tick never becomes
    // this agent's tick.
    expect(claim).toBeNull();
  });

  it.each([
    ["a different agent", '"identity":"attacker.yc.viz",'],
    ["no identity at all", ""],
    ["a non-string identity", '"identity":123,'],
    ["a null identity", '"identity":null,'],
  ])("classifies %s as malformed", async (_label, ident) => {
    const seen: BehaviourUnavailableInfo[] = [];
    const lookup = new BehaviourLookup({
      fetchFn: async () => new Response(`{${ident}"blue_tick":true,${rep}}`, { status: 200 }),
      onUnavailable: (i) => seen.push(i),
    });

    await expect(lookup.get(VICTIM)).resolves.toBeNull();
    expect(seen).toHaveLength(1);
    expect(seen[0].reason).toBe("malformed");
  });

  it("binds case-insensitively, because .viz names are not case-sensitive", async () => {
    const { lookupBehaviour } = await import("../src/core/behaviour.js");
    const claim = await lookupBehaviour(VICTIM, {
      fetchFn: async () =>
        new Response(`{"identity":"VICTIM.YC.VIZ","blue_tick":true,${rep}}`, { status: 200 }),
    });
    expect(claim).not.toBeNull();
    expect(claim!.blue_tick).toBe(true);
  });

  it("binds the absence answer too, not just the measured one", async () => {
    // A misrouted "nothing measured" is less dangerous than a misrouted tick,
    // but it is still not an answer about us, and treating it as one would let
    // a wrong response masquerade as a real absence.
    const seen: BehaviourUnavailableInfo[] = [];
    const lookup = new BehaviourLookup({
      fetchFn: async () =>
        new Response('{"identity":"someone.else.viz","blue_tick":null,"reputation":null}', {
          status: 200,
        }),
      onUnavailable: (i) => seen.push(i),
    });

    await expect(lookup.get(VICTIM)).resolves.toBeNull();
    expect(seen[0].reason).toBe("malformed");
  });
});

describe("a measured response must carry a real boolean tick", () => {
  // Finding 1b — the mirror of the fabrication
  // bug. `data.blue_tick === true` turned an ABSENT or non-boolean tick into a
  // definite `false`, which reads to a human as "not held". Fabricating a
  // negative from garbage breaks the same rule as fabricating a positive:
  // never a pass, never a failure, `unknown` when we do not know.
  const V = "gary.yc.viz";
  const rep =
    '"reputation":{"calibration_stage":"full","entropy_score":0.04,"z_score":3.1,"drift_detected":false}';

  it.each([
    ["absent", ""],
    ["a string", '"blue_tick":"true",'],
    ["a number", '"blue_tick":1,'],
    ["null", '"blue_tick":null,'],
  ])("refuses to read %s as 'not held'", async (_label, tick) => {
    const seen: BehaviourUnavailableInfo[] = [];
    const lookup = new BehaviourLookup({
      fetchFn: async () => new Response(`{"identity":"${V}",${tick}${rep}}`, { status: 200 }),
      onUnavailable: (i) => seen.push(i),
    });

    const claim = await lookup.get(V);
    expect(claim).toBeNull();
    expect(seen[0].reason).toBe("malformed");
  });

  it("still accepts an honest false", async () => {
    // The whole point of the milestone is that a real negative survives. Only
    // an unreadable one is discarded.
    const { lookupBehaviour } = await import("../src/core/behaviour.js");
    const claim = await lookupBehaviour(V, {
      fetchFn: async () =>
        new Response(`{"identity":"${V}","blue_tick":false,${rep}}`, { status: 200 }),
    });
    expect(claim).not.toBeNull();
    expect(claim!.blue_tick).toBe(false);
    expect(claim!.summary).toContain("not held");
  });

  it("leaves the unmeasured path alone — that is an answer, not a malformed body", async () => {
    const seen: BehaviourUnavailableInfo[] = [];
    const fetchFn = scripted(
      always({ identity: V, blue_tick: null, reputation: null })
    );
    const lookup = new BehaviourLookup({ fetchFn, onUnavailable: (i) => seen.push(i) });

    await expect(lookup.get(V)).resolves.toBeNull();
    await expect(lookup.get(V)).resolves.toBeNull();

    expect(seen).toHaveLength(0);
    expect(fetchFn).toHaveBeenCalledTimes(2); // uncached: a real absence re-asks
  });
});

describe("the response must match the producer contract, whole", () => {
  // The bar was "at least one usable field",
  // which I chose in round three and flagged as possibly too loose. It was.
  // Verified against both producers rather than taken on trust:
  //
  //   the registry returns either `blue_tick: null` with `reputation: null`,
  //   or a boolean tick with a reputation object of exactly four fields:
  //   `drift_detected` (always a boolean), `entropy_score` and `z_score`
  //   (number or null), and `calibration_stage` (never null: a measured
  //   stage or the `unseen` sentinel).
  //
  // So a partial or wrong-typed body is not an early ladder rung to be
  // tolerated — it is a response the service would never send, and it was
  // minting earned ticks.
  const V = "victim.yc.viz";
  const full = {
    identity: V,
    blue_tick: true,
    reputation: {
      entropy_score: 0.0405,
      drift_detected: false,
      z_score: 3.066,
      calibration_stage: "full",
    },
  };
  const withRep = (over: Record<string, unknown>) => ({
    ...full,
    reputation: { ...full.reputation, ...over },
  });
  const dropRep = (key: string) => {
    const rep: Record<string, unknown> = { ...full.reputation };
    delete rep[key];
    return { ...full, reputation: rep };
  };

  const accepted: Array<[string, unknown]> = [
    ["the fully measured form", full],
    [
      "a measured negative with no latest composite",
      { ...withRep({ entropy_score: null }), blue_tick: false },
    ],
    ["an honest negative", { ...full, blue_tick: false }],
    [
      "a drifting agent with the tick withheld",
      { ...withRep({ drift_detected: true }), blue_tick: false },
    ],
    ["the unmeasured form", { identity: V, blue_tick: null, reputation: null }],
    [
      "the exact unseen no-claim form",
      {
        identity: V,
        blue_tick: false,
        reputation: {
          entropy_score: null,
          drift_detected: false,
          z_score: null,
          calibration_stage: "unseen",
        },
      },
    ],
    ...(["basic", "full"].map(
      (stage) => [`a positive '${stage}' rung`, withRep({ calibration_stage: stage })] as [string, unknown]
    )),
    ...(["uncalibrated", "declared", "cohort", "degenerate"].map(
      (stage) => [
        `a negative '${stage}' rung`,
        { ...withRep({ calibration_stage: stage }), blue_tick: false },
      ] as [string, unknown]
    )),
  ];

  const rejected: Array<[string, unknown]> = [
    ["a missing entropy_score", dropRep("entropy_score")],
    ["a missing z_score", dropRep("z_score")],
    ["a missing drift_detected", dropRep("drift_detected")],
    ["a missing calibration_stage", dropRep("calibration_stage")],
    ["a stringified entropy_score", withRep({ entropy_score: "0.1" })],
    ["a negative entropy_score", withRep({ entropy_score: -0.01 })],
    ["an entropy_score above one", withRep({ entropy_score: 1.01 })],
    ["an array z_score", withRep({ z_score: [] })],
    ["a null measured z_score", { ...withRep({ z_score: null }), blue_tick: false }],
    ["a negative measured z_score", { ...withRep({ z_score: -0.01 }), blue_tick: false }],
    ["a stringified drift_detected", withRep({ drift_detected: "false" })],
    ["a non-finite entropy_score string", withRep({ entropy_score: "NaN" })],
    ["an invented calibration_stage", withRep({ calibration_stage: "fabricated" })],
    ["the invented stage 'calibrated'", withRep({ calibration_stage: "calibrated" })],
    ["a non-string calibration_stage", withRep({ calibration_stage: 3 })],
    [
      "a tick on the unseen no-claim shape",
      {
        identity: V,
        blue_tick: true,
        reputation: {
          entropy_score: null,
          drift_detected: false,
          z_score: null,
          calibration_stage: "unseen",
        },
      },
    ],
    ["unseen with measured scores", withRep({ calibration_stage: "unseen" })],
    [
      "unseen with drift",
      {
        identity: V,
        blue_tick: false,
        reputation: {
          entropy_score: null,
          drift_detected: true,
          z_score: null,
          calibration_stage: "unseen",
        },
      },
    ],
    ["a tick asserted while drifting", withRep({ drift_detected: true })],
    ["a tick without a latest composite", withRep({ entropy_score: null })],
    ...(["uncalibrated", "declared", "cohort", "degenerate"].map(
      (stage) => [
        `a tick asserted at the '${stage}' rung`,
        withRep({ calibration_stage: stage }),
      ] as [string, unknown]
    )),
    // The contradiction: the producer only ever pairs a null tick with a null
    // reputation. A true tick beside no measurement at all is not an absence.
    ["a tick asserted with no measurement", { identity: V, blue_tick: true, reputation: null }],
    ["a false tick asserted with no measurement", { identity: V, blue_tick: false, reputation: null }],
    ["a missing reputation key entirely", { identity: V, blue_tick: true }],
  ];

  it.each(accepted)("accepts %s", async (_label, body) => {
    const { lookupBehaviour } = await import("../src/core/behaviour.js");
    const claim = await lookupBehaviour(V, { fetchFn: always(body) });
    // The unmeasured form is a real absence: null claim, but NOT malformed.
    const isUnmeasured = (body as { reputation: unknown }).reputation === null;
    if (isUnmeasured) expect(claim).toBeNull();
    else expect(claim).not.toBeNull();
  });

  it.each(accepted)("does not report %s as an outage", async (_label, body) => {
    const seen: BehaviourUnavailableInfo[] = [];
    const lookup = new BehaviourLookup({ fetchFn: always(body), onUnavailable: (i) => seen.push(i) });
    await lookup.get(V);
    expect(seen).toHaveLength(0);
  });

  it.each(rejected)("rejects %s, with no claim and a malformed report", async (_label, body) => {
    const seen: BehaviourUnavailableInfo[] = [];
    const lookup = new BehaviourLookup({ fetchFn: always(body), onUnavailable: (i) => seen.push(i) });

    await expect(lookup.get(V)).resolves.toBeNull();
    expect(seen).toHaveLength(1);
    expect(seen[0].reason).toBe("malformed");
  });

  it("ignores unknown extra fields, so the producer can grow", async () => {
    // Forward compatibility deliberately survives the tightening: a new field
    // must not take the whole response down.
    const { lookupBehaviour } = await import("../src/core/behaviour.js");
    const claim = await lookupBehaviour(V, {
      fetchFn: always({
        ...full,
        measured: true,
        some_future_field: { nested: true },
        reputation: { ...full.reputation, extra_number: 191 },
      }),
    });
    expect(claim).not.toBeNull();
    expect(claim!.blue_tick).toBe(true);
    expect(claim!.calibration_stage).toBe("full");
    expect(claim).not.toHaveProperty("extra_number");
    expect(claim).not.toHaveProperty("some_future_field");
    expect(claim).not.toHaveProperty("measured");
  });
});

describe("BehaviourLookup — an outage is audible", () => {
  it("reports the reason and status when a lookup is unavailable", async () => {
    const seen: BehaviourUnavailableInfo[] = [];
    const fetchFn = scripted(always({}, 429));
    const lookup = new BehaviourLookup({
      fetchFn,
      onUnavailable: (info) => seen.push(info),
    });

    await lookup.get("gary.yc.viz");

    expect(seen).toHaveLength(1);
    expect(seen[0].domain).toBe("gary.yc.viz");
    expect(seen[0].reason).toBe("http_status");
    expect(seen[0].status).toBe(429);
    expect(seen[0].cached_for_ms).toBeGreaterThan(0);
  });

  it.each([
    ["a network failure", throws(), "network"],
    ["a timeout", throws("TimeoutError"), "timeout"],
    ["a malformed body", async () => new Response("nope", { status: 200 }), "malformed"],
  ])("names %s as its own reason", async (_label, step, reason) => {
    const seen: BehaviourUnavailableInfo[] = [];
    const lookup = new BehaviourLookup({
      fetchFn: scripted(step as () => Promise<Response>),
      onUnavailable: (info) => seen.push(info),
    });

    await lookup.get("gary.yc.viz");

    expect(seen).toHaveLength(1);
    expect(seen[0].reason).toBe(reason);
  });

  it("stays silent when the answer is a real absence rather than an outage", async () => {
    // Neither a 404 nor a measured-nothing-yet is an outage. Auditing them
    // would bury the real outages in noise from agents that simply have no
    // reading yet.
    const seen: BehaviourUnavailableInfo[] = [];
    const make = (step: () => Promise<Response>) =>
      new BehaviourLookup({ fetchFn: scripted(step), onUnavailable: (i) => seen.push(i) });

    await make(always({}, 404)).get("new.yc.viz");
    await make(
      always({ identity: "new.yc.viz", blue_tick: null, reputation: null })
    ).get("new.yc.viz");

    expect(seen).toHaveLength(0);
  });

  it("survives an audit sink that throws", async () => {
    // Finding 4. `onUnavailable` reaches the host's
    // audit log, which may write to a database and can therefore throw — a locked or
    // full database. Unguarded, that rejection propagated out of get() and
    // turned an optional trust enrichment into a 500 on the claim it sits
    // inside: the precise failure this module exists to avoid.
    const lookup = new BehaviourLookup({
      fetchFn: scripted(always({}, 503)),
      onUnavailable: () => {
        throw new Error("SQLITE_BUSY: database is locked");
      },
    });

    await expect(lookup.get("gary.yc.viz")).resolves.toBeNull();
    // And the outage is still remembered — the failed write must not cost us
    // the cache entry as well.
    await expect(lookup.get("gary.yc.viz")).resolves.toBeNull();
  });

  it("reports shed load rather than dropping it silently", async () => {
    // Degrading to `unknown` under pressure
    // is right — a behaviour lookup must never fail the claim it sits inside —
    // but degrading INVISIBLY means saturation is unobservable exactly when
    // someone needs to see it. Quiet to the caller, loud to the operator.
    const seen: BehaviourUnavailableInfo[] = [];
    let release: (() => void) | undefined;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const fetchFn = vi.fn(async () => {
      await gate;
      return ok(TICKED);
    });
    const lookup = new BehaviourLookup({
      fetchFn,
      maxConcurrent: 1,
      onUnavailable: (i) => seen.push(i),
    });

    const pending = [lookup.get("a.yc.viz"), lookup.get("b.yc.viz")];
    await expect(pending[1]).resolves.toBeNull();

    expect(seen).toHaveLength(1);
    expect(seen[0].domain).toBe("b.yc.viz");
    expect(seen[0].reason).toBe("capacity");
    // NOT cached: we declined to ask rather than failed to, and the next call
    // may find a free slot. Caching it would turn one busy instant into ten
    // seconds of blindness.
    expect(seen[0].cached_for_ms).toBe(0);

    release!();
    await Promise.all(pending);

    await lookup.get("b.yc.viz");
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("does not re-report an outage it is already serving from the cache", async () => {
    const seen: BehaviourUnavailableInfo[] = [];
    const lookup = new BehaviourLookup({
      fetchFn: scripted(always({}, 503)),
      onUnavailable: (info) => seen.push(info),
    });

    await lookup.get("gary.yc.viz");
    await lookup.get("gary.yc.viz");
    await lookup.get("gary.yc.viz");

    expect(seen).toHaveLength(1);
  });
});

describe("BehaviourLookup — it asks the public endpoint", () => {
  it("uses the same URL any third party would", async () => {
    let seen = "";
    const lookup = new BehaviourLookup({
      apiBase: "https://api.example.test/",
      fetchFn: async (url) => {
        seen = String(url);
        return ok(TICKED);
      },
    });

    await lookup.get("gary.yc.viz");

    expect(seen).toBe("https://api.example.test/v1/blue-tick/gary.yc.viz");
  });
});

describe("the shared instance", () => {
  it("is process-wide, and resettable so one test cannot poison the next", async () => {
    // The MCP tool surfaces share one lookup because they run inside a
    // long-lived server. That is right in production and hazardous in a test
    // file, where a scripted outage would otherwise silence the next case's
    // request. The reset seam is what keeps those two facts compatible.
    const { sharedBehaviourLookup, resetSharedBehaviourLookup } = await import(
      "../src/core/behaviour.js"
    );

    const first = sharedBehaviourLookup();
    expect(sharedBehaviourLookup()).toBe(first);

    resetSharedBehaviourLookup();
    expect(sharedBehaviourLookup()).not.toBe(first);
    resetSharedBehaviourLookup();
  });

  it("is not touched by a caller that injects its own transport", async () => {
    // attestReply with an explicit behaviourFetchFn must build a throwaway
    // lookup. If it used the shared one, a test's scripted 503 would leak into
    // every later send in the same process.
    const { sharedBehaviourLookup, resetSharedBehaviourLookup } = await import(
      "../src/core/behaviour.js"
    );
    resetSharedBehaviourLookup();

    const injected = new BehaviourLookup({ fetchFn: scripted(always({}, 503)) });
    await injected.get("gary.yc.viz");

    // The shared instance never saw it: a fresh lookup for the same domain
    // still issues a request.
    const probe = scripted(always(TICKED));
    const shared = sharedBehaviourLookup();
    // Prove they are distinct objects rather than asserting on private state.
    expect(shared).not.toBe(injected);
    await new BehaviourLookup({ fetchFn: probe }).get("gary.yc.viz");
    expect(probe).toHaveBeenCalledTimes(1);
    resetSharedBehaviourLookup();
  });
});
