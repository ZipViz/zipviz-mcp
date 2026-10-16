import { describe, it, expect, vi, afterEach } from "vitest";
import {
  attestReply,
  extractReplyMetadata,
  type VerifyFn,
} from "../src/lib/reply-attestation.js";
import type { A2AResponse, VerifyResponse } from "../src/lib/types.js";

const RECIPIENT = "ticki.adkgo.viz";
const REPLY_TEXT = "Yes, I'm here Bluey. Ticki, online.";
const GOOD_META = {
  from: RECIPIENT,
  timestamp: "2026-07-25T01:00:00.000Z",
  signature: "c2lnbmF0dXJlLWJ5dGVzLWJhc2U2NA==",
};

// A verify fn that returns a fixed verdict and records what it was asked to
// verify — so we can assert the exact {from,message,timestamp,signature} the
// module reconstructs from the reply metadata.
/**
 * A complete reputation object in the producer's shape — the companion a
 * boolean `blue_tick` always travels with. `entropy_score`/`z_score` are
 * numbers here; both are legitimately null on the cold-start path.
 */
const MEASURED_REPUTATION = {
  entropy_score: 0.42,
  drift_detected: false,
  z_score: 1.1,
  calibration_stage: "full",
};

function stubVerify(
  verdict: VerifyResponse
): { fn: VerifyFn; calls: any[] } {
  const calls: any[] = [];
  const fn: VerifyFn = async (body) => {
    calls.push(body);
    if (!verdict.verified) return verdict;
    // Answer with a body the SERVICE COULD ACTUALLY SEND.
    //
    // This helper already did that for `identity` — "a fixture answering with
    // no identity is not a simplification, it is a body the service would never
    // send" — and then went on to answer with a tick and no reputation, and no
    // `freshness_checked`, which the Worker cannot emit either. Since the whole
    // contract is now validated, those fixtures would be rejected, and rightly.
    //
    // The producer's success body (the registry, POST /v1/verify):
    //   { verified, identity, signing_version: 0|1, freshness_checked: true,
    //     reputation: null|{4 fields}, blue_tick: null|boolean }
    // `blue_tick` and `reputation` are set together or not at all.
    //
    // A test that wants an off-contract body sets the fields explicitly; the
    // adversarial matrix in reply_attestation_boundary.test.ts does exactly
    // that, and this default must never be used to make one of those pass.
    const filled: VerifyResponse = { ...verdict };
    if (filled.identity === undefined) filled.identity = body.from;
    if (filled.signing_version === undefined) filled.signing_version = 1;
    if (filled.freshness_checked === undefined) filled.freshness_checked = true;
    if (typeof filled.blue_tick === "boolean" && filled.reputation === undefined) {
      filled.reputation = MEASURED_REPUTATION;
    }
    return filled;
  };
  return { fn, calls };
}

function messageShape(meta?: unknown): A2AResponse {
  return {
    jsonrpc: "2.0",
    id: 1,
    result: {
      message: {
        messageId: "resp-1",
        role: "agent",
        parts: [{ kind: "text", text: REPLY_TEXT }],
        ...(meta !== undefined ? { metadata: { zipviz: meta as any } } : {}),
      },
    },
  };
}

function taskShape(meta: unknown): A2AResponse {
  return {
    jsonrpc: "2.0",
    id: 1,
    result: {
      artifacts: [
        { artifactId: "a1", parts: [{ kind: "text", text: REPLY_TEXT }] },
      ],
      status: {
        state: "completed",
        message: {
          role: "agent",
          parts: [],
          metadata: { zipviz: meta as any },
        },
      },
    },
  };
}

function bandShape(meta: unknown): A2AResponse {
  // BAND-compatible: signed-reply block on the top-level result.metadata.
  return {
    jsonrpc: "2.0",
    id: 1,
    result: {
      message: {
        role: "agent",
        parts: [{ kind: "text", text: REPLY_TEXT }],
      },
      metadata: { zipviz: meta as any },
    },
  };
}

describe("extractReplyMetadata", () => {
  it("finds metadata in the message-based shape", () => {
    expect(extractReplyMetadata(messageShape(GOOD_META))).toEqual(GOOD_META);
  });
  it("finds metadata in the task-based (status.message) shape", () => {
    expect(extractReplyMetadata(taskShape(GOOD_META))).toEqual(GOOD_META);
  });
  it("finds metadata on a task artifact", () => {
    const resp: A2AResponse = {
      jsonrpc: "2.0",
      id: 1,
      result: {
        artifacts: [
          {
            artifactId: "a1",
            parts: [{ kind: "text", text: REPLY_TEXT }],
            metadata: { zipviz: GOOD_META },
          },
        ],
      },
    };
    expect(extractReplyMetadata(resp)).toEqual(GOOD_META);
  });
  it("finds metadata in the BAND-compatible top-level result.metadata", () => {
    expect(extractReplyMetadata(bandShape(GOOD_META))).toEqual(GOOD_META);
  });
  it("returns null when there is no result", () => {
    expect(extractReplyMetadata({ jsonrpc: "2.0", id: 1 })).toBeNull();
  });
  it("returns null when no zipviz metadata is attached", () => {
    expect(extractReplyMetadata(messageShape())).toBeNull();
  });
});

describe("attestReply", () => {
  it("verifies a valid signed reply (message shape) and reports the exact verify body", async () => {
    const { fn, calls } = stubVerify({
      verified: true,
      signing_version: 1,
      blue_tick: true,
    });
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape(GOOD_META),
      verifyFn: fn,
      // no network: this suite stubs the verifier only
      behaviourFetchFn: null,
    });
    expect(att.reply_verified).toBe(true);
    expect(att.reply_from).toBe(RECIPIENT);
    expect(att.reply_blue_tick).toBe(true);
    expect(att.reply_signing_version).toBe(1);
    expect(att.reply_failure_reason).toBeUndefined();
    // The module verified the EXACT reply text/timestamp/signature.
    expect(calls[0]).toEqual({
      from: RECIPIENT,
      message: REPLY_TEXT,
      timestamp: GOOD_META.timestamp,
      signature: GOOD_META.signature,
    });
  });

  it("canonicalizes the bounded reply_from on a verified success", async () => {
    const upper = RECIPIENT.toUpperCase();
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape({ ...GOOD_META, from: upper }),
      verifyFn: async () => ({
        verified: true,
        identity: upper,
        signing_version: 1,
        freshness_checked: true,
        blue_tick: null,
        reputation: null,
      }),
      behaviourFetchFn: null,
    });
    expect(att.reply_verified).toBe(true);
    expect(att.reply_from).toBe(RECIPIENT);
  });

  it("verifies the task-based (ADK Go) shape", async () => {
    const { fn } = stubVerify({
      verified: true,
      signing_version: 1,
      blue_tick: true,
    });
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: taskShape(GOOD_META),
      verifyFn: fn,
      // no network: this suite stubs the verifier only
      behaviourFetchFn: null,
    });
    expect(att.reply_verified).toBe(true);
    expect(att.reply_blue_tick).toBe(true);
  });

  it("verifies the BAND-compatible shape and preserves the metadata", async () => {
    const { fn, calls } = stubVerify({
      verified: true,
      signing_version: 1,
      blue_tick: false,
    });
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: bandShape(GOOD_META),
      verifyFn: fn,
      // no network: this suite stubs the verifier only
      behaviourFetchFn: null,
    });
    expect(att.reply_verified).toBe(true);
    expect(att.reply_blue_tick).toBe(false); // verified, but no trust status
    expect(calls[0].signature).toBe(GOOD_META.signature);
  });

  // The signing version MUST come from the verifier's
  // authenticated result, never the recipient's untrusted reply metadata.
  it("uses the verifier's signing_version, not an inflated metadata claim", async () => {
    const { fn } = stubVerify({
      verified: true,
      signing_version: 1,
      blue_tick: true,
    });
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      // Reply metadata lies and claims v2; the verifier authenticated v1.
      response: messageShape({ ...GOOD_META, signing_version: 2 }),
      verifyFn: fn,
      // no network: this suite stubs the verifier only
      behaviourFetchFn: null,
    });
    // The verifier wins: 1, never the metadata's 2.
    expect(att.reply_signing_version).toBe(1);
  });

  it("reports a verifier-confirmed legacy v0 signature as 0, never defaulting to 1", async () => {
    const { fn } = stubVerify({ verified: true, signing_version: 0 });
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape(GOOD_META), // no version declared in metadata
      verifyFn: fn,
      // no network: this suite stubs the verifier only
      behaviourFetchFn: null,
    });
    expect(att.reply_verified).toBe(true);
    expect(att.reply_signing_version).toBe(0);
  });

  it("does not let a metadata version override a verifier-confirmed v0", async () => {
    const { fn } = stubVerify({ verified: true, signing_version: 0 });
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape({ ...GOOD_META, signing_version: 2 }),
      verifyFn: fn,
      // no network: this suite stubs the verifier only
      behaviourFetchFn: null,
    });
    expect(att.reply_signing_version).toBe(0);
  });

  it("makes no claim at all when a success verdict omits the signing version", async () => {
    // SUPERSEDED ASSERTION, named rather than quietly changed. This used to
    // assert `reply_verified: true` with `reply_signing_version: null` — "no
    // authenticated version available → null, not the metadata's 2". The intent
    // (never inflate a version from metadata) was right and still holds; the
    // shape it was asserted on was wrong. `/v1/verify` emits `signing_version`
    // on every success (0 or 1), so a success body without one is
    // not a producer body at all, and the whole-contract check now refuses to
    // attribute it. Refusing outright is strictly stronger than verifying it
    // and reporting null: the metadata's 2 cannot leak into the attestation if
    // there is no attestation.
    const exact: VerifyFn = async (body) => ({
      verified: true,
      identity: body.from,
      freshness_checked: true,
      blue_tick: null,
      reputation: null,
    });
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape({ ...GOOD_META, signing_version: 2 }),
      verifyFn: exact,
      // no network: this suite stubs the verifier only
      behaviourFetchFn: null,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("verdict_off_contract");
    expect(att.reply_signing_version).toBeNull();
    expect(att.reply_blue_tick).toBe("unknown");
  });

  it("never claims verification when metadata is missing (unsigned reply)", async () => {
    const verify = vi.fn();
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape(), // no metadata
      verifyFn: verify as unknown as VerifyFn,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("missing_metadata");
    expect(att.reply_from).toBeNull();
    // Fails closed WITHOUT calling the verify endpoint.
    expect(verify).not.toHaveBeenCalled();
  });

  it("fails closed on identity mismatch and does not call verify", async () => {
    const verify = vi.fn();
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape({ ...GOOD_META, from: "evil.smc.viz" }),
      verifyFn: verify as unknown as VerifyFn,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("identity_mismatch");
    expect(att.reply_from).toBe("evil.smc.viz");
    expect(verify).not.toHaveBeenCalled();
  });

  it("nulls an invalid claimed identity on the identity-mismatch path", async () => {
    const verify = vi.fn();
    const hostileFrom = "evil\u001b[31m." + "x".repeat(10_000) + ".viz";
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape({ ...GOOD_META, from: hostileFrom }),
      verifyFn: verify as unknown as VerifyFn,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("identity_mismatch");
    expect(att.reply_from).toBeNull();
    expect(JSON.stringify(att)).not.toContain(hostileFrom);
    expect(verify).not.toHaveBeenCalled();
  });

  it("fails closed on malformed metadata (missing signature) without calling verify", async () => {
    const verify = vi.fn();
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape({ from: RECIPIENT, timestamp: GOOD_META.timestamp }),
      verifyFn: verify as unknown as VerifyFn,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("malformed_metadata");
    expect(verify).not.toHaveBeenCalled();
  });

  it.each([
    ["oversized text", "x".repeat(10_000) + ".viz"],
    ["control text", "evil\u001b[31m.viz"],
    ["a Unicode lookalike", "t\u212Acki.adkgo.viz"],
  ])("does not echo %s as reply_from on an early failure", async (_label, from) => {
    const verify = vi.fn();
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape({ from, timestamp: GOOD_META.timestamp }),
      verifyFn: verify as unknown as VerifyFn,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("malformed_metadata");
    expect(att.reply_from).toBeNull();
    expect(JSON.stringify(att)).not.toContain(from);
    expect(verify).not.toHaveBeenCalled();
  });

  it("fails closed on malformed metadata (non-string signature)", async () => {
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape({ ...GOOD_META, signature: 12345 }),
      verifyFn: stubVerify({ verified: true }).fn,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("malformed_metadata");
  });

  it("fails when the reply text was modified (verifier returns E_SIG_MISMATCH)", async () => {
    const { fn } = stubVerify({ verified: false, code: "E_SIG_MISMATCH" });
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: "tampered reply text",
      response: messageShape(GOOD_META),
      verifyFn: fn,
      // no network: this suite stubs the verifier only
      behaviourFetchFn: null,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_blue_tick).toBe("unknown");
    expect(att.reply_failure_reason).toBe("E_SIG_MISMATCH");
    // A failed verify never carries an authenticated signing version.
    expect(att.reply_signing_version).toBeNull();
  });

  it("fails on a stale signature (verifier rejects the freshness window)", async () => {
    const { fn } = stubVerify({ verified: false, code: "E_STALE" });
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape(GOOD_META),
      verifyFn: fn,
      // no network: this suite stubs the verifier only
      behaviourFetchFn: null,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("E_STALE");
    expect(att.reply_signing_version).toBeNull();
  });

  it("surfaces an unknown-agent verdict code rather than misreporting it", async () => {
    const { fn } = stubVerify({ verified: false, code: "E_AGENT_NOT_FOUND" });
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape(GOOD_META),
      verifyFn: fn,
      // no network: this suite stubs the verifier only
      behaviourFetchFn: null,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("E_AGENT_NOT_FOUND");
  });

  it("falls back to signature_invalid when a failure verdict carries no code", async () => {
    const { fn } = stubVerify({ verified: false });
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape(GOOD_META),
      verifyFn: fn,
      // no network: this suite stubs the verifier only
      behaviourFetchFn: null,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("signature_invalid");
  });

  it("bounds a hostile/oversized verifier code instead of passing it through", async () => {
    const { fn } = stubVerify({
      verified: false,
      code: "E_" + "X".repeat(200), // exceeds the safe code shape
    });
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape(GOOD_META),
      verifyFn: fn,
      // no network: this suite stubs the verifier only
      behaviourFetchFn: null,
    });
    expect(att.reply_verified).toBe(false);
    // Not passed through verbatim; falls back to the bounded generic reason.
    expect(att.reply_failure_reason).toBe("signature_invalid");
  });

  it("fails closed to verify_unavailable when the verify endpoint is down (null)", async () => {
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape(GOOD_META),
      verifyFn: async () => null,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("verify_unavailable");
  });

  it("fails closed to verify_unavailable when the verify fn throws", async () => {
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape(GOOD_META),
      verifyFn: async () => {
        throw new Error("network down");
      },
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("verify_unavailable");
  });

  it("bounds a hostile verifier reason and strips every control character", async () => {
    const nasty =
      "line1\nline2\t\u001b[31m\u0000\u0085\u202eRTL\u2066isolate\u200bhidden" +
      "x".repeat(400);
    const { fn } = stubVerify({ verified: false, reason: nasty });
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape(GOOD_META),
      verifyFn: fn,
      // no network: this suite stubs the verifier only
      behaviourFetchFn: null,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason!.length).toBeLessThanOrEqual(121);
    expect(att.reply_failure_reason).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/);
    expect(att.reply_failure_reason).not.toMatch(
      /[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/
    );
  });
});

// Exercises the REAL defaultVerify transport (no injected verifyFn) against the
// live /v1/verify contract, via a stubbed global fetch. Covers review findings
// 2 (non-2xx verdicts keep their machine code) and 3 (the verify hop is bounded
// by a timeout and fails closed to verify_unavailable).
describe("attestReply — default verify transport (findings 2 & 3)", () => {
  // Reuses the module-scope GOOD_META (identity == RECIPIENT) so the verify hop
  // is actually reached.
  const response = messageShape(GOOD_META);

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // Minimal fetch Response double: defaultVerify only reads .json().
  function fakeResponse(opts: {
    ok: boolean;
    status: number;
    json: () => Promise<unknown>;
  }) {
    return {
      ok: opts.ok,
      status: opts.status,
      headers: { get: () => null },
      json: opts.json,
      text: async () => "",
    };
  }

  it("preserves a non-2xx E_STALE verdict as its code, NOT verify_unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        fakeResponse({
          ok: false,
          status: 400,
          json: async () => ({
            verified: false,
            error: "timestamp outside ±5 min freshness window",
            code: "E_STALE",
          }),
        })
      )
    );
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("E_STALE");
  });

  it("preserves a 404 E_AGENT_NOT_FOUND verdict from a non-2xx response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        fakeResponse({
          ok: false,
          status: 404,
          json: async () => ({
            verified: false,
            error: "agent not found",
            code: "E_AGENT_NOT_FOUND",
          }),
        })
      )
    );
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response,
    });
    expect(att.reply_failure_reason).toBe("E_AGENT_NOT_FOUND");
  });

  it("verifies through the real transport using the verifier's signing_version (v0)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        fakeResponse({
          ok: true,
          status: 200,
          json: async () => ({
            verified: true,
            // The Worker echoes `identity: from` on every verified response,
            // and the contract binds it. A fixture omitting it is a body the
            // service does not send.
            identity: RECIPIENT,
            signing_version: 0,
            freshness_checked: true,
            // A boolean tick travels WITH its reputation; the Worker sets both
            // inside the behaviour fetch or neither at all.
            blue_tick: true,
            reputation: MEASURED_REPUTATION,
          }),
        })
      )
    );
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response,
    });
    expect(att.reply_verified).toBe(true);
    expect(att.reply_signing_version).toBe(0);
    expect(att.reply_blue_tick).toBe(true);
  });

  it("treats an unparseable (proxy error page) response as verify_unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        fakeResponse({
          ok: false,
          status: 502,
          json: async () => {
            throw new SyntaxError("Unexpected token < in JSON");
          },
        })
      )
    );
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("verify_unavailable");
  });

  it("treats a 2xx body that is not a verdict as verify_unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        fakeResponse({
          ok: true,
          status: 200,
          json: async () => ({ something: "else" }), // no `verified`/`code`
        })
      )
    );
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response,
    });
    expect(att.reply_failure_reason).toBe("verify_unavailable");
  });

  it("fails closed to verify_unavailable when the verify hop times out", async () => {
    // A fetch that never settles until its abort signal fires — modelling a
    // hung verifier connection. The bounded timeout must abort it.
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_url: string, opts: { signal: AbortSignal }) =>
          new Promise((_resolve, reject) => {
            opts.signal.addEventListener("abort", () =>
              reject(new DOMException("The operation was aborted.", "AbortError"))
            );
          })
      )
    );
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response,
      timeoutMs: 10, // tiny bound so the test resolves fast
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("verify_unavailable");
  });

  // A 502 gateway response whose JSON body claims
  // verified:true must never authenticate a reply. Operator decision
  // (2026-07-25): reply_verified:true may originate ONLY from a 2xx
  // response; every non-2xx body returns reply_verified:false regardless of
  // what it claims.
  it("never authenticates a reply from a non-2xx response claiming verified:true", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        fakeResponse({
          ok: false,
          status: 502,
          json: async () => ({
            verified: true,
            signing_version: 1,
            blue_tick: true,
          }),
        })
      )
    );
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_signing_version).toBeNull();
    expect(att.reply_blue_tick).toBe("unknown");
  });

  // Same fixture, but with a recognized failure code attached — the code
  // must still surface (not collapse to verify_unavailable) even though the
  // response was non-2xx and the body's own verified:true is discarded.
  it("treats a non-2xx body that claims verified:true as unavailable, even with a known code", async () => {
    // The producer never emits verified:true with a failure code. Keeping the
    // code used to turn a contradictory body into an authoritative E_STALE.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        fakeResponse({
          ok: false,
          status: 400,
          json: async () => ({ verified: true, code: "E_STALE" }),
        })
      )
    );
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("verify_unavailable");
  });

  // A non-2xx body with no recognized code isn't a genuine verdict at all
  // (e.g. a misconfigured proxy) — treat it as an availability failure, not
  // a signature-invalid claim.
  it("treats a non-2xx body with no recognized code as verify_unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        fakeResponse({
          ok: false,
          status: 503,
          json: async () => ({ verified: false }),
        })
      )
    );
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response,
    });
    expect(att.reply_verified).toBe(false);
    expect(att.reply_failure_reason).toBe("verify_unavailable");
  });

  it("does not treat HTTP 503 E_VERIFY as a verification verdict", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        fakeResponse({
          ok: false,
          status: 503,
          json: async () => ({ verified: false, code: "E_VERIFY", error: "verification failed" }),
        })
      )
    );
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response,
    });
    expect(att.reply_failure_reason).toBe("verify_unavailable");
  });

  it("does not treat a 400 E_SIG_MISMATCH pair as a verification verdict", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        fakeResponse({
          ok: false,
          status: 400,
          json: async () => ({ verified: false, code: "E_SIG_MISMATCH", error: "signature mismatch" }),
        })
      )
    );
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response,
    });
    expect(att.reply_failure_reason).toBe("verify_unavailable");
  });

  it("preserves a 500 E_STORED_KEY producer failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        fakeResponse({
          ok: false,
          status: 500,
          json: async () => ({ verified: false, code: "E_STORED_KEY", error: "stored key is malformed" }),
        })
      )
    );
    const att = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response,
    });
    expect(att.reply_failure_reason).toBe("E_STORED_KEY");
  });
});

describe("one precedence rule: the registry record wins", () => {
  // The bug: `tick` took the /v1/verify verdict when it had one, while
  // reply_behaviour was attached unconditionally from the registry. Once
  // production ships the trust-status fanout those are two sources, and an attestation
  // could carry `reply_blue_tick: true` above `reply_behaviour.blue_tick: false`
  // with no way for a reader to know which to believe. status.ts already gave
  // the registry precedence, so the two surfaces resolved the same conflict in
  // opposite directions.
    // Uses the file's existing fixtures rather than inventing helpers.

  function registrySays(blue_tick: boolean) {
    return async () =>
      new Response(
        JSON.stringify({
          identity: RECIPIENT,
          blue_tick,
          reputation: {
            entropy_score: 0.04,
            z_score: 3.06,
            drift_detected: !blue_tick,
            calibration_stage: "full",
          },
        }),
        { status: 200 }
      );
  }

  it("overrides a verdict that claims a tick the registry does not hold", async () => {
    const { fn } = stubVerify({ verified: true, blue_tick: true, signing_version: 1 });
    const a = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape(GOOD_META),
      verifyFn: fn,
      behaviourFetchFn: registrySays(false),
    });
    expect(a.reply_blue_tick).toBe(false);
    expect(a.reply_behaviour?.blue_tick).toBe(false);
  });

  it("and the converse — a verdict denying a tick the registry does hold", async () => {
    const { fn } = stubVerify({ verified: true, blue_tick: false, signing_version: 1 });
    const a = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: REPLY_TEXT,
      response: messageShape(GOOD_META),
      verifyFn: fn,
      behaviourFetchFn: registrySays(true),
    });
    expect(a.reply_blue_tick).toBe(true);
    expect(a.reply_behaviour?.blue_tick).toBe(true);
  });

  it("headline and detail can never contradict, because one derives from the other", async () => {
    for (const held of [true, false]) {
      const { fn } = stubVerify({ verified: true, blue_tick: !held, signing_version: 1 });
      const a = await attestReply({
        recipientDomain: RECIPIENT,
        replyText: REPLY_TEXT,
        response: messageShape(GOOD_META),
        verifyFn: fn,
        behaviourFetchFn: registrySays(held),
      });
      expect(a.reply_blue_tick).toBe(a.reply_behaviour?.blue_tick);
    }
  });
});
