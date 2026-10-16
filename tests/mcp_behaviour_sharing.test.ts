// The MCP process's two behaviour-bearing surfaces share one lookup.
//
// Within this process, every behaviour-bearing surface shares one lookup.
// Separate processes each hold their own instance; no in-process object is
// shared between processes. What these tests pin is:
//
//   1. every call site goes through BehaviourLookup rather than a raw fetch, so
//      there is one policy and not four; and
//   2. within each process, the surfaces that CAN share an instance do.
//
// The surfaces here are zipviz_status and the send attestation.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { resetSharedBehaviourLookup } from "../src/core/behaviour.js";

const AGENT = "gary.yc.viz";

const mockCard = {
  name: AGENT,
  description: "verified identity",
  url: "https://example.agents.zipviz.ai",
  capabilities: [],
  authentication: { schemes: ["ed25519"] },
  public_key: "96be1f42206903c96fd4adfc96c02e4da92440fc7543b5c5bb73cba8805e6376",
  protocols: ["a2a"],
  created: "2026-04-03 09:15:14",
};

const TICKED = {
  identity: AGENT,
  blue_tick: true,
  reputation: {
    entropy_score: 0.0405,
    drift_detected: false,
    z_score: 3.066,
    calibration_stage: "full",
  },
};

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerStatus } from "../src/tools/status.js";
import { attestReply } from "../src/lib/reply-attestation.js";

/** Counts trust-status hops specifically, answering everything else plausibly. */
function countingFetch(blueTick: () => { ok: boolean; body: unknown }) {
  const counts = { blueTick: 0, other: 0 };
  const fn = vi.fn((url: string) => {
    if (String(url).includes("/v1/blue-tick/")) {
      counts.blueTick += 1;
      const r = blueTick();
      return Promise.resolve({
        ok: r.ok,
        status: r.ok ? 200 : 503,
        json: () => Promise.resolve(r.body),
      });
    }
    counts.other += 1;
    return Promise.resolve({
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: () => Promise.resolve(mockCard),
      text: () => Promise.resolve(JSON.stringify(mockCard)),
    });
  });
  return { fn, counts };
}

function statusHandler() {
  const server = new McpServer({ name: "test", version: "0.0.1" });
  let handler: any;
  const original = server.registerTool.bind(server);
  server.registerTool = ((name: string, config: any, cb: any) => {
    if (name === "zipviz_status") handler = cb;
    return original(name, config, cb);
  }) as any;
  registerStatus(server);
  return handler as (args: { domain: string }) => Promise<any>;
}

/** A minimal signed-looking reply for the attestation path to chew on. */
function replyResponse() {
  return {
    result: {
      message: {
        messageId: "resp-1",
        role: "agent",
        parts: [{ kind: "text", text: "ack" }],
        metadata: {
          zipviz: {
            from: AGENT,
            timestamp: "2026-08-22T01:00:00.000Z",
            signature: "cmVwbHktc2ln",
          },
        },
      },
    },
  };
}

describe("the MCP process shares one behaviour lookup", () => {
  beforeEach(() => {
    resetSharedBehaviourLookup();
    vi.restoreAllMocks();
  });

  it("makes ONE request across status and the send attestation once throttled", async () => {
    // The sharing proof for this process. Two instances would each learn about
    // the outage separately and each spend a request discovering it.
    const { fn, counts } = countingFetch(() => ({ ok: false, body: {} }));
    vi.stubGlobal("fetch", fn);

    await statusHandler()({ domain: AGENT });
    await attestReply({
      recipientDomain: AGENT,
      replyText: "ack",
      response: replyResponse() as never,
      verifyFn: async () =>
        ({
          verified: true,
          identity: AGENT,
          signing_version: 1,
          // The rest of the producer's success contract. Without it the
          // verdict is off-contract and the behaviour lookup this test
          // counts never runs.
          freshness_checked: true,
          blue_tick: null,
          reputation: null,
        }) as never,
    });

    expect(counts.blueTick).toBe(1);
  });

  it("still asks per surface while the endpoint is healthy", async () => {
    // A success is never cached, so each surface gets a live reading. Two is
    // the correct number here; caching the pass would be the defect.
    const { fn, counts } = countingFetch(() => ({ ok: true, body: TICKED }));
    vi.stubGlobal("fetch", fn);

    await statusHandler()({ domain: AGENT });
    await statusHandler()({ domain: AGENT });

    expect(counts.blueTick).toBe(2);
  });

  it("reports an outage on stderr, because this process has no audit table", async () => {
    // The production singleton was built
    // with no reporter at all, so saturation or throttling in zipviz_status and
    // the send attestation went nowhere: no row, no line, and the only symptom
    // a quietly missing behaviour section. A host with an audit table writes a row; this
    // process has no table, so it writes a line.
    const written: string[] = [];
    const spy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(((chunk: unknown) => {
        written.push(String(chunk));
        return true;
      }) as never);

    const { fn } = countingFetch(() => ({ ok: false, body: {} }));
    vi.stubGlobal("fetch", fn);

    await statusHandler()({ domain: AGENT });

    const line = written.find((l) => l.includes("behaviour lookup unavailable"));
    expect(line).toBeDefined();
    expect(line).toContain(AGENT);
    expect(line).toContain("http_status");
    spy.mockRestore();
  });

  it("writes that line to stderr and never to stdout", async () => {
    // A stdio MCP server speaks JSON-RPC on stdout. A log line written there
    // corrupts the protocol stream, so this is not a stylistic preference.
    const out = vi
      .spyOn(process.stdout, "write")
      .mockImplementation((() => true) as never);
    const err = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((() => true) as never);

    const { fn } = countingFetch(() => ({ ok: false, body: {} }));
    vi.stubGlobal("fetch", fn);
    await statusHandler()({ domain: AGENT });

    expect(err).toHaveBeenCalled();
    expect(out).not.toHaveBeenCalled();
    out.mockRestore();
    err.mockRestore();
  });

  it("keeps a caller's injected transport out of the shared instance", async () => {
    // attestReply with an explicit behaviourFetchFn builds a throwaway lookup.
    // If it used the shared one, a caller's scripted outage would leak into
    // every other tool call in the process — including zipviz_status.
    const injected = vi.fn(async () => new Response("{}", { status: 503 }));
    await attestReply({
      recipientDomain: AGENT,
      replyText: "ack",
      response: replyResponse() as never,
      verifyFn: async () =>
        ({
          verified: true,
          identity: AGENT,
          signing_version: 1,
          // The rest of the producer's success contract. Without it the
          // verdict is off-contract and the behaviour lookup this test
          // counts never runs.
          freshness_checked: true,
          blue_tick: null,
          reputation: null,
        }) as never,
      behaviourFetchFn: injected as never,
    });
    expect(injected).toHaveBeenCalledTimes(1);

    // The shared instance never heard about that 503, so status still asks.
    const { fn, counts } = countingFetch(() => ({ ok: true, body: TICKED }));
    vi.stubGlobal("fetch", fn);
    await statusHandler()({ domain: AGENT });

    expect(counts.blueTick).toBe(1);
  });
});
