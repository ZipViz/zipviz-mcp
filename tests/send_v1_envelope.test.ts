// End-to-end coverage for the signed-send path.
//
// `tests/send.test.ts` mocks signMessage to assert envelope SHAPE only —
// that test never actually computes a real Ed25519 signature, so it
// can't catch a format mismatch between the bytes the helper signs and
// the bytes the trust root reconstructs to verify.
//
// This file uses the REAL signMessage with a real ephemeral keypair
// and a temp HOME directory, calls zipviz_send with `as:` set, captures
// the outgoing A2A envelope, and asserts the signature in
// metadata.zipviz re-verifies locally against the v=1 canonical
// payload — i.e. the exact bytes the registry
// reconstructs at /v1/verify.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetSharedBehaviourLookup } from "../src/core/behaviour.js";
import { generateKeyPairSync, KeyObject, verify } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerSend } from "../src/tools/send.js";

// Keep this end-to-end signing test hermetic: stub the SSRF egress guard so it
// does not perform a real DNS lookup on the mock tunnel host. The guard's
// logic is covered in tests/egress.test.ts.
vi.mock("../src/lib/egress.js", () => {
  class EgressBlockedError extends Error {
    constructor(message: string) {
      super(message);
      this.name = "EgressBlockedError";
    }
  }
  const safeEgressFetch = vi.fn(async (url: string, init: RequestInit, opts: any) => {
    const response = await fetch(url, { ...init, redirect: "manual" });
    const raw = await response.text();
    const max = opts.bodyPolicy.mode === "read" ? opts.bodyPolicy.maxBytes : 0;
    const bytes = Buffer.from(raw, "utf8");
    const bodyTruncated = opts.bodyPolicy.mode === "read" && bytes.length > max;
    const bodyText = opts.bodyPolicy.mode === "read"
      ? bytes.subarray(0, max).toString("utf8")
      : "";
    return { response, bodyText, bodyBytes: Buffer.byteLength(bodyText), bodyTruncated };
  });
  return {
    EgressBlockedError,
    assertSafeEgressUrl: vi.fn(async (_url: string) => {}),
    safeEgressFetch,
  };
});

const TEST_VIZ_DOMAIN = "elu40-v1.smc.viz";

const mockCard = {
  name: "ticki.adkgo.viz",
  description: "ExampleAgent verified identity",
  url: "https://d5ababffe892.agents.zipviz.ai",
  capabilities: [],
  authentication: { schemes: ["ed25519"] },
  public_key:
    "96be1f42206903c96fd4adfc96c02e4da92440fc7543b5c5bb73cba8805e6376",
  protocols: ["a2a"],
  created: "2026-04-03 09:15:14",
};

const mockA2AResponse = {
  jsonrpc: "2.0",
  id: 1,
  result: {
    message: {
      messageId: "resp-elu40",
      role: "agent",
      parts: [{ kind: "text", text: "ack" }],
    },
  },
};

describe("zipviz_send v=1 signed envelope (real keypair, no mock)", () => {
  let tmpHome: string;
  let prevHome: string | undefined;
  let senderPublicKey: KeyObject;
  let handler: (args: {
    domain: string;
    message: string;
    as?: string;
  }) => Promise<any>;
  let fetchStub: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    // The behaviour lookup is a process-wide instance so that real MCP tool
    // calls coalesce. Reset it between cases: without this, one test's scripted
    // outage is remembered and the next test's request never happens.
    resetSharedBehaviourLookup();
    // 1. Temp HOME so signMessage's default key-path resolver lands in
    //    a per-test directory instead of the real ~/.zipviz/keys.
    tmpHome = await mkdtemp(join(tmpdir(), "zipviz-elu40-"));
    await mkdir(join(tmpHome, ".zipviz", "keys"), { recursive: true });
    prevHome = process.env.HOME;
    process.env.HOME = tmpHome;

    // 2. Real Ed25519 keypair; write PKCS#8 PEM to the temp keys dir.
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    senderPublicKey = publicKey;
    const pem = privateKey
      .export({ format: "pem", type: "pkcs8" })
      .toString();
    await writeFile(
      join(tmpHome, ".zipviz", "keys", `${TEST_VIZ_DOMAIN}.key`),
      pem
    );

    // 3. fetch stub: first call returns the agent card, second returns
    //    the A2A response. The card's public_key field is irrelevant
    //    to send.ts (it doesn't verify recipient identity there) — only
    //    the `url` is used.
    let n = 0;
    fetchStub = vi.fn(() => {
      n += 1;
      if (n === 1) {
        return Promise.resolve({
          ok: true,
          headers: { get: () => null },
          json: () => Promise.resolve(mockCard),
          text: () => Promise.resolve(JSON.stringify(mockCard)),
        });
      }
      // send.ts reads res.headers.get(...) + res.text() then JSON.parse.
      return Promise.resolve({
        ok: true,
        headers: { get: () => null },
        json: () => Promise.resolve(mockA2AResponse),
        text: () => Promise.resolve(JSON.stringify(mockA2AResponse)),
      });
    });
    vi.stubGlobal("fetch", fetchStub);

    // 4. Wire up the MCP tool handler.
    const server = new McpServer({ name: "test", version: "0.0.1" });
    const original = server.registerTool.bind(server);
    server.registerTool = ((name: string, config: any, cb: any) => {
      if (name === "zipviz_send") handler = cb;
      return original(name, config, cb);
    }) as any;
    registerSend(server);
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    if (prevHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = prevHome;
    }
    await rm(tmpHome, { recursive: true, force: true });
  });

  it("signs the outgoing message so the wire envelope re-verifies against the v=1 canonical payload", async () => {
    const message = "end-to-end smoke";

    const result = await handler({
      domain: "ticki.adkgo.viz",
      message,
      as: TEST_VIZ_DOMAIN,
    });

    expect(result.isError).toBeUndefined();

    // Outbound A2A POST body (second fetch call).
    const a2aBody = JSON.parse(fetchStub.mock.calls[1][1].body);
    const meta = a2aBody.params.message.metadata.zipviz;
    expect(meta.from).toBe(TEST_VIZ_DOMAIN);
    expect(typeof meta.timestamp).toBe("string");
    expect(typeof meta.signature).toBe("string");

    // THE assertion: reconstruct the exact v=1 canonical payload that
    // the registry would build from {from, message,
    // timestamp} extracted from this envelope, and confirm the
    // signature in the envelope verifies against it under the sender's
    // public key. If this fails, /v1/verify will return
    // verified:false, code:E_SIG_MISMATCH on the live trust root.
    const expectedPayload = Buffer.from(
      JSON.stringify({
        v: 1,
        from: meta.from,
        message,
        timestamp: meta.timestamp,
      }),
      "utf8"
    );
    const sigBytes = Buffer.from(meta.signature, "base64");
    expect(verify(null, expectedPayload, senderPublicKey, sigBytes)).toBe(
      true
    );

    // Regression guard: the older wire format (signature over bare
    // message bytes, plus a fresh post-sign timestamp on the envelope)
    // must NOT verify. If this passes again we've slipped back.
    expect(
      verify(
        null,
        Buffer.from(message, "utf8"),
        senderPublicKey,
        sigBytes
      )
    ).toBe(false);
  });

  it("preserves the exact timestamp signMessage used — envelope.timestamp drives the verify payload", async () => {
    // Sanity: send.ts must NOT regenerate a fresh timestamp after the
    // sign call. The wire timestamp must equal the timestamp baked
    // into the signed v=1 payload. (Covered transitively by the test
    // above — if the envelope timestamp diverged, the verify would
    // fail. This case asserts the relationship directly so a future
    // regression has an obvious pinpoint failure.)
    const message = "timestamp-pinning check";

    await handler({
      domain: "ticki.adkgo.viz",
      message,
      as: TEST_VIZ_DOMAIN,
    });

    const a2aBody = JSON.parse(fetchStub.mock.calls[1][1].body);
    const wireTimestamp = a2aBody.params.message.metadata.zipviz.timestamp;
    const sigBytes = Buffer.from(
      a2aBody.params.message.metadata.zipviz.signature,
      "base64"
    );

    // The wire timestamp is the ONLY timestamp the signature can be
    // verifying against — there is no other. Re-verify to confirm.
    const payloadWithWireTs = Buffer.from(
      JSON.stringify({
        v: 1,
        from: TEST_VIZ_DOMAIN,
        message,
        timestamp: wireTimestamp,
      }),
      "utf8"
    );
    expect(
      verify(null, payloadWithWireTs, senderPublicKey, sigBytes)
    ).toBe(true);
  });

  it("no `as` is REJECTED — no unsigned send path, no fetch, no signing key access", async () => {
    // The unsigned path no longer exists: a call without `as` fails closed at
    // the tool boundary BEFORE any network or key access.
    const result = await handler({
      domain: "ticki.adkgo.viz",
      message: "anonymous",
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/`as` is required|no unsigned send path/i);
    // Neither the agent-card lookup nor the A2A send happened (so no signing
    // key was read either — signing is after the lookup).
    expect(fetchStub).not.toHaveBeenCalled();
  });
});
