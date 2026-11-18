import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetSharedBehaviourLookup } from "../src/core/behaviour.js";
import { generateKeyPairSync, KeyObject, verify } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { canonicalEnvelopeV2 } from "../src/core/envelope.js";
import { signMessage } from "../src/tools/sign_message.js";
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

const TEST_VIZ_DOMAIN = "sender.synthetic.viz";

const mockCard = {
  name: "recipient.synthetic.viz",
  description: "Example verified identity",
  url: "https://recipient.invalid",
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
      messageId: "response-1",
      role: "agent",
      parts: [{ kind: "text", text: "ack" }],
    },
  },
};

describe("zipviz_send bound network envelope (real keypair)", () => {
  let tmpHome: string;
  let prevHome: string | undefined;
  let senderPublicKey: KeyObject;
  let handler: (args: {
    domain: string;
    message: string;
    as?: string;
    envelope_v?: number;
  }) => Promise<any>;
  let fetchStub: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    // The behaviour lookup is a process-wide instance so that real MCP tool
    // calls coalesce. Reset it between cases: without this, one test's scripted
    // outage is remembered and the next test's request never happens.
    resetSharedBehaviourLookup();
    // 1. Temp HOME so the signing helper's default key-path resolver lands in
    //    a per-test directory instead of the real ~/.zipviz/keys.
    tmpHome = await mkdtemp(join(tmpdir(), "zipviz-bound-send-"));
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
    //    the A2A response. Receipt verification also consumes the card key.
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

  it("defaults omitted envelope_v to recipient-bound canonical V2", async () => {
    const message = "synthetic bound send";

    const result = await handler({
      domain: "recipient.synthetic.viz",
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

    expect(meta.v).toBe(2);
    expect(meta.to).toBe("recipient.synthetic.viz");
    expect(meta.msg_id).toBe(a2aBody.params.message.messageId);
    const expectedPayload = Buffer.from(canonicalEnvelopeV2({ ...meta, message }));
    const sigBytes = Buffer.from(meta.signature, "base64");
    expect(verify(null, expectedPayload, senderPublicKey, sigBytes)).toBe(
      true
    );

    // Regression guard: the legacy bare-message signature must not verify as
    // a recipient-bound envelope.
    expect(
      verify(
        null,
        Buffer.from(message, "utf8"),
        senderPublicKey,
        sigBytes
      )
    ).toBe(false);
  });

  it.each([
    ["recipient", { to: "other.smc.viz" }],
    ["message id", { msg_id: "message-retargeted" }],
    ["expiry", { expires_at: "2026-08-13T12:00:00.000Z" }],
    ["reply context", { reply_to: "message-another-context" }],
  ])("rejects tampered %s with a real valid signature", async (_name, change) => {
    const message = "synthetic recipient binding";
    await handler({ domain: "recipient.synthetic.viz", message, as: TEST_VIZ_DOMAIN });
    const wire = JSON.parse(fetchStub.mock.calls[1][1].body);
    const meta = wire.params.message.metadata.zipviz;
    const sig = Buffer.from(meta.signature, "base64");
    // Positive control: same key/signature and original bytes are valid.
    expect(verify(null, Buffer.from(canonicalEnvelopeV2({ ...meta, message })), senderPublicKey, sig)).toBe(true);
    expect(verify(null, Buffer.from(canonicalEnvelopeV2({ ...meta, message, ...change })), senderPublicKey, sig)).toBe(false);
  });

  it("rejects a cryptographically valid V1 reply retargeted into this send", async () => {
    const recipient = "recipient.synthetic.viz";
    const message = "synthetic valid legacy reply";
    const keyPath = join(tmpHome, ".zipviz", "keys", `${TEST_VIZ_DOMAIN}.key`);
    const signed = await signMessage({ viz_domain: recipient, message, key_path: keyPath });
    const canonical = Buffer.from(JSON.stringify({ v: 1, from: recipient, message, timestamp: signed.timestamp }));
    expect(verify(null, canonical, senderPublicKey, Buffer.from(signed.signature, "base64"))).toBe(true);
    const card = { ...mockCard, public_key: (senderPublicKey.export({ type: "spki", format: "der" }) as Buffer).subarray(-32).toString("hex") };
    const response = { jsonrpc: "2.0", id: 1, result: { message: { parts: [{ kind: "text", text: message }], metadata: { zipviz: { from: recipient, timestamp: signed.timestamp, signature: signed.signature } } } } };
    fetchStub.mockReset().mockImplementation(async (url: string, init?: RequestInit) => {
      if (url.endsWith("/v1/verify")) {
        const body = JSON.parse(String(init?.body));
        const bytes = Buffer.from(JSON.stringify({ v: 1, from: body.from, message: body.message, timestamp: body.timestamp }));
        return new Response(JSON.stringify({
          verified: verify(null, bytes, senderPublicKey, Buffer.from(body.signature, "base64")),
          identity: recipient, signing_version: 1, freshness_checked: true,
        }));
      }
      return new Response(JSON.stringify({ identity: recipient, blue_tick: null, reputation: null }));
    }).mockResolvedValueOnce(new Response(JSON.stringify(card))).mockResolvedValueOnce(new Response(JSON.stringify(response)));
    const result = await handler({ domain: recipient, message: "another context", as: TEST_VIZ_DOMAIN });
    expect(result.isError).toBeUndefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.reply_attestation.reply_verified).toBe(false);
    expect(parsed.reply_attestation.reply_signing_version).toBeNull();
    expect(parsed.response).toContain(message);
    expect(parsed.response_is_untrusted).toBe(true);
    expect(fetchStub).toHaveBeenCalledTimes(2);
  });

  it.each([1, 3, null, "2"])("rejects unsupported network version %s before I/O", async (envelope_v) => {
    const result = await handler({ domain: "recipient.synthetic.viz", message: "synthetic", as: TEST_VIZ_DOMAIN, envelope_v } as any);
    expect(result.isError).toBe(true);
    expect(fetchStub).not.toHaveBeenCalled();
  });

  it("rejects a missing sender before lookup, signing, or delivery", async () => {
    // The unsigned path no longer exists: a call without `as` fails closed at
    // the tool boundary BEFORE any network or key access.
    const result = await handler({
      domain: "recipient.synthetic.viz",
      message: "anonymous",
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/`as` is required|no unsigned send path/i);
    // Neither the agent-card lookup nor the A2A send happened (so no signing
    // key was read either — signing is after the lookup).
    expect(fetchStub).not.toHaveBeenCalled();
  });
});
