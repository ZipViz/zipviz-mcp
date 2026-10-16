import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetSharedBehaviourLookup } from "../src/core/behaviour.js";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerSend } from "../src/tools/send.js";
import { signReceipt } from "../src/core/receipts.js";
import { ED25519_SPKI_PREFIX } from "../src/core/envelope.js";

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
    assertSafeEgressUrl: vi.fn(async () => {}),
    safeEgressFetch,
  };
});

const SENDER = "zip-grok.smc.viz";
const RECIPIENT = "viz-grok.smc.viz";
const MSG = "hello v2 envelope";

function spkiHex(publicKey: KeyObject): string {
  const der = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return der.subarray(ED25519_SPKI_PREFIX.length).toString("hex");
}

describe("zipviz_send envelope_v=2 + local receipt verify", () => {
  let tmpHome: string;
  let prevHome: string | undefined;
  let recipientHex: string;
  let handler: (args: {
    domain: string;
    message: string;
    as?: string;
    envelope_v?: 1 | 2;
  }) => Promise<any>;
  let lastA2A: unknown;
  let fetchUrls: string[];

  beforeEach(async () => {
    // The behaviour lookup is a process-wide instance so that real MCP tool
    // calls coalesce. Reset it between cases: without this, one test's scripted
    // outage is remembered and the next test's request never happens.
    resetSharedBehaviourLookup();
    fetchUrls = [];
    tmpHome = await mkdtemp(join(tmpdir(), "zipviz-send-v2-"));
    await mkdir(join(tmpHome, ".zipviz", "keys"), { recursive: true });
    prevHome = process.env.HOME;
    process.env.HOME = tmpHome;

    const sender = generateKeyPairSync("ed25519");
    const recipient = generateKeyPairSync("ed25519");
    recipientHex = spkiHex(recipient.publicKey);
    await writeFile(
      join(tmpHome, ".zipviz", "keys", `${SENDER}.key`),
      sender.privateKey.export({ type: "pkcs8", format: "pem" }) as string
    );
    await writeFile(
      join(tmpHome, ".zipviz", "keys", `${RECIPIENT}.key`),
      recipient.privateKey.export({ type: "pkcs8", format: "pem" }) as string
    );

    const card = {
      name: RECIPIENT,
      url: "https://viz-grok.agents.zipviz.ai",
      public_key: recipientHex,
      capabilities: [],
      authentication: { schemes: ["ed25519"] },
      protocols: ["a2a"],
      created: "2026-08-13",
    };

    vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
      fetchUrls.push(String(url));
      if (String(url).includes("/card")) {
        return {
          ok: true,
          headers: { get: () => null },
          json: async () => card,
          text: async () => JSON.stringify(card),
        };
      }
      lastA2A = init?.body ? JSON.parse(String(init.body)) : null;
      const zipviz = (lastA2A as any)?.params?.message?.metadata?.zipviz;
      const receipt = await signReceipt({
        recipient: RECIPIENT,
        sender: SENDER,
        msg_id: zipviz?.msg_id ?? "msg-fallback-xxxxxxxx",
        received_at: "2026-08-13T10:00:00.123Z",
        timestamp: "2026-08-13T10:00:00.123Z",
        nonce: "0123456789abcdef",
        owner_relationship: "SAME_OWNER",
      });
      const a2a = {
        jsonrpc: "2.0",
        id: 1,
        result: {
          message: {
            messageId: "receipt-1",
            role: "agent",
            parts: [{ kind: "text", text: `ACCEPTED ${receipt.msg_id} for ${RECIPIENT}` }],
            metadata: { zipviz: receipt },
          },
        },
      };
      return {
        ok: true,
        headers: { get: () => null },
        json: async () => a2a,
        text: async () => JSON.stringify(a2a),
      };
    });

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
    if (prevHome === undefined) delete process.env.HOME;
    else process.env.HOME = prevHome;
    await rm(tmpHome, { recursive: true, force: true });
  });

  it("emits v2 metadata and verifies a local ACCEPTED receipt", async () => {
    const result = await handler({
      domain: RECIPIENT,
      message: MSG,
      as: SENDER,
      envelope_v: 2,
    });
    expect(result.isError).toBeUndefined();
    const zipviz = (lastA2A as any).params.message.metadata.zipviz;
    expect(zipviz.v).toBe(2);
    expect(zipviz.from).toBe(SENDER);
    expect(zipviz.to).toBe(RECIPIENT);
    expect(zipviz.msg_id).toMatch(/^msg-/);
    expect(zipviz.expires_at).toBeTruthy();
    expect(JSON.stringify(result.content[0].text)).not.toMatch(zipviz.signature);

    const payload = JSON.parse(result.content[0].text);
    // The receipt verifies and is attached; the reply text it travels with is
    // unsigned, so it is not reported as verified.
    expect(
      payload.reply_attestation.reply_verified,
      JSON.stringify(payload.reply_attestation)
    ).toBe(false);
    expect(payload.reply_attestation.reply_failure_reason).toBe("reply_text_unsigned");
    expect(payload.reply_attestation.reply_signing_version).toBeNull();
    expect(payload.reply_attestation.receipt).toEqual({
      status: "ACCEPTED",
      msg_id: zipviz.msg_id,
      received_at: "2026-08-13T10:00:00.123Z",
    });
    expect(fetchUrls.some((url) => url.includes("/v1/blue-tick/"))).toBe(false);
    expect(JSON.stringify(payload)).not.toContain(payload.reply_attestation.receipt?.signature);
  });

  it("fails closed on a missing receipt", async () => {
    vi.stubGlobal("fetch", async (url: string) => {
        // The attestation now falls back to /v1/blue-tick when the verify
        // verdict carries no tick. Answer it
        // here or it falls through to the A2A branch below and overwrites what
        // this stub is recording.
        if (String(url).includes("/v1/blue-tick/")) {
          return {
            ok: true,
            headers: { get: () => null },
            json: async () => ({ identity: RECIPIENT, blue_tick: false, reputation: null }),
            text: async () => "{}",
          };
        }
      if (String(url).includes("/card")) {
        return {
          ok: true,
          headers: { get: () => null },
          json: async () => ({
            name: RECIPIENT,
            url: "https://viz-grok.agents.zipviz.ai",
            public_key: recipientHex,
          }),
          text: async () => "{}",
        };
      }
      const a2a = {
        jsonrpc: "2.0",
        id: 1,
        result: { message: { parts: [{ kind: "text", text: "unsigned" }] } },
      };
      return {
        ok: true,
        headers: { get: () => null },
        json: async () => a2a,
        text: async () => JSON.stringify(a2a),
      };
    });
    const result = await handler({
      domain: RECIPIENT,
      message: MSG,
      as: SENDER,
      envelope_v: 2,
    });
    const payload = JSON.parse(result.content[0].text);
    expect(payload.reply_attestation.reply_verified).toBe(false);
    expect(payload.reply_attestation.reply_failure_reason).toBe("missing_metadata");
    expect(payload.reply_attestation.receipt).toBeUndefined();
  });

  it("fails closed on a replayed receipt for a different msg_id", async () => {
    // The recipient returns a receipt it validly signed for an EARLIER
    // message. Signature checks out against the card key; only the msg_id
    // binding can catch the replay.
    vi.stubGlobal("fetch", async (url: string) => {
        // The attestation now falls back to /v1/blue-tick when the verify
        // verdict carries no tick. Answer it
        // here or it falls through to the A2A branch below and overwrites what
        // this stub is recording.
        if (String(url).includes("/v1/blue-tick/")) {
          return {
            ok: true,
            headers: { get: () => null },
            json: async () => ({ identity: RECIPIENT, blue_tick: false, reputation: null }),
            text: async () => "{}",
          };
        }
      if (String(url).includes("/card")) {
        return {
          ok: true,
          headers: { get: () => null },
          json: async () => ({
            name: RECIPIENT,
            url: "https://viz-grok.agents.zipviz.ai",
            public_key: recipientHex,
          }),
          text: async () => "{}",
        };
      }
      const staleReceipt = await signReceipt({
        recipient: RECIPIENT,
        sender: SENDER,
        msg_id: "msg-00000000-0000-4000-8000-00000000dead",
        received_at: "2026-08-01T00:00:00.000Z",
        owner_relationship: "SAME_OWNER",
      });
      const a2a = {
        jsonrpc: "2.0",
        id: 1,
        result: {
          message: {
            parts: [{ kind: "text", text: `ACCEPTED ${staleReceipt.msg_id} for ${RECIPIENT}` }],
            metadata: { zipviz: staleReceipt },
          },
        },
      };
      return {
        ok: true,
        headers: { get: () => null },
        json: async () => a2a,
        text: async () => JSON.stringify(a2a),
      };
    });
    const result = await handler({
      domain: RECIPIENT,
      message: MSG,
      as: SENDER,
      envelope_v: 2,
    });
    const payload = JSON.parse(result.content[0].text);
    expect(payload.reply_attestation.reply_verified).toBe(false);
    expect(payload.reply_attestation.reply_failure_reason).toBe("E_RECEIPT_MISMATCH");
    expect(payload.reply_attestation.receipt).toBeUndefined();
  });

  it("fails closed on a receipt addressed to a different sender", async () => {
    // Validly signed, correct msg_id, but `to` names someone else — a receipt
    // issued to another sender must not attest THIS sender's delivery.
    vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
        // The attestation now falls back to /v1/blue-tick when the verify
        // verdict carries no tick. Answer it
        // here or it falls through to the A2A branch below and overwrites what
        // this stub is recording.
        if (String(url).includes("/v1/blue-tick/")) {
          return {
            ok: true,
            headers: { get: () => null },
            json: async () => ({ identity: RECIPIENT, blue_tick: false, reputation: null }),
            text: async () => "{}",
          };
        }
      if (String(url).includes("/card")) {
        return {
          ok: true,
          headers: { get: () => null },
          json: async () => ({
            name: RECIPIENT,
            url: "https://viz-grok.agents.zipviz.ai",
            public_key: recipientHex,
          }),
          text: async () => "{}",
        };
      }
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      const msg_id = body?.params?.message?.metadata?.zipviz?.msg_id ?? "msg-x-xxxxxxxx";
      const receipt = await signReceipt({
        recipient: RECIPIENT,
        sender: "other-sender.smc.viz",
        msg_id,
        received_at: "2026-08-13T10:00:00.123Z",
        owner_relationship: "EXTERNAL",
      });
      const a2a = {
        jsonrpc: "2.0",
        id: 1,
        result: {
          message: {
            parts: [{ kind: "text", text: `ACCEPTED ${msg_id} for ${RECIPIENT}` }],
            metadata: { zipviz: receipt },
          },
        },
      };
      return {
        ok: true,
        headers: { get: () => null },
        json: async () => a2a,
        text: async () => JSON.stringify(a2a),
      };
    });
    const result = await handler({
      domain: RECIPIENT,
      message: MSG,
      as: SENDER,
      envelope_v: 2,
    });
    const payload = JSON.parse(result.content[0].text);
    expect(payload.reply_attestation.reply_verified).toBe(false);
    expect(payload.reply_attestation.reply_failure_reason).toBe("E_RECEIPT_MISMATCH");
  });

  it("does not attach receipt fields from a v1-verified reply (fabrication guard)", async () => {
    // A reply whose signature verifies as v1 covers only {v,from,message,
    // timestamp}. Receipt-shaped metadata riding alongside it is UNSIGNED and
    // attacker-chosen — it must never surface as attestation.receipt.
    const { attestReply } = await import("../src/lib/reply-attestation.js");
    const forged = {
      jsonrpc: "2.0",
      id: 1,
      result: {
        message: {
          parts: [{ kind: "text", text: "legit v1-signed text" }],
          metadata: {
            zipviz: {
              kind: "receipt",
              status: "ACCEPTED",
              from: RECIPIENT,
              to: SENDER,
              msg_id: "msg-forged-0000-4000-8000-000000000bad",
              received_at: "2026-08-13T10:00:00.123Z",
              owner_relationship: "SAME_OWNER",
              timestamp: "2026-08-13T10:00:00.000Z",
              signature: "dmFsaWQtdjEtc2ln",
            },
          },
        },
      },
    } as any;
    const attestation = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: "legit v1-signed text",
      response: forged,
      // Verifier authenticates the signature as v1 — receipt must be dropped.
      // The verdict is the producer's full success shape: since the body is now
      // validated whole, a half-shaped one would be refused before this test's
      // actual subject (the receipt) was ever reached.
      verifyFn: async () => ({
        verified: true,
        identity: RECIPIENT,
        signing_version: 1,
        freshness_checked: true,
        blue_tick: null,
        reputation: null,
      }),
    });
    expect(attestation.reply_verified).toBe(true);
    expect(attestation.reply_signing_version).toBe(1);
    expect(attestation.receipt).toBeUndefined();

    // SUPERSEDED, deliberately. This used to assert that a
    // verdict of `signing_version: 2` attached the receipt — and asserted the
    // attached `msg_id` was `msg-forged-…bad`, the attacker-chosen value from
    // the metadata block. The test named the value "forged" and expected it:
    // it encoded the defect rather than catching it.
    //
    // A version number is not a proof. A verdict that merely CLAIMS v2 now
    // attaches nothing.
    const claimsV2 = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: "legit v1-signed text",
      response: forged,
      verifyFn: async () => ({
        verified: true,
        identity: RECIPIENT,
        signing_version: 2,
        freshness_checked: true,
        blue_tick: null,
        reputation: null,
      }),
    });
    expect(claimsV2.receipt).toBeUndefined();
    // And, since the whole body is now validated, no verification either:
    // `/v1/verify` emits 0 or 1, so a remote verdict announcing 2 is not a
    // producer body at all.
    expect(claimsV2.reply_verified).toBe(false);
    expect(claimsV2.reply_failure_reason).toBe("verdict_off_contract");

    // Only a verifier that actually performed the proof attaches one — and it
    // attaches the receipt IT verified, never the metadata's.
    //
    // Through the REAL verifier. This used to import the proof symbol and
    // attach the marker by hand, which proved only that the consumer reads it;
    // the symbol is now private to the receipt module, so the sole route to a
    // proven receipt is to sign one and have it verified.
    const { localV2ReceiptVerifyFn } = await import("../src/core/receipts.js");
    const realMsgId = "msg-the-one-we-actually-sent";
    const realReceipt = await signReceipt({
      recipient: RECIPIENT,
      sender: SENDER,
      msg_id: realMsgId,
      received_at: "2026-08-13T10:00:00.123Z",
      timestamp: "2026-08-13T10:00:00.123Z",
      nonce: "0123456789abcdef",
      owner_relationship: "SAME_OWNER",
    });
    const signedResponse = {
      jsonrpc: "2.0",
      id: 1,
      result: {
        message: {
          parts: [{ kind: "text", text: "legit v1-signed text" }],
          metadata: { zipviz: { ...realReceipt, kind: "receipt" } },
        },
      },
    } as any;
    const proven = await attestReply({
      recipientDomain: RECIPIENT,
      replyText: "legit v1-signed text",
      response: signedResponse,
      verifyFn: localV2ReceiptVerifyFn(recipientHex, signedResponse, {
        msg_id: realMsgId,
        to: SENDER,
      }),
      behaviourFetchFn: null,
    });
    expect(proven.reply_verified).toBe(false);
    expect(proven.reply_failure_reason).toBe("reply_text_unsigned");
    expect(proven.receipt?.msg_id).toBe(realMsgId);
    expect(JSON.stringify(proven.receipt)).not.toContain("forged");
  });

  it("fails closed on an identity-mismatched receipt", async () => {
    vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
        // The attestation now falls back to /v1/blue-tick when the verify
        // verdict carries no tick. Answer it
        // here or it falls through to the A2A branch below and overwrites what
        // this stub is recording.
        if (String(url).includes("/v1/blue-tick/")) {
          return {
            ok: true,
            headers: { get: () => null },
            json: async () => ({ identity: RECIPIENT, blue_tick: false, reputation: null }),
            text: async () => "{}",
          };
        }
      if (String(url).includes("/card")) {
        return {
          ok: true,
          headers: { get: () => null },
          json: async () => ({
            name: RECIPIENT,
            url: "https://x.agents.zipviz.ai",
            public_key: recipientHex,
          }),
          text: async () => "{}",
        };
      }
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      const msg_id = body?.params?.message?.metadata?.zipviz?.msg_id ?? "msg-x-xxxxxxxx";
      const receipt = await signReceipt({
        recipient: RECIPIENT,
        sender: SENDER,
        msg_id,
        received_at: "2026-08-13T10:00:00.123Z",
        owner_relationship: "SAME_OWNER",
      });
      receipt.from = "evil.smc.viz";
      const a2a = {
        jsonrpc: "2.0",
        id: 1,
        result: {
          message: {
            parts: [{ kind: "text", text: "ACCEPTED" }],
            metadata: { zipviz: receipt },
          },
        },
      };
      return {
        ok: true,
        headers: { get: () => null },
        json: async () => a2a,
        text: async () => JSON.stringify(a2a),
      };
    });
    const result = await handler({
      domain: RECIPIENT,
      message: MSG,
      as: SENDER,
      envelope_v: 2,
    });
    const payload = JSON.parse(result.content[0].text);
    expect(payload.reply_attestation.reply_verified).toBe(false);
    expect(payload.reply_attestation.reply_failure_reason).toBe("identity_mismatch");
  });
});
