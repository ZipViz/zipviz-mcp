// The whole-request limit on zipviz_send, separate from the text limit.
//
// A message within the 32 KiB text limit can still produce a request over the
// receiver's 128 KiB body limit: JSON escapes each control character as six
// bytes, and the envelope and signature add more. The send must refuse such a
// request after building it and before anything goes out, and must not
// shorten the message to make it fit.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { resetSharedBehaviourLookup } from "../src/core/behaviour.js";
import { MAX_SEND_MESSAGE_BYTES, MAX_SEND_REQUEST_BYTES } from "../src/lib/input-limits.js";

// Record what would be posted to the recipient instead of resolving or
// connecting anywhere.
const posted: string[] = [];
vi.mock("../src/lib/egress.js", () => {
  class EgressBlockedError extends Error {}
  return {
    EgressBlockedError,
    assertSafeEgressUrl: vi.fn(async () => {}),
    safeEgressFetch: vi.fn(async (_url: string, init: RequestInit) => {
      posted.push(String(init.body));
      const body = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: { message: { messageId: "r", role: "agent", parts: [{ kind: "text", text: "ack" }] } },
      });
      return {
        response: new Response(body, { status: 200 }),
        bodyText: body,
        bodyBytes: Buffer.byteLength(body),
        bodyTruncated: false,
      };
    }),
  };
});

const { registerSend } = await import("../src/tools/send.js");

const AS = "limits-test.smc.viz";
const card = {
  name: "ticki.adkgo.viz",
  url: "https://d5ababffe892.agents.zipviz.ai",
  public_key: "96be1f42206903c96fd4adfc96c02e4da92440fc7543b5c5bb73cba8805e6376",
  protocols: ["a2a"],
  authentication: { schemes: ["ed25519"] },
};

describe("zipviz_send whole-request limit", () => {
  let home: string;
  let savedHome: string | undefined;
  let handler: (args: { domain: string; message: string; as: string }) => Promise<{
    isError?: boolean;
    content: Array<{ text: string }>;
  }>;

  beforeEach(async () => {
    resetSharedBehaviourLookup();
    posted.length = 0;
    home = await mkdtemp(join(tmpdir(), "zipviz-request-limit-"));
    await mkdir(join(home, ".zipviz", "keys"), { recursive: true });
    savedHome = process.env.HOME;
    process.env.HOME = home;
    const { privateKey } = generateKeyPairSync("ed25519");
    await writeFile(
      join(home, ".zipviz", "keys", `${AS}.key`),
      privateKey.export({ format: "pem", type: "pkcs8" }).toString()
    );
    // Every registry read answers with the card; behaviour reads find nothing.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify(card), { status: 200 }))
    );
    const server = new McpServer({ name: "test", version: "0.0.1" });
    const original = server.registerTool.bind(server);
    server.registerTool = ((name: string, config: unknown, cb: typeof handler) => {
      if (name === "zipviz_send") handler = cb;
      return original(name, config as never, cb as never);
    }) as typeof server.registerTool;
    registerSend(server);
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    await rm(home, { recursive: true, force: true });
  });

  it("refuses a message within the text limit whose request is over 128 KiB, and posts nothing", async () => {
    // 32 KiB of a control character: within the text limit, but each one
    // encodes as \u0001 in JSON, so the request is about six times larger.
    const message = "\u0001".repeat(MAX_SEND_MESSAGE_BYTES);
    const result = await handler({ domain: "ticki.adkgo.viz", message, as: AS });
    expect(result.isError).toBe(true);
    const text = result.content.map((c) => c.text).join("\n");
    expect(text).toContain(`over the ${MAX_SEND_REQUEST_BYTES}-byte limit`);
    expect(text).toContain("Nothing was sent");
    expect(posted).toHaveLength(0);
  });

  it("sends a full 32 KiB message whose request fits, unshortened", async () => {
    const message = "a".repeat(MAX_SEND_MESSAGE_BYTES);
    const result = await handler({ domain: "ticki.adkgo.viz", message, as: AS });
    expect(result.isError).toBeFalsy();
    expect(posted).toHaveLength(1);
    expect(Buffer.byteLength(posted[0])).toBeLessThanOrEqual(MAX_SEND_REQUEST_BYTES);
    const sent = JSON.parse(posted[0]);
    expect(sent.params.message.parts[0].text).toBe(message);
  });
});
