// Input size limits at the tool boundary and on the stdio frame.
//
// Every argument reaches a tool from the MCP client, and the schema is the
// first thing that sees it. These tests hold the limits in place: an oversized
// argument is refused before the handler runs (so before any signing, hashing,
// filesystem access or network call) and is never truncated to fit, a value at
// the limit still gets through, and the stdio transport refuses a frame larger
// than MAX_FRAME_BYTES.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createClientServer } from "../src/server-core.js";
import {
  MAX_DOMAIN_CHARS,
  MAX_FRAME_BYTES,
  MAX_SEND_MESSAGE_BYTES,
  MAX_SIGNATURE_CHARS,
  MAX_TIMESTAMP_CHARS,
  fitsSendMessage,
} from "../src/lib/input-limits.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

type ToolResult = { isError?: boolean; content: Array<{ type: string; text?: string }> };

async function connect(): Promise<Client> {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "input-limits-test", version: "0.0.0" });
  await Promise.all([createClientServer().connect(serverSide), client.connect(clientSide)]);
  return client;
}

function text(result: ToolResult): string {
  return result.content.map((c) => c.text ?? "").join("\n");
}

/** `count` copies of `ch`, plus the UTF-8 byte length of the result. */
function repeat(ch: string, count: number): { value: string; bytes: number } {
  const value = ch.repeat(count);
  return { value, bytes: Buffer.byteLength(value, "utf8") };
}

describe("send message limit", () => {
  it("is 32 KiB", () => {
    expect(MAX_SEND_MESSAGE_BYTES).toBe(32768);
  });

  // One case per UTF-8 width, each exactly at the limit and one character over.
  it.each([
    ["1-byte (a)", "a", 1],
    ["2-byte (é)", "é", 2],
    ["3-byte (€)", "€", 3],
    ["4-byte (😀, two UTF-16 units)", "😀", 4],
  ])("counts UTF-8 bytes for %s characters", (_label, ch, width) => {
    const atLimit = repeat(ch, Math.floor(MAX_SEND_MESSAGE_BYTES / width));
    const over = repeat(ch, Math.floor(MAX_SEND_MESSAGE_BYTES / width) + 1);
    expect(atLimit.bytes).toBeLessThanOrEqual(MAX_SEND_MESSAGE_BYTES);
    expect(over.bytes).toBeGreaterThan(MAX_SEND_MESSAGE_BYTES);
    expect(fitsSendMessage(atLimit.value)).toBe(true);
    expect(fitsSendMessage(over.value)).toBe(false);
  });

  it("refuses a message one byte over even when its character count is well under", () => {
    // 16,383 two-byte characters plus two ASCII bytes: 32,768 bytes fits,
    // a third ASCII byte makes 32,769.
    const base = "é".repeat(16383);
    expect(fitsSendMessage(base + "aa")).toBe(true);
    expect(fitsSendMessage(base + "aaa")).toBe(false);
    expect((base + "aaa").length).toBeLessThan(MAX_SEND_MESSAGE_BYTES);
  });
});

describe("tool argument limits", () => {
  let client: Client;
  let home: string;
  let savedHome: string | undefined;
  const fetchSpy = vi.fn(async () => new Response("{}", { status: 500 }));

  beforeEach(async () => {
    // No key exists under this HOME, and the global fetch is a spy: a call that
    // got past the schema shows up as a key error or a fetch, never silently.
    home = mkdtempSync(join(tmpdir(), "zipviz-limits-"));
    savedHome = process.env.HOME;
    process.env.HOME = home;
    fetchSpy.mockClear();
    vi.stubGlobal("fetch", fetchSpy);
    client = await connect();
  });

  afterEach(async () => {
    await client.close();
    vi.unstubAllGlobals();
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    rmSync(home, { recursive: true, force: true });
  });

  const longDomain = "a".repeat(MAX_DOMAIN_CHARS - 4) + "x.viz"; // one over the limit
  const overSend = "a".repeat(MAX_SEND_MESSAGE_BYTES + 1);
  const ts = "2026-10-16T00:00:00.000Z";

  const oversized: Array<[string, Record<string, unknown>]> = [
    ["zipviz_lookup", { domain: longDomain }],
    ["zipviz_status", { domain: longDomain }],
    ["zipviz_send", { domain: longDomain, message: "hi", as: "me.smc.viz" }],
    ["zipviz_send", { domain: "ticki.adkgo.viz", message: "hi", as: longDomain }],
    [
      "zipviz_verify",
      { domain: "ticki.adkgo.viz", message: "hi", timestamp: "2".repeat(MAX_TIMESTAMP_CHARS + 1), signature: "s" },
    ],
    [
      "zipviz_verify",
      { domain: "ticki.adkgo.viz", message: "hi", timestamp: ts, signature: "A".repeat(MAX_SIGNATURE_CHARS + 1) },
    ],
    ["zipviz_sign_message", { viz_domain: longDomain, message: "hi" }],
    ["zipviz_sign_message", { viz_domain: "me.smc.viz", message: "hi", timestamp: "2".repeat(MAX_TIMESTAMP_CHARS + 1) }],
  ];

  it.each(oversized)("%s refuses an oversized argument before the handler runs (%#)", async (name, args) => {
    expect(longDomain.length).toBe(MAX_DOMAIN_CHARS + 1);
    const result = (await client.callTool({ name, arguments: args })) as ToolResult;
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/Input validation error/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refuses a send message one byte over with a clear error, and sends nothing", async () => {
    const result = (await client.callTool({
      name: "zipviz_send",
      arguments: { domain: "ticki.adkgo.viz", message: overSend, as: "me.smc.viz" },
    })) as ToolResult;
    expect(result.isError).toBe(true);
    expect(text(result)).toContain(`message must be at most ${MAX_SEND_MESSAGE_BYTES} bytes of UTF-8 text`);
    // Refused outright: no lookup, no signing, no send of a shortened copy.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("lets a send message of exactly 32 KiB through to the handler", async () => {
    // 8,192 four-byte characters: exactly the limit in bytes, half of it in
    // UTF-16 units. The handler runs and reaches the registry lookup (the
    // fetch spy answers 500), which proves the schema accepted it.
    const atLimit = "😀".repeat(MAX_SEND_MESSAGE_BYTES / 4);
    expect(Buffer.byteLength(atLimit, "utf8")).toBe(MAX_SEND_MESSAGE_BYTES);
    const result = (await client.callTool({
      name: "zipviz_send",
      arguments: { domain: "ticki.adkgo.viz", message: atLimit, as: "me.smc.viz" },
    })) as ToolResult;
    expect(text(result)).not.toMatch(/Input validation error/i);
    expect(fetchSpy).toHaveBeenCalled();
  });

  it("does not apply the send limit to signing", async () => {
    // Signing is local and not addressed to a receiver; only the frame bounds
    // it. The handler runs and stops at the missing key.
    const result = (await client.callTool({
      name: "zipviz_sign_message",
      arguments: { viz_domain: "me.smc.viz", message: overSend },
    })) as ToolResult;
    expect(text(result)).not.toMatch(/Input validation error/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("does not apply the send limit to verification", async () => {
    const result = (await client.callTool({
      name: "zipviz_verify",
      arguments: { domain: "ticki.adkgo.viz", message: overSend, timestamp: ts, signature: "s" },
    })) as ToolResult;
    expect(text(result)).not.toMatch(/Input validation error/i);
  });
});

describe("stdio frame limit", () => {
  it("is wired into the stdio entry point", () => {
    const source = readFileSync(join(ROOT, "src/stdio.ts"), "utf8");
    expect(source).toMatch(/maxBufferSize:\s*MAX_FRAME_BYTES/);
  });

  it("holds a full-size send message even when every character needs escaping", () => {
    // A control character serializes as \uXXXX, six bytes for one byte of text.
    const frame = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "zipviz_send",
        arguments: { domain: "ticki.adkgo.viz", as: "me.smc.viz", message: "\u0001".repeat(MAX_SEND_MESSAGE_BYTES) },
      },
    });
    expect(Buffer.byteLength(frame) + 1).toBeLessThan(MAX_FRAME_BYTES);
  });

  it("refuses a frame over the limit and closes the transport", async () => {
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const transport = new StdioServerTransport(stdin, stdout, { maxBufferSize: MAX_FRAME_BYTES });
    const errors: Error[] = [];
    let closed = false;
    const messages: unknown[] = [];
    transport.onerror = (e) => errors.push(e);
    transport.onclose = () => {
      closed = true;
    };
    transport.onmessage = (m) => messages.push(m);
    await transport.start();

    stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');
    expect(messages).toHaveLength(1);

    stdin.write(Buffer.alloc(MAX_FRAME_BYTES + 1, 0x61));
    await new Promise((r) => setImmediate(r));
    expect(errors.map((e) => e.message).join()).toMatch(/exceeded maximum size/);
    expect(closed).toBe(true);
    expect(messages).toHaveLength(1);
  });
});
