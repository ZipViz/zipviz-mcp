// Input size limits at the tool boundary and on the stdio frame.
//
// Every argument reaches a tool from the MCP client, and the schema is the
// first thing that sees it. These tests hold the limits in place: an oversized
// argument is refused before the handler runs (so before any signing, hashing,
// filesystem access or network call), a value at the limit still gets through,
// and the stdio transport refuses a frame larger than MAX_FRAME_BYTES.

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
  MAX_MESSAGE_BYTES,
  MAX_SIGNATURE_CHARS,
  MAX_TIMESTAMP_CHARS,
  fitsMessageBudget,
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

describe("fitsMessageBudget", () => {
  it("counts UTF-8 bytes, not characters", () => {
    expect(fitsMessageBudget("a".repeat(MAX_MESSAGE_BYTES))).toBe(true);
    expect(fitsMessageBudget("a".repeat(MAX_MESSAGE_BYTES + 1))).toBe(false);
    // "é" is two bytes: half the budget in characters is exactly the limit.
    expect(fitsMessageBudget("é".repeat(MAX_MESSAGE_BYTES / 2))).toBe(true);
    expect(fitsMessageBudget("é".repeat(MAX_MESSAGE_BYTES / 2 + 1))).toBe(false);
  });
});

describe("tool argument limits", () => {
  let client: Client;
  let home: string;
  let savedHome: string | undefined;
  const fetchSpy = vi.fn(async () => new Response("{}", { status: 500 }));

  beforeEach(async () => {
    // No key exists under this HOME, and the global fetch is a spy: a call that
    // got past the schema would show up as a key error or a fetch, not silently.
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
  const bigMessage = "a".repeat(MAX_MESSAGE_BYTES + 1);
  const ts = "2026-10-16T00:00:00.000Z";

  const oversized: Array<[string, Record<string, unknown>]> = [
    ["zipviz_lookup", { domain: longDomain }],
    ["zipviz_status", { domain: longDomain }],
    ["zipviz_send", { domain: longDomain, message: "hi", as: "me.smc.viz" }],
    ["zipviz_send", { domain: "ticki.adkgo.viz", message: "hi", as: longDomain }],
    ["zipviz_send", { domain: "ticki.adkgo.viz", message: bigMessage, as: "me.smc.viz" }],
    ["zipviz_verify", { domain: "ticki.adkgo.viz", message: bigMessage, timestamp: ts, signature: "s" }],
    [
      "zipviz_verify",
      { domain: "ticki.adkgo.viz", message: "hi", timestamp: "2".repeat(MAX_TIMESTAMP_CHARS + 1), signature: "s" },
    ],
    [
      "zipviz_verify",
      { domain: "ticki.adkgo.viz", message: "hi", timestamp: ts, signature: "A".repeat(MAX_SIGNATURE_CHARS + 1) },
    ],
    ["zipviz_sign_message", { viz_domain: longDomain, message: "hi" }],
    ["zipviz_sign_message", { viz_domain: "me.smc.viz", message: bigMessage }],
    ["zipviz_sign_message", { viz_domain: "me.smc.viz", message: "hi", timestamp: "2".repeat(MAX_TIMESTAMP_CHARS + 1) }],
  ];

  it.each(oversized)("%s refuses an oversized argument before the handler runs (%#)", async (name, args) => {
    expect(longDomain.length).toBe(MAX_DOMAIN_CHARS + 1);
    const result = (await client.callTool({ name, arguments: args })) as ToolResult;
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/Input validation error/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("lets a message at exactly the byte limit through to the handler", async () => {
    // The handler runs and stops at the missing key, which proves the schema
    // accepted a full-size message.
    const result = (await client.callTool({
      name: "zipviz_sign_message",
      arguments: { viz_domain: "me.smc.viz", message: "é".repeat(MAX_MESSAGE_BYTES / 2) },
    })) as ToolResult;
    expect(text(result)).not.toMatch(/Input validation error/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("stdio frame limit", () => {
  it("is wired into the stdio entry point", () => {
    const source = readFileSync(join(ROOT, "src/stdio.ts"), "utf8");
    expect(source).toMatch(/maxBufferSize:\s*MAX_FRAME_BYTES/);
  });

  it("holds a full-size message even when every character needs escaping", () => {
    // A control character serializes as \uXXXX, six bytes for one byte of text.
    const frame = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "zipviz_sign_message", arguments: { viz_domain: "me.smc.viz", message: "\u0001".repeat(MAX_MESSAGE_BYTES) } },
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
