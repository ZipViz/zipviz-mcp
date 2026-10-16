import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createClientServer } from "../src/server-core.js";

const CLIENT_TOOLS = [
  "zipviz_lookup",
  "zipviz_status",
  "zipviz_send",
  "zipviz_verify",
  "zipviz_explain_verification",
  "zipviz_sign_message",
];

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(ROOT, "src");

/** Every relative import (value, type-only and dynamic) reachable from `entry`. */
export function importClosure(entry: string): Set<string> {
  const pattern =
    /(?:import|export)\s[^'"]*?from\s*['"]([^'"]+)['"]|import\s*\(\s*['"]([^'"]+)['"]\s*\)|import\s+['"]([^'"]+)['"]/g;
  const seen = new Set<string>();
  const todo = [resolve(entry)];
  while (todo.length > 0) {
    const file = todo.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    for (const match of readFileSync(file, "utf8").matchAll(pattern)) {
      const spec = match[1] ?? match[2] ?? match[3];
      if (!spec.startsWith(".")) continue;
      todo.push(resolve(dirname(file), spec.replace(/\.js$/, ".ts")));
    }
  }
  return seen;
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sourceFiles(path) : path.endsWith(".ts") ? [path] : [];
  });
}

async function listToolNames(server: McpServer): Promise<string[]> {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "surface-test", version: "0.0.0" });
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
  const { tools } = await client.listTools();
  await client.close();
  return tools.map((tool) => tool.name);
}

describe("client tool surface", () => {
  it("is exactly the six client tools", async () => {
    expect((await listToolNames(createClientServer())).sort()).toEqual([...CLIENT_TOOLS].sort());
  });

  it("runs the instrument hook before any tool is registered", async () => {
    let registeredAtHook = -1;
    const server = createClientServer({
      instrument: (s) => {
        registeredAtHook = Object.keys(
          (s as unknown as { _registeredTools: Record<string, unknown> })._registeredTools,
        ).length;
      },
    });
    expect(registeredAtHook).toBe(0);
    expect(await listToolNames(server)).toHaveLength(CLIENT_TOOLS.length);
  });

  it("ships only code the stdio entry reaches, with no persistence or file writes", () => {
    const closure = importClosure(join(SRC, "stdio.ts"));
    for (const file of closure) {
      expect(statSync(file).isFile(), relative(ROOT, file)).toBe(true);
      const text = readFileSync(file, "utf8");
      expect(text, relative(ROOT, file)).not.toMatch(/node:sqlite|appendFile|writeFile|createWriteStream|mkdir/);
    }
    const unreachable = sourceFiles(SRC)
      .filter((file) => !closure.has(file))
      .map((file) => relative(ROOT, file));
    expect(unreachable).toEqual([]);
  });
});
