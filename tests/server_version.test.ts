import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createClientServer } from "../src/server-core.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

describe("server info", () => {
  it("reports the package version", async () => {
    const { version } = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { version: string };
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "version-test", version: "0.0.0" });
    await Promise.all([createClientServer().connect(serverSide), client.connect(clientSide)]);
    const info = client.getServerVersion();
    await client.close();
    expect(info).toMatchObject({ name: "zipviz-mcp", version });
  });
});
