import { describe, it, expect, vi, beforeEach } from "vitest";
import { resetSharedBehaviourLookup } from "../src/core/behaviour.js";

const mockCard = {
  name: "ticki.adkgo.viz",
  description: "ExampleAgent verified identity",
  url: "https://d5ababffe892.agents.zipviz.ai",
  capabilities: [],
  authentication: { schemes: ["ed25519"] },
  public_key: "96be1f42206903c96fd4adfc96c02e4da92440fc7543b5c5bb73cba8805e6376",
  protocols: ["a2a"],
  created: "2026-04-03 09:15:14",
  blue_tick: true,
};

vi.stubGlobal(
  "fetch",
  vi.fn(() =>
    Promise.resolve({
      ok: true,
      json: () => Promise.resolve(mockCard),
    })
  )
);

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerStatus } from "../src/tools/status.js";

describe("zipviz_status", () => {
  let server: McpServer;
  let handler: (args: { domain: string }) => Promise<any>;

  beforeEach(() => {
    // The behaviour lookup is a process-wide instance so that real MCP tool
    // calls coalesce. Reset it between cases: without this, one test's scripted
    // outage is remembered and the next test's request never happens.
    resetSharedBehaviourLookup();
    server = new McpServer({ name: "test", version: "0.0.1" });
    const original = server.registerTool.bind(server);
    server.registerTool = ((name: string, config: any, cb: any) => {
      if (name === "zipviz_status") handler = cb;
      return original(name, config, cb);
    }) as any;
    registerStatus(server);
  });

  it("returns only trust-relevant fields", async () => {
    const result = await handler({ domain: "ticki.adkgo.viz" });

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toEqual({
      domain: "ticki.adkgo.viz",
      name: "ticki.adkgo.viz",
      blueTick: true,
      protocols: ["a2a"],
    });
    // Should NOT include url or public_key
    expect(parsed.url).toBeUndefined();
    expect(parsed.public_key).toBeUndefined();
  });
});
