import { describe, it, expect, vi, beforeEach } from "vitest";

const mockCard = {
  name: "ticki.adkgo.viz",
  description: "ExampleAgent verified identity",
  url: "https://d5ababffe892.agents.zipviz.ai",
  capabilities: [],
  authentication: { schemes: ["ed25519"] },
  public_key: "96be1f42206903c96fd4adfc96c02e4da92440fc7543b5c5bb73cba8805e6376",
  protocols: ["a2a"],
  created: "2026-04-03 09:15:14",
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
import { registerLookup } from "../src/tools/lookup.js";

describe("zipviz_lookup", () => {
  let server: McpServer;
  let handler: (args: { domain: string }) => Promise<any>;

  beforeEach(() => {
    server = new McpServer({ name: "test", version: "0.0.1" });
    const original = server.registerTool.bind(server);
    server.registerTool = ((name: string, config: any, cb: any) => {
      if (name === "zipviz_lookup") handler = cb;
      return original(name, config, cb);
    }) as any;
    registerLookup(server);
  });

  it("fetches agent card and returns formatted JSON", async () => {
    const result = await handler({ domain: "ticki.adkgo.viz" });

    expect(fetch).toHaveBeenCalledWith(
      "https://api.zipviz.ai/v1/agent/ticki.adkgo.viz/card",
      expect.objectContaining({ headers: expect.any(Object) })
    );
    expect(result.content[0].type).toBe("text");
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.name).toBe("ticki.adkgo.viz");
    expect(parsed.url).toBe("https://d5ababffe892.agents.zipviz.ai");
  });

  it("URL-encodes the domain", async () => {
    await handler({ domain: "agent with spaces.viz" });

    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("agent%20with%20spaces.viz"),
      expect.any(Object)
    );
  });
});
