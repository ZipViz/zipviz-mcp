import { describe, it, expect, vi } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { generateKeyPairSync } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

const mockVerifyResponse = {
  verified: true,
  blue_tick: true,
  entropy_score: 0.91,
};

let lastFetchBody: any = null;
vi.stubGlobal(
  "fetch",
  vi.fn((_url: string, init: any) => {
    lastFetchBody = JSON.parse(init.body as string);
    return Promise.resolve({
      ok: true,
      json: () => Promise.resolve(mockVerifyResponse),
    });
  })
);

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerSignMessage } from "../src/tools/sign_message.js";
import { registerVerify } from "../src/tools/verify.js";

const BASE64_SHAPE = /^[A-Za-z0-9+/]+={0,2}$/;

describe("sign_message → verify handoff", () => {
  it("verify accepts the base64 signature produced by sign_message via the MCP handler path", async () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey
      .export({ format: "pem", type: "pkcs8" })
      .toString();

    // The tool rejects key_path and always signs with the default
    // key at ~/.zipviz/keys/<domain>.key. os.homedir() resolves $HOME on
    // POSIX, so redirect HOME at a temp dir and place the key there.
    const dir = await mkdtemp(join(tmpdir(), "zipviz-handoff-"));
    const keysDir = join(dir, ".zipviz", "keys");
    await mkdir(keysDir, { recursive: true });
    await writeFile(join(keysDir, "test.smc.viz.key"), pem);
    const savedHome = process.env.HOME;
    process.env.HOME = dir;

    try {
      const server = new McpServer({ name: "test", version: "0.0.1" });
      let signHandler: any;
      let verifyHandler: any;
      const original = server.registerTool.bind(server);
      server.registerTool = ((name: string, config: any, cb: any) => {
        if (name === "zipviz_sign_message") signHandler = cb;
        if (name === "zipviz_verify") verifyHandler = cb;
        return original(name, config, cb);
      }) as any;
      registerSignMessage(server);
      registerVerify(server);

      const message = "handoff smoke";
      const signResult = await signHandler({
        viz_domain: "test.smc.viz",
        message,
      });
      const signParsed = JSON.parse(signResult.content[0].text);

      expect(signParsed.signature).toMatch(BASE64_SHAPE);
      expect(signParsed.signature).toHaveLength(88);

      await verifyHandler({
        domain: "test.smc.viz",
        message,
        timestamp: "2026-05-07T03:00:00Z",
        signature: signParsed.signature,
      });

      expect(lastFetchBody).toEqual({
        from: "test.smc.viz",
        message,
        timestamp: "2026-05-07T03:00:00Z",
        signature: signParsed.signature,
      });
    } finally {
      if (savedHome === undefined) delete process.env.HOME;
      else process.env.HOME = savedHome;
      await rm(dir, { recursive: true, force: true });
    }
  });
});
