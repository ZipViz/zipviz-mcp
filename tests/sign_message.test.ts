import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { generateKeyPairSync, verify } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  signMessage,
  registerSignMessage,
} from "../src/tools/sign_message.js";

async function makeKeyFile(dir: string, name = "test.key") {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const path = join(dir, name);
  await writeFile(path, pem);
  return { path, publicKey };
}

describe("signMessage", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "zipviz-sign-"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("signs the v=1 canonical envelope that api.zipviz.ai /v1/verify accepts", async () => {
    const { path, publicKey } = await makeKeyFile(dir);
    const message = "hello from claudais";

    const result = await signMessage({
      viz_domain: "claudais.smc.viz",
      message,
      key_path: path,
    });

    expect(result.viz_domain).toBe("claudais.smc.viz");
    expect(result).not.toHaveProperty("key_path");
    expect(typeof result.signature).toBe("string");
    expect(result.signing_version).toBe(1);
    expect(typeof result.timestamp).toBe("string");

    // Positive: the signature must verify against the v=1 canonical payload
    // that the trust root reconstructs in the registry
    // (JSON.stringify({v:1, from, message, timestamp}), field order fixed).
    const expectedPayload = Buffer.from(
      JSON.stringify({
        v: 1,
        from: "claudais.smc.viz",
        message,
        timestamp: result.timestamp,
      }),
      "utf8"
    );
    const sigBytes = Buffer.from(result.signature, "base64");
    expect(verify(null, expectedPayload, publicKey, sigBytes)).toBe(true);

    // Regression guard: the older behavior (signing bare message
    // bytes) must NOT verify against the new sig. If this ever passes
    // again we've slipped back to the broken format.
    expect(
      verify(null, Buffer.from(message, "utf8"), publicKey, sigBytes)
    ).toBe(false);
  });

  it("bakes a caller-supplied timestamp into the signed payload and echoes it back", async () => {
    const { path, publicKey } = await makeKeyFile(dir);
    const message = "fixed-time hello";
    const fixedTs = "2026-05-14T00:00:00Z";

    const result = await signMessage({
      viz_domain: "alice.smc.viz",
      message,
      key_path: path,
      timestamp: fixedTs,
    });

    expect(result.timestamp).toBe(fixedTs);
    expect(result.signing_version).toBe(1);

    const expectedPayload = Buffer.from(
      JSON.stringify({
        v: 1,
        from: "alice.smc.viz",
        message,
        timestamp: fixedTs,
      }),
      "utf8"
    );
    expect(
      verify(
        null,
        expectedPayload,
        publicKey,
        Buffer.from(result.signature, "base64")
      )
    ).toBe(true);
  });

  it("generates a fresh ISO 8601 timestamp within ~2s of now when omitted", async () => {
    const { path } = await makeKeyFile(dir);
    const before = Date.now();
    const result = await signMessage({
      viz_domain: "bob.smc.viz",
      message: "auto-timestamp",
      key_path: path,
    });
    const after = Date.now();

    expect(result.timestamp).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/
    );
    const parsed = Date.parse(result.timestamp);
    expect(parsed).toBeGreaterThanOrEqual(before - 2000);
    expect(parsed).toBeLessThanOrEqual(after + 2000);
  });

  it("throws a clear error when the key file is missing", async () => {
    const path = join(dir, "does-not-exist.key");
    const error = await signMessage({
        viz_domain: "ghost.smc.viz",
        message: "anything",
        key_path: path,
      }).catch((err: unknown) => err as Error);
    expect(error.message).toMatch(/Private key unavailable/);
    expect(error.message).not.toContain(path);
  });

  it("throws a clear error when the key file is not a valid PEM", async () => {
    const path = join(dir, "junk.key");
    await writeFile(path, "this is not a key");

    const error = await signMessage({
        viz_domain: "junk.smc.viz",
        message: "anything",
        key_path: path,
      }).catch((err: unknown) => err as Error);
    expect(error.message).toMatch(/Invalid private key/);
    expect(error.message).not.toContain(path);
  });

  it("rejects a non-ed25519 key", async () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    const path = join(dir, "rsa.key");
    await writeFile(path, pem);

    const error = await signMessage({
        viz_domain: "rsa.smc.viz",
        message: "anything",
        key_path: path,
      }).catch((err: unknown) => err as Error);
    expect(error.message).toMatch(/expected ed25519/);
    expect(error.message).not.toContain(path);
  });

  it("rejects a viz_domain that is not a valid .viz domain before touching the filesystem", async () => {
    // A path-traversal viz_domain must never reach defaultKeyPath(); the
    // primitive itself refuses it, so no readFile of an out-of-keys-dir path
    // is even attempted. key_path is set to prove the domain check runs first.
    await expect(
      signMessage({
        viz_domain: "../../../../etc/shadow",
        message: "anything",
        key_path: join(dir, "unused.key"),
      })
    ).rejects.toThrow(/Invalid viz_domain/);

    await expect(
      signMessage({
        viz_domain: "Alice.SMC.viz",
        message: "anything",
      })
    ).rejects.toThrow(/Invalid viz_domain/);
  });
});

describe("zipviz_sign_message MCP tool", () => {
  let server: McpServer;
  let handler: (args: {
    viz_domain: string;
    message: string;
    key_path?: string;
  }) => Promise<any>;
  let dir: string;
  let keysDir: string;
  let savedHome: string | undefined;

  // The tool always signs with the default key at ~/.zipviz/keys/<domain>.key.
  // os.homedir()
  // resolves $HOME on POSIX, so we point HOME at a temp dir and place keys
  // under <HOME>/.zipviz/keys to exercise the real default-path resolution.
  async function placeDefaultKey(viz_domain: string) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    await writeFile(join(keysDir, `${viz_domain}.key`), pem);
    return { publicKey };
  }

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "zipviz-sign-mcp-"));
    keysDir = join(dir, ".zipviz", "keys");
    await mkdir(keysDir, { recursive: true });
    savedHome = process.env.HOME;
    process.env.HOME = dir;

    server = new McpServer({ name: "test", version: "0.0.1" });
    const original = server.registerTool.bind(server);
    server.registerTool = ((name: string, config: any, cb: any) => {
      if (name === "zipviz_sign_message") handler = cb;
      return original(name, config, cb);
    }) as any;
    registerSignMessage(server);
  });

  afterEach(async () => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    await rm(dir, { recursive: true, force: true });
  });

  it("returns the v=1 signed envelope (signature + timestamp + signing_version) in JSON content on success", async () => {
    const { publicKey } = await placeDefaultKey("alice.smc.viz");
    const message = "ping";

    const result = await handler({
      viz_domain: "alice.smc.viz",
      message,
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.viz_domain).toBe("alice.smc.viz");
    expect(payload).not.toHaveProperty("key_path");
    expect(result.content[0].text).not.toContain(keysDir);
    expect(payload.signing_version).toBe(1);
    expect(typeof payload.timestamp).toBe("string");

    const expectedPayload = Buffer.from(
      JSON.stringify({
        v: 1,
        from: "alice.smc.viz",
        message,
        timestamp: payload.timestamp,
      }),
      "utf8"
    );
    expect(
      verify(
        null,
        expectedPayload,
        publicKey,
        Buffer.from(payload.signature, "base64")
      )
    ).toBe(true);
  });

  it("returns a generic error (no missing/bad-PEM/wrong-type file oracle) when the key cannot be loaded", async () => {
    const result = await handler({
      viz_domain: "missing.smc.viz",
      message: "x",
    });

    expect(result.isError).toBe(true);
    const text = result.content[0].text as string;
    // Generic: actionable but does not reveal which stage failed.
    expect(text).toMatch(/no usable Ed25519 signing key/);
    expect(text).not.toMatch(/Private key not found/);
    expect(text).not.toMatch(/Invalid private key/);
    expect(text).not.toMatch(/expected ed25519/);
    expect(text).not.toContain(dir);
    expect(text).not.toContain(".zipviz/keys");
  });

  it("rejects key_path at the tool boundary, independent of the relay", async () => {
    // Even with a perfectly valid key present at the default location, an
    // explicit key_path must be refused before any I/O — it would otherwise
    // let a caller sign with any PEM the process can read.
    await placeDefaultKey("alice.smc.viz");
    const result = await handler({
      viz_domain: "alice.smc.viz",
      message: "x",
      key_path: "/etc/ssh/ssh_host_ed25519_key",
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/key_path is not permitted/);
    expect(result.content[0].text).not.toContain("/etc/ssh");
    expect(result.content[0].text).not.toContain(".zipviz/keys");
  });

  it("rejects a path-traversal / malformed viz_domain at the tool boundary", async () => {
    const traversal = await handler({
      viz_domain: "../../../../etc/shadow",
      message: "x",
    });
    expect(traversal.isError).toBe(true);
    expect(traversal.content[0].text).toMatch(/Invalid viz_domain/);

    const uppercase = await handler({
      viz_domain: "Alice.SMC.viz",
      message: "x",
    });
    expect(uppercase.isError).toBe(true);
    expect(uppercase.content[0].text).toMatch(/Invalid viz_domain/);
  });
});
