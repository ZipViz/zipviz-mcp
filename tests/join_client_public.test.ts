import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash, createPublicKey, verify } from "node:crypto";
import { lstat, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JoinClient, joinTransport, type JoinResponse } from "../src/lib/join-client.js";
import { JoinStore } from "../src/lib/join-store.js";

// The join client against a synthetic sign-up service. The transport is injected,
// so nothing leaves the process. The signature check below is independent of the
// client's own codec: plain RFC 8785 canonical JSON and node:crypto Ed25519.

const SIGNUP_ID = "6f1c2a4e-8b3d-4c5e-9f7a-0b1c2d3e4f50";
const NOW = 1_793_000_000_000;
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function jcs(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${jcs(v)}`).join(",")}}`;
}

function proofVerifies(proof: Record<string, unknown>): boolean {
  const { signature, ...unsigned } = proof as { signature: { value_base64url: string } } & Record<string, unknown>;
  const publicKey = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(String(unsigned.public_key), "hex")]),
    format: "der", type: "spki" });
  const bytes = Buffer.from(`ZipViz signup-start v1\0${jcs(unsigned)}`, "utf8");
  return verify(null, bytes, publicKey, Buffer.from(signature.value_base64url, "base64url"));
}

describe("join client against a synthetic sign-up service", () => {
  let temporary: string;
  let root: string;
  const requests: Array<{ path: string; method: string; bytes?: string }> = [];

  const transport = async (path: string, method: "GET" | "POST", bytes?: string): Promise<JoinResponse> => {
    requests.push({ path, method, bytes });
    if (method === "POST" && path === "/v1/signup/start") {
      return { status: 201, body: { schema_version: "1.0", signup_id: SIGNUP_ID, state: "pending",
        proposed_domain: "fixture-agent.z.viz", user_code: "BCDF-GHJK", approval_url: "https://zipviz.ai/approve/BCDF-GHJK",
        expires_at_ms: NOW + 600_000, poll_interval_ms: 5000 } };
    }
    if (method === "GET" && path === `/v1/signup/${SIGNUP_ID}`) {
      return { status: 200, body: { schema_version: "1.0", signup_id: SIGNUP_ID, state: "pending",
        proposed_domain: "fixture-agent.z.viz", expires_at_ms: NOW + 600_000, poll_interval_ms: 5000 } };
    }
    return { status: 404, body: { code: "E_NOT_FOUND" } };
  };

  beforeEach(async () => {
    requests.length = 0;
    temporary = await mkdtemp(join(tmpdir(), "join-client-public-"));
    root = join(temporary, "keys");
  });
  afterEach(async () => { vi.unstubAllGlobals(); await rm(temporary, { recursive: true, force: true }); });

  const client = () => new JoinClient({ store: new JoinStore(root), transport, now: () => NOW, uuid: () => SIGNUP_ID,
    wait: async () => {} });

  it("sends one signed, canonical start request and returns the approval link for the human", async () => {
    const result = await client().start({ name: "fixture-agent", owner_email: "owner@example.invalid", runtime: "other" });
    expect(result).toMatchObject({ signup_id: SIGNUP_ID, state: "pending", user_code: "BCDF-GHJK",
      approval_url: "https://zipviz.ai/approve/BCDF-GHJK" });
    expect(result.key_fingerprint).toMatch(/\S/);

    const starts = requests.filter((r) => r.path === "/v1/signup/start");
    expect(starts).toHaveLength(1);
    const body = JSON.parse(starts[0]!.bytes!);
    // The wire bytes are exactly their own canonical form.
    expect(starts[0]!.bytes).toBe(jcs(body));
    expect(body.proof).toMatchObject({ schema_version: "1.0", type: "zipviz.signup.start", signup_id: SIGNUP_ID,
      audience: "api.zipviz.ai", issued_at_ms: NOW });
    expect(proofVerifies(body.proof)).toBe(true);
    // The proof's exact key set and signature object, as the sign-up API requires.
    expect(Object.keys(body.proof).sort()).toEqual(["audience", "bound_digest", "issued_at_ms", "public_key",
      "schema_version", "signature", "signup_id", "type"]);
    const raw = Buffer.from(body.proof.public_key, "hex");
    expect(raw).toHaveLength(32);
    expect(body.proof.signature).toEqual({ alg: "Ed25519", key_id: `sha256:${createHash("sha256").update(raw).digest("hex")}`,
      value_base64url: expect.stringMatching(/^[A-Za-z0-9_-]{86}$/) });
    // bound_digest commits to the fields the human approves, with no intro as JSON null.
    expect(body.proof.bound_digest).toBe(createHash("sha256")
      .update(jcs({ introduced_by: null, owner_email: "owner@example.invalid", runtime: "other" }), "utf8").digest("hex"));
    expect(body).toMatchObject({ name: "fixture-agent", owner_email: "owner@example.invalid", runtime: "other", introduced_by: null });
    // A changed proof field no longer verifies.
    expect(proofVerifies({ ...body.proof, audience: "evil.example.invalid" })).toBe(false);
  });

  it("keeps the pending key on this machine only, owner-only, and never sends it", async () => {
    await client().start({ name: "fixture-agent", owner_email: "owner@example.invalid", runtime: "other" });
    expect((await lstat(root)).mode & 0o777).toBe(0o700);
    expect((await lstat(join(root, "pending"))).mode & 0o777).toBe(0o700);
    const files = await readdir(join(root, "pending"));
    expect(files).toContain(`${SIGNUP_ID}.key`);
    expect((await lstat(join(root, "pending", `${SIGNUP_ID}.key`))).mode & 0o777).toBe(0o600);
    const pem = await readFile(join(root, "pending", `${SIGNUP_ID}.key`), "utf8");
    expect(pem).toContain("PRIVATE KEY");
    for (const request of requests) expect(request.bytes ?? "").not.toContain("PRIVATE KEY");
    const body = JSON.parse(requests.find((r) => r.path === "/v1/signup/start")!.bytes!);
    const derived = createPublicKey(pem).export({ type: "spki", format: "der" }).subarray(SPKI_PREFIX.length).toString("hex");
    expect(body.proof.public_key).toBe(derived);
  });

  it("the default transport only talks to https://api.zipviz.ai and refuses redirects", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    });
    await joinTransport("/v1/signup/start", "POST", "{}");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://api.zipviz.ai/v1/signup/start");
    expect(calls[0]!.init.redirect).toBe("error");
    expect(calls[0]!.init.headers).not.toHaveProperty("Authorization");
  });
});
