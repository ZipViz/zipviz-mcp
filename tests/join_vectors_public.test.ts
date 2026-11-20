import { createPrivateKey, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { JOIN_SIGNING_DOMAINS, keyId, makeCancel, makeStart, publicKeyHex, signingBytes } from "../src/lib/join-codec.js";

// Public deterministic synthetic vectors (test-vectors/signup-v1.json). The keys
// are test-only seeds and must never be used for a real identity. For every
// vector the sign-up service accepts, the client must produce the pinned bytes
// exactly, and the pinned signature must verify with plain node:crypto.

interface Vector {
  id: string; kind: "start" | "cancel" | "intro" | "policy"; request_bytes: string;
  unsigned_jcs: string; signing_bytes_hex: string; key_id: string; bound_digest: string | null;
  signature: string; expected: { status: number; code: string | null };
}
const fixture = JSON.parse(readFileSync(new URL("../test-vectors/signup-v1.json", import.meta.url), "utf8")) as {
  test_only: boolean; now_ms: number; audience: string;
  keys: { agent: { test_only_seed_hex: string; public_key: string } };
  vectors: Vector[];
};
const agentKey = createPrivateKey({ format: "der", type: "pkcs8", key: Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  Buffer.from(fixture.keys.agent.test_only_seed_hex, "hex"),
]) });
const agentPublic = createPublicKey(agentKey);
const accepted = (kind: Vector["kind"]) =>
  fixture.vectors.filter((v) => v.kind === kind && (v.expected.status === 200 || v.expected.status === 201));

describe("public synthetic sign-up vectors", () => {
  it("are marked test-only and use the agent key they publish", () => {
    expect(fixture.test_only).toBe(true);
    expect(fixture.audience).toBe("api.zipviz.ai");
    expect(publicKeyHex(agentKey)).toBe(fixture.keys.agent.public_key);
    expect(accepted("start").length).toBeGreaterThan(0);
    expect(accepted("cancel").length).toBeGreaterThan(0);
  });

  for (const vector of accepted("start")) {
    it(`${vector.id}: the client builds the pinned start request byte for byte`, () => {
      const body = JSON.parse(vector.request_bytes);
      expect(body.proof.public_key).toBe(fixture.keys.agent.public_key);
      const rebuilt = makeStart({ name: body.name, owner_email: body.owner_email, runtime: body.runtime,
        introduced_by: body.introduced_by }, body.proof.signup_id, agentKey, body.proof.issued_at_ms, fixture.audience);
      expect(rebuilt).toBe(vector.request_bytes);
      const { signature, ...unsigned } = body.proof;
      expect(signingBytes(unsigned, JOIN_SIGNING_DOMAINS.start).toString("hex")).toBe(vector.signing_bytes_hex);
      expect(signature.key_id).toBe(keyId(fixture.keys.agent.public_key));
      expect(verify(null, Buffer.from(vector.signing_bytes_hex, "hex"), agentPublic,
        Buffer.from(signature.value_base64url, "base64url"))).toBe(true);
    });
  }

  for (const vector of accepted("cancel")) {
    it(`${vector.id}: the client builds the pinned cancel request byte for byte`, () => {
      const body = JSON.parse(vector.request_bytes);
      const rebuilt = makeCancel(body.signup_id, body.nonce, agentKey, body.issued_at_ms, fixture.audience);
      expect(rebuilt).toBe(vector.request_bytes);
      expect(verify(null, Buffer.from(vector.signing_bytes_hex, "hex"), agentPublic,
        Buffer.from(body.signature.value_base64url, "base64url"))).toBe(true);
    });
  }
});
