import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";
import { signFileKeySync, signCanonicalSync } from "../signer/backend.js";
import type { JoinHandle } from "../signer/join-handle.js";
export type JoinSigningKey = KeyObject | JoinHandle;
import { z } from "zod";

export const JOIN_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const JOIN_DOMAIN = /^[a-z0-9-]{1,20}\.z\.viz$/;
export const JOIN_BODY_MAX_BYTES = 4096;
export const JOIN_SIGNING_DOMAINS = {
  start: "ZipViz signup-start v1",
  cancel: "ZipViz signup-cancel v1",
} as const;
export const JOIN_RUNTIMES = ["claude", "codex", "buzz", "openclaw", "hermes", "other"] as const;
export type Runtime = typeof JOIN_RUNTIMES[number];
export interface StartFields {
  name: string;
  owner_email: string;
  runtime: Runtime;
  introduced_by: string | null;
}

/** Safe codes only: malformed private pending data must never reach an error. */
export class JoinCodecError extends Error {
  constructor(readonly code: string, readonly status = 400) {
    super(code);
    this.name = "JoinCodecError";
  }
}
function fail(code = "E_SIGNUP_SHAPE", status = 400): never { throw new JoinCodecError(code, status); }
const ms = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const audienceSchema = z.string().min(1).max(253);
const signatureSchema = z.object({
  alg: z.literal("Ed25519"), key_id: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  value_base64url: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
}).strict();
const proofSchema = z.object({
  schema_version: z.literal("1.0"), type: z.literal("zipviz.signup.start"),
  signup_id: z.string().regex(JOIN_UUID), public_key: z.string(),
  audience: audienceSchema, issued_at_ms: ms, bound_digest: z.string().regex(/^[0-9a-f]{64}$/),
  signature: signatureSchema,
}).strict();
const requestSchema = z.object({
  proof: proofSchema, name: z.string().max(254), owner_email: z.string(),
  runtime: z.string(), introduced_by: z.string().max(1024).nullable(),
}).strict();
export type StartRequest = Omit<z.infer<typeof requestSchema>, "runtime"> & { runtime: Runtime };

function wellFormed(value: string): void {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail();
    } else if (code >= 0xdc00 && code <= 0xdfff) fail();
  }
}

/** RFC 8785 spelling for the small closed join objects; no coercion or toJSON. */
export function canonicalize(value: unknown): string {
  const seen = new Set<object>();
  function encode(item: unknown, depth: number): string {
    if (depth > 32) fail();
    if (item === null) return "null";
    if (typeof item === "string") { wellFormed(item); return JSON.stringify(item); }
    if (typeof item === "boolean") return JSON.stringify(item);
    if (typeof item === "number" && Number.isFinite(item)) return JSON.stringify(item);
    if (typeof item !== "object" || item === null || seen.has(item)
      || Object.getOwnPropertySymbols(item).length > 0) fail();
    seen.add(item);
    try {
      if (Array.isArray(item)) {
        if (Object.keys(item).length !== item.length
          || Object.keys(item).some((key, index) => key !== String(index))) fail();
        return `[${item.map(child => encode(child, depth + 1)).join(",")}]`;
      }
      if (Object.getPrototypeOf(item) !== Object.prototype && Object.getPrototypeOf(item) !== null) fail();
      return `{${Object.keys(item).sort().map(key => {
        wellFormed(key);
        return `${JSON.stringify(key)}:${encode((item as Record<string, unknown>)[key], depth + 1)}`;
      }).join(",")}}`;
    } finally { seen.delete(item); }
  }
  return encode(value, 0);
}

export const hash = (input: string | Uint8Array): string => createHash("sha256").update(input).digest("hex");
export function publicKeyHex(key: JoinSigningKey): string {
  if ("signupId" in key) {
    if (!/^[0-9a-f]{64}$/.test(key.publicKey)) fail("E_KEY_INVALID");
    return key.publicKey;
  }
  if (key.asymmetricKeyType !== "ed25519") fail("E_KEY_INVALID");
  const publicKey = key.type === "public" ? key : createPublicKey(key);
  const der = publicKey.export({ format: "der", type: "spki" });
  if (der.length !== 44 || der.subarray(0, 12).toString("hex") !== "302a300506032b6570032100") fail("E_KEY_INVALID");
  return der.subarray(12).toString("hex");
}
export function keyId(publicKey: string): string {
  if (!/^[0-9a-f]{64}$/.test(publicKey)) fail("E_KEY_INVALID");
  return `sha256:${hash(Buffer.from(publicKey, "hex"))}`;
}
export function fingerprint(publicKey: string): string {
  return keyId(publicKey).slice(7, 23).match(/.{4}/g)!.join(" ");
}
export function normalizeEmail(email: string): string {
  if (typeof email !== "string") fail();
  const normalized = email.trim().toLowerCase();
  if (normalized.length < 3 || normalized.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) fail();
  return normalized;
}
export function boundDigest(fields: Pick<StartFields, "owner_email" | "runtime" | "introduced_by">): string {
  return hash(canonicalize({ introduced_by: fields.introduced_by, owner_email: normalizeEmail(fields.owner_email), runtime: fields.runtime }));
}
export function signingBytes(unsigned: Record<string, unknown>, domain: string): Buffer {
  const { signature: _signature, ...object } = unsigned;
  return Buffer.from(`${domain}\0${canonicalize(object)}`, "utf8");
}
function signed(unsigned: Record<string, unknown>, key: JoinSigningKey, domain: string): Record<string, unknown> {
  const publicKey = publicKeyHex(key);
  if ("signupId" in key && unsigned.signup_id !== key.signupId) fail("E_KEY_INVALID");
  const bytes = signingBytes(unsigned, domain);
  const signature = "signupId" in key
    ? signCanonicalSync(key.identity, "join-v1", bytes.toString("utf8"), key.keyId)
    : signFileKeySync(key, bytes);
  return { ...unsigned, signature: { alg: "Ed25519", key_id: keyId(publicKey),
    value_base64url: signature.toString("base64url") } };
}
function bounded(bytes: string): string {
  if (Buffer.byteLength(bytes, "utf8") > JOIN_BODY_MAX_BYTES) fail();
  return bytes;
}
export function makeStart(fields: StartFields, signupId: string, privateKey: JoinSigningKey, issuedAt: number, audience: string): string {
  if (!JOIN_UUID.test(signupId) || !ms.safeParse(issuedAt).success || !audienceSchema.safeParse(audience).success) fail();
  if (typeof fields.name !== "string" || fields.name.length > 254) fail();
  if (!JOIN_RUNTIMES.includes(fields.runtime)) fail("E_RUNTIME");
  if (!(fields.introduced_by === null || (typeof fields.introduced_by === "string" && fields.introduced_by.length <= 1024))) fail();
  const normalized = { name: fields.name, owner_email: normalizeEmail(fields.owner_email), runtime: fields.runtime, introduced_by: fields.introduced_by };
  const proof = signed({ schema_version: "1.0", type: "zipviz.signup.start", signup_id: signupId,
    public_key: publicKeyHex(privateKey), audience, issued_at_ms: issuedAt, bound_digest: boundDigest(normalized) }, privateKey, JOIN_SIGNING_DOMAINS.start);
  return bounded(canonicalize({ ...normalized, proof }));
}
export function makeCancel(signupId: string, nonce: string, privateKey: JoinSigningKey, issuedAt: number, audience: string): string {
  if (!JOIN_UUID.test(signupId) || !JOIN_UUID.test(nonce) || !ms.safeParse(issuedAt).success || !audienceSchema.safeParse(audience).success) fail();
  return bounded(canonicalize(signed({ schema_version: "1.0", type: "zipviz.signup.cancel", signup_id: signupId,
    audience, nonce, issued_at_ms: issuedAt }, privateKey, JOIN_SIGNING_DOMAINS.cancel)));
}

/** Validates private retained bytes without applying freshness or current name policy. */
export function parseStart(bytes: string): StartRequest {
  if (typeof bytes !== "string") fail();
  bounded(bytes);
  let unknown: unknown;
  try { unknown = JSON.parse(bytes); } catch { fail(); }
  if (canonicalize(unknown) !== bytes) fail(); // Also rejects duplicate JSON members.
  const result = requestSchema.safeParse(unknown);
  if (!result.success) fail();
  const body = result.data;
  if (!/^[0-9a-f]{64}$/.test(body.proof.public_key)) fail("E_KEY_INVALID");
  if (!(JOIN_RUNTIMES as readonly string[]).includes(body.runtime)) fail("E_RUNTIME");
  normalizeEmail(body.owner_email);
  const request = body as StartRequest;
  const signature = Buffer.from(request.proof.signature.value_base64url, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== request.proof.signature.value_base64url) fail();
  if (request.proof.signature.key_id !== keyId(request.proof.public_key)
    || request.proof.bound_digest !== boundDigest(request)) fail("E_SIGNUP_PROOF", 403);
  try {
    const key = createPublicKey({ format: "der", type: "spki", key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(request.proof.public_key, "hex"),
    ]) });
    if (!verify(null, signingBytes(request.proof, JOIN_SIGNING_DOMAINS.start), key, signature)) fail("E_SIGNUP_PROOF", 403);
  } catch { fail("E_SIGNUP_PROOF", 403); }
  return request;
}
