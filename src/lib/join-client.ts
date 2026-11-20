import { generateKeyPairSync, randomUUID, type KeyObject } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { z } from "zod";
import { JoinStore } from "./join-store.js";
import { protectedSignerSelected, publicBinding } from "../signer/backend.js";
import { readJoinHandle, type JoinHandle } from "../signer/join-handle.js";
import {
  JOIN_UUID, JOIN_DOMAIN, JOIN_RUNTIMES, canonicalize, fingerprint, hash, makeCancel,
  makeStart, parseStart, publicKeyHex, type StartFields, type StartRequest, type JoinSigningKey,
} from "./join-codec.js";

const ms = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const uuid = z.string().regex(JOIN_UUID);
const domain = z.string().regex(JOIN_DOMAIN);
const publicKey = z.string().regex(/^[0-9a-f]{64}$/);
export const joinNewSchema = z.object({
  name: z.string().regex(/^[a-z0-9](?:[a-z0-9-]{0,13}[a-z0-9])?$/).refine(v => !/-[0-9]{4}$/.test(v)),
  owner_email: z.string().min(3).max(254), runtime: z.enum(JOIN_RUNTIMES),
  introduced_by: z.string().max(1024).nullable().optional(),
}).strict();
export const joinResumeSchema = z.object({ signup_id: uuid }).strict();
export const joinStartSchema = z.union([joinNewSchema, joinResumeSchema]);
export const joinStatusSchema = z.object({ signup_id: uuid, wait: z.boolean().optional() }).strict();
const receiptSchema = z.object({
  schema_version: z.literal("1.0"), signup_id: uuid, state: z.literal("pending"),
  proposed_domain: domain, user_code: z.string().regex(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/),
  approval_url: z.string().max(256), expires_at_ms: ms, poll_interval_ms: z.literal(5000),
}).strict();
const common = { schema_version: z.literal("1.0"), signup_id: uuid };
const liveSchema = z.object({ ...common, state: z.literal("live"), domain,
  public_key: publicKey, incarnation: z.string().regex(/^[0-9a-f]{32}$/),
  subject_agent_id: z.string().regex(/^sub1_[A-Za-z0-9_-]{43}$/), live_at_ms: ms,
}).strict();
const pollSchema = z.discriminatedUnion("state", [liveSchema,
  z.object({ ...common, state: z.literal("pending"), proposed_domain: domain, expires_at_ms: ms, poll_interval_ms: z.literal(5000) }).strict(),
  z.object({ ...common, state: z.literal("expired"), expires_at_ms: ms }).strict(),
  z.object({ ...common, state: z.literal("rejected"), decided_at_ms: ms }).strict(),
  z.object({ ...common, state: z.literal("cancelled"), decided_at_ms: ms }).strict(),
]);
const metadataSchema = z.object({
  schema_version: z.literal("1.0"), signup_id: uuid, public_key: publicKey,
  attempts: z.array(z.object({ request_b64url: z.string().max(5462).regex(/^[A-Za-z0-9_-]+$/),
    request_digest: z.string().regex(/^[0-9a-f]{64}$/), issued_at_ms: ms }).strict()).min(1).max(8),
  receipt: receiptSchema.nullable(), foreign: z.boolean(), adoption_domain: domain.nullable().optional(),
}).strict();
type Metadata = z.infer<typeof metadataSchema>;
type Receipt = z.infer<typeof receiptSchema>;
export type JoinPoll = z.infer<typeof pollSchema>;
export type JoinStartInput = z.infer<typeof joinStartSchema>;
export interface JoinResponse { status: number; body: unknown; retryAfter?: number }
export type JoinTransport = (path: string, method: "GET" | "POST", bytes?: string) => Promise<JoinResponse>;

/** Messages are local constants; upstream bodies and private pending bytes are never echoed. */
export const JOIN_MESSAGES: Readonly<Record<string, string>> = {
  E_SIGNUP_SHAPE: "The join request has an invalid shape.", E_NAME_FORMAT: "Use a valid agent name.",
  E_KEY_INVALID: "The local signing key is invalid.", E_RUNTIME: "Choose a supported runtime.",
  E_STALE: "The signing clock is outside the accepted window.", E_SIGNUP_AUD: "The registry audience does not match.",
  E_SIGNUP_PROOF: "The registry refused the key proof.", E_NAME_RESERVED: "That name is reserved.",
  E_NAME_EXHAUSTED: "The registry could not assign a name.", E_KEY_REGISTERED: "This key is already registered.",
  E_KEY_PENDING: "This key already has a pending request.", E_SIGNUP_ID_CONFLICT: "Another attempt owns this signup ID.",
  E_INTRO_INVALID: "The introduction is invalid.", E_INTRO_USED: "The introduction was already used.",
  E_INTRO_UNAVAILABLE: "The introduction is unavailable.", E_RATE_LIMITED: "Too many requests. Try again later.",
  E_SLOW_DOWN: "Wait before polling again.", E_RATE_LIMIT_UNAVAILABLE: "The registry cannot enforce admission limits.",
  E_SIGNUP_BUSY: "The registry is busy.", E_SIGNUP_UNAVAILABLE: "Join is unavailable. Resume with the same signup ID.",
  E_SIGNUP_PAUSED: "Join approvals are paused.", E_SIGNUP_NOT_FOUND: "No signup was found; retained attempts are unchanged.",
  E_SIGNUP_FINAL: "This signup is already final.", E_REPLAY: "This cancellation was already used.",
  E_JOIN_RETRY_LIMIT: "Eight attempts are retained. No more attempts will be created.",
  E_JOIN_NETWORK: "The response is uncertain. Resume with the same signup ID.",
  E_UNEXPECTED_RESPONSE: "The registry response does not match this local signup.",
  E_JOIN_STORE: "The private pending store is unavailable or unsafe.",
  E_JOIN_EXISTS: "A key already exists; no key was replaced.", E_JOIN_BUSY: "This pending signup is in use.",
  E_JOIN_INPUT: "Use the closed join input fields.",
};
export class JoinError extends Error {
  constructor(readonly code: string, readonly signupId?: string, readonly retryAfter?: number) {
    super(JOIN_MESSAGES[code] ?? JOIN_MESSAGES.E_UNEXPECTED_RESPONSE);
    this.name = "JoinError";
  }
}
function unexpected(id?: string): never { throw new JoinError("E_UNEXPECTED_RESPONSE", id); }
function parse<T extends z.ZodTypeAny>(schema: T, body: unknown, id?: string): z.infer<T> {
  const result = schema.safeParse(body);
  if (!result.success) unexpected(id);
  return result.data;
}

/** Fixed egress, no redirects/bearers, bounded response and timeout. Tests inject a synthetic transport. */
export const joinTransport: JoinTransport = async (path, method, bytes) => {
  const response = await fetch(`https://api.zipviz.ai${path}`, { method, body: bytes,
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    redirect: "error", cache: "no-store", signal: AbortSignal.timeout(10000) });
  const reader = response.body?.getReader();
  let size = 0;
  const chunks: Uint8Array[] = [];
  if (reader) {
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        size += chunk.value.length;
        if (size > 16384) { await reader.cancel(); unexpected(); }
        chunks.push(chunk.value);
      }
    } finally { reader.releaseLock(); }
  }
  let body: unknown;
  try { body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))); }
  catch { unexpected(); }
  const retry = response.headers.get("retry-after");
  const retryAfter = retry && /^[0-9]{1,5}$/.test(retry) && Number(retry) >= 1 && Number(retry) <= 86400 ? Number(retry) : undefined;
  return { status: response.status, body, retryAfter };
};

export interface JoinClientOptions {
  store?: JoinStore; transport?: JoinTransport; now?: () => number;
  wait?: (milliseconds: number) => Promise<void>; uuid?: () => string;
  generateKey?: () => KeyObject; audience?: string; approvalOrigin?: string;
}
export class JoinClient {
  readonly store: JoinStore;
  private readonly transport: JoinTransport;
  private readonly now: () => number;
  private readonly wait: (ms: number) => Promise<void>;
  private readonly uuid: () => string;
  private readonly generateKey: () => KeyObject;
  private readonly audience: string;
  private readonly approvalOrigin: string;
  private readonly nextPoll = new Map<string, number>();
  constructor(options: JoinClientOptions = {}) {
    this.store = options.store ?? new JoinStore();
    this.transport = options.transport ?? joinTransport; this.now = options.now ?? Date.now;
    this.wait = options.wait ?? (async ms => { await delay(ms); }); this.uuid = options.uuid ?? randomUUID;
    this.generateKey = options.generateKey ?? (() => generateKeyPairSync("ed25519").privateKey);
    this.audience = options.audience ?? "api.zipviz.ai";
    this.approvalOrigin = options.approvalOrigin ?? "https://zipviz.ai";
  }
  private receipt(body: unknown, id: string): Receipt {
    const value = parse(receiptSchema, body, id);
    if (value.signup_id !== id || value.approval_url !== `${this.approvalOrigin}/approve/${value.user_code}`) unexpected(id);
    return value;
  }
  private async request(path: string, method: "GET" | "POST", bytes?: string): Promise<JoinResponse> {
    try { return await this.transport(path, method, bytes); }
    catch (error) { if (error instanceof JoinError) throw error; throw new JoinError("E_JOIN_NETWORK"); }
  }
  private code(response: JoinResponse): string {
    const body = response.body as { code?: unknown } | null;
    return body && typeof body.code === "string" && Object.hasOwn(JOIN_MESSAGES, body.code) ? body.code : "E_UNEXPECTED_RESPONSE";
  }
  private async send(bytes: string, id: string): Promise<JoinResponse> {
    for (let retry = 0;; retry++) {
      let response: JoinResponse;
      try { response = await this.request("/v1/signup/start", "POST", bytes); }
      catch (error) {
        if (!(error instanceof JoinError) || error.code !== "E_JOIN_NETWORK" || retry >= 2) throw new JoinError("E_JOIN_NETWORK", id);
        await this.wait(1000 * 2 ** retry); continue;
      }
      if (response.status === 503 && this.code(response) === "E_SIGNUP_UNAVAILABLE" && retry < 2) {
        const backoff = Math.max(1000 * 2 ** retry, (response.retryAfter ?? 0) * 1000);
        if (backoff > 10000) return response;
        await this.wait(backoff); continue;
      }
      return response;
    }
  }
  private async protectedKey(id?: string): Promise<JoinHandle> {
    try {
      const handle = readJoinHandle();
      if (id !== undefined && id !== handle.signupId) throw 0;
      const binding = await publicBinding(handle.identity, "join-v1");
      if (binding.keyId !== handle.keyId || binding.publicKey !== handle.publicKey) throw 0;
      return handle;
    } catch { throw new JoinError("E_JOIN_STORE", id); }
  }
  private async load(id: string): Promise<{ metadata: Metadata; key: JoinSigningKey; first: StartRequest }> {
    const metadata = parse(metadataSchema, await this.store.read(id), id);
    const key = protectedSignerSelected() ? await this.protectedKey(id) : await this.store.readKey(id, metadata.adoption_domain ?? undefined);
    if (metadata.signup_id !== id || metadata.public_key !== publicKeyHex(key)) unexpected(id);
    let first: StartRequest | undefined;
    for (const attempt of metadata.attempts) {
      const bytes = Buffer.from(attempt.request_b64url, "base64url");
      if (bytes.toString("base64url") !== attempt.request_b64url || hash(bytes) !== attempt.request_digest) unexpected(id);
      const request = parseStart(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      if (request.proof.signup_id !== id || request.proof.public_key !== metadata.public_key
        || request.proof.audience !== this.audience || request.proof.issued_at_ms !== attempt.issued_at_ms) unexpected(id);
      first ??= request;
      const fields = (r: StartRequest) => ({ name: r.name, owner_email: r.owner_email, runtime: r.runtime,
        introduced_by: r.introduced_by, proof: { ...r.proof, issued_at_ms: 0, signature: null } });
      if (canonicalize(fields(request)) !== canonicalize(fields(first))) unexpected(id);
    }
    if (metadata.receipt) this.receipt(metadata.receipt, id);
    return { metadata, key, first: first! };
  }
  private attempt(bytes: string) {
    return { request_b64url: Buffer.from(bytes).toString("base64url"), request_digest: hash(bytes),
      issued_at_ms: parseStart(bytes).proof.issued_at_ms };
  }
  async start(input: JoinStartInput) {
    const parsed = joinStartSchema.safeParse(input);
    if (!parsed.success) throw new JoinError("E_JOIN_INPUT");
    const value = parsed.data;
    const provisioned = protectedSignerSelected() ? await this.protectedKey("signup_id" in value ? value.signup_id : undefined) : undefined;
    const id = "signup_id" in value ? value.signup_id : provisioned?.signupId ?? this.uuid();
    if (!JOIN_UUID.test(id)) throw new JoinError("E_JOIN_INPUT");
    return this.store.withLock(id, async () => {
      try {
        if (!("signup_id" in value)) {
          if (provisioned?.adopted) throw new JoinError("E_JOIN_EXISTS", id);
          const key = provisioned ?? this.generateKey();
          const fields: StartFields = { ...value, introduced_by: value.introduced_by ?? null };
          const bytes = makeStart(fields, id, key, this.now(), this.audience);
          if ("signupId" in key) await this.store.reserveMetadata(id);
          else await this.store.create(id, key);
          await this.store.write(id, { schema_version: "1.0", signup_id: id, public_key: publicKeyHex(key),
            attempts: [this.attempt(bytes)], receipt: null, foreign: false });
        }
        const { metadata, key, first } = await this.load(id);
        if (metadata.foreign) unexpected(id);
        let index = metadata.attempts.length - 1;
        for (;;) {
          const bytes = Buffer.from(metadata.attempts[index].request_b64url, "base64url").toString("utf8");
          const response = await this.send(bytes, id);
          if (response.status === 200 || response.status === 201) {
            metadata.receipt = this.receipt(response.body, id);
            await this.store.write(id, metadata); break;
          }
          const code = this.code(response);
          if (response.status === 401 && code === "E_STALE") {
            if (metadata.attempts.length === 8) throw new JoinError("E_JOIN_RETRY_LIMIT", id);
            const next = makeStart(first, id, key, this.now(), this.audience);
            metadata.attempts.push(this.attempt(next));
            await this.store.write(id, metadata); // fsync+rename finishes before any send.
            index = metadata.attempts.length - 1; continue;
          }
          if (response.status === 409 && code === "E_SIGNUP_ID_CONFLICT") {
            let recovered = false;
            for (let other = metadata.attempts.length - 1; other >= 0; other--) {
              if (other === index) continue;
              const retained = Buffer.from(metadata.attempts[other].request_b64url, "base64url").toString("utf8");
              const swept = await this.send(retained, id);
              if (swept.status === 200) {
                metadata.receipt = this.receipt(swept.body, id);
                await this.store.write(id, metadata); recovered = true; break;
              }
              if (swept.status !== 409 || this.code(swept) !== "E_SIGNUP_ID_CONFLICT") throw new JoinError(this.code(swept), id, swept.retryAfter);
            }
            if (recovered) break;
            metadata.foreign = true; await this.store.write(id, metadata); unexpected(id);
          }
          throw new JoinError(code, id, response.retryAfter);
        }
        const current = await this.status({ signup_id: id });
        return { ...metadata.receipt!, key_fingerprint: fingerprint(metadata.public_key), current,
          owner_instructions: "Give your human the approval URL, code and key fingerprint. Only approve if this key matches what your agent showed you." };
      } catch (error) {
        if (error instanceof JoinError) throw new JoinError(error.code, id, error.retryAfter);
        const code = (error as { code?: unknown })?.code;
        throw new JoinError(typeof code === "string" && Object.hasOwn(JOIN_MESSAGES, code) ? code : "E_JOIN_STORE", id);
      }
    });
  }
  /** Polling never opens, moves, removes or generates a key or pending metadata file. */
  async status(input: z.infer<typeof joinStatusSchema>): Promise<JoinPoll> {
    const args = joinStatusSchema.safeParse(input);
    if (!args.success) throw new JoinError("E_JOIN_INPUT");
    const { signup_id: id, wait } = args.data;
    const deadline = this.now() + 50000;
    // One bounded tool call may wait for at most ten polls; repeat status to continue.
    for (let count = 0; count < (wait ? 10 : 1); count++) {
      const due = Math.max(this.nextPoll.get(id) ?? 0, this.now());
      if (due > deadline) throw new JoinError("E_SLOW_DOWN", id, Math.ceil((due - this.now()) / 1000));
      this.nextPoll.set(id, due + 5000); // Reserve this slot before awaiting IO.
      if (due > this.now()) await this.wait(due - this.now());
      const response = await this.request(`/v1/signup/${id}`, "GET");
      if (response.status === 429 && this.code(response) === "E_SLOW_DOWN") {
        this.nextPoll.set(id, Math.max(this.nextPoll.get(id) ?? 0, this.now() + Math.max(5000, (response.retryAfter ?? 5) * 1000)));
        if (wait && count < 9) continue;
        throw new JoinError("E_SLOW_DOWN", id, response.retryAfter ?? 5);
      }
      if (response.status !== 200) throw new JoinError(this.code(response), id, response.retryAfter);
      const poll = parse(pollSchema, response.body, id);
      if (poll.signup_id !== id) unexpected(id);
      this.nextPoll.set(id, Math.max(this.nextPoll.get(id) ?? 0, this.now() + 5000));
      if (poll.state !== "pending" || !wait || count === 9) return poll;
    }
    return unexpected(id);
  }
  async cancel(id: string) {
    if (!JOIN_UUID.test(id)) throw new JoinError("E_JOIN_INPUT");
    return this.store.withLock(id, async () => {
      const { metadata, key } = await this.load(id);
      if (metadata.foreign || !metadata.receipt) unexpected(id);
      const response = await this.request(`/v1/signup/${id}/cancel`, "POST", makeCancel(id, this.uuid(), key, this.now(), this.audience));
      if (response.status !== 200) throw new JoinError(this.code(response), id, response.retryAfter);
      parse(z.object({ state: z.literal("cancelled") }).strict(), response.body, id);
      return { signup_id: id, state: "cancelled" as const };
    });
  }
  async adopt(id: string) {
    if (!JOIN_UUID.test(id)) throw new JoinError("E_JOIN_INPUT");
    return this.store.withLock(id, async () => {
      const { metadata } = await this.load(id);
      if (metadata.foreign || !metadata.receipt) unexpected(id);
      const live = await this.status({ signup_id: id });
      if (live.state !== "live" || live.public_key !== metadata.public_key) unexpected(id);
      const response = await this.request(`/v1/agent/${encodeURIComponent(live.domain)}`, "GET");
      if (response.status !== 200) unexpected(id);
      // Lookup has other public fields; read only the explicit identity contract.
      const current = z.object({ domain, public_key: publicKey, incarnation: z.string().regex(/^[0-9a-f]{32}$/),
        revision: ms, status: z.literal("registered"), identity_status: z.literal("active") }).safeParse(response.body);
      if (!current.success || current.data.domain !== live.domain || current.data.public_key !== live.public_key
        || current.data.incarnation !== live.incarnation) unexpected(id);
      const subject = `sub1_${Buffer.from(hash(Buffer.from(`ZipViz subject-id v1\0${canonicalize({
        registry_origin: "https://api.zipviz.ai", domain: live.domain, incarnation: live.incarnation,
      })}`, "utf8")), "hex").toString("base64url")}`;
      if (subject !== live.subject_agent_id) unexpected(id);
      metadata.adoption_domain = live.domain;
      await this.store.write(id, metadata);
      if (protectedSignerSelected()) {
        const handle = await this.protectedKey(id);
        if (!handle.adopted || handle.identity !== live.domain || handle.publicKey !== live.public_key) throw new JoinError("E_JOIN_STORE", id);
        await this.store.removeMetadata(id);
      } else await this.store.adopt(id, live.domain, metadata.public_key);
      return { signup_id: id, state: "adopted" as const, domain: live.domain, key_fingerprint: fingerprint(live.public_key) };
    });
  }
}
