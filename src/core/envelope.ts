import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { isValidVizDomain } from "../lib/viz-domain.js";
import { readJsonBounded } from "../lib/bounded-json.js";
import {
  ConversationWireError,
  encodeConversationWire,
  parseConversationWire,
  type ConversationWire,
} from "./conversation-wire.js";

// Envelope v2 canonical + local Ed25519 verify against a cached registry-card
// pubkey. Canonical field order is load-bearing — JSON.stringify is stable
// only because the object literal below declares keys in this exact order.
// Never re-implement this ad hoc.

export const MSG_ID_RE = /^[A-Za-z0-9_-]{8,128}$/;

export const FRESHNESS_WINDOW_MS = 5 * 60 * 1000;
export const DEFAULT_ENVELOPE_TTL_MS = 10 * 60 * 1000;
export const MAX_ENVELOPE_TTL_MS = 24 * 60 * 60 * 1000;
export const PUBKEY_CACHE_TTL_MS = 60_000;
export const PUBKEY_NEGATIVE_CACHE_MS = 10_000;

// RFC 8410 Ed25519 SubjectPublicKeyInfo prefix: 30 2a 30 05 06 03 2b 65 70 03 21 00
export const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const CARD_BASE = "https://api.zipviz.ai/v1/agent";

export type EnvelopeV2Fields = {
  from: string;
  to: string;
  msg_id: string;
  message: string;
  timestamp: string;
  expires_at: string;
  reply_to?: string;
};

export type EnvelopeV3Fields = EnvelopeV2Fields & {
  conversation: ConversationWire;
};

export class EnvelopeVerifyError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "EnvelopeVerifyError";
    this.code = code;
  }
}

export function isValidMsgId(value: unknown): value is string {
  return typeof value === "string" && MSG_ID_RE.test(value);
}

export function canonicalEnvelopeV2(fields: EnvelopeV2Fields): string {
  if (fields.reply_to !== undefined) {
    return JSON.stringify({
      v: 2,
      from: fields.from,
      to: fields.to,
      msg_id: fields.msg_id,
      message: fields.message,
      timestamp: fields.timestamp,
      expires_at: fields.expires_at,
      reply_to: fields.reply_to,
    });
  }
  return JSON.stringify({
    v: 2,
    from: fields.from,
    to: fields.to,
    msg_id: fields.msg_id,
    message: fields.message,
    timestamp: fields.timestamp,
    expires_at: fields.expires_at,
  });
}

export function canonicalEnvelopeV3(fields: EnvelopeV3Fields): string {
  const conversation = encodeConversationWire(
    fields.conversation,
    fields.timestamp
  );
  if (fields.reply_to !== undefined) {
    return JSON.stringify({
      v: 3,
      from: fields.from,
      to: fields.to,
      msg_id: fields.msg_id,
      message: fields.message,
      timestamp: fields.timestamp,
      expires_at: fields.expires_at,
      reply_to: fields.reply_to,
      conversation,
    });
  }
  return JSON.stringify({
    v: 3,
    from: fields.from,
    to: fields.to,
    msg_id: fields.msg_id,
    message: fields.message,
    timestamp: fields.timestamp,
    expires_at: fields.expires_at,
    conversation,
  });
}

export function defaultExpiresAt(timestamp: string): string {
  const t = Date.parse(timestamp);
  if (!Number.isFinite(t)) {
    throw new EnvelopeVerifyError("E_TIMESTAMP_FORMAT", "timestamp is not valid ISO-8601");
  }
  return new Date(t + DEFAULT_ENVELOPE_TTL_MS).toISOString();
}

export function assertEnvelopeExpiry(timestamp: string, expiresAt: string): void {
  const t = Date.parse(timestamp);
  const exp = Date.parse(expiresAt);
  if (!Number.isFinite(t) || !Number.isFinite(exp)) {
    throw new EnvelopeVerifyError("E_TIMESTAMP_FORMAT", "timestamp/expires_at is not valid ISO-8601");
  }
  if (exp > t + MAX_ENVELOPE_TTL_MS) {
    throw new EnvelopeVerifyError(
      "E_EXPIRED",
      "expires_at exceeds timestamp + 24h"
    );
  }
  if (exp <= t) {
    throw new EnvelopeVerifyError("E_EXPIRED", "expires_at must be after timestamp");
  }
}

export function ed25519HexToPublicKey(hex: string): KeyObject {
  const cleaned = hex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(cleaned)) {
    throw new EnvelopeVerifyError(
      "E_STORED_KEY",
      "Ed25519 public key must be 32 bytes (64 hex chars)"
    );
  }
  const raw = Buffer.from(cleaned, "hex");
  if (raw.length !== 32) {
    throw new EnvelopeVerifyError("E_STORED_KEY", "Ed25519 public key must be 32 bytes");
  }
  const spki = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

type FetchFn = (url: string, init?: RequestInit) => Promise<Response>;

type PositiveEntry = { hex: string; fetchedAt: number };
type NegativeEntry = { fetchedAt: number };

// DoS bounds: the card fetch runs on the PUBLIC
// ingress path before signature verification, so arbitrary valid-shaped .viz
// sender names could previously drive an unbounded number of timeout-free
// registry fetches and grow both maps without limit.
export const PUBKEY_CACHE_MAX_ENTRIES = 1_024;
export const PUBKEY_FETCH_TIMEOUT_MS = 5_000;
export const PUBKEY_FETCH_MAX_CONCURRENT = 8;

export class RegistryPubkeyCache {
  private readonly positive = new Map<string, PositiveEntry>();
  private readonly negative = new Map<string, NegativeEntry>();
  // Coalescing: concurrent misses for the same domain share one fetch.
  private readonly inFlight = new Map<string, Promise<string>>();
  private readonly fetchFn: FetchFn;
  private readonly nowFn: () => number;
  private readonly ttlMs: number;
  private readonly negativeTtlMs: number;
  private readonly maxEntries: number;
  private readonly fetchTimeoutMs: number;
  private readonly maxConcurrent: number;

  constructor(opts: {
    fetchFn?: FetchFn;
    nowFn?: () => number;
    ttlMs?: number;
    negativeTtlMs?: number;
    maxEntries?: number;
    fetchTimeoutMs?: number;
    maxConcurrent?: number;
  } = {}) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.nowFn = opts.nowFn ?? Date.now;
    this.ttlMs = opts.ttlMs ?? PUBKEY_CACHE_TTL_MS;
    this.negativeTtlMs = opts.negativeTtlMs ?? PUBKEY_NEGATIVE_CACHE_MS;
    this.maxEntries = opts.maxEntries ?? PUBKEY_CACHE_MAX_ENTRIES;
    this.fetchTimeoutMs = opts.fetchTimeoutMs ?? PUBKEY_FETCH_TIMEOUT_MS;
    this.maxConcurrent = opts.maxConcurrent ?? PUBKEY_FETCH_MAX_CONCURRENT;
  }

  // LRU by insertion order: Map iteration order is insertion order, and every
  // set() below deletes first, so the oldest entry is always first.
  private capped(map: Map<string, unknown>): void {
    while (map.size > this.maxEntries) {
      const oldest = map.keys().next().value as string | undefined;
      if (oldest === undefined) return;
      map.delete(oldest);
    }
  }

  private setPositive(from: string, entry: PositiveEntry): void {
    this.positive.delete(from);
    this.positive.set(from, entry);
    this.capped(this.positive);
  }

  private setNegative(from: string, entry: NegativeEntry): void {
    this.negative.delete(from);
    this.negative.set(from, entry);
    this.capped(this.negative);
  }

  async getPubkeyHex(from: string): Promise<string> {
    if (!isValidVizDomain(from)) {
      throw new EnvelopeVerifyError("E_AGENT_NOT_FOUND", "invalid sender domain");
    }
    const now = this.nowFn();
    const hit = this.positive.get(from);
    if (hit && now - hit.fetchedAt < this.ttlMs) return hit.hex;
    const miss = this.negative.get(from);
    if (miss && now - miss.fetchedAt < this.negativeTtlMs) {
      throw new EnvelopeVerifyError("E_AGENT_NOT_FOUND", `no registry card for ${from}`);
    }

    const pending = this.inFlight.get(from);
    if (pending) return pending;
    if (this.inFlight.size >= this.maxConcurrent) {
      // Fail closed under fetch pressure rather than queueing unbounded work:
      // 503-shaped, so a legitimate sender's retry succeeds once the burst
      // passes, while a flood of unique names cannot amplify into unlimited
      // concurrent registry connections.
      throw new EnvelopeVerifyError("E_REGISTRY_BUSY", "registry lookup capacity exceeded");
    }
    const run = this.fetchPubkeyHex(from, now).finally(() => {
      this.inFlight.delete(from);
    });
    this.inFlight.set(from, run);
    return run;
  }

  // Two defects fixed here:
  //  - The abort timer was cleared as soon as HEADERS arrived, so a stalled
  //    BODY held an in-flight slot forever — eight stalled bodies permanently
  //    occupied all lookup capacity. The timeout now covers body consumption,
  //    and both awaits are raced against the abort so the slot frees even if
  //    a misbehaving upstream ignores the signal.
  //  - Transient registry trouble (network error, timeout, 5xx, malformed
  //    body) was collapsed into E_AGENT_NOT_FOUND, which ingress maps to 404
  //    — and a durable sender treats 404 as PERMANENT, so a registry blip at
  //    the recipient dead-ended deliveries. Availability failures are now
  //    E_REGISTRY_UNAVAILABLE (503 at ingress, retryable) and are never
  //    negative-cached; only a genuine 4xx / unusable card is
  //    E_AGENT_NOT_FOUND.
  private async fetchPubkeyHex(from: string, now: number): Promise<string> {
    const url = `${CARD_BASE}/${encodeURIComponent(from)}/card`;
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.fetchTimeoutMs);
    const aborted = new Promise<never>((_resolve, reject) => {
      ac.signal.addEventListener(
        "abort",
        () =>
          reject(
            new EnvelopeVerifyError("E_REGISTRY_UNAVAILABLE", `registry timed out for ${from}`)
          ),
        { once: true }
      );
    });
    let res: Response;
    let body: unknown;
    try {
      try {
        res = await Promise.race([this.fetchFn(url, { signal: ac.signal }), aborted]);
      } catch (err) {
        if (err instanceof EnvelopeVerifyError) throw err;
        throw new EnvelopeVerifyError("E_REGISTRY_UNAVAILABLE", `registry unreachable for ${from}`);
      }
      // Only an EXPLICIT absence verdict means the agent is absent. Review
      // flagged 408/429; reproducing at head showed 400
      // and 403 were mis-classified the same way — every non-OK status except
      // 5xx was negative-cached as E_AGENT_NOT_FOUND, which ingress maps to
      // 404 and a durable sender treats as PERMANENT. So registry throttling
      // (429), a registry-side timeout (408), or our own misconfiguration
      // (401/403) permanently killed deliveries from a perfectly valid sender
      // and poisoned its cache entry for 10 s. Anything that is not 404/410 is
      // an availability answer: 503, retryable, never negative-cached.
      if (!res.ok) {
        if (res.status === 404 || res.status === 410) {
          this.setNegative(from, { fetchedAt: now });
          this.positive.delete(from);
          throw new EnvelopeVerifyError("E_AGENT_NOT_FOUND", `no registry card for ${from}`);
        }
        throw new EnvelopeVerifyError(
          "E_REGISTRY_UNAVAILABLE",
          `registry error ${res.status} for ${from}`
        );
      }
      try {
        body = await Promise.race([readJsonBounded(res), aborted]);
      } catch (err) {
        if (err instanceof EnvelopeVerifyError) throw err;
        // Malformed body on a 200 is an availability problem (proxy
        // interstitial, truncation) — it must not negative-cache the sender.
        throw new EnvelopeVerifyError(
          "E_REGISTRY_UNAVAILABLE",
          `malformed registry response for ${from}`
        );
      }
    } finally {
      clearTimeout(timer);
    }
    const hex =
      typeof body === "object" && body !== null && typeof (body as { public_key?: unknown }).public_key === "string"
        ? (body as { public_key: string }).public_key.trim().toLowerCase()
        : "";
    if (!/^[0-9a-f]{64}$/.test(hex)) {
      this.setNegative(from, { fetchedAt: now });
      throw new EnvelopeVerifyError("E_AGENT_NOT_FOUND", `registry card for ${from} has no usable public_key`);
    }
    this.negative.delete(from);
    this.setPositive(from, { hex, fetchedAt: now });
    return hex;
  }
}

export async function verifyEnvelopeV2(params: {
  from: string;
  to: string;
  msg_id: string;
  message: string;
  timestamp: string;
  expires_at: string;
  reply_to?: string;
  signature: string;
  now?: Date;
  cache: RegistryPubkeyCache;
  expectedTo?: string;
}): Promise<{ ok: true; pubkeyHex: string }> {
  if (!isValidVizDomain(params.from) || !isValidVizDomain(params.to)) {
    throw new EnvelopeVerifyError("E_SIG_INVALID", "from/to must be valid .viz domains");
  }
  if (!isValidMsgId(params.msg_id)) {
    throw new EnvelopeVerifyError("E_SIG_INVALID", "msg_id shape invalid");
  }
  if (params.reply_to !== undefined && !isValidMsgId(params.reply_to)) {
    throw new EnvelopeVerifyError("E_SIG_INVALID", "reply_to shape invalid");
  }
  if (params.expectedTo !== undefined && params.to !== params.expectedTo) {
    throw new EnvelopeVerifyError("E_WRONG_RECIPIENT", "envelope to does not match this recipient");
  }

  const nowMs = (params.now ?? new Date()).getTime();
  const ts = Date.parse(params.timestamp);
  const exp = Date.parse(params.expires_at);
  if (!Number.isFinite(ts) || !Number.isFinite(exp)) {
    throw new EnvelopeVerifyError("E_STALE", "timestamp/expires_at is not valid ISO-8601");
  }
  if (nowMs >= exp) {
    throw new EnvelopeVerifyError("E_EXPIRED", "envelope has expired");
  }
  if (exp > ts + MAX_ENVELOPE_TTL_MS) {
    throw new EnvelopeVerifyError("E_EXPIRED", "expires_at exceeds timestamp + 24h");
  }
  // Freshness is governed by the SIGNED expires_at, not by timestamp age.
  // The outbound worker retransmits exact
  // signed bytes, and a ±5 min staleness window made retry attempts 6-7 (and
  // any recovery after a >5 min outage) structurally impossible against a
  // compliant receiver. Replay does not reopen: every accepted msg_id is held
  // in the dedup store whose retention floor (2 days) exceeds the 24 h max
  // envelope TTL, so an old envelope is either a dedup hit or expired. Only a
  // FUTURE timestamp beyond clock skew is rejected here.
  if (ts > nowMs + FRESHNESS_WINDOW_MS) {
    throw new EnvelopeVerifyError("E_STALE", "envelope timestamp is in the future beyond +5 min skew");
  }

  const pubkeyHex = await params.cache.getPubkeyHex(params.from);
  const pubkey = ed25519HexToPublicKey(pubkeyHex);
  let sigBytes: Buffer;
  try {
    sigBytes = Buffer.from(params.signature, "base64");
  } catch {
    throw new EnvelopeVerifyError("E_SIG_INVALID", "signature is not valid base64");
  }
  if (sigBytes.length !== 64) {
    throw new EnvelopeVerifyError("E_SIG_INVALID", "signature is not 64 bytes");
  }
  const canonical = Buffer.from(
    canonicalEnvelopeV2({
      from: params.from,
      to: params.to,
      msg_id: params.msg_id,
      message: params.message,
      timestamp: params.timestamp,
      expires_at: params.expires_at,
      reply_to: params.reply_to,
    }),
    "utf8"
  );
  const ok = verify(null, canonical, pubkey, sigBytes);
  if (!ok) {
    throw new EnvelopeVerifyError("E_SIG_INVALID", "envelope signature mismatch");
  }
  return { ok: true, pubkeyHex };
}

export async function verifyEnvelopeV3(params: {
  from: string;
  to: string;
  msg_id: string;
  message: string;
  timestamp: string;
  expires_at: string;
  reply_to?: string;
  conversation: unknown;
  signature: string;
  now?: Date;
  cache: RegistryPubkeyCache;
  expectedTo?: string;
}): Promise<{ ok: true; pubkeyHex: string }> {
  let conversation: ConversationWire;
  try {
    conversation = parseConversationWire(params.conversation, params.timestamp);
  } catch (error) {
    if (error instanceof ConversationWireError) {
      throw new EnvelopeVerifyError(error.code, error.message);
    }
    throw error;
  }

  if (!isValidVizDomain(params.from) || !isValidVizDomain(params.to)) {
    throw new EnvelopeVerifyError("E_SIG_INVALID", "from/to must be valid .viz domains");
  }
  if (!isValidMsgId(params.msg_id)) {
    throw new EnvelopeVerifyError("E_SIG_INVALID", "msg_id shape invalid");
  }
  if (params.reply_to !== undefined && !isValidMsgId(params.reply_to)) {
    throw new EnvelopeVerifyError("E_SIG_INVALID", "reply_to shape invalid");
  }
  if (params.expectedTo !== undefined && params.to !== params.expectedTo) {
    throw new EnvelopeVerifyError("E_WRONG_RECIPIENT", "envelope to does not match this recipient");
  }

  const nowMs = (params.now ?? new Date()).getTime();
  const ts = Date.parse(params.timestamp);
  const exp = Date.parse(params.expires_at);
  if (!Number.isFinite(ts) || !Number.isFinite(exp)) {
    throw new EnvelopeVerifyError("E_STALE", "timestamp/expires_at is not valid ISO-8601");
  }
  if (nowMs >= exp) {
    throw new EnvelopeVerifyError("E_EXPIRED", "envelope has expired");
  }
  if (exp > ts + MAX_ENVELOPE_TTL_MS) {
    throw new EnvelopeVerifyError("E_EXPIRED", "expires_at exceeds timestamp + 24h");
  }
  if (ts > nowMs + FRESHNESS_WINDOW_MS) {
    throw new EnvelopeVerifyError("E_STALE", "envelope timestamp is in the future beyond +5 min skew");
  }

  const pubkeyHex = await params.cache.getPubkeyHex(params.from);
  const pubkey = ed25519HexToPublicKey(pubkeyHex);
  const sigBytes = Buffer.from(params.signature, "base64");
  if (sigBytes.length !== 64) {
    throw new EnvelopeVerifyError("E_SIG_INVALID", "signature is not 64 bytes");
  }
  const canonical = Buffer.from(
    canonicalEnvelopeV3({
      from: params.from,
      to: params.to,
      msg_id: params.msg_id,
      message: params.message,
      timestamp: params.timestamp,
      expires_at: params.expires_at,
      reply_to: params.reply_to,
      conversation,
    }),
    "utf8"
  );
  if (!verify(null, canonical, pubkey, sigBytes)) {
    throw new EnvelopeVerifyError("E_SIG_INVALID", "envelope signature mismatch");
  }
  return { ok: true, pubkeyHex };
}
