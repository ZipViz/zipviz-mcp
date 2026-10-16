// B1: envelope v2 + receipt crypto. Pure functions; fetch is stubbed — no
// network. Canonical field order is load-bearing.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  verify,
} from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  canonicalEnvelopeV2,
  ed25519HexToPublicKey,
  ED25519_SPKI_PREFIX,
  EnvelopeVerifyError,
  MSG_ID_RE,
  PUBKEY_CACHE_TTL_MS,
  PUBKEY_NEGATIVE_CACHE_MS,
  RegistryPubkeyCache,
  verifyEnvelopeV2,
} from "../src/core/envelope.js";
import {
  canonicalReceipt,
  signReceipt,
  verifyReceipt,
} from "../src/core/receipts.js";
import { signEnvelopeV2, signMessage } from "../src/tools/sign_message.js";

const FROM = "zip-grok.smc.viz";
const TO = "viz-grok.smc.viz";
const MSG_ID = "msg-11111111-2222-4333-8444-555555555555";
const MESSAGE = "hello envelope v2";
const TS = "2026-08-13T10:00:00.000Z";
const EXPIRES = "2026-08-13T10:10:00.000Z";

function spkiHex(publicKey: KeyObject): string {
  const der = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return der.subarray(ED25519_SPKI_PREFIX.length).toString("hex");
}

async function writePem(dir: string, domain: string, privateKey: KeyObject) {
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  await writeFile(join(dir, `${domain}.key`), pem);
}

describe("canonicalEnvelopeV2 byte-order stability", () => {
  it("request form is exactly v,from,to,msg_id,message,timestamp,expires_at", () => {
    const canonical = canonicalEnvelopeV2({
      from: FROM,
      to: TO,
      msg_id: MSG_ID,
      message: MESSAGE,
      timestamp: TS,
      expires_at: EXPIRES,
    });
    expect(canonical).toBe(
      JSON.stringify({
        v: 2,
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE,
        timestamp: TS,
        expires_at: EXPIRES,
      })
    );
    expect(canonical).not.toContain("reply_to");
    expect(canonical.startsWith('{"v":2,"from":')).toBe(true);
  });

  it("reply form appends reply_to as the FINAL field only", () => {
    const replyTo = "msg-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const canonical = canonicalEnvelopeV2({
      from: TO,
      to: FROM,
      msg_id: "msg-reply-01-xxxxxxxx",
      message: "ack",
      timestamp: TS,
      expires_at: EXPIRES,
      reply_to: replyTo,
    });
    expect(canonical).toBe(
      JSON.stringify({
        v: 2,
        from: TO,
        to: FROM,
        msg_id: "msg-reply-01-xxxxxxxx",
        message: "ack",
        timestamp: TS,
        expires_at: EXPIRES,
        reply_to: replyTo,
      })
    );
    expect(canonical.endsWith(`"reply_to":"${replyTo}"}`)).toBe(true);
  });
});

describe("signEnvelopeV2 → local verify round trip", () => {
  let dir: string;
  let keysDir: string;
  let savedHome: string | undefined;
  let publicKey: KeyObject;
  let pubkeyHex: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "zipviz-env-v2-"));
    keysDir = join(dir, ".zipviz", "keys");
    await mkdir(keysDir, { recursive: true });
    savedHome = process.env.HOME;
    process.env.HOME = dir;
    const kp = generateKeyPairSync("ed25519");
    publicKey = kp.publicKey;
    pubkeyHex = spkiHex(publicKey);
    await writePem(keysDir, FROM, kp.privateKey);
  });

  afterEach(async () => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    await rm(dir, { recursive: true, force: true });
  });

  it("signs bytes that verify against the v2 canonical and the signer pubkey", async () => {
    const signed = await signEnvelopeV2({
      viz_domain: FROM,
      to: TO,
      message: MESSAGE,
      msg_id: MSG_ID,
      timestamp: TS,
      expires_at: EXPIRES,
    });
    expect(signed.signing_version).toBe(2);
    expect(signed.timestamp).toBe(TS);
    expect(signed.expires_at).toBe(EXPIRES);
    expect(signed.msg_id).toBe(MSG_ID);
    expect(signed).not.toHaveProperty("key_path");

    const canonical = Buffer.from(
      canonicalEnvelopeV2({
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE,
        timestamp: TS,
        expires_at: EXPIRES,
      }),
      "utf8"
    );
    expect(
      verify(null, canonical, publicKey, Buffer.from(signed.signature, "base64"))
    ).toBe(true);

    const cache = new RegistryPubkeyCache({
      fetchFn: async () =>
        new Response(JSON.stringify({ public_key: pubkeyHex, name: FROM }), {
          status: 200,
        }),
    });
    await expect(
      verifyEnvelopeV2({
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE,
        timestamp: TS,
        expires_at: EXPIRES,
        signature: signed.signature,
        now: new Date(TS),
        cache,
      })
    ).resolves.toEqual({ ok: true, pubkeyHex });
  });

  it("does not change v1 signMessage canonical bytes", async () => {
    const v1 = await signMessage({
      viz_domain: FROM,
      message: MESSAGE,
      timestamp: TS,
    });
    const v1Canonical = Buffer.from(
      JSON.stringify({ v: 1, from: FROM, message: MESSAGE, timestamp: TS }),
      "utf8"
    );
    expect(
      verify(null, v1Canonical, publicKey, Buffer.from(v1.signature, "base64"))
    ).toBe(true);
    expect(v1.signing_version).toBe(1);
  });

  it("defaults expires_at to timestamp + 10 minutes", async () => {
    const signed = await signEnvelopeV2({
      viz_domain: FROM,
      to: TO,
      message: MESSAGE,
      msg_id: MSG_ID,
      timestamp: TS,
    });
    expect(signed.expires_at).toBe("2026-08-13T10:10:00.000Z");
  });

  it("rejects expires_at beyond timestamp + 24h", async () => {
    await expect(
      signEnvelopeV2({
        viz_domain: FROM,
        to: TO,
        message: MESSAGE,
        msg_id: MSG_ID,
        timestamp: TS,
        expires_at: "2026-08-15T10:00:00.001Z",
      })
    ).rejects.toThrow(/expires_at/);
  });

  it("rejects a malformed msg_id", async () => {
    await expect(
      signEnvelopeV2({
        viz_domain: FROM,
        to: TO,
        message: MESSAGE,
        msg_id: "short",
      })
    ).rejects.toThrow(/msg_id/);
    expect(MSG_ID_RE.test("short")).toBe(false);
    expect(MSG_ID_RE.test(MSG_ID)).toBe(true);
  });
});

describe("verifyEnvelopeV2 negatives", () => {
  let publicKey: KeyObject;
  let privateKey: KeyObject;
  let pubkeyHex: string;
  let cache: RegistryPubkeyCache;
  let signature: string;

  beforeEach(async () => {
    const kp = generateKeyPairSync("ed25519");
    publicKey = kp.publicKey;
    privateKey = kp.privateKey;
    pubkeyHex = spkiHex(publicKey);
    cache = new RegistryPubkeyCache({
      fetchFn: async () =>
        new Response(JSON.stringify({ public_key: pubkeyHex, name: FROM }), {
          status: 200,
        }),
    });
    const dir = await mkdtemp(join(tmpdir(), "zipviz-env-neg-"));
    const keysDir = join(dir, ".zipviz", "keys");
    await mkdir(keysDir, { recursive: true });
    const prev = process.env.HOME;
    process.env.HOME = dir;
    await writePem(keysDir, FROM, privateKey);
    const signed = await signEnvelopeV2({
      viz_domain: FROM,
      to: TO,
      message: MESSAGE,
      msg_id: MSG_ID,
      timestamp: TS,
      expires_at: EXPIRES,
    });
    signature = signed.signature;
    if (prev === undefined) delete process.env.HOME;
    else process.env.HOME = prev;
    await rm(dir, { recursive: true, force: true });
  });

  it("fails when a signed field is tampered", async () => {
    await expect(
      verifyEnvelopeV2({
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE + " tampered",
        timestamp: TS,
        expires_at: EXPIRES,
        signature,
        now: new Date(TS),
        cache,
      })
    ).rejects.toBeInstanceOf(EnvelopeVerifyError);
    await expect(
      verifyEnvelopeV2({
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE + " tampered",
        timestamp: TS,
        expires_at: EXPIRES,
        signature,
        now: new Date(TS),
        cache,
      })
    ).rejects.toMatchObject({ code: "E_SIG_INVALID" });
  });

  it("fails when `to` does not match the expected recipient", async () => {
    await expect(
      verifyEnvelopeV2({
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE,
        timestamp: TS,
        expires_at: EXPIRES,
        signature,
        now: new Date(TS),
        cache,
        expectedTo: "other.smc.viz",
      })
    ).rejects.toMatchObject({ code: "E_WRONG_RECIPIENT" });
  });

  it("fails when the envelope is expired (now >= expires_at)", async () => {
    // Stay inside the ±5 min freshness window so E_EXPIRED is the specific code.
    const shortExpiry = "2026-08-13T10:01:00.000Z";
    const dir = await mkdtemp(join(tmpdir(), "zipviz-env-exp-"));
    const keysDir = join(dir, ".zipviz", "keys");
    await mkdir(keysDir, { recursive: true });
    const prev = process.env.HOME;
    process.env.HOME = dir;
    const kp = generateKeyPairSync("ed25519");
    await writePem(keysDir, FROM, kp.privateKey);
    const signed = await signEnvelopeV2({
      viz_domain: FROM,
      to: TO,
      message: MESSAGE,
      msg_id: MSG_ID,
      timestamp: TS,
      expires_at: shortExpiry,
    });
    if (prev === undefined) delete process.env.HOME;
    else process.env.HOME = prev;
    await rm(dir, { recursive: true, force: true });

    const hex = (kp.publicKey.export({ type: "spki", format: "der" }) as Buffer)
      .subarray(ED25519_SPKI_PREFIX.length)
      .toString("hex");
    const expCache = new RegistryPubkeyCache({
      fetchFn: async () =>
        new Response(JSON.stringify({ public_key: hex, name: FROM }), { status: 200 }),
    });
    await expect(
      verifyEnvelopeV2({
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE,
        timestamp: TS,
        expires_at: shortExpiry,
        signature: signed.signature,
        now: new Date("2026-08-13T10:02:00.000Z"),
        cache: expCache,
      })
    ).rejects.toMatchObject({ code: "E_EXPIRED" });
  });

  it("verifies an old-timestamp envelope while its signed expiry holds (retry tail)", async () => {
    // The outbound worker retransmits exact signed bytes and
    // backoff puts attempt 6 past 300 s — the old ±5 min staleness window made
    // those attempts structurally dead. Freshness is governed by the SIGNED
    // expires_at; a 7-minute-old timestamp inside a 10-minute expiry verifies.
    await expect(
      verifyEnvelopeV2({
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE,
        timestamp: TS,
        expires_at: EXPIRES,
        signature,
        now: new Date("2026-08-13T10:07:00.000Z"),
        cache,
      })
    ).resolves.toBeDefined();
  });

  it("rejects a future timestamp beyond +5 min clock skew", async () => {
    // E_STALE is raised BEFORE the pubkey fetch or signature verification
    // (asserted by the suite passing with the suite signature over different
    // fields), so no signing is needed here. A later review: the
    // previous version of this test called signEnvelopeV2 outside the temp
    // HOME and only passed on machines with a real key at ~/.zipviz/keys.
    await expect(
      verifyEnvelopeV2({
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE,
        timestamp: "2026-08-13T10:20:00.000Z",
        expires_at: "2026-08-13T10:30:00.000Z",
        signature,
        now: new Date("2026-08-13T10:00:00.000Z"),
        cache,
      })
    ).rejects.toMatchObject({ code: "E_STALE" });
  });

  it("still verifies locally against the reconstructed canonical (pubkey path)", () => {
    const canonical = Buffer.from(
      canonicalEnvelopeV2({
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE,
        timestamp: TS,
        expires_at: EXPIRES,
      }),
      "utf8"
    );
    expect(
      verify(null, canonical, publicKey, Buffer.from(signature, "base64"))
    ).toBe(true);
  });
});

describe("hex → SPKI conversion", () => {
  it("wraps 32 raw pubkey bytes in the Ed25519 SPKI prefix", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const hex = spkiHex(publicKey);
    expect(hex).toMatch(/^[0-9a-f]{64}$/);
    const rebuilt = ed25519HexToPublicKey(hex);
    const roundTrip = (rebuilt.export({ type: "spki", format: "der" }) as Buffer).toString(
      "hex"
    );
    const original = (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString(
      "hex"
    );
    expect(roundTrip).toBe(original);
    expect(ED25519_SPKI_PREFIX.toString("hex")).toBe("302a300506032b6570032100");
  });

  it("rejects a non-32-byte hex key", () => {
    expect(() => ed25519HexToPublicKey("aa")).toThrow(/32/);
    expect(() => ed25519HexToPublicKey("zz")).toThrow();
  });
});

describe("RegistryPubkeyCache TTL + negative cache", () => {
  it("reuses a hit within 60s and refetches after TTL", async () => {
    let now = 1_000_000;
    let fetches = 0;
    const cache = new RegistryPubkeyCache({
      nowFn: () => now,
      fetchFn: async () => {
        fetches += 1;
        return new Response(
          JSON.stringify({ public_key: "a".repeat(64), name: FROM }),
          { status: 200 }
        );
      },
    });
    await expect(cache.getPubkeyHex(FROM)).resolves.toBe("a".repeat(64));
    now += PUBKEY_CACHE_TTL_MS - 1;
    await cache.getPubkeyHex(FROM);
    expect(fetches).toBe(1);
    now += 2;
    await cache.getPubkeyHex(FROM);
    expect(fetches).toBe(2);
  });

  it("negative-caches a missing card for 10s", async () => {
    let now = 1_000_000;
    let fetches = 0;
    const cache = new RegistryPubkeyCache({
      nowFn: () => now,
      fetchFn: async () => {
        fetches += 1;
        return new Response("missing", { status: 404 });
      },
    });
    await expect(cache.getPubkeyHex(FROM)).rejects.toMatchObject({
      code: "E_AGENT_NOT_FOUND",
    });
    now += PUBKEY_NEGATIVE_CACHE_MS - 1;
    await expect(cache.getPubkeyHex(FROM)).rejects.toMatchObject({
      code: "E_AGENT_NOT_FOUND",
    });
    expect(fetches).toBe(1);
    now += 2;
    await expect(cache.getPubkeyHex(FROM)).rejects.toMatchObject({
      code: "E_AGENT_NOT_FOUND",
    });
    expect(fetches).toBe(2);
  });

  it("does not call fetch when verifying with an injected cache hit", async () => {
    const fetchFn = vi.fn();
    const cache = new RegistryPubkeyCache({ fetchFn });
    // Force a cache entry without going through fetch.
    (cache as unknown as { positive: Map<string, { hex: string; fetchedAt: number }> }).positive.set(
      FROM,
      { hex: "b".repeat(64), fetchedAt: Date.now() }
    );
    await expect(cache.getPubkeyHex(FROM)).resolves.toBe("b".repeat(64));
    expect(fetchFn).not.toHaveBeenCalled();
  });
});

describe("receipt canonical + sign → verify", () => {
  let dir: string;
  let keysDir: string;
  let savedHome: string | undefined;
  let publicKey: KeyObject;
  let pubkeyHex: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "zipviz-receipt-"));
    keysDir = join(dir, ".zipviz", "keys");
    await mkdir(keysDir, { recursive: true });
    savedHome = process.env.HOME;
    process.env.HOME = dir;
    const kp = generateKeyPairSync("ed25519");
    publicKey = kp.publicKey;
    pubkeyHex = spkiHex(publicKey);
    await writePem(keysDir, TO, kp.privateKey);
  });

  afterEach(async () => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    await rm(dir, { recursive: true, force: true });
  });

  it("pins receipt field order and round-trips", async () => {
    const receivedAt = "2026-08-13T10:00:00.123Z";
    const nonce = "0123456789abcdef";
    const timestamp = "2026-08-13T10:00:00.200Z";
    const canonical = canonicalReceipt({
      from: TO,
      to: FROM,
      msg_id: MSG_ID,
      status: "ACCEPTED",
      received_at: receivedAt,
      nonce,
      timestamp,
      owner_relationship: "SAME_OWNER",
    });
    expect(canonical).toBe(
      JSON.stringify({
        v: 2,
        kind: "receipt",
        from: TO,
        to: FROM,
        msg_id: MSG_ID,
        status: "ACCEPTED",
        received_at: receivedAt,
        nonce,
        timestamp,
        owner_relationship: "SAME_OWNER",
      })
    );

    const signed = await signReceipt({
      recipient: TO,
      sender: FROM,
      msg_id: MSG_ID,
      received_at: receivedAt,
      nonce,
      timestamp,
      owner_relationship: "SAME_OWNER",
    });
    expect(signed.status).toBe("ACCEPTED");
    expect(
      verify(
        null,
        Buffer.from(canonical, "utf8"),
        publicKey,
        Buffer.from(signed.signature, "base64")
      )
    ).toBe(true);
    expect(
      verifyReceipt({
        ...signed,
        pubkeyHex,
      })
    ).toBe(true);
  });

  it("rejects a tampered receipt field", async () => {
    const signed = await signReceipt({
      recipient: TO,
      sender: FROM,
      msg_id: MSG_ID,
      received_at: TS,
      nonce: "0123456789abcdef",
      timestamp: TS,
      owner_relationship: "EXTERNAL",
    });
    expect(
      verifyReceipt({
        ...signed,
        msg_id: "msg-mutated-xxxxxxxxx",
        pubkeyHex,
      })
    ).toBe(false);
  });
});

describe("registry cache DoS bounds", () => {
  const cardResponse = (hex: string) =>
    new Response(JSON.stringify({ public_key: hex, name: "x" }), { status: 200 });

  it("coalesces concurrent misses for one domain into a single fetch", async () => {
    let fetches = 0;
    let release: (r: Response) => void = () => {};
    const gate = new Promise<Response>((r) => {
      release = r;
    });
    const cache = new RegistryPubkeyCache({
      fetchFn: async () => {
        fetches += 1;
        return gate;
      },
    });
    const a = cache.getPubkeyHex("solo.smc.viz");
    const b = cache.getPubkeyHex("solo.smc.viz");
    const c = cache.getPubkeyHex("solo.smc.viz");
    release(cardResponse("a".repeat(64)));
    const [ra, rb, rc] = await Promise.all([a, b, c]);
    expect(fetches).toBe(1);
    expect(ra).toBe("a".repeat(64));
    expect(rb).toBe(ra);
    expect(rc).toBe(ra);
  });

  it("caps concurrent distinct-domain fetches and fails closed with E_REGISTRY_BUSY", async () => {
    const holds: Array<(r: Response) => void> = [];
    const cache = new RegistryPubkeyCache({
      maxConcurrent: 2,
      fetchFn: async () =>
        new Promise<Response>((r) => {
          holds.push(r);
        }),
    });
    const p1 = cache.getPubkeyHex("one.smc.viz");
    const p2 = cache.getPubkeyHex("two.smc.viz");
    await expect(cache.getPubkeyHex("three.smc.viz")).rejects.toMatchObject({
      code: "E_REGISTRY_BUSY",
    });
    holds.forEach((r) => r(cardResponse("b".repeat(64))));
    await Promise.all([p1, p2]);
    // Capacity released — the third domain now fetches fine.
    const cache2Fetch = cache.getPubkeyHex("three.smc.viz");
    holds.forEach((r) => r(cardResponse("b".repeat(64))));
    await expect(cache2Fetch).resolves.toBe("b".repeat(64));
  });

  it("bounds both maps with LRU eviction", async () => {
    const cache = new RegistryPubkeyCache({
      maxEntries: 3,
      fetchFn: async (url) => {
        // negative for n-*, positive for p-*
        if (url.includes("n-")) return new Response("no", { status: 404 });
        return cardResponse("c".repeat(64));
      },
    });
    for (let i = 0; i < 10; i++) {
      await cache.getPubkeyHex(`p-${i}.smc.viz`);
      await cache.getPubkeyHex(`n-${i}.smc.viz`).catch(() => {});
    }
    // Internals are private; prove the bound behaviorally — the oldest positive
    // entry was evicted, so it re-fetches instead of hitting cache.
    let refetches = 0;
    const probe = new RegistryPubkeyCache({ maxEntries: 3, fetchFn: async () => {
      refetches += 1;
      return cardResponse("d".repeat(64));
    }});
    await probe.getPubkeyHex("a1.smc.viz");
    await probe.getPubkeyHex("a2.smc.viz");
    await probe.getPubkeyHex("a3.smc.viz");
    await probe.getPubkeyHex("a4.smc.viz"); // evicts a1
    await probe.getPubkeyHex("a1.smc.viz"); // must re-fetch
    expect(refetches).toBe(5);
    await probe.getPubkeyHex("a4.smc.viz"); // still cached
    expect(refetches).toBe(5);
  });

  it("aborts a hung registry fetch at the timeout and fails closed", async () => {
    const cache = new RegistryPubkeyCache({
      fetchTimeoutMs: 30,
      fetchFn: (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        }),
    });
    await expect(cache.getPubkeyHex("hung.smc.viz")).rejects.toMatchObject({
      code: "E_REGISTRY_UNAVAILABLE",
    });
  });
});

describe("registry availability taxonomy", () => {
  it("a stalled BODY is timed out and releases its in-flight slot", async () => {
    let fetches = 0;
    const cache = new RegistryPubkeyCache({
      fetchTimeoutMs: 20,
      maxConcurrent: 1,
      fetchFn: async () => {
        fetches += 1;
        if (fetches === 1) {
          // Headers arrive fine; the body never does and IGNORES the abort
          // signal — the old code cleared the timer on headers and hung here
          // forever, permanently occupying a lookup slot.
          return new Response(new ReadableStream({ start() {} }));
        }
        return new Response(JSON.stringify({ public_key: "e".repeat(64) }), { status: 200 });
      },
    });
    await expect(cache.getPubkeyHex("stall.smc.viz")).rejects.toMatchObject({
      code: "E_REGISTRY_UNAVAILABLE",
    });
    // Slot released: with maxConcurrent=1 this would E_REGISTRY_BUSY if the
    // stalled lookup still held capacity.
    await expect(cache.getPubkeyHex("next.smc.viz")).resolves.toBe("e".repeat(64));
    expect(fetches).toBe(2);
  });

  it("throttling/timeout/config statuses are availability, not identity", async () => {
    // A later review: 408 and 429 were negative-cached as E_AGENT_NOT_FOUND
    // (404 at ingress = permanent for a durable sender). Reproducing showed
    // 400/401/403 shared the fault. Only 404/410 are genuine absence.
    for (const status of [408, 425, 429, 400, 401, 403, 500, 502, 503]) {
      const cache = new RegistryPubkeyCache({
        fetchFn: async () => new Response("x", { status }),
      });
      await expect(
        cache.getPubkeyHex("transient.smc.viz"),
        `status ${status} must be availability`
      ).rejects.toMatchObject({ code: "E_REGISTRY_UNAVAILABLE" });
    }
    for (const status of [404, 410]) {
      const cache = new RegistryPubkeyCache({
        fetchFn: async () => new Response("x", { status }),
      });
      await expect(
        cache.getPubkeyHex("absent.smc.viz"),
        `status ${status} must be identity`
      ).rejects.toMatchObject({ code: "E_AGENT_NOT_FOUND" });
    }
  });

  it("429-then-success: throttling is not negative-cached and recovers immediately", async () => {
    let fetches = 0;
    const cache = new RegistryPubkeyCache({
      fetchFn: async () => {
        fetches += 1;
        if (fetches === 1) return new Response("slow down", { status: 429 });
        return new Response(JSON.stringify({ public_key: "9".repeat(64) }), { status: 200 });
      },
    });
    await expect(cache.getPubkeyHex("throttled.smc.viz")).rejects.toMatchObject({
      code: "E_REGISTRY_UNAVAILABLE",
    });
    await expect(cache.getPubkeyHex("throttled.smc.viz")).resolves.toBe("9".repeat(64));
    expect(fetches).toBe(2);
  });

  it("registry 5xx is E_REGISTRY_UNAVAILABLE and is NOT negative-cached", async () => {
    let fetches = 0;
    const cache = new RegistryPubkeyCache({
      fetchFn: async () => {
        fetches += 1;
        if (fetches === 1) return new Response("boom", { status: 500 });
        return new Response(JSON.stringify({ public_key: "f".repeat(64) }), { status: 200 });
      },
    });
    await expect(cache.getPubkeyHex("blip.smc.viz")).rejects.toMatchObject({
      code: "E_REGISTRY_UNAVAILABLE",
    });
    // Immediate retry refetches (no 10 s negative-cache poisoning) and succeeds.
    await expect(cache.getPubkeyHex("blip.smc.viz")).resolves.toBe("f".repeat(64));
    expect(fetches).toBe(2);
  });

  it("malformed 200 body is availability, not identity", async () => {
    let fetches = 0;
    const cache = new RegistryPubkeyCache({
      fetchFn: async () => {
        fetches += 1;
        if (fetches === 1) return new Response("<html>proxy error</html>", { status: 200 });
        return new Response(JSON.stringify({ public_key: "0".repeat(64) }), { status: 200 });
      },
    });
    await expect(cache.getPubkeyHex("proxy.smc.viz")).rejects.toMatchObject({
      code: "E_REGISTRY_UNAVAILABLE",
    });
    await expect(cache.getPubkeyHex("proxy.smc.viz")).resolves.toBe("0".repeat(64));
  });

  it("genuine 404 stays E_AGENT_NOT_FOUND and negative-caches", async () => {
    let fetches = 0;
    const cache = new RegistryPubkeyCache({
      fetchFn: async () => {
        fetches += 1;
        return new Response("no", { status: 404 });
      },
    });
    await expect(cache.getPubkeyHex("ghost.smc.viz")).rejects.toMatchObject({
      code: "E_AGENT_NOT_FOUND",
    });
    await expect(cache.getPubkeyHex("ghost.smc.viz")).rejects.toMatchObject({
      code: "E_AGENT_NOT_FOUND",
    });
    expect(fetches).toBe(1); // second hit served from the negative cache
  });
});
