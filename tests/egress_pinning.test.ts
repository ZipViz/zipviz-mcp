// Connection pinning for recipient egress.
//
// The egress check resolves a recipient host and refuses private addresses.
// Before pinning, the fetch that followed resolved the hostname again, so a
// recipient-controlled DNS server could answer "public" to the check and
// "loopback" to the connection (DNS rebinding). These tests hold the fix in
// place: the connection may only use the addresses the check accepted, every
// redirect hop is validated and pinned on its own, and the caller's abort
// bounds the DNS step.

import { createServer, type AddressInfo, type Socket } from "node:net";
import { describe, expect, it, vi } from "vitest";
import {
  EgressBlockedError,
  pinnedHttpsFetch,
  pinnedLookup,
  safeEgressFetch,
  type LookupFn,
  type ValidatedTarget,
} from "../src/lib/egress.js";

const PUBLIC = "93.184.216.34";
const post: RequestInit = { method: "POST", body: "{}", headers: { "Content-Type": "application/json" } };

function lookupResult(lookup: ReturnType<typeof pinnedLookup>, host: string, options: object) {
  return new Promise<{ err: NodeJS.ErrnoException | null; address: unknown; family?: number }>((resolve) => {
    (lookup as unknown as (h: string, o: object, cb: (...a: unknown[]) => void) => void)(
      host,
      options,
      (err, address, family) => resolve({ err: err as NodeJS.ErrnoException | null, address, family: family as number })
    );
  });
}

describe("pinnedLookup", () => {
  const target: ValidatedTarget = {
    hostname: "agent.example",
    addresses: [
      { address: PUBLIC, family: 4 },
      { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 },
    ],
  };

  it("answers only with the validated addresses, never DNS", async () => {
    const one = await lookupResult(pinnedLookup(target), "agent.example", {});
    expect(one.err).toBeNull();
    expect(one.address).toBe(PUBLIC);
    const all = await lookupResult(pinnedLookup(target), "agent.example", { all: true });
    expect(all.address).toEqual(target.addresses);
    const v6 = await lookupResult(pinnedLookup(target), "agent.example", { family: 6 });
    expect(v6.address).toBe("2606:2800:220:1:248:1893:25c8:1946");
  });

  it("refuses any hostname it was not validated for", async () => {
    const other = await lookupResult(pinnedLookup(target), "localhost", {});
    expect(other.err?.code).toBe("ENOTFOUND");
  });
});

describe("pinnedHttpsFetch", () => {
  it("connects to the pinned address and keeps the hostname for TLS SNI", async () => {
    // A plain TCP listener stands in for the recipient: it records where the
    // connection landed and what the TLS ClientHello asked for, then hangs up.
    // The hostname below does not resolve anywhere, so reaching this socket at
    // all proves the request used the pinned address and not DNS.
    let seen: Buffer | undefined;
    const server = createServer((socket: Socket) => {
      socket.once("data", (chunk: Buffer) => {
        seen = chunk;
        socket.destroy();
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    try {
      const host = "pinned-target.invalid";
      await expect(
        pinnedHttpsFetch(`https://${host}:${port}/a2a/invoke`, post, {
          hostname: host,
          addresses: [{ address: "127.0.0.1", family: 4 }],
        })
      ).rejects.toThrow();
      expect(seen, "the pinned address received the connection").toBeDefined();
      expect(seen!.includes(Buffer.from(host, "ascii")), "ClientHello carries the hostname as SNI").toBe(true);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("refuses a URL whose host differs from the validated target", async () => {
    await expect(
      pinnedHttpsFetch("https://other.example/a2a", post, {
        hostname: "agent.example",
        addresses: [{ address: PUBLIC, family: 4 }],
      })
    ).rejects.toBeInstanceOf(EgressBlockedError);
  });
});

describe("safeEgressFetch pinning", () => {
  it("hands the transport the addresses validation accepted, not a later DNS answer", async () => {
    // First answer public, every later answer loopback: the classic rebind.
    let calls = 0;
    const rebinding: LookupFn = async () => {
      calls += 1;
      return [{ address: calls === 1 ? PUBLIC : "127.0.0.1", family: 4 }];
    };
    const targets: ValidatedTarget[] = [];
    const fetchFn = vi.fn(async (_url: string, _init: RequestInit, target: ValidatedTarget) => {
      targets.push(target);
      return new Response("ok", { status: 200 });
    });
    await safeEgressFetch("https://rebind.example/a2a", post, {
      fetchFn,
      lookupFn: rebinding,
      bodyPolicy: { mode: "cancel" },
    });
    expect(calls).toBe(1);
    expect(targets).toEqual([{ hostname: "rebind.example", addresses: [{ address: PUBLIC, family: 4 }] }]);
  });

  it("validates and pins every redirect hop on its own", async () => {
    const answers: Record<string, string> = { "one.example": PUBLIC, "two.example": "1.1.1.1" };
    const lookupFn: LookupFn = async (host) => [{ address: answers[host], family: 4 }];
    const targets: ValidatedTarget[] = [];
    const fetchFn = vi.fn(async (url: string, _init: RequestInit, target: ValidatedTarget) => {
      targets.push(target);
      return url.startsWith("https://one.example")
        ? new Response(null, { status: 307, headers: { Location: "https://two.example/final" } })
        : new Response("ok", { status: 200 });
    });
    await safeEgressFetch("https://one.example/a2a", post, { fetchFn, lookupFn, bodyPolicy: { mode: "cancel" } });
    expect(targets.map((t) => [t.hostname, t.addresses[0].address])).toEqual([
      ["one.example", PUBLIC],
      ["two.example", "1.1.1.1"],
    ]);
  });

  it("refuses a redirect hop that rebinds to loopback", async () => {
    const lookupFn: LookupFn = async (host) => [
      { address: host === "one.example" ? PUBLIC : "127.0.0.1", family: 4 },
    ];
    const fetchFn = vi.fn(async () =>
      new Response(null, { status: 307, headers: { Location: "https://two.example/final" } })
    );
    await expect(
      safeEgressFetch("https://one.example/a2a", post, { fetchFn, lookupFn, bodyPolicy: { mode: "cancel" } })
    ).rejects.toBeInstanceOf(EgressBlockedError);
    expect(fetchFn).toHaveBeenCalledOnce();
  });

  it("uses the pinned transport by default, never the global fetch", async () => {
    // Fully offline: the validation hook hands back a target pinned to a local
    // listener, so the only way that listener sees a connection is through the
    // default pinned transport. The global fetch is a spy that must stay unused.
    const globalFetch = vi.fn(async () => new Response("should not be used"));
    vi.stubGlobal("fetch", globalFetch);
    let connected = false;
    const server = createServer((socket: Socket) => {
      connected = true;
      socket.destroy();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    try {
      const host = "default-transport.invalid";
      await expect(
        safeEgressFetch(`https://${host}:${port}/a2a`, post, {
          assertEgress: async () => ({ hostname: host, addresses: [{ address: "127.0.0.1", family: 4 }] }),
          bodyPolicy: { mode: "cancel" },
        })
      ).rejects.toThrow();
      expect(connected, "the default transport reached the pinned address").toBe(true);
      expect(globalFetch).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("lets the caller's abort end a send whose DNS lookup is still pending", async () => {
    let release: (() => void) | undefined;
    const pending: LookupFn = () =>
      new Promise((resolve) => {
        release = () => resolve([{ address: PUBLIC, family: 4 }]);
      });
    const fetchFn = vi.fn(async () => new Response("ok", { status: 200 }));
    const controller = new AbortController();
    const started = Date.now();
    const send = safeEgressFetch(
      "https://slow-dns.example/a2a",
      { ...post, signal: controller.signal },
      { fetchFn, lookupFn: pending, bodyPolicy: { mode: "cancel" } }
    );
    setTimeout(() => controller.abort(), 20);
    await expect(send).rejects.toMatchObject({ name: "AbortError" });
    expect(Date.now() - started).toBeLessThan(1000);
    expect(fetchFn).not.toHaveBeenCalled();
    release?.();
  });
});
