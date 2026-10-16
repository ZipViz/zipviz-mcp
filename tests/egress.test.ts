import { describe, it, expect, vi } from "vitest";
import {
  assertSafeEgressUrl,
  safeEgressFetch,
  isBlockedAddress,
  EgressBlockedError,
  type LookupFn,
} from "../src/lib/egress.js";

// A resolver that must never be consulted (IP literals and scheme checks
// short-circuit before DNS).
const noResolve: LookupFn = () => {
  throw new Error("resolver should not be called");
};

function resolvesTo(...addresses: string[]): LookupFn {
  return async () => addresses.map((address) => ({ address, family: 4 }));
}

describe("isBlockedAddress", () => {
  const blocked = [
    "0.0.0.0",
    "127.0.0.1",
    "10.0.0.5",
    "169.254.169.254", // cloud metadata
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "100.64.0.1", // CGNAT
    "198.18.0.1", // benchmarking
    "224.0.0.1", // multicast
    "255.255.255.255",
    "::1",
    "::",
    "fe80::1", // link-local
    "fec0::1", // deprecated site-local
    "fc00::1", // ULA
    "fd12:3456::1", // ULA
    "ff02::1", // multicast
    "::ffff:127.0.0.1", // IPv4-mapped loopback
    "::ffff:10.0.0.1", // IPv4-mapped private
  ];
  const allowed = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "172.32.0.1", // just outside 172.16/12
    "2606:4700:4700::1111", // public IPv6 (Cloudflare)
    "::ffff:8.8.8.8", // IPv4-mapped public
  ];

  it.each(blocked)("blocks %s", (ip) => {
    expect(isBlockedAddress(ip)).toBe(true);
  });

  it.each(allowed)("allows %s", (ip) => {
    expect(isBlockedAddress(ip)).toBe(false);
  });
});

describe("assertSafeEgressUrl", () => {
  it("rejects non-https schemes", async () => {
    await expect(
      assertSafeEgressUrl("http://example.com/x", noResolve)
    ).rejects.toBeInstanceOf(EgressBlockedError);
  });

  it("rejects credentials while accepting valid public HTTPS custom ports", async () => {
    for (const url of [
      "https://user@example.com/a2a",
      "https://user:secret@example.com/a2a",
    ]) {
      await expect(
        assertSafeEgressUrl(url, resolvesTo("93.184.216.34"))
      ).rejects.toBeInstanceOf(EgressBlockedError);
    }
    await expect(
      assertSafeEgressUrl("https://example.com:8443/a2a", resolvesTo("93.184.216.34"))
    ).resolves.toBeUndefined();
    await expect(
      assertSafeEgressUrl("https://example.com:443/a2a", resolvesTo("93.184.216.34"))
    ).resolves.toBeUndefined();
  });

  it.each([
    "https://example.com:65536/a2a",
    "https://example.com:-1/a2a",
    "https://example.com:not-a-port/a2a",
  ])("rejects malformed or out-of-range ports: %s", async (url) => {
    await expect(
      assertSafeEgressUrl(url, resolvesTo("93.184.216.34"))
    ).rejects.toBeInstanceOf(EgressBlockedError);
  });

  it("rejects a malformed URL", async () => {
    await expect(
      assertSafeEgressUrl("not a url", noResolve)
    ).rejects.toBeInstanceOf(EgressBlockedError);
  });

  it("rejects internal IPv4 literals without resolving", async () => {
    for (const host of ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.0.1"]) {
      await expect(
        assertSafeEgressUrl(`https://${host}/a2a`, noResolve)
      ).rejects.toBeInstanceOf(EgressBlockedError);
    }
  });

  it("rejects internal IPv6 literals without resolving", async () => {
    for (const host of [
      "[::1]",
      "[fe80::1]",
      "[fec0::1]",
      "[fc00::1]",
      "[::ffff:127.0.0.1]",
    ]) {
      await expect(
        assertSafeEgressUrl(`https://${host}/a2a`, noResolve)
      ).rejects.toBeInstanceOf(EgressBlockedError);
    }
  });

  it("allows public IP literals without resolving", async () => {
    await expect(
      assertSafeEgressUrl("https://8.8.8.8/a2a", noResolve)
    ).resolves.toBeUndefined();
    await expect(
      assertSafeEgressUrl("https://[2606:4700:4700::1111]/a2a", noResolve)
    ).resolves.toBeUndefined();
  });

  it("rejects internal hostnames before resolving", async () => {
    for (const host of ["localhost", "svc.localhost", "db.local", "api.internal"]) {
      await expect(
        assertSafeEgressUrl(`https://${host}/a2a`, noResolve)
      ).rejects.toBeInstanceOf(EgressBlockedError);
    }
  });

  it("rejects a public hostname that resolves to an internal address (rebinding/misdirection)", async () => {
    await expect(
      assertSafeEgressUrl("https://evil.example.com/a2a", resolvesTo("127.0.0.1"))
    ).rejects.toBeInstanceOf(EgressBlockedError);

    // Mixed: one public, one internal — still blocked.
    await expect(
      assertSafeEgressUrl(
        "https://evil.example.com/a2a",
        resolvesTo("93.184.216.34", "10.0.0.1")
      )
    ).rejects.toBeInstanceOf(EgressBlockedError);

    await expect(
      assertSafeEgressUrl(
        "https://evil.example.com:8443/a2a",
        resolvesTo("fec0::1")
      )
    ).rejects.toBeInstanceOf(EgressBlockedError);
  });

  it("allows a public hostname that resolves to public addresses", async () => {
    await expect(
      assertSafeEgressUrl(
        "https://agents.zipviz.ai/a2a",
        resolvesTo("93.184.216.34")
      )
    ).resolves.toBeUndefined();
  });

  it("fails closed when the resolver throws", async () => {
    const throwingResolver = vi.fn(async () => {
      throw new Error("ENOTFOUND");
    });
    await expect(
      assertSafeEgressUrl("https://maybe-down.example.com/a2a", throwingResolver)
    ).rejects.toBeInstanceOf(EgressBlockedError);
    expect(throwingResolver).toHaveBeenCalledOnce();
  });

  it("fails closed when resolution returns no addresses", async () => {
    const emptyResolver: LookupFn = async () => [];
    await expect(
      assertSafeEgressUrl("https://no-records.example.com/a2a", emptyResolver)
    ).rejects.toBeInstanceOf(EgressBlockedError);
  });
});

describe("safeEgressFetch", () => {
  const lookup = resolvesTo("93.184.216.34");
  const post = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0" }),
  } satisfies RequestInit;

  it("blocks a public-to-private redirect before the private fetch", async () => {
    const fetchFn = vi.fn(async () =>
      new Response(null, {
        status: 307,
        headers: { Location: "https://127.0.0.1/private" },
      })
    );

    await expect(
      safeEgressFetch("https://public.example/a2a", post, {
        fetchFn,
        lookupFn: lookup,
        bodyPolicy: { mode: "cancel" },
      })
    ).rejects.toBeInstanceOf(EgressBlockedError);
    expect(fetchFn).toHaveBeenCalledOnce();
    expect(fetchFn.mock.calls[0][1]?.redirect).toBe("manual");
  });

  it.each([
    ["downgraded scheme", "http://93.184.216.34/private"],
    ["credentials", "https://user:secret@93.184.216.34/private"],
    ["internal hostname", "https://service.internal/private"],
    ["site-local IPv6", "https://[fec0::1]:9443/private"],
  ])("revalidates and blocks a redirect with %s", async (_label, location) => {
    const fetchFn = vi.fn(async () =>
      new Response(null, { status: 302, headers: { Location: location } })
    );

    await expect(
      safeEgressFetch("https://public.example/a2a", post, {
        fetchFn,
        lookupFn: lookup,
        bodyPolicy: { mode: "cancel" },
      })
    ).rejects.toBeInstanceOf(EgressBlockedError);
    expect(fetchFn).toHaveBeenCalledOnce();
  });

  it("allows public HTTPS custom ports on the initial URL and a redirect", async () => {
    const seen: string[] = [];
    const fetchFn = vi.fn(async (url: string) => {
      seen.push(url);
      return seen.length === 1
        ? new Response(null, {
            status: 307,
            headers: { Location: "https://next.example:9443/final" },
          })
        : new Response("ok", { status: 200 });
    });

    const result = await safeEgressFetch(
      "https://public.example:8443/a2a",
      post,
      {
        fetchFn,
        lookupFn: lookup,
        bodyPolicy: { mode: "read", maxBytes: 16 },
      }
    );

    expect(result.bodyText).toBe("ok");
    expect(seen).toEqual([
      "https://public.example:8443/a2a",
      "https://next.example:9443/final",
    ]);
  });

  it("follows safe relative multi-hop redirects and preserves 307/308 POST bodies", async () => {
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    const fetchFn = vi.fn(async (url: string, init?: RequestInit) => {
      seen.push({ url, init });
      if (url === "https://one.example/a2a") {
        return new Response(null, { status: 307, headers: { Location: "/next" } });
      }
      if (url === "https://one.example/next") {
        return new Response(null, {
          status: 308,
          headers: { Location: "https://two.example/final" },
        });
      }
      return new Response("{\"ok\":true}", { status: 200 });
    });

    const result = await safeEgressFetch("https://one.example/a2a", post, {
      fetchFn,
      lookupFn: lookup,
      bodyPolicy: { mode: "read", maxBytes: 1024 },
    });

    expect(result.response.status).toBe(200);
    expect(result.bodyText).toBe("{\"ok\":true}");
    expect(result.bodyTruncated).toBe(false);
    expect(seen.map(({ url }) => url)).toEqual([
      "https://one.example/a2a",
      "https://one.example/next",
      "https://two.example/final",
    ]);
    for (const { init } of seen) {
      expect(init?.redirect).toBe("manual");
      expect(init?.method).toBe("POST");
      expect(init?.body).toBe(post.body);
    }
  });

  it.each([301, 302, 303])(
    "uses Fetch-compatible GET semantics for a POST redirected with HTTP %s",
    async (status) => {
      const calls: RequestInit[] = [];
      const fetchFn = vi.fn(async (_url: string, init?: RequestInit) => {
        calls.push(init ?? {});
        return calls.length === 1
          ? new Response(null, { status, headers: { Location: "/result" } })
          : new Response("done", { status: 200 });
      });

      const result = await safeEgressFetch("https://public.example/a2a", post, {
        fetchFn,
        lookupFn: lookup,
        bodyPolicy: { mode: "read", maxBytes: 16 },
      });

      expect(result.bodyText).toBe("done");
      expect(calls[1].method).toBe("GET");
      expect(calls[1].body).toBeUndefined();
      expect(new Headers(calls[1].headers).has("content-type")).toBe(false);
    }
  );

  it.each([
    ["missing", undefined],
    ["malformed", "https://["],
  ])("fails closed on a %s redirect Location", async (_label, location) => {
    const fetchFn = vi.fn(async () =>
      new Response(null, {
        status: 307,
        ...(location ? { headers: { Location: location } } : {}),
      })
    );

    await expect(
      safeEgressFetch("https://public.example/a2a", post, {
        fetchFn,
        lookupFn: lookup,
        bodyPolicy: { mode: "cancel" },
      })
    ).rejects.toBeInstanceOf(EgressBlockedError);
    expect(fetchFn).toHaveBeenCalledOnce();
  });

  it("enforces a fixed redirect bound", async () => {
    const fetchFn = vi.fn(async (_url: string, _init?: RequestInit) =>
      new Response(null, { status: 307, headers: { Location: "/again" } })
    );

    await expect(
      safeEgressFetch("https://public.example/a2a", post, {
        fetchFn,
        lookupFn: lookup,
        maxRedirects: 1,
        bodyPolicy: { mode: "cancel" },
      })
    ).rejects.toBeInstanceOf(EgressBlockedError);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("stops and cancels a chunked body at the byte ceiling", async () => {
    let pulls = 0;
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        controller.enqueue(new TextEncoder().encode("12345678"));
      },
      cancel() {
        cancelled = true;
      },
    });
    const fetchFn = vi.fn(async () => new Response(stream, { status: 200 }));

    const result = await safeEgressFetch("https://public.example/a2a", post, {
      fetchFn,
      lookupFn: lookup,
      bodyPolicy: { mode: "read", maxBytes: 10 },
    });

    expect(result.bodyText).toBe("1234567812");
    expect(result.bodyBytes).toBe(10);
    expect(result.bodyTruncated).toBe(true);
    expect(cancelled).toBe(true);
    expect(pulls).toBeLessThanOrEqual(3);
  });
});
