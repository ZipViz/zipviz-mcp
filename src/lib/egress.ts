// SSRF egress guard for outbound calls to recipient-controlled URLs.
//
// zipviz_send fetches a recipient agent's tunnel URL, and that URL comes from
// the registry — i.e. it is attacker-influenced (a hostile agent can register
// a card whose `url` points at an internal address). The MCP server runs on a
// user's machine (stdio) or a small host (http), so an unguarded fetch is a
// classic SSRF primitive: `http://169.254.169.254/...` (cloud metadata),
// `http://localhost:…`, `http://10.0.0.0/8`, etc.
//
// This module refuses https URLs whose host is — or resolves to — a private,
// loopback, link-local, CGNAT, ULA, multicast, or otherwise non-public
// address, and refuses obvious internal hostnames.
//
// The addresses that pass that check are the only ones the connection may use.
// `pinnedHttpsFetch` hands Node a lookup that answers with exactly those
// validated addresses, so a second DNS answer between the check and the
// connection (DNS rebinding) cannot redirect the request. The hostname still
// drives TLS: SNI and certificate verification are against the name in the URL.
// Every redirect hop is validated and pinned afresh, connections are never
// reused across hops, and the DNS step sits inside the caller's abort signal.

import { isIP, type LookupFunction } from "node:net";
import { lookup as dnsLookup } from "node:dns/promises";
import type { LookupAddress } from "node:dns";
import { request as httpsRequest } from "node:https";
import { Readable } from "node:stream";

export type LookupFn = (
  hostname: string
) => Promise<Array<{ address: string; family: number }>>;

/** A host that passed the egress check, with the only addresses it may connect to. */
export type ValidatedTarget = {
  hostname: string;
  addresses: Array<{ address: string; family: 4 | 6 }>;
};

export type EgressFetchFn = (
  url: string,
  init: RequestInit,
  target: ValidatedTarget
) => Promise<Response>;

export type EgressBodyPolicy =
  | { mode: "cancel" }
  | { mode: "read"; maxBytes: number };

export type SafeEgressFetchResult = {
  response: Response;
  bodyText: string;
  bodyBytes: number;
  bodyTruncated: boolean;
};

export const MAX_EGRESS_REDIRECTS = 3;

const defaultLookup: LookupFn = (hostname) =>
  dnsLookup(hostname, { all: true, verbatim: true });

export class EgressBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EgressBlockedError";
  }
}

function ipv4ToBytes(addr: string): number[] | null {
  const parts = addr.split(".");
  if (parts.length !== 4) return null;
  const bytes = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : NaN));
  if (bytes.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) return null;
  return bytes;
}

function isBlockedIPv4(b: number[]): boolean {
  const [a, b1, c] = b;
  if (a === 0) return true; // 0.0.0.0/8 (this host / unspecified)
  if (a === 10) return true; // 10/8 private
  if (a === 127) return true; // 127/8 loopback
  if (a === 169 && b1 === 254) return true; // 169.254/16 link-local (incl. 169.254.169.254 metadata)
  if (a === 172 && b1 >= 16 && b1 <= 31) return true; // 172.16/12 private
  if (a === 192 && b1 === 168) return true; // 192.168/16 private
  if (a === 100 && b1 >= 64 && b1 <= 127) return true; // 100.64/10 CGNAT
  if (a === 192 && b1 === 0 && c === 0) return true; // 192.0.0/24 IETF protocol assignments
  if (a === 198 && (b1 === 18 || b1 === 19)) return true; // 198.18/15 benchmarking
  if (a >= 224) return true; // 224/4 multicast + 240/4 reserved + 255.255.255.255
  return false;
}

// Expand any IPv6 literal (including `::` compression and embedded IPv4) to
// its 16 constituent bytes. Returns null if the literal is unparseable.
function expandIPv6(addr: string): number[] | null {
  const zone = addr.indexOf("%");
  let a = zone >= 0 ? addr.slice(0, zone) : addr;

  // Embedded IPv4 tail, e.g. ::ffff:127.0.0.1 → rewrite the dotted-quad as two
  // hextets so the rest of the parser only deals with hex groups.
  if (a.includes(".")) {
    const lastColon = a.lastIndexOf(":");
    const v4 = ipv4ToBytes(a.slice(lastColon + 1));
    if (!v4) return null;
    const hi = ((v4[0] << 8) | v4[1]).toString(16);
    const lo = ((v4[2] << 8) | v4[3]).toString(16);
    a = `${a.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = a.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(":") : []) : null;

  let groups: string[];
  if (tail === null) {
    groups = head;
  } else {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = [...head, ...Array(missing).fill("0"), ...tail];
  }
  if (groups.length !== 8) return null;

  const bytes: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    const v = parseInt(g, 16);
    bytes.push((v >> 8) & 0xff, v & 0xff);
  }
  return bytes;
}

function isBlockedIPv6(bytes: number[]): boolean {
  if (bytes.every((x) => x === 0)) return true; // :: unspecified
  if (bytes.slice(0, 15).every((x) => x === 0) && bytes[15] === 1) return true; // ::1 loopback

  const b0 = bytes[0];
  if (b0 === 0xff) return true; // ff00::/8 multicast
  if (b0 === 0xfe && (bytes[1] & 0xc0) === 0x80) return true; // fe80::/10 link-local
  if (b0 === 0xfe && (bytes[1] & 0xc0) === 0xc0) return true; // fec0::/10 deprecated site-local
  if ((b0 & 0xfe) === 0xfc) return true; // fc00::/7 unique-local

  // IPv4-mapped ::ffff:0:0/96 and deprecated IPv4-compatible ::/96 — judge the
  // embedded IPv4 on its own merits.
  const mapped =
    bytes.slice(0, 10).every((x) => x === 0) &&
    bytes[10] === 0xff &&
    bytes[11] === 0xff;
  const compat = bytes.slice(0, 12).every((x) => x === 0);
  if (mapped || compat) {
    return isBlockedIPv4([bytes[12], bytes[13], bytes[14], bytes[15]]);
  }
  return false;
}

// True if `ip` (an IPv4 or IPv6 literal) is a non-public address we refuse to
// connect to. An unparseable literal is treated as blocked (fail closed).
export function isBlockedAddress(ip: string): boolean {
  const fam = isIP(ip);
  if (fam === 4) {
    const b = ipv4ToBytes(ip);
    return b ? isBlockedIPv4(b) : true;
  }
  if (fam === 6) {
    const b = expandIPv6(ip);
    return b ? isBlockedIPv6(b) : true;
  }
  return true; // not an IP literal — callers must not pass hostnames here
}

function isBlockedHostname(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h.endsWith(".local")) return true; // mDNS
  if (h.endsWith(".internal")) return true; // common internal TLD
  return false;
}

// Validate that `rawUrl` is an https URL whose host is not, and does not
// resolve to, a non-public address. Throws EgressBlockedError on refusal.
// Fails closed: if the host cannot be resolved (the lookup throws or returns
// no addresses) we refuse rather than letting an unverified host through to
// fetch. A transient DNS failure blocking a send is the safe tradeoff — the
// alternative leaks an SSRF bypass whenever resolution is induced to fail on
// the guard's lookup but succeed at fetch time.
export async function assertSafeEgressUrl(
  rawUrl: string,
  lookupFn: LookupFn = defaultLookup
): Promise<ValidatedTarget> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new EgressBlockedError("Refusing to connect: malformed URL.");
  }

  if (url.protocol !== "https:") {
    throw new EgressBlockedError(
      "Refusing to connect: only https endpoints are allowed."
    );
  }

  if (url.username !== "" || url.password !== "") {
    throw new EgressBlockedError(
      "Refusing to connect: URL credentials are not allowed."
    );
  }

  const host = url.hostname.replace(/^\[|\]$/g, ""); // strip IPv6 brackets

  if (host === "") {
    throw new EgressBlockedError("Refusing to connect: URL has no hostname.");
  }

  const literalFamily = isIP(host);
  if (literalFamily !== 0) {
    if (isBlockedAddress(host)) {
      throw new EgressBlockedError(
        "Refusing to connect to a private, loopback, or link-local address."
      );
    }
    return { hostname: host, addresses: [{ address: host, family: literalFamily as 4 | 6 }] };
  }

  if (isBlockedHostname(host)) {
    throw new EgressBlockedError(
      "Refusing to connect to an internal hostname."
    );
  }

  let addrs: Array<{ address: string; family: number }>;
  try {
    addrs = await lookupFn(host);
  } catch {
    // Fail closed: an unresolvable host cannot be proven public, so refuse it
    // here instead of handing an unverified target to fetch.
    throw new EgressBlockedError(
      "Refusing to connect: DNS resolution failed, so the destination cannot be confirmed public."
    );
  }
  if (addrs.length === 0) {
    throw new EgressBlockedError(
      "Refusing to connect: DNS resolution returned no addresses."
    );
  }
  const validated: ValidatedTarget["addresses"] = [];
  for (const a of addrs) {
    const family = isIP(a.address);
    if (family === 0 || isBlockedAddress(a.address)) {
      throw new EgressBlockedError(
        "Refusing to connect: hostname resolves to a private, loopback, or link-local address."
      );
    }
    validated.push({ address: a.address, family: family as 4 | 6 });
  }
  return { hostname: host, addresses: validated };
}

// A Node `lookup` that can only ever answer with the validated addresses. It
// refuses any other hostname outright, so it cannot be reused for a different
// target, and it never consults DNS. It answers on a later tick, as
// `dns.lookup` does: a synchronous answer lets a connect that fails at once
// (no route, for instance) report its error before the HTTP client has
// attached its socket listeners.
export function pinnedLookup(target: ValidatedTarget): LookupFunction {
  return ((hostname: string, options: unknown, callback: (...args: unknown[]) => void) => {
    const done = typeof options === "function" ? (options as typeof callback) : callback;
    const cb = (...args: unknown[]) => process.nextTick(() => done(...args));
    const opts = (typeof options === "object" && options !== null ? options : {}) as {
      family?: number | string;
      all?: boolean;
    };
    const asked = hostname.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, "");
    if (asked !== target.hostname.toLowerCase().replace(/\.$/, "")) {
      const err = Object.assign(new Error("pinned lookup refused an unvalidated hostname"), {
        code: "ENOTFOUND",
      });
      cb(err, "", 0);
      return;
    }
    const family = opts.family === "IPv4" ? 4 : opts.family === "IPv6" ? 6 : Number(opts.family ?? 0);
    const usable = family === 4 || family === 6
      ? target.addresses.filter((a) => a.family === family)
      : target.addresses;
    if (usable.length === 0) {
      const err = Object.assign(new Error("no validated address for the requested family"), {
        code: "ENOTFOUND",
      });
      cb(err, "", 0);
      return;
    }
    if (opts.all) {
      cb(null, usable.map((a): LookupAddress => ({ address: a.address, family: a.family })));
      return;
    }
    cb(null, usable[0].address, usable[0].family);
  }) as LookupFunction;
}

const NULL_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);

// One HTTPS request whose connection may only reach `target`'s validated
// addresses. No connection pooling (`agent: false`), so a later hop or a later
// send can never inherit a socket opened for another name.
export function pinnedHttpsFetch(
  rawUrl: string,
  init: RequestInit,
  target: ValidatedTarget
): Promise<Response> {
  const url = new URL(rawUrl);
  if (url.protocol !== "https:") {
    return Promise.reject(new EgressBlockedError("Refusing to connect: only https endpoints are allowed."));
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (host.toLowerCase() !== target.hostname.toLowerCase()) {
    return Promise.reject(new EgressBlockedError("Refusing to connect: target was not validated for this host."));
  }
  if (init.body != null && typeof init.body !== "string") {
    return Promise.reject(new TypeError("pinnedHttpsFetch only sends string bodies"));
  }
  const body = init.body ?? undefined;
  const method = (init.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = {};
  new Headers(init.headers).forEach((value, name) => {
    headers[name] = value;
  });
  if (body !== undefined) headers["content-length"] = String(Buffer.byteLength(body));
  const signal = init.signal ?? undefined;

  return new Promise<Response>((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? new DOMException("This operation was aborted", "AbortError"));
      return;
    }
    const req = httpsRequest(
      {
        protocol: "https:",
        hostname: host,
        port: url.port || 443,
        path: `${url.pathname}${url.search}`,
        method,
        headers,
        agent: false,
        lookup: pinnedLookup(target),
        servername: isIP(host) === 0 ? host : undefined,
        signal,
      },
      (res) => {
        const status = res.statusCode ?? 0;
        const responseHeaders = new Headers();
        for (const [name, value] of Object.entries(res.headers)) {
          if (value === undefined) continue;
          if (Array.isArray(value)) for (const v of value) responseHeaders.append(name, v);
          else responseHeaders.set(name, String(value));
        }
        const nullBody = method === "HEAD" || NULL_BODY_STATUSES.has(status);
        try {
          const response = new Response(
            nullBody ? null : (Readable.toWeb(res) as unknown as ReadableStream<Uint8Array>),
            { status, headers: responseHeaders }
          );
          if (nullBody) res.resume();
          resolve(response);
        } catch (err) {
          res.destroy();
          reject(err);
        }
      }
    );
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

// Settle with the caller's abort as soon as it fires, even while `work` (a DNS
// lookup, for instance) is still pending. The pending work is left to finish
// on its own; its result is ignored.
function untilAborted<T>(work: Promise<T>, signal: AbortSignal | null | undefined): Promise<T> {
  if (!signal) return work;
  if (signal.aborted) {
    return Promise.reject(signal.reason ?? new DOMException("This operation was aborted", "AbortError"));
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = () =>
      reject(signal.reason ?? new DOMException("This operation was aborted", "AbortError"));
    signal.addEventListener("abort", onAbort, { once: true });
    work.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (err) => {
        signal.removeEventListener("abort", onAbort);
        reject(err);
      }
    );
  });
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const BODY_HEADERS = [
  "content-encoding",
  "content-language",
  "content-length",
  "content-location",
  "content-type",
  "transfer-encoding",
];
const CREDENTIAL_HEADERS = [
  "authorization",
  "proxy-authorization",
  "cookie",
  "cookie2",
];

async function cancelResponseBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // Cancellation is best-effort cleanup. Never replace a deterministic
    // policy result with attacker-influenced stream/cancellation detail.
  }
}

async function readBoundedResponseBody(
  response: Response,
  maxBytes: number
): Promise<Pick<SafeEgressFetchResult, "bodyText" | "bodyBytes" | "bodyTruncated">> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new TypeError("maxBytes must be a non-negative safe integer");
  }

  const declared = response.headers.get("content-length");
  if (declared !== null && /^\d+$/.test(declared.trim())) {
    const declaredBytes = Number(declared);
    if (Number.isSafeInteger(declaredBytes) && declaredBytes > maxBytes) {
      await cancelResponseBody(response);
      return { bodyText: "", bodyBytes: 0, bodyTruncated: true };
    }
  }

  if (!response.body) {
    return { bodyText: "", bodyBytes: 0, bodyTruncated: false };
  }

  // Allocate only the accepted ceiling. A dishonest/missing Content-Length can
  // no longer make us retain an unbounded response before applying the limit.
  const accepted = Buffer.allocUnsafe(maxBytes);
  const reader = response.body.getReader();
  let used = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      const remaining = maxBytes - used;
      const take = Math.min(remaining, value.byteLength);
      if (take > 0) {
        Buffer.from(value.buffer, value.byteOffset, take).copy(accepted, used);
        used += take;
      }
      if (take < value.byteLength || used === maxBytes) {
        // Reaching exactly the limit is not by itself oversized. Read one more
        // chunk to distinguish an exact-size body from limit+1 without ever
        // retaining that extra data.
        if (take < value.byteLength) {
          truncated = true;
          await reader.cancel();
          break;
        }
        let next = await reader.read();
        while (!next.done && (!next.value || next.value.byteLength === 0)) {
          next = await reader.read();
        }
        if (!next.done) {
          truncated = true;
          await reader.cancel();
        }
        break;
      }
    }
  } finally {
    reader.releaseLock();
  }

  return {
    bodyText: accepted.subarray(0, used).toString("utf8"),
    bodyBytes: used,
    bodyTruncated: truncated,
  };
}

function redirectedInit(
  current: URL,
  next: URL,
  status: number,
  init: RequestInit
): RequestInit {
  const headers = new Headers(init.headers);
  let method = (init.method ?? "GET").toUpperCase();
  let body = init.body;

  // Match Fetch redirect behavior so existing safe redirects retain their
  // public contract. In particular, 307/308 preserve the A2A POST and signed
  // JSON body; 301/302/303 transform POST to a bodyless GET.
  if (
    ((status === 301 || status === 302) && method === "POST") ||
    (status === 303 && method !== "GET" && method !== "HEAD")
  ) {
    method = "GET";
    body = undefined;
    for (const name of BODY_HEADERS) headers.delete(name);
  }

  if (current.origin !== next.origin) {
    for (const name of CREDENTIAL_HEADERS) headers.delete(name);
  }

  return { ...init, method, body, headers, redirect: "manual" };
}

// Fetch a registry-derived endpoint without ever letting the HTTP client own
// redirects. Validation and use remain in this one helper: each exact URL is
// parsed and resolved immediately before its manual fetch, the connection is
// pinned to the addresses that validation accepted, every intermediate body is
// cancelled, and the final body is either cancelled or streamed into a fixed
// byte ceiling chosen by the caller. The caller's abort signal bounds the DNS
// step as well as the request.
export async function safeEgressFetch(
  rawUrl: string,
  init: RequestInit,
  opts: {
    /** Transport. Defaults to `pinnedHttpsFetch`; it receives the validated target for each hop. */
    fetchFn?: EgressFetchFn;
    lookupFn?: LookupFn;
    assertEgress?: (url: string) => Promise<ValidatedTarget>;
    /** Synchronous final policy hook, called after URL validation before every fetch. */
    beforeFetch?: (url: string) => void;
    maxRedirects?: number;
    bodyPolicy: EgressBodyPolicy;
  }
): Promise<SafeEgressFetchResult> {
  const fetchFn: EgressFetchFn = opts.fetchFn ?? pinnedHttpsFetch;
  const assertEgress =
    opts.assertEgress ??
    ((url: string) => assertSafeEgressUrl(url, opts.lookupFn ?? defaultLookup));
  const maxRedirects = opts.maxRedirects ?? MAX_EGRESS_REDIRECTS;
  if (!Number.isSafeInteger(maxRedirects) || maxRedirects < 0) {
    throw new TypeError("maxRedirects must be a non-negative safe integer");
  }

  let currentUrl = rawUrl;
  let currentInit: RequestInit = {
    ...init,
    headers: new Headers(init.headers),
    redirect: "manual",
  };

  for (let redirects = 0; ; redirects += 1) {
    const target = await untilAborted(assertEgress(currentUrl), currentInit.signal);
    opts.beforeFetch?.(currentUrl);
    const response = await fetchFn(currentUrl, currentInit, target);
    if (!REDIRECT_STATUSES.has(response.status)) {
      if (opts.bodyPolicy.mode === "cancel") {
        await cancelResponseBody(response);
        return {
          response,
          bodyText: "",
          bodyBytes: 0,
          bodyTruncated: false,
        };
      }
      const body = await readBoundedResponseBody(
        response,
        opts.bodyPolicy.maxBytes
      );
      return { response, ...body };
    }

    const location = response.headers.get("location");
    await cancelResponseBody(response);
    if (!location) {
      throw new EgressBlockedError(
        "Refusing to connect: redirect response has no Location."
      );
    }
    if (redirects >= maxRedirects) {
      throw new EgressBlockedError(
        "Refusing to connect: redirect limit exceeded."
      );
    }

    let next: URL;
    try {
      next = new URL(location, currentUrl);
    } catch {
      throw new EgressBlockedError(
        "Refusing to connect: redirect Location is malformed."
      );
    }
    const current = new URL(currentUrl);
    currentInit = redirectedInit(current, next, response.status, currentInit);
    currentUrl = next.toString();
  }
}
