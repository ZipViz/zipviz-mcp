import { readJsonBounded } from "./bounded-json.js";

const BASE_URL = "https://api.zipviz.ai";

// Every request through this client is bounded.
//
// It was not. An earlier review said only the verify tool needed a timeout.
// That was wrong about this client: it had none either, so `zipviz_lookup`, `zipviz_status` and every
// other call could hang on a connection that was accepted and never answered.
// Rather than correct the sentence, correct the
// code.
const DEFAULT_TIMEOUT_MS = 10_000;

export async function zipvizFetch<T>(
  path: string,
  options?: RequestInit & { timeoutMs?: number }
): Promise<T> {
  const url = `${BASE_URL}${path}`;
  const { timeoutMs, ...init } = options ?? {};
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    // A caller that supplies its own signal keeps it; otherwise bound it.
    signal: init.signal ?? AbortSignal.timeout(timeoutMs ?? DEFAULT_TIMEOUT_MS),
  });

  if (!res.ok) {
    // Surface status + statusText only. The raw upstream body is never
    // echoed into an Error that a tool handler may return to the calling model —
    // it can carry internal detail, and (for a compromised/misbehaving upstream)
    // attacker-influenced content. Consume the body so the socket can be reused,
    // then discard it.
    await res.body?.cancel().catch(() => {});
    throw new Error(`ZipViz API error: ${res.status} ${res.statusText}`.trim());
  }

  return (await readJsonBounded(res)) as T;
}
