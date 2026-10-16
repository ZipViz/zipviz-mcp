// Registry responses are small JSON documents. Every registry read already has
// a timeout; this adds a byte ceiling, so a misbehaving or compromised upstream
// cannot make the client buffer an unbounded body before parsing it.

export const REGISTRY_MAX_BYTES = 256 * 1024;

export class BodyTooLargeError extends Error {
  constructor(maxBytes: number) {
    super(`response body exceeded ${maxBytes} bytes`);
    this.name = "BodyTooLargeError";
  }
}

/**
 * Parse a JSON response body, refusing anything larger than `maxBytes`.
 * Throws BodyTooLargeError past the ceiling and SyntaxError on malformed JSON,
 * so callers keep their existing "unparseable" handling for both.
 */
export async function readJsonBounded(
  res: Response,
  maxBytes: number = REGISTRY_MAX_BYTES
): Promise<unknown> {
  const body = (res as { body?: unknown }).body;
  if (!(body instanceof ReadableStream)) {
    // Only hand-built test doubles reach this: a real fetch Response always
    // carries a stream (or a null body, which json() rejects as before).
    return res.json();
  }
  const declared = res.headers?.get?.("content-length");
  if (declared && /^\d+$/.test(declared.trim()) && Number(declared) > maxBytes) {
    await body.cancel().catch(() => {});
    throw new BodyTooLargeError(maxBytes);
  }
  const reader = (body as ReadableStream<Uint8Array>).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new BodyTooLargeError(maxBytes);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}
