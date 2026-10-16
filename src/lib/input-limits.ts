// Size limits for tool inputs. Every tool argument arrives from the MCP client
// over stdio, and before these limits a single call could hand a tool a
// multi-megabyte domain, signature or message, which was then hashed, signed,
// encoded into a URL or sent upstream. The limits sit at the schema, so an
// oversized argument is rejected before any handler runs.

/** A DNS name is at most 253 characters; `isValidVizDomain` applies the same bound. */
export const MAX_DOMAIN_CHARS = 253;

/** Message text, measured in UTF-8 bytes because that is what gets signed and sent. */
export const MAX_MESSAGE_BYTES = 64 * 1024;

/** ISO 8601 with fractional seconds and an offset is about 35 characters. */
export const MAX_TIMESTAMP_CHARS = 64;

/** Base64 of a 64-byte Ed25519 signature is 88 characters. */
export const MAX_SIGNATURE_CHARS = 128;

/**
 * Largest single JSON-RPC line the stdio transport buffers. It is well above a
 * maximal message (JSON escaping can grow 64 KiB of text roughly sixfold) and
 * well below the SDK default of 10 MiB. Past it the transport reports an error
 * and closes.
 */
export const MAX_FRAME_BYTES = 1024 * 1024;

export const MESSAGE_TOO_LARGE = `Must be at most ${MAX_MESSAGE_BYTES} bytes of UTF-8`;

export function fitsMessageBudget(value: string): boolean {
  // A UTF-16 code unit never encodes to fewer than one UTF-8 byte, so a string
  // longer than the budget in code units is over it without counting bytes.
  return value.length <= MAX_MESSAGE_BYTES && Buffer.byteLength(value, "utf8") <= MAX_MESSAGE_BYTES;
}
