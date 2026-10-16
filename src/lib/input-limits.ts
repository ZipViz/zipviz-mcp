// Size limits for tool inputs. Every tool argument arrives from the MCP client
// over stdio, and before these limits a single call could hand a tool a
// multi-megabyte domain, signature or message, which was then hashed, signed,
// encoded into a URL or sent upstream. The limits sit at the schema, so an
// oversized argument is rejected before any handler runs, and nothing is ever
// truncated to fit.

/** A DNS name is at most 253 characters; `isValidVizDomain` applies the same bound. */
export const MAX_DOMAIN_CHARS = 253;

/**
 * Text of a message sent with `zipviz_send`, in UTF-8 bytes. The receiving
 * side refuses message text over 32 KiB, so a longer message could only fail
 * after being signed and sent. This is the text limit only: the whole request
 * the receiver accepts is larger, because it also carries the envelope and
 * signature. Signing and verifying are not tied to this limit; their inputs
 * are bounded by the stdio frame below.
 */
export const MAX_SEND_MESSAGE_BYTES = 32 * 1024;

/**
 * The whole encoded request `zipviz_send` posts, in bytes. The receiving side
 * refuses a request body over 128 KiB, a limit separate from the text limit
 * above: JSON escaping, the envelope and the signature all count toward it, so
 * a message within the text limit can still produce a request over this one.
 */
export const MAX_SEND_REQUEST_BYTES = 128 * 1024;

/** ISO 8601 with fractional seconds and an offset is about 35 characters. */
export const MAX_TIMESTAMP_CHARS = 64;

/** Base64 of a 64-byte Ed25519 signature is 88 characters. */
export const MAX_SIGNATURE_CHARS = 128;

/**
 * Largest single JSON-RPC line the stdio transport buffers: well above a
 * maximal send message even when JSON escaping grows it sixfold, and well
 * below the SDK default of 10 MiB. Past it the transport reports an error and
 * closes.
 */
export const MAX_FRAME_BYTES = 1024 * 1024;

export const SEND_MESSAGE_TOO_LARGE = `message must be at most ${MAX_SEND_MESSAGE_BYTES} bytes of UTF-8 text`;

export function fitsSendMessage(value: string): boolean {
  // A UTF-16 code unit never encodes to fewer than one UTF-8 byte, so a string
  // longer than the limit in code units is over it without counting bytes.
  return (
    value.length <= MAX_SEND_MESSAGE_BYTES &&
    Buffer.byteLength(value, "utf8") <= MAX_SEND_MESSAGE_BYTES
  );
}

export function sendRequestTooLarge(bytes: number): string {
  return (
    `The request would be ${bytes} bytes, over the ${MAX_SEND_REQUEST_BYTES}-byte limit the ` +
    "receiver accepts for a whole request. JSON escaping of quotes, backslashes and control " +
    "characters makes the request larger than the message text. Nothing was sent; shorten the message."
  );
}
