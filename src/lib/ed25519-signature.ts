/** Canonical base64 for exactly 64 Ed25519 signature bytes.
 * Buffer's decoder alone permits whitespace, suffixes and non-zero pad bits.
 */
export function isCanonicalEd25519Signature(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9+/]{86}==$/.test(value) &&
    Buffer.from(value, "base64").toString("base64") === value;
}
