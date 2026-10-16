// Single source of truth for the .viz domain regex used at trust boundaries.
//
// The zipviz_send and zipviz_sign_message tools (src/tools/) validate caller-supplied identifiers against this
// pattern before letting them reach signMessage / file-system key lookup.
//
// Lowercase alphanumerics (with hyphens, not at segment edges) in
// dot-separated segments, ending in `.viz`. Rejects path-traversal,
// non-.viz suffixes, and uppercase / underscore mischief.
export const VIZ_DOMAIN_RE =
  /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.viz$/;

export function isValidVizDomain(value: unknown): value is string {
  return typeof value === "string" && value.length <= 253 && VIZ_DOMAIN_RE.test(value);
}

/** Return the canonical ASCII-lower identity, or null for an invalid value. */
export function canonicalVizDomain(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 253) return null;
  const canonical = asciiLower(value);
  return isValidVizDomain(canonical) ? canonical : null;
}

/**
 * RFC 1035 DNS-label rule used by the registry.
 * 1–63 chars, lowercase alphanumerics + hyphens, no leading/trailing hyphen.
 */
export const VIZ_DOMAIN_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * 2-label sovereign or 3-label delegated agent domain, matching the
 * registry's agent-domain rule.
 */
export function isValidVizAgentDomain(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > 253) return false;
  const parts = value.split(".");
  if (parts.length !== 2 && parts.length !== 3) return false;
  if (parts[parts.length - 1] !== "viz") return false;
  return parts.slice(0, -1).every((p) => VIZ_DOMAIN_LABEL_RE.test(p));
}

/**
 * Room name grammar, matching the registry:
 * 3–6 dotted labels, last label `viz`, each other label a DNS label,
 * total length 1–100. No Unicode folding — the label regex is ASCII.
 */
export function isValidRoomName(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > 100) return false;
  const parts = value.split(".");
  if (parts.length < 3 || parts.length > 6) return false;
  if (parts[parts.length - 1] !== "viz") return false;
  return parts.slice(0, -1).every((p) => VIZ_DOMAIN_LABEL_RE.test(p));
}

/**
 * Are these the same `.viz` identity?
 *
 * ONE equality rule, shared, because two trust boundaries binding the same kind
 * of name must not disagree about what equality means. Before this existed the
 * behaviour lookup compared case-insensitively and the reply attestation
 * compared strictly — both safe in isolation, but a difference nobody had
 * decided on.
 *
 * **Both sides must be valid `.viz` domains.** Equality is only meaningful
 * between two well-formed names: comparing junk to junk and answering "same"
 * is not a binding, it is a coincidence. `sameVizIdentity("not a domain",
 * "not a domain")` was `true` before this check existed.
 *
 * The case folding is ASCII-only **and is implemented as ASCII-only**, which
 * the first version of this function claimed but did not do. `String.prototype
 * .toLowerCase()` performs Unicode case mapping, so U+212A KELVIN SIGN folded
 * to `k` and `sameVizIdentity("\u212Aelvin.viz", "kelvin.viz")` answered true —
 * two visually distinct byte sequences compared equal, which is exactly what
 * the doc comment promised could not happen. The
 * validity check above is now the real defence: `VIZ_DOMAIN_RE` admits ASCII
 * lowercase, digits and hyphens only, so no non-ASCII character survives to be
 * folded. The explicit ASCII fold is belt to that braces.
 *
 * Whitespace is likewise rejected rather than trimmed. A padded identity is a
 * body the producer never sent, and quietly trimming it made
 * `" ticki.adkgo.viz "` bind to `ticki.adkgo.viz`.
 *
 * Non-strings and empty strings are never equal to anything, including each
 * other: an absent identity is not a match, it is a missing binding.
 */
export function sameVizIdentity(a: unknown, b: unknown): boolean {
  const left = canonicalVizDomain(a);
  const right = canonicalVizDomain(b);
  return left !== null && right !== null && left === right;
}

/**
 * ASCII case folding, and nothing else. `toLowerCase()` is Unicode-aware and
 * therefore maps characters this codebase never wants mapped; this maps A-Z and
 * leaves every other code point exactly as it found it.
 */
function asciiLower(value: string): string {
  let out = "";
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    out += code >= 65 && code <= 90 ? String.fromCharCode(code + 32) : value[i];
  }
  return out;
}
