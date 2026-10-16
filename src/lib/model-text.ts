/**
 * Bound text before placing it in an unwrapped model-facing result.
 *
 * C0/C1 controls, bidi controls, isolates, zero-width formatters and BOM can
 * restructure or conceal rendered text. Replace them uniformly so individual
 * trust surfaces cannot drift toward weaker sanitizers.
 */
const UNSAFE_MODEL_TEXT_RE =
  /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]+/g;

// Non-global probe of the same class, for callers that must REFUSE rather
// than rewrite (a .test on a /g regex is stateful, so it gets its own copy).
const UNSAFE_MODEL_TEXT_PROBE = new RegExp(UNSAFE_MODEL_TEXT_RE.source);
export function hasUnsafeModelText(value: string): boolean {
  return UNSAFE_MODEL_TEXT_PROBE.test(value);
}

export function boundModelText(
  value: unknown,
  maxLength: number,
  appendEllipsis = false
): string {
  if (typeof value !== "string" || maxLength <= 0) return "";
  const cleaned = value.replace(UNSAFE_MODEL_TEXT_RE, " ").replace(/\s+/g, " ").trim();
  if (cleaned.length <= maxLength) return cleaned;
  return cleaned.slice(0, maxLength) + (appendEllipsis ? "…" : "");
}
