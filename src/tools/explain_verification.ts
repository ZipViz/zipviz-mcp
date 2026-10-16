import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { VerifyToolResult } from "./verify.js";
import { boundModelText } from "../lib/model-text.js";

// ============================================================================
// Plain-English explanation of a verification
// ============================================================================
// This is a PURE FORMATTER over a verdict THIS PROCESS produced, and that is
// the whole security property. It is not exposed as a tool that accepts a
// verdict from a caller, because there is no way for such a tool to know
// whether the verdict is real.
//
// What it used to be, and why binding alone was not enough. The tool took a
// `result` object and explained it. Nothing tied that object to a verification
// anyone had performed, and over a relay the caller is remote — so
// the caller wrote the verdict it was then told the meaning of:
//
//   {verified:true, blue_tick_status:"verified", signer:"attacker.viz"}
//     => "The cryptographic signature is valid. The signer is attacker.viz.
//         Trust status: verified."
//
// The first fix required the caller to name a `domain` and bound the verdict's
// echoed `identity` to it. That is necessary and it is not provenance: a caller
// can fabricate a matching pair — `domain` and `identity` are both fields it
// writes. A symbol-keyed proof cannot close the
// gap either, because `zipviz_verify` and this call are separate MCP calls: the
// verdict is serialised to text for the model and arrives back as re-parsed
// JSON, and symbols do not survive JSON.
//
// So verification and explanation are fused. `zipviz_verify` fetches,
// validates, binds, and returns the explanation alongside its verdict, derived
// from the same validated object. There is nothing left for a caller to hand
// in, and therefore nothing to forge. The standalone tool remains registered
// only as a deprecation notice that mints no claim of any kind.
//
// The second live defect this file had is gone with the input: it read
// `signer ?? domain`, and `/v1/verify` emits `identity`, so every real
// verification rendered "The signer could not be identified" and "The .viz
// domain was not found in the registry" — impossible, since the endpoint looks
// the key up BY domain and 404s when there is no row.
// ============================================================================

/**
 * Turn a verdict this process produced into a sentence a person can read.
 *
 * Takes `VerifyToolResult` — the projected, contract-validated, identity-bound
 * verdict built by `verifyMessage` — and nothing else. It cannot be handed a
 * body off the network or out of a model's context.
 */
export function explainVerification(v: VerifyToolResult): string {
  const who = v.domain ? boundModelText(v.domain, 253) : "the requested agent";

  if (v.verified === true) {
    return [
      `The signature checks out: this message really was signed by ${who}.`,
      tickSentence(v.blue_tick, who),
    ].join("\n");
  }

  if (v.verified === false) {
    // Our own sentence, from the machine `code`. The upstream `error`/`reason`
    // text is never repeated: it is written elsewhere and would land in front
    // of a reader as though ZipViz had said it.
    return failureSentence(v.code, who);
  }

  return unknownSentence(v.unavailable_reason, who);
}

function tickSentence(tick: boolean | undefined, who: string): string {
  if (tick === true) {
    return `${who} currently holds trust status, which is earned from measured behavior.`;
  }
  if (tick === false) {
    // A measured negative is NOT "pending". `blue_tick: false` from the producer
    // means measured and not earned; "still pending" turned a finding into a
    // promise.
    return `${who} has been measured and does not hold trust status.`;
  }
  return `Whether ${who} holds trust status is not known from this check.`;
}

function failureSentence(code: string | undefined, who: string): string {
  switch (code) {
    case "E_SIG_MISMATCH":
      return `The signature does not match: this message was not signed by ${who}, or it has been altered since. Do not trust it.`;
    case "E_STALE":
      // The producer rejects a timestamp outside ±5 min BEFORE registry lookup,
      // key import, base64 parsing, or Ed25519 verify.
      // E_STALE therefore proves only that the timestamp is outside the window.
      return `The receipt timestamp is outside the accepted freshness window. The signature was not verified, so authenticity remains unknown.`;
    case "E_AGENT_NOT_FOUND":
      return `There is no agent registered as ${who}, so there is no key to check this message against.`;
    case "E_MISSING_FIELDS":
    case "E_TIMESTAMP_FORMAT":
    case "E_SIG_FORMAT":
      return `This message is malformed and could not be checked. It has not been shown to be genuine, and it has not been shown to be fake.`;
    case "E_STORED_KEY":
    case "E_VERIFY":
      return `ZipViz's verifier could not complete this check. The signature has not been shown to be genuine, and it has not been shown to be fake.`;
    default:
      // An unrecognised code is a fact about the verifier, not about the agent.
      return `This message did not pass verification. The reason given is not one this version recognises, so nothing more specific can be said about ${who}.`;
  }
}

function unknownSentence(reason: string | undefined, who: string): string {
  const tail =
    "It has not been shown to be genuine, and it has not been shown to be fake.";
  switch (reason) {
    case "invalid_domain":
      return `The requested identity is not a valid .viz domain, so no verification request was made. ${tail}`;
    case "transport":
      return `ZipViz's verifier could not be reached, so this message has not been checked. ${tail}`;
    case "identity_mismatch":
      return `The verifier answered about a different agent than ${who}, so this tells you nothing about ${who}. ${tail}`;
    case "off_contract":
    case "unparseable":
      return `The verifier's answer was not one ZipViz can produce, so it cannot be relied on. ${tail}`;
    default:
      return `This message has not been checked. ${tail}`;
  }
}

/**
 * The standalone tool is a DEPRECATION NOTICE, not an explainer.
 *
 * It is kept registered rather than deleted so an existing configuration gets a
 * sentence telling it where the explanation went, instead of "unknown tool" —
 * and because a tool that mints nothing is safe to leave in the surface. It
 * accepts and ignores whatever it is given; it never reads the input, so there
 * is nothing to fabricate.
 */
export function registerExplainVerification(server: McpServer) {
  server.registerTool(
    "zipviz_explain_verification",
    {
      description:
        "DEPRECATED and non-functional. zipviz_verify now returns the " +
        "plain-English explanation alongside its verdict, derived from the " +
        "verification it performed. This tool explains nothing: a verification " +
        "result supplied by a caller cannot be told apart from one a caller " +
        "invented, so explaining it would mint a trust claim with nothing " +
        "behind it.",
      inputSchema: {
        result: z
          .unknown()
          .optional()
          .describe("Ignored. Call zipviz_verify instead."),
      },
    },
    async () => ({
      content: [
        {
          type: "text" as const,
          text:
            "zipviz_explain_verification is deprecated and explains nothing. " +
            "Call zipviz_verify with the domain, message, timestamp and " +
            "signature: it returns the verdict and its plain-English " +
            "explanation together, built from the verification it performed. " +
            "An explanation of a result supplied by the caller would be a " +
            "trust claim with nothing behind it.",
        },
      ],
    })
  );
}
