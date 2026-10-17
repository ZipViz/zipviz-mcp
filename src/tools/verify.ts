import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { MAX_DOMAIN_CHARS, MAX_SIGNATURE_CHARS, MAX_TIMESTAMP_CHARS } from "../lib/input-limits.js";
import { validateRemoteFailure, validateRemoteSuccess } from "../lib/verify-contract.js";
import type { ProducerReputation } from "../lib/producer-reputation.js";
import { isValidVizDomain, sameVizIdentity } from "../lib/viz-domain.js";
import { explainVerification } from "./explain_verification.js";
import { readJsonBounded } from "../lib/bounded-json.js";

const VERIFY_URL = "https://api.zipviz.ai/v1/verify";

// The verify hop is bounded for the same reason the attestation path's is: an
// endpoint that accepts the connection and never answers would otherwise hang
// the tool indefinitely. Ten seconds, then `unknown`.
const VERIFY_TIMEOUT_MS = 10_000;

/**
 * What we are willing to say about a verification, and nothing else.
 *
 * The tool used to return `JSON.parse` of the upstream body verbatim — every
 * field it happened to carry, including on a non-2xx, which is the behaviour
 * already removed from the shared client for being attacker-influenceable. It
 * also never compared the echoed `identity` to the domain asked about, which an
 * earlier fix had left standing on the tool surface.
 *
 * This is a deliberate projection: the fields below are the ones this tool
 * means to surface, each checked before it is copied.
 */
export interface VerifyToolResult {
  /** `true`, `false`, or `"unknown"` — never a guess in either direction. */
  verified: boolean | "unknown";
  domain: string | null;
  /** The version the verifier authenticated, never the caller's claim. */
  signing_version?: 0 | 1;
  blue_tick?: boolean;
  reputation?: ProducerReputation;
  /** Stable machine code on a failure. Never free text from the body. */
  code?: string;
  /** Why we could not attribute the answer, when that is what happened. */
  unavailable_reason?:
    | "invalid_domain"
    | "off_contract"
    | "identity_mismatch"
    | "transport"
    | "unparseable";
}

export async function verifyMessage(params: {
  domain: string;
  message: string;
  timestamp: string;
  signature: string;
  fetchFn?: typeof fetch;
  timeoutMs?: number;
}): Promise<VerifyToolResult> {
  const { domain } = params;
  if (!isValidVizDomain(domain)) {
    return { verified: "unknown", domain: null, unavailable_reason: "invalid_domain" };
  }
  const doFetch = params.fetchFn ?? fetch;

  let res: Response;
  try {
    res = await doFetch(VERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        from: domain,
        message: params.message,
        timestamp: params.timestamp,
        signature: params.signature,
      }),
      signal: AbortSignal.timeout(params.timeoutMs ?? VERIFY_TIMEOUT_MS),
    });
  } catch {
    // An outage reads as unknown. Never a pass, and never a failure — the two
    // are different and only one of them is safe to invent, which is neither.
    return { verified: "unknown", domain, unavailable_reason: "transport" };
  }

  // NO CAST. The body is `unknown` until the contract validator says what it
  // is; `as VerifyResponse` would be an assertion about a stranger's JSON.
  let body: unknown;
  try {
    body = await readJsonBounded(res);
  } catch {
    return { verified: "unknown", domain, unavailable_reason: "unparseable" };
  }

  const seen = body as Record<string, unknown> | null;
  if (seen?.verified === true) {
    // Whole contract, one shared rule with the attestation path.
    const contract = validateRemoteSuccess(seen);
    if (!contract.ok || !res.ok) {
      return { verified: "unknown", domain, unavailable_reason: "off_contract" };
    }
    // BIND THE ANSWER TO THE QUESTION.
    if (!sameVizIdentity(contract.identity, domain)) {
      return { verified: "unknown", domain, unavailable_reason: "identity_mismatch" };
    }
    return {
      verified: true,
      domain,
      signing_version: contract.version,
      ...(typeof contract.tick === "boolean" ? { blue_tick: contract.tick } : {}),
      ...(contract.reputation ? { reputation: contract.reputation } : {}),
    };
  }

  // Exact producer status/code matrix. A 503, an invented code, a mismatched
  // pair, or a failure body carrying success-only fields is not a verdict.
  const failure = validateRemoteFailure(res.status, body);
  if (failure.ok) {
    return { verified: false, domain, code: failure.code };
  }

  return { verified: "unknown", domain, unavailable_reason: "off_contract" };
}

export function registerVerify(server: McpServer) {
  server.registerTool(
    "zipviz_verify",
    {
      description:
        "Verify a signed message from an agent. Checks the Ed25519 signature " +
        "against the agent's registered public key and returns the verdict " +
        "bound to the domain you asked about. A verdict that cannot be " +
        "attributed to ZipViz's verifier reads as unknown — never as a pass, " +
        "and never as a failure.",
      inputSchema: {
        domain: z
          .string()
          .max(MAX_DOMAIN_CHARS)
          .refine(isValidVizDomain, "Must be a valid lowercase .viz domain")
          .describe("The domain of the agent that signed the message"),
        message: z.string().describe("The original message content"),
        timestamp: z
          .string()
          .max(MAX_TIMESTAMP_CHARS)
          .describe("ISO 8601 timestamp of when the message was signed"),
        signature: z
          .string()
          .max(MAX_SIGNATURE_CHARS)
          .describe("The Ed25519 signature to verify (base64)"),
      },
    },
    async ({ domain, message, timestamp, signature }) => {
      const result = await verifyMessage({ domain, message, timestamp, signature });
      // The explanation is built HERE, from the verdict this call just produced
      // and validated — not from anything a caller could hand back later. That
      // is what closes the oracle `zipviz_explain_verification` used to be: the
      // two are fused, so there is no unproven object to explain.
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              { ...result, explanation: explainVerification(result) },
              null,
              2
            ),
          },
        ],
        ...(result.verified === false ? { isError: true } : {}),
      };
    }
  );
}
