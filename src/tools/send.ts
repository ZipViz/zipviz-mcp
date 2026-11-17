import { z } from "zod";
import { randomUUID } from "node:crypto";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { zipvizFetch } from "../lib/api.js";
import type { AgentCard, A2AResponse } from "../lib/types.js";
import { isValidVizDomain } from "../lib/viz-domain.js";
import { safeEgressFetch, EgressBlockedError } from "../lib/egress.js";
import { signEnvelopeV2 } from "./sign_message.js";
import { attestReply, type ReplyAttestation, VERIFY_TIMEOUT_MS } from "../lib/reply-attestation.js";
import { wrapUntrusted } from "../lib/untrusted.js";
import { boundModelText } from "../lib/model-text.js";
import { localV2ReceiptVerifyFn } from "../core/receipts.js";
import {
  MAX_DOMAIN_CHARS,
  MAX_SEND_REQUEST_BYTES,
  SEND_MESSAGE_TOO_LARGE,
  fitsSendMessage,
  sendRequestTooLarge,
} from "../lib/input-limits.js";

// Cap the recipient's response we read, parse, and surface. A hostile or
// broken recipient must not be able to flood the caller's context (or our
// memory) with an unbounded body. 256 KiB is far above any legitimate A2A
// reply.
const MAX_A2A_RESPONSE_BYTES = 256 * 1024;
const MAX_A2A_ERROR_MESSAGE_CHARS = 1_000;

// Outbound A2A POST timeout. Signed replies can include a /v1/verify hop,
// which pushes round-trip latency to 20-25s typical, 30s+ in cold-start
// scenarios. A 30s cap timed out against healthy recipients.
// 60s gives headroom for a slow first model call without
// hiding a genuinely-stuck recipient indefinitely.
const A2A_TIMEOUT_MS = 60_000;

export interface ZipvizSenderMetadata {
  from: string;
  timestamp: string;
  signature: string;
  v: 2;
  to: string;
  msg_id: string;
  expires_at: string;
  reply_to?: string;
}

interface A2AMessageOut {
  messageId: string;
  role: "user";
  parts: Array<{ kind: "text"; text: string }>;
  metadata?: { zipviz: ZipvizSenderMetadata };
}

function projectA2AError(value: unknown): { code: number; message: string } | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const error = value as Record<string, unknown>;
  if (typeof error.code !== "number" || !Number.isSafeInteger(error.code)) return null;
  const message = boundModelText(error.message, MAX_A2A_ERROR_MESSAGE_CHARS, true);
  if (message.length === 0) return null;
  return { code: error.code as number, message };
}

export function registerSend(server: McpServer) {
  server.registerTool(
    "zipviz_send",
    {
      description:
        "Send a message to an agent on the ZipViz network. Looks up the recipient's tunnel URL and POSTs an A2A message. " +
        "The message is ALWAYS Ed25519-signed locally as the identity given in `as` (required), using that identity's " +
        "private key (default location ~/.zipviz/keys/<as>.key); the signature is attached as " +
        "params.message.metadata.zipviz as a recipient-bound V2 envelope. " +
        "There is no unsigned send path — recipients running strict signed-inbound reject unsigned messages.",
      inputSchema: {
        domain: z
          .string()
          .max(MAX_DOMAIN_CHARS)
          .describe("The agent domain to message, e.g. ticki.adkgo.viz"),
        message: z
          .string()
          .refine(fitsSendMessage, SEND_MESSAGE_TOO_LARGE)
          .describe("The message to send to the agent"),
        as: z
          .string()
          .max(MAX_DOMAIN_CHARS)
          .describe(
            "REQUIRED. The .viz domain to send AS, e.g. stuart-clau.smc.viz. " +
              "The message is signed locally with that identity's Ed25519 key and " +
              "the signature is attached to the outbound A2A envelope's metadata.zipviz block. " +
              "Every send must be signed; there is no unsigned path."
          ),
        envelope_v: z
          .literal(2)
          .optional()
          .describe(
            "Envelope version. Defaults to 2, binding the recipient, msg_id and expiry. Legacy V1 network sends are rejected."
          ),
      },
    },
    async ({ domain, message, as, envelope_v }) => {
      // Step 0: validate both identities before they reach URL construction,
      // response labels, filesystem access, or the unwrapped attestation.
      if (typeof domain !== "string" || !isValidVizDomain(domain)) {
        return {
          content: [
            {
              type: "text" as const,
              text:
                "`domain` must be a valid .viz domain " +
                "(at most 253 lowercase ASCII characters in dot-separated segments). " +
                "No lookup or send happened.",
            },
          ],
          isError: true,
        };
      }

      // REQUIRE a valid `as` at the tool boundary, BEFORE any network
      // I/O or filesystem access. The Zod schema already makes `as` required, so
      // the in-process /mcp SDK rejects a call that omits it — but a direct
      // caller of this handler (or any path that bypasses Zod) must ALSO fail
      // closed: there is no unsigned send path. Reject a MISSING or
      // invalid `as` here; the `.viz` shape is also the path-traversal defense
      // (signing loads ~/.zipviz/keys/<as>.key).
      if (typeof as !== "string" || !isValidVizDomain(as)) {
        return {
          content: [
            {
              type: "text" as const,
              text:
                "`as` is required and must be a valid .viz domain " +
                "(lowercase alphanumerics and hyphens in dot-separated segments, " +
                "ending in '.viz'). There is no unsigned send path; no signing or send happened.",
            },
          ],
          isError: true,
        };
      }

      // Direct callers can bypass the schema. Reject legacy or unknown formats
      // before lookup or signing; there is no downgrade for old receivers.
      if (envelope_v !== undefined && envelope_v !== 2) {
        return {
          content: [
            {
              type: "text" as const,
              text:
                "Only recipient-bound envelope_v: 2 is supported for network sends. " +
                "No lookup, signing or send happened.",
            },
          ],
          isError: true,
        };
      }

      // Step 1: Look up the agent to get tunnel URL
      const card = await zipvizFetch<AgentCard>(
        `/v1/agent/${encodeURIComponent(domain)}/card`
      );

      if (!card.url) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Agent ${domain} has no URL configured. Cannot send message.`,
            },
          ],
          isError: true,
        };
      }

      // Step 2: Sign the shared V2 canonical envelope. Read back the exact
      // timestamp, expiry and message id covered by the signature. Network
      // sends never use the local V1 primitive.
      let senderMeta: ZipvizSenderMetadata;
      let messageId = `msg-${randomUUID()}`;
      try {
        const signed = await signEnvelopeV2({
          viz_domain: as,
          to: domain,
          message,
          msg_id: messageId,
        });
        senderMeta = {
          v: 2,
          from: as,
          to: domain,
          msg_id: signed.msg_id,
          timestamp: signed.timestamp,
          expires_at: signed.expires_at,
          signature: signed.signature,
        };
        messageId = signed.msg_id;
      } catch (err) {
        return {
          content: [
            {
              type: "text" as const,
              text:
                `Could not sign as ${as}: no usable local Ed25519 signing ` +
                `key is configured.`,
            },
          ],
          isError: true,
        };
      }

      // Step 3: Send A2A JSON-RPC message
      const a2aMessage: A2AMessageOut = {
        messageId,
        role: "user",
        parts: [{ kind: "text", text: message }],
      };
      if (senderMeta) {
        a2aMessage.metadata = { zipviz: senderMeta };
      }
      const a2aPayload = {
        jsonrpc: "2.0",
        id: 1,
        method: "message/send",
        params: {
          message: a2aMessage,
        },
      };
      // The text limit alone does not bound the request: escaping, the envelope
      // and the signature add to it. Refuse here rather than send a request the
      // receiver will reject.
      const requestBody = JSON.stringify(a2aPayload);
      const requestBytes = Buffer.byteLength(requestBody, "utf8");
      if (requestBytes > MAX_SEND_REQUEST_BYTES) {
        return {
          content: [{ type: "text" as const, text: sendRequestTooLarge(requestBytes) }],
          isError: true,
        };
      }

      const tunnelBase = card.url.startsWith("https://")
        ? card.url
        : `https://${card.url}`;

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), A2A_TIMEOUT_MS);

      let response: A2AResponse;
      try {
        // The egress helper owns validation and the fetch as one boundary. It
        // manually follows a small redirect chain, revalidates the exact target
        // before every hop, and streams the final body into this byte ceiling.
        const {
          response: res,
          bodyText,
          bodyTruncated,
        } = await safeEgressFetch(
          `${tunnelBase}/a2a/invoke`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: requestBody,
            signal: controller.signal,
          },
          {
            bodyPolicy: {
              mode: "read",
              maxBytes: MAX_A2A_RESPONSE_BYTES,
            },
          }
        );

        if (!res.ok) {
          // The error-path body is recipient-controlled too. Cap it and
          // wrap it as untrusted, exactly like the success path — otherwise a
          // hostile recipient can return a non-2xx status whose body is a
          // prompt-injection payload (or an unbounded flood) that reaches the
          // calling model as an unframed tool result.
          const cappedBody = bodyTruncated
            ? bodyText + "…[truncated]"
            : bodyText;
          // With no body, report the status code alone: the reason phrase is
          // recipient-chosen text and would reach the model unframed.
          const detail = cappedBody ? "\n" + wrapUntrusted(domain, cappedBody) : "";
          return {
            content: [
              {
                type: "text" as const,
                text: `Agent ${domain} returned HTTP ${res.status}.${detail}`,
              },
            ],
            isError: true,
          };
        }

        // Parse only a response that fit inside the helper's streaming byte
        // ceiling. HTML/junk still fails JSON.parse below.
        if (bodyTruncated) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Agent ${domain} returned an oversized response (limit ${MAX_A2A_RESPONSE_BYTES} bytes).`,
              },
            ],
            isError: true,
          };
        }
        try {
          response = JSON.parse(bodyText) as A2AResponse;
        } catch {
          return {
            content: [
              {
                type: "text" as const,
                text: `Agent ${domain} returned a non-JSON response.`,
              },
            ],
            isError: true,
          };
        }
      } catch (err: unknown) {
        const msg =
          err instanceof EgressBlockedError
            ? `Cannot send to ${domain}: outbound destination blocked by egress policy.`
            : err instanceof Error && err.name === "AbortError"
            ? `Agent ${domain} is unreachable (timed out after ${A2A_TIMEOUT_MS / 1000}s)`
            : `Failed to reach agent ${domain}: ${err instanceof Error ? err.message : String(err)}`;
        return {
          content: [{ type: "text" as const, text: msg }],
          isError: true,
        };
      } finally {
        clearTimeout(timeout);
      }

      // Step 3: Strip JSON-RPC envelope, return clean response
      if (typeof response !== "object" || response === null || Array.isArray(response)) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Agent ${domain} returned a malformed JSON-RPC response.`,
            },
          ],
          isError: true,
        };
      }
      if ("error" in response && response.error !== undefined && response.error !== null) {
        const remoteError = projectA2AError(response.error);
        if (!remoteError) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Agent ${domain} returned a malformed JSON-RPC error.`,
              },
            ],
            isError: true,
          };
        }
        return {
          content: [
            {
              type: "text" as const,
              text:
                `Agent ${domain} returned JSON-RPC error ${remoteError.code}. ` +
                `The remote error message is untrusted:\n` +
                wrapUntrusted(domain, remoteError.message),
            },
          ],
          isError: true,
        };
      }

      // Handle both task-based (ADK Go) and message-based A2A response formats
      const responseParts =
        response.result?.artifacts?.flatMap((a) => a.parts) ??
        response.result?.message?.parts ??
        [];
      const responseText = responseParts
        .filter((p) => p.kind === "text" && p.text)
        .map((p) => p.text)
        .join("\n");

      // A receipt proves only that the recipient accepted this message; it
      // does not verify the reply text. Accept only a locally verified V2
      // receipt bound to this send. The response remains untrusted model text.
      const replyAttestation: ReplyAttestation = await attestReply({
        recipientDomain: domain,
        replyText: responseText,
        response,
        verifyFn: localV2ReceiptVerifyFn(
          card.public_key,
          response,
          { msg_id: messageId, to: as },
          VERIFY_TIMEOUT_MS
        ),
        // The receipt verifies fully offline after the required card lookup.
        behaviourFetchFn: null,
      });

      const result: {
        agent: string;
        messageId: string;
        response_is_untrusted: true;
        response: string;
        signed_as?: string;
        reply_attestation: ReplyAttestation;
      } = {
        agent: domain,
        messageId,
        response_is_untrusted: true,
        response: wrapUntrusted(domain, responseText || "(no text response)"),
        reply_attestation: replyAttestation,
      };
      if (senderMeta) {
        result.signed_as = senderMeta.from;
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    }
  );
}
