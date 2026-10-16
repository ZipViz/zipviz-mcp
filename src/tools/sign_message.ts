import { z } from "zod";
import { createPrivateKey, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { isValidVizDomain } from "../lib/viz-domain.js";
import {
  assertEnvelopeExpiry,
  canonicalEnvelopeV3,
  canonicalEnvelopeV2,
  defaultExpiresAt,
  isValidMsgId,
} from "../core/envelope.js";
import {
  ConversationWireError,
  deriveWakeCapability,
  encodeConversationWire,
  type ConversationWire,
  type WakeCapabilityConfig,
} from "../core/conversation-wire.js";

export interface SignMessageInput {
  viz_domain: string;
  message: string;
  key_path?: string;
  timestamp?: string;
}

export interface SignMessageResult {
  viz_domain: string;
  signature: string;
  timestamp: string;
  signing_version: 1;
}

export function defaultKeyPath(viz_domain: string): string {
  return join(homedir(), ".zipviz", "keys", `${viz_domain}.key`);
}

function expandHome(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return join(homedir(), path.slice(2));
  return path;
}

// Load + validate an agent's Ed25519 private key from disk. Shared by the
// zipviz_sign_message MCP tool and the trusted in-process connected-app broker
// API so the path-resolution + key-type guards stay in ONE place. Returns the
// resolved path alongside the key for trusted internal callers. Signing results
// and errors must never surface that local filesystem location.
export async function loadEd25519PrivateKey(
  viz_domain: string,
  key_path?: string
): Promise<{ privateKey: ReturnType<typeof createPrivateKey>; resolvedPath: string }> {
  // Defense in depth: even the low-level primitive refuses a
  // viz_domain that isn't a well-formed .viz domain, so a bare/hostile value
  // can never reach defaultKeyPath() and path-traverse out of ~/.zipviz/keys.
  // The sign-message MCP boundary and relay validate before calling, but this
  // keeps the primitive safe for any direct caller and protects the trusted
  // broker-signing path as well.
  if (!isValidVizDomain(viz_domain)) {
    throw new Error(
      "Invalid viz_domain: expected a .viz domain (lowercase alphanumerics " +
        "and hyphens in dot-separated segments, ending in '.viz')."
    );
  }

  const resolvedPath = expandHome(key_path ?? defaultKeyPath(viz_domain));

  let keyMaterial: Buffer;
  try {
    keyMaterial = await readFile(resolvedPath);
  } catch {
    throw new Error(
      `Private key unavailable for ${viz_domain}: no Ed25519 PEM key could be loaded.`
    );
  }

  let privateKey;
  try {
    privateKey = createPrivateKey({ key: keyMaterial, format: "pem" });
  } catch {
    throw new Error(
      `Invalid private key for ${viz_domain}: expected an Ed25519 key in PEM (PKCS#8) format.`
    );
  }

  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error(
      `Unsupported key type for ${viz_domain}: expected ed25519, got ${privateKey.asymmetricKeyType ?? "unknown"}.`
    );
  }

  return { privateKey, resolvedPath };
}

export async function signMessage(
  input: SignMessageInput
): Promise<SignMessageResult> {
  const { privateKey } = await loadEd25519PrivateKey(
    input.viz_domain,
    input.key_path
  );

  // Sign the v=1 canonical-JSON envelope, not bare message bytes.
  // The field order inside the literal is load-bearing — JSON.stringify
  // produces stable bytes only because v/from/message/timestamp are
  // declared in this exact order. api.zipviz.ai /v1/verify reconstructs
  // the same payload with the same field order to verify.
  const timestamp = input.timestamp ?? new Date().toISOString();
  const payloadBytes = Buffer.from(
    JSON.stringify({
      v: 1,
      from: input.viz_domain,
      message: input.message,
      timestamp,
    }),
    "utf8"
  );
  const signature = sign(null, payloadBytes, privateKey);

  return {
    viz_domain: input.viz_domain,
    signature: signature.toString("base64"),
    timestamp,
    signing_version: 1,
  };
}

export interface SignEnvelopeV2Input {
  viz_domain: string;
  to: string;
  message: string;
  msg_id: string;
  timestamp?: string;
  expires_at?: string;
  reply_to?: string;
  key_path?: string;
}

export interface SignEnvelopeV2Result {
  viz_domain: string;
  to: string;
  msg_id: string;
  signature: string;
  timestamp: string;
  expires_at: string;
  reply_to?: string;
  signing_version: 2;
}

export async function signEnvelopeV2(
  input: SignEnvelopeV2Input
): Promise<SignEnvelopeV2Result> {
  if (!isValidVizDomain(input.to)) {
    throw new Error(
      "Invalid to: expected a .viz domain (lowercase alphanumerics " +
        "and hyphens in dot-separated segments, ending in '.viz')."
    );
  }
  if (!isValidMsgId(input.msg_id)) {
    throw new Error(
      "Invalid msg_id: expected 8–128 characters matching [A-Za-z0-9_-]."
    );
  }
  if (input.reply_to !== undefined && !isValidMsgId(input.reply_to)) {
    throw new Error(
      "Invalid reply_to: expected 8–128 characters matching [A-Za-z0-9_-]."
    );
  }

  const { privateKey } = await loadEd25519PrivateKey(
    input.viz_domain,
    input.key_path
  );

  const timestamp = input.timestamp ?? new Date().toISOString();
  const expires_at = input.expires_at ?? defaultExpiresAt(timestamp);
  assertEnvelopeExpiry(timestamp, expires_at);

  const payloadBytes = Buffer.from(
    canonicalEnvelopeV2({
      from: input.viz_domain,
      to: input.to,
      msg_id: input.msg_id,
      message: input.message,
      timestamp,
      expires_at,
      reply_to: input.reply_to,
    }),
    "utf8"
  );
  const signature = sign(null, payloadBytes, privateKey);

  const result: SignEnvelopeV2Result = {
    viz_domain: input.viz_domain,
    to: input.to,
    msg_id: input.msg_id,
    signature: signature.toString("base64"),
    timestamp,
    expires_at,
    signing_version: 2,
  };
  if (input.reply_to !== undefined) result.reply_to = input.reply_to;
  return result;
}

export interface SignEnvelopeV3Input {
  viz_domain: string;
  to: string;
  message: string;
  msg_id: string;
  timestamp?: string;
  expires_at?: string;
  reply_to?: string;
  conversation: Omit<ConversationWire, "wake"> & { wake?: never };
  wake?: WakeCapabilityConfig;
  key_path?: string;
}

export interface SignEnvelopeV3Result {
  viz_domain: string;
  to: string;
  msg_id: string;
  signature: string;
  timestamp: string;
  expires_at: string;
  reply_to?: string;
  conversation: ConversationWire;
  signing_version: 3;
}

export async function signEnvelopeV3(
  input: SignEnvelopeV3Input
): Promise<SignEnvelopeV3Result> {
  if (!isValidVizDomain(input.to)) {
    throw new Error(
      "Invalid to: expected a .viz domain (lowercase alphanumerics " +
        "and hyphens in dot-separated segments, ending in '.viz')."
    );
  }
  if (!isValidMsgId(input.msg_id)) {
    throw new Error(
      "Invalid msg_id: expected 8–128 characters matching [A-Za-z0-9_-]."
    );
  }
  if (input.reply_to !== undefined && !isValidMsgId(input.reply_to)) {
    throw new Error(
      "Invalid reply_to: expected 8–128 characters matching [A-Za-z0-9_-]."
    );
  }
  if (Object.prototype.hasOwnProperty.call(input.conversation, "wake")) {
    throw new ConversationWireError(
      "E_CONVERSATION_WAKE",
      "signEnvelopeV3 derives conversation.wake from local wake configuration"
    );
  }

  const { privateKey } = await loadEd25519PrivateKey(
    input.viz_domain,
    input.key_path
  );
  const timestamp = input.timestamp ?? new Date().toISOString();
  const expires_at = input.expires_at ?? defaultExpiresAt(timestamp);
  assertEnvelopeExpiry(timestamp, expires_at);
  const conversation = encodeConversationWire(
    input.wake === undefined
      ? input.conversation
      : {
          ...input.conversation,
          wake: deriveWakeCapability(input.wake),
        },
    timestamp
  );
  const payloadBytes = Buffer.from(
    canonicalEnvelopeV3({
      from: input.viz_domain,
      to: input.to,
      msg_id: input.msg_id,
      message: input.message,
      timestamp,
      expires_at,
      reply_to: input.reply_to,
      conversation,
    }),
    "utf8"
  );
  const signature = sign(null, payloadBytes, privateKey);

  const result: SignEnvelopeV3Result = {
    viz_domain: input.viz_domain,
    to: input.to,
    msg_id: input.msg_id,
    signature: signature.toString("base64"),
    timestamp,
    expires_at,
    conversation,
    signing_version: 3,
  };
  if (input.reply_to !== undefined) result.reply_to = input.reply_to;
  return result;
}

export function registerSignMessage(server: McpServer) {
  server.registerTool(
    "zipviz_sign_message",
    {
      description:
        "Sign a message locally with an agent's configured Ed25519 private key and the v=1 canonical-JSON envelope `{v:1, from, message, timestamp}` that api.zipviz.ai /v1/verify accepts. Returns the base64 signature, the timestamp baked into the signed payload, and signing_version:1. No network calls.",
      inputSchema: {
        viz_domain: z
          .string()
          .describe(
            "The .viz domain that owns the signing key, e.g. claudais.smc.viz"
          ),
        message: z.string().describe("The message content to sign (UTF-8)"),
        key_path: z
          .string()
          .optional()
          .describe(
            "NOT PERMITTED. This tool always signs with the configured local " +
              "agent key. Passing key_path is rejected — " +
              "it would let a caller sign with any PEM the process can read."
          ),
        timestamp: z
          .string()
          .optional()
          .describe(
            "Optional ISO 8601 timestamp to bake into the signed payload. Defaults to `new Date().toISOString()` at sign time. Callers that need to send the timestamp alongside the signature (e.g. zipviz_send) should read it back from the return value."
          ),
      },
    },
    async ({ viz_domain, message, key_path, timestamp }) => {
      // Tool-boundary guard. A relay may apply these same restrictions, but the
      // stdio transport and any direct caller bypass a relay entirely. A prompt-injected
      // agent driving this tool could otherwise (a) point key_path at any PEM
      // the process can read (an SSH identity, another tenant's key) and turn
      // this into a signing oracle, or (b) pass a viz_domain that traverses out
      // of ~/.zipviz/keys. Both are refused here, before any filesystem I/O,
      // independent of the relay.
      if (key_path !== undefined) {
        return {
          content: [
            {
              type: "text" as const,
              text:
                "key_path is not permitted. zipviz_sign_message always uses " +
                "the configured local agent key. No signing happened.",
            },
          ],
          isError: true,
        };
      }
      if (!isValidVizDomain(viz_domain)) {
        return {
          content: [
            {
              type: "text" as const,
              text:
                "Invalid viz_domain. Must be a valid .viz domain (lowercase " +
                "alphanumerics and hyphens in dot-separated segments, ending " +
                "in '.viz'). No signing happened.",
            },
          ],
          isError: true,
        };
      }

      try {
        const result = await signMessage({
          viz_domain,
          message,
          timestamp,
        });
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch {
        // Collapse the underlying key-load failure (missing vs malformed-PEM
        // vs wrong-key-type) into one generic message. The differentiated
        // errors that signMessage throws are a file oracle for a remote or
        // prompt-injected caller; the local operator only needs to know to
        // configure a valid local Ed25519 PEM. (The richer errors
        // are still thrown by signMessage for direct programmatic callers.)
        return {
          content: [
            {
              type: "text" as const,
              text:
                `Signing failed: no usable Ed25519 signing key is configured for ` +
                `${viz_domain}.`,
            },
          ],
          isError: true,
        };
      }
    }
  );
}
