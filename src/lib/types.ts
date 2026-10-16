export interface AgentCard {
  name: string;
  description: string;
  url: string;
  capabilities: string[];
  authentication: {
    schemes: string[];
  };
  public_key: string;
  protocols: string[];
  created: string;
  blue_tick?: boolean;
}

// The api.zipviz.ai POST /v1/verify response contract. A genuine verdict ALWAYS carries a boolean `verified`;
// failures additionally carry a stable machine `code` (E_STALE,
// E_SIG_MISMATCH, E_AGENT_NOT_FOUND, E_TIMESTAMP_FORMAT, E_SIG_FORMAT, …) —
// note the endpoint returns these as non-2xx JSON (400/404/500) for expected
// verification failures, plus a 200 E_SIG_MISMATCH. On success it reports the
// `signing_version` that ACTUALLY verified (1 = canonical v=1, 0 = legacy
// concat) — this is authoritative and must never be sourced from untrusted
// reply metadata.
/**
 * Proof that a v2 ACCEPTED receipt was verified LOCALLY and bound to this send.
 *
 * A symbol key, deliberately. `JSON.parse` cannot produce one, so a remote
 * `/v1/verify` body is structurally incapable of forging this marker — the
 * guarantee holds by construction rather than by a caller remembering to check
 * a flag. Only `localV2ReceiptVerifyFn` attaches it, and only after it has
 * checked the signature and matched `msg_id`/`to` against the send in hand.
 *
 * This replaces gating receipt attachment on `signing_version === 2`. A scalar
 * cannot stand in for a proof performed in another module: a remote verdict
 * claiming version 2 used to make `attestReply` build a receipt out of
 * unverified metadata, with an attacker-chosen `msg_id`.
 */

export interface ProvenReceipt {
  status: "ACCEPTED";
  msg_id: string;
  received_at: string;
}

export interface VerifyResponse {
  verified: boolean;
  // The locally verified receipt proof is NOT declared here. It travels under a
  // symbol key private to `src/core/receipts.ts`, readable only through
  // `provenReceipt()` — declaring it here would require exporting the symbol,
  // which is the thing being fixed.
  // Authoritative signing version the verifier confirmed (0 or 1). Present on
  // the verified path only.
  signing_version?: number | null;
  identity?: string;
  freshness_checked?: boolean;
  reputation?: unknown;
  blue_tick?: boolean | null;
  blue_tick_status?: "verified" | "pending" | "unavailable";
  domain?: string;
  signer?: string;
  // Stable machine-readable failure code on a verification failure.
  code?: string;
  error?: string;
  reason?: string;
  entropy_score?: number;
}

type A2APart = { kind: string; text?: string };

// The recipient's signed-reply metadata, mirroring the sender-side
// ZipvizSenderMetadata the Worker attaches to outbound envelopes. All fields
// are `unknown` because this arrives from a remote, possibly-adversarial
// recipient — reply-attestation.ts validates the shape before trusting any of
// it. `v`/`signing_version` are optional; today the only canonical envelope is
// v=1 (the one api.zipviz.ai /v1/verify reconstructs).
export interface ZipvizReplyMetadata {
  from?: unknown;
  timestamp?: unknown;
  signature?: unknown;
  v?: unknown;
  signing_version?: unknown;
  kind?: unknown;
  to?: unknown;
  msg_id?: unknown;
  status?: unknown;
  received_at?: unknown;
  nonce?: unknown;
  owner_relationship?: unknown;
  conversation?: unknown;
}

type A2AMessageLike = {
  messageId?: string;
  role?: string;
  parts: A2APart[];
  metadata?: { zipviz?: ZipvizReplyMetadata };
};

export interface A2AResponse {
  jsonrpc: string;
  id: number;
  result?: {
    kind?: string;
    // Task-based format (ADK Go)
    artifacts?: Array<{
      artifactId: string;
      parts: A2APart[];
      metadata?: { zipviz?: ZipvizReplyMetadata };
    }>;
    status?: { state?: string; message?: A2AMessageLike };
    // Message-based format
    message?: A2AMessageLike;
    // BAND-compatible / top-level result metadata
    metadata?: { zipviz?: ZipvizReplyMetadata };
  };
  error?: {
    code: number;
    message: string;
  };
}
