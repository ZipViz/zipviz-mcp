// The A2A reply shapes the verify path shares with the receipt path.
//
// This module exists so `src/core/receipts.ts` — which holds the locally
// verified receipt proof — does not have to import `reply-attestation.ts`, and
// `reply-attestation.ts` can import the proof READER from it without the two
// forming an import cycle. That layering is what lets the proof symbol stay
// private to the one module allowed to set it.

import type { A2AResponse, VerifyResponse, ZipvizReplyMetadata } from "./types.js";

// Body posted to /v1/verify — identical shape to zipviz_verify's request.
export interface VerifyRequest {
  from: string;
  message: string;
  timestamp: string;
  signature: string;
}

export type VerifyFn = (body: VerifyRequest) => Promise<VerifyResponse | null>;

// Pull the recipient's `metadata.zipviz` out of whichever A2A result shape the
// recipient used. We accept the message-based shape, the task-based (ADK Go)
// shape (status.message and per-artifact metadata), and a top-level
// result.metadata (BAND-compatible). First location that carries an object
// wins — recipients attach exactly one signed-reply block.
export function extractReplyMetadata(
  response: A2AResponse
): ZipvizReplyMetadata | null {
  const r = response.result;
  if (!r) return null;
  const candidates: Array<ZipvizReplyMetadata | undefined> = [
    r.message?.metadata?.zipviz,
    r.status?.message?.metadata?.zipviz,
    r.metadata?.zipviz,
    ...(r.artifacts?.map((a) => a.metadata?.zipviz) ?? []),
  ];
  for (const c of candidates) {
    if (c && typeof c === "object") return c;
  }
  return null;
}
