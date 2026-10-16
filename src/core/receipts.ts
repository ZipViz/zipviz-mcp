import { randomBytes, sign, verify } from "node:crypto";
import { loadEd25519PrivateKey } from "../tools/sign_message.js";
import { ed25519HexToPublicKey, isValidMsgId } from "./envelope.js";
import { isValidVizDomain } from "../lib/viz-domain.js";
import type { A2AResponse, ProvenReceipt, VerifyResponse } from "../lib/types.js";
import { extractReplyMetadata, type VerifyFn } from "../lib/a2a-reply.js";
import { isCanonicalIsoTimestamp } from "../lib/iso-timestamp.js";

/**
 * The proof that a receipt was verified HERE, by the code below, against a
 * signature and a binding to the send it belongs to.
 *
 * Private to this module, and that privacy is the whole mechanism. A symbol key
 * cannot be produced by `JSON.parse`, so no remote body can forge one — that
 * part was true. But the symbol was exported from `lib/types.ts`, so
 * any in-process caller could import it and attach an arbitrary receipt, and
 * the boundary tests did exactly that to build their positive case. "Only the
 * local verifier can produce it" was a claim the construction did not support.
 *
 * Now there is no exported way to write it. `provenReceipt` reads it; the only
 * code that sets it is `localV2ReceiptVerifyFn` below, after a signature check
 * and an `msg_id`/`to` binding.
 */
const RECEIPT_PROOF: unique symbol = Symbol("zipviz.receipt.locally-verified");

/** Read the proof, if this verdict carries one. Shape-checked, not assumed. */
export function provenReceipt(
  vr: VerifyResponse | null | undefined
): ProvenReceipt | null {
  if (!vr || typeof vr !== "object") return null;
  const carried = (vr as unknown as Record<symbol, unknown>)[RECEIPT_PROOF];
  if (!carried || typeof carried !== "object") return null;
  const r = carried as Record<string, unknown>;
  if (r.status !== "ACCEPTED") return null;
  if (!isValidMsgId(r.msg_id)) return null;
  if (!isCanonicalIsoTimestamp(r.received_at)) return null;
  return { status: "ACCEPTED", msg_id: r.msg_id, received_at: r.received_at };
}

/** Seal a verdict with the proof. Module-private on purpose — see above. */
function sealProven(vr: VerifyResponse, receipt: ProvenReceipt): VerifyResponse {
  return Object.assign(vr, { [RECEIPT_PROOF]: receipt });
}

export type OwnerRelationship = "SAME_OWNER" | "EXTERNAL";

export type ReceiptFields = {
  from: string;
  to: string;
  msg_id: string;
  status: "ACCEPTED";
  received_at: string;
  nonce: string;
  timestamp: string;
  owner_relationship: OwnerRelationship;
};

export type SignedReceipt = ReceiptFields & {
  v: 2;
  kind: "receipt";
  signature: string;
};

export type ReceiptConversation = { id: string; turn: number };
export type SignedReceiptV3 = ReceiptFields & {
  v: 3;
  kind: "receipt";
  conversation: ReceiptConversation;
  signature: string;
};

export function canonicalReceipt(fields: ReceiptFields): string {
  return JSON.stringify({
    v: 2,
    kind: "receipt",
    from: fields.from,
    to: fields.to,
    msg_id: fields.msg_id,
    status: fields.status,
    received_at: fields.received_at,
    nonce: fields.nonce,
    timestamp: fields.timestamp,
    owner_relationship: fields.owner_relationship,
  });
}

export function canonicalReceiptV3(
  fields: ReceiptFields & { conversation: ReceiptConversation }
): string {
  return JSON.stringify({
    v: 3,
    kind: "receipt",
    from: fields.from,
    to: fields.to,
    msg_id: fields.msg_id,
    status: fields.status,
    received_at: fields.received_at,
    nonce: fields.nonce,
    timestamp: fields.timestamp,
    owner_relationship: fields.owner_relationship,
    conversation: fields.conversation,
  });
}

export async function signReceiptV3(params: {
  recipient: string;
  sender: string;
  msg_id: string;
  received_at: string;
  owner_relationship: OwnerRelationship;
  conversation: ReceiptConversation;
  nonce?: string;
  timestamp?: string;
}): Promise<SignedReceiptV3> {
  if (!isValidVizDomain(params.recipient) || !isValidVizDomain(params.sender)) {
    throw new Error("receipt from/to must be valid .viz domains");
  }
  if (!isValidMsgId(params.msg_id)) throw new Error("receipt msg_id shape invalid");
  if (!isValidMsgId(params.conversation.id) || !Number.isSafeInteger(params.conversation.turn) || params.conversation.turn < 1) {
    throw new Error("receipt conversation binding invalid");
  }
  const nonce = params.nonce ?? mintReceiptNonce();
  if (!/^[0-9a-f]{16}$/.test(nonce)) throw new Error("receipt nonce must be 16 hex chars");
  const timestamp = params.timestamp ?? new Date().toISOString();
  const fields = {
    from: params.recipient, to: params.sender, msg_id: params.msg_id,
    status: "ACCEPTED" as const, received_at: params.received_at, nonce, timestamp,
    owner_relationship: params.owner_relationship, conversation: params.conversation,
  };
  const { privateKey } = await loadEd25519PrivateKey(params.recipient);
  const signature = sign(null, Buffer.from(canonicalReceiptV3(fields), "utf8"), privateKey);
  return { v: 3, kind: "receipt", ...fields, signature: signature.toString("base64") };
}

export function verifyBoundReceipt(
  params: SignedReceiptV3 & { pubkeyHex: string },
  expected: { msg_id: string; from: string; to: string; conversation: ReceiptConversation }
): { ok: true } | { ok: false; code: "E_RECEIPT_MISMATCH" | "E_SIG_MISMATCH" } {
  if (params.msg_id !== expected.msg_id || params.from !== expected.from || params.to !== expected.to ||
      params.conversation.id !== expected.conversation.id ||
      params.conversation.turn !== expected.conversation.turn ||
      !isCanonicalIsoTimestamp(params.received_at) ||
      !isCanonicalIsoTimestamp(params.timestamp)) {
    return { ok: false, code: "E_RECEIPT_MISMATCH" };
  }
  try {
    const pubkey = ed25519HexToPublicKey(params.pubkeyHex);
    const ok = verify(null, Buffer.from(canonicalReceiptV3(params), "utf8"), pubkey,
      Buffer.from(params.signature, "base64"));
    return ok ? { ok: true } : { ok: false, code: "E_SIG_MISMATCH" };
  } catch {
    return { ok: false, code: "E_SIG_MISMATCH" };
  }
}

export function mintReceiptNonce(): string {
  return randomBytes(8).toString("hex");
}

export async function signReceipt(params: {
  recipient: string;
  sender: string;
  msg_id: string;
  received_at: string;
  owner_relationship: OwnerRelationship;
  nonce?: string;
  timestamp?: string;
}): Promise<SignedReceipt> {
  if (!isValidVizDomain(params.recipient) || !isValidVizDomain(params.sender)) {
    throw new Error("receipt from/to must be valid .viz domains");
  }
  if (!isValidMsgId(params.msg_id)) {
    throw new Error("receipt msg_id shape invalid");
  }
  const nonce = params.nonce ?? mintReceiptNonce();
  if (!/^[0-9a-f]{16}$/.test(nonce)) {
    throw new Error("receipt nonce must be 16 hex chars");
  }
  const timestamp = params.timestamp ?? new Date().toISOString();
  const fields: ReceiptFields = {
    from: params.recipient,
    to: params.sender,
    msg_id: params.msg_id,
    status: "ACCEPTED",
    received_at: params.received_at,
    nonce,
    timestamp,
    owner_relationship: params.owner_relationship,
  };
  const { privateKey } = await loadEd25519PrivateKey(params.recipient);
  const signature = sign(null, Buffer.from(canonicalReceipt(fields), "utf8"), privateKey);
  return { v: 2, kind: "receipt", ...fields, signature: signature.toString("base64") };
}

export function verifyReceipt(params: SignedReceipt & { pubkeyHex: string }): boolean {
  try {
    const pubkey = ed25519HexToPublicKey(params.pubkeyHex);
    const sig = Buffer.from(params.signature, "base64");
    const canonical = Buffer.from(
      canonicalReceipt({
        from: params.from,
        to: params.to,
        msg_id: params.msg_id,
        status: params.status,
        received_at: params.received_at,
        nonce: params.nonce,
        timestamp: params.timestamp,
        owner_relationship: params.owner_relationship,
      }),
      "utf8"
    );
    return verify(null, canonical, pubkey, sig);
  } catch {
    return false;
  }
}

function isOwnerRel(v: unknown): v is OwnerRelationship {
  return v === "SAME_OWNER" || v === "EXTERNAL";
}

export function localV2ReceiptVerifyFn(
  pubkeyHex: string,
  response: A2AResponse,
  // A valid signature alone is not enough: an old receipt the recipient
  // signed for a DIFFERENT message (or a different sender) verifies against
  // the same card key. The receipt must be bound to THIS send — its msg_id
  // must be the one we just minted and its `to` must be the identity we sent
  // as — or a replayed receipt becomes a false "ACCEPTED" attestation.
  expect: { msg_id: string; to: string },
  timeoutMs = 10_000
): VerifyFn {
  return async (body) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), timeoutMs);
    });
    const run = async () => {
      const meta = extractReplyMetadata(response);
      if (
        !meta ||
        meta.kind !== "receipt" ||
        meta.status !== "ACCEPTED" ||
        typeof meta.from !== "string" ||
        meta.from !== body.from ||
        typeof meta.to !== "string" ||
        typeof meta.msg_id !== "string" ||
        typeof meta.nonce !== "string" ||
        typeof meta.timestamp !== "string" ||
        !isOwnerRel(meta.owner_relationship) ||
        typeof meta.signature !== "string"
      ) {
        return { verified: false as const, code: "E_SIG_MISMATCH" };
      }
      if (!isCanonicalIsoTimestamp(meta.received_at)) {
        return { verified: false as const, code: "E_RECEIPT_MISMATCH" };
      }
      if (meta.msg_id !== expect.msg_id || meta.to !== expect.to) {
        return { verified: false as const, code: "E_RECEIPT_MISMATCH" };
      }
      const ok = verifyReceipt({
        v: 2,
        kind: "receipt",
        from: meta.from,
        to: meta.to,
        msg_id: meta.msg_id,
        status: "ACCEPTED",
        received_at: meta.received_at,
        nonce: meta.nonce,
        timestamp: meta.timestamp,
        owner_relationship: meta.owner_relationship,
        signature: meta.signature,
        pubkeyHex,
      });
      if (!ok) return { verified: false as const, code: "E_SIG_MISMATCH" };
      // Emit the proof, and the receipt it proves. `attestReply` attaches this
      // object verbatim rather than re-deriving one from the metadata block —
      // the values below are the ones whose signature was just verified and
      // whose msg_id was just bound to this send. `identity` is echoed so the
      // local path satisfies the same binding check as the remote one, rather
      // than being exempt from it.
      return sealProven(
        {
          verified: true as const,
          identity: meta.from,
          signing_version: 2,
        },
        {
          status: "ACCEPTED" as const,
          msg_id: meta.msg_id,
          received_at: meta.received_at,
        }
      );
    };
    try {
      return await Promise.race([run(), timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
}
