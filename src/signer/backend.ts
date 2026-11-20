import { sign, type KeyObject } from "node:crypto";

// Signing for the join tools in the public stdio package. The package uses a
// local Ed25519 file key only: there is no protected signer daemon here, so
// protectedSignerSelected() is always false and the protected-signer entry
// points the join client can reach in other builds refuse rather than sign.

export function protectedSignerSelected(): boolean {
  return false;
}

export function signFileKeySync(key: KeyObject, bytes: Buffer): Buffer {
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") throw new Error("Join signing needs an Ed25519 private key");
  return sign(null, bytes, key);
}

export function signCanonicalSync(_identity: string, _purpose: string, _canonical: string, _expectedKeyId?: string): Buffer {
  throw new Error("Protected signer unavailable");
}

export async function publicBinding(_identity: string, _purpose: string): Promise<{ keyId: string; publicKey: string }> {
  throw new Error("Protected signer unavailable");
}
