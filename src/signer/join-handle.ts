// A protected signer's join handle. The public stdio package has no protected
// signer (see backend.ts), so no handle is ever provisioned and reading one
// always fails; the join client then uses its local file key.

export type JoinHandle = {
  keyId: string;
  publicKey: string;
  signupId: string;
  identity: string;
  adopted: boolean;
};

export function readJoinHandle(): JoinHandle {
  throw new Error("Join signer is not provisioned");
}
