import bs58 from "bs58";
import nacl from "tweetnacl";
import { PublicKey } from "@solana/web3.js";
import { err } from "./errors.js";

export function canonicalMessage(params: {
  domain: string;
  pubkey: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  statement?: string;
}): string {
  const statement = params.statement?.trim() || "Sign this message to authenticate with SolAuth.";
  // Domain binding + explicit times to reduce reuse ambiguity.
  // Message format is intentionally simple, line-oriented, and stable.
  return [
    `${params.domain} wants you to sign in with your Solana account:`,
    `${params.pubkey}`,
    ``,
    statement,
    ``,
    `Nonce: ${params.nonce}`,
    `Issued At: ${params.issuedAt}`,
    `Expiration Time: ${params.expiresAt}`,
  ].join("\n");
}

export function verifyDetachedSignature(params: {
  pubkey: string;     // base58
  signature: string;  // base58
  message: string;
}): boolean {
  let pkBytes: Uint8Array;
  let sigBytes: Uint8Array;

  try {
    // Ensures valid Solana public key (ed25519) and base58 encoding
    const pk = new PublicKey(params.pubkey);
    pkBytes = pk.toBytes();
  } catch {
    throw err.invalidInput("Invalid pubkey");
  }

  try {
    sigBytes = bs58.decode(params.signature);
  } catch {
    throw err.invalidInput("Invalid signature encoding (expected base58)");
  }

  const msgBytes = new TextEncoder().encode(params.message);
  const ok = nacl.sign.detached.verify(msgBytes, sigBytes, pkBytes);
  return ok;
}
