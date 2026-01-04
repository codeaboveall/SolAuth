import { randomBytes } from "node:crypto";
import { err } from "./errors.js";

export type NonceRecord = {
  nonce: string;
  pubkey: string;
  domain: string;
  issuedAtMs: number;
  expiresAtMs: number;
};

export function generateNonce(bytes = 16): string {
  // base64url-ish nonce without special chars
  return randomBytes(bytes).toString("base64url");
}

export function nowMs(): number {
  return Date.now();
}

export function makeExpiry(msFromNow: number): number {
  return nowMs() + msFromNow;
}

export function assertNotExpired(expiresAtMs: number) {
  if (nowMs() > expiresAtMs) throw err.invalidNonce();
}
