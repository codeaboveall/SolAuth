import { v4 as uuidv4 } from "uuid";
import { err } from "./errors.js";
import type { Session, Store } from "./types.js";

export type SessionRecord = Session & { token: string };

export function createSession(params: {
  pubkey: string;
  ttlSeconds: number;
}): Session {
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + params.ttlSeconds * 1000).toISOString();
  return {
    token: uuidv4().replaceAll("-", ""),
    pubkey: params.pubkey,
    createdAt,
    expiresAt,
  };
}

export function assertSessionValid(session: Session | undefined): Session {
  if (!session) throw err.unauthorized();
  if (Date.now() > Date.parse(session.expiresAt)) throw err.sessionExpired();
  return session;
}

export function revokeSession(store: Store<Session>, token: string) {
  store.delete(token);
}
