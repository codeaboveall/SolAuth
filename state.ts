import { InMemoryStore } from "../core/store.js";
import type { NonceRecord } from "../core/nonce.js";
import type { Session } from "../core/types.js";

export const nonceStore = new InMemoryStore<NonceRecord>();
export const sessionStore = new InMemoryStore<Session>();
