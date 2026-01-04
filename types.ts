export type IsoDateString = string;

export type Challenge = {
  domain: string;
  pubkey: string; // base58
  nonce: string;
  issuedAt: IsoDateString;
  expiresAt: IsoDateString;
  statement: string;
  message: string; // canonical signing message
};

export type VerifyRequest = {
  pubkey: string; // base58
  signature: string; // base58 (detached signature)
  nonce: string;
  domain: string;
};

export type Session = {
  token: string;         // opaque bearer token
  pubkey: string;        // base58
  createdAt: IsoDateString;
  expiresAt: IsoDateString;
};

export type Store<T> = {
  get(key: string): T | undefined;
  set(key: string, value: T): void;
  delete(key: string): void;
};
