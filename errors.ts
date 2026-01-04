export class SolAuthError extends Error {
  code: string;
  status: number;

  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export const err = {
  invalidInput: (m = "Invalid input") => new SolAuthError("INVALID_INPUT", m, 400),
  invalidNonce: (m = "Invalid or expired nonce") => new SolAuthError("INVALID_NONCE", m, 401),
  invalidSignature: (m = "Invalid signature") => new SolAuthError("INVALID_SIGNATURE", m, 401),
  sessionExpired: (m = "Session expired") => new SolAuthError("SESSION_EXPIRED", m, 401),
  unauthorized: (m = "Unauthorized") => new SolAuthError("UNAUTHORIZED", m, 401),
};
