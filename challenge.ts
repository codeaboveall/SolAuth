import { Router } from "express";
import { z } from "zod";
import { generateNonce, makeExpiry } from "../../core/nonce.js";
import { canonicalMessage } from "../../core/verify.js";
import { nonceStore } from "../state.js";
import { err } from "../../core/errors.js";

export const challengeRouter = Router();

const Query = z.object({
  pubkey: z.string().min(32),
  domain: z.string().min(1).optional(),
  statement: z.string().min(1).optional(),
});

challengeRouter.get("/challenge", (req, res, next) => {
  try {
    const parsed = Query.safeParse(req.query);
    if (!parsed.success) throw err.invalidInput(parsed.error.message);

    const domain = parsed.data.domain || process.env.SOLAUTH_DOMAIN || "localhost";
    const pubkey = parsed.data.pubkey;
    const nonce = generateNonce(16);

    const ttlSeconds = Number(process.env.NONCE_TTL_SECONDS || 300);
    const issuedAt = new Date().toISOString();
    const expiresAtMs = makeExpiry(ttlSeconds * 1000);
    const expiresAt = new Date(expiresAtMs).toISOString();

    const message = canonicalMessage({
      domain,
      pubkey,
      nonce,
      issuedAt,
      expiresAt,
      statement: parsed.data.statement,
    });

    nonceStore.set(nonce, {
      nonce,
      pubkey,
      domain,
      issuedAtMs: Date.now(),
      expiresAtMs,
    });

    res.json({
      ok: true,
      challenge: {
        domain,
        pubkey,
        nonce,
        issuedAt,
        expiresAt,
        statement: parsed.data.statement || "Sign this message to authenticate with SolAuth.",
        message,
      },
    });
  } catch (e) {
    next(e);
  }
});
