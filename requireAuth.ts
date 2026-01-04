import type { Request, Response, NextFunction } from "express";
import { sessionStore } from "../state.js";
import { assertSessionValid } from "../../core/session.js";
import { err } from "../../core/errors.js";

export function requireAuth(req: Request, _res: Response, next: NextFunction) {
  const header = req.header("authorization");
  if (!header) return next(err.unauthorized("Missing Authorization header"));

  const [kind, token] = header.split(" ");
  if (kind?.toLowerCase() !== "bearer" || !token) {
    return next(err.unauthorized("Invalid Authorization header (expected Bearer token)"));
  }

  const session = sessionStore.get(token);
  const valid = assertSessionValid(session);

  // attach to req for downstream routes
  (req as any).solauth = { session: valid };
  return next();
}
