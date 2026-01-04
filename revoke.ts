import { Router } from "express";
import { requireAuth } from "../middleware/requireAuth.js";
import { sessionStore } from "../state.js";

export const revokeRouter = Router();

revokeRouter.post("/revoke", requireAuth, (req, res) => {
  const session = (req as any).solauth.session;
  sessionStore.delete(session.token);
  res.json({ ok: true, revoked: true });
});
