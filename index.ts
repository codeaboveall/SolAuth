import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";

import { challengeRouter } from "./routes/challenge.js";
import { verifyRouter } from "./routes/verify.js";
import { sessionRouter } from "./routes/session.js";
import { revokeRouter } from "./routes/revoke.js";

const app = express();

app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "solauth", ts: new Date().toISOString() });
});

app.use("/auth", challengeRouter);
app.use("/auth", verifyRouter);
app.use("/auth", sessionRouter);
app.use("/auth", revokeRouter);

// Error handler
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const status = typeof err?.status === "number" ? err.status : 500;
  const code = err?.code || "INTERNAL_ERROR";
  const message = err?.message || "Internal error";
  res.status(status).json({ ok: false, code, message });
});

const port = Number(process.env.PORT || 8787);
app.listen(port, () => {
  console.log(`[solauth] listening on http://localhost:${port}`);
});
