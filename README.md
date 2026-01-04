<p align="center">
  <img src="./assets/solauth.png" width="220" />
</p>

# SolAuth

This repository contains a ZAuth-grade skeleton implementation of SolAuth (challenge → sign → verify → session) for Solana wallets.

Replace this README with your Claude-generated longform README. The code in this repo is intentionally written to match what that README describes:
- challenge issuance with TTL and domain binding
- Ed25519 signature verification against Solana public keys
- session issuance and revocation
- minimal, framework-agnostic core primitives

## Quickstart

```bash
cp .env.example .env
npm i
npm run dev
```

Server will start on `http://localhost:8787`.

## Endpoints

- `GET /auth/challenge?pubkey=<base58>&domain=<string>`
- `POST /auth/verify`
- `GET /auth/session` (requires `Authorization: Bearer <token>`)
- `POST /auth/revoke` (requires `Authorization: Bearer <token>`)

## Repo Layout

- `core/` — domain primitives (nonce, verify, sessions)
- `server/` — express API surface
- `docs/` — architecture + threat model
- `examples/` — minimal client scripts

License: MIT.
