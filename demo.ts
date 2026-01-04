import { Keypair } from "@solana/web3.js";
import bs58 from "bs58";
import nacl from "tweetnacl";

const BASE = "http://localhost:8787";

async function main() {
  const kp = Keypair.generate();
  const pubkey = kp.publicKey.toBase58();

  // 1) challenge
  const ch = await fetch(`${BASE}/auth/challenge?pubkey=${pubkey}&domain=localhost`).then(r => r.json());
  if (!ch.ok) throw new Error(JSON.stringify(ch));
  const message: string = ch.challenge.message;

  // 2) sign
  const msgBytes = new TextEncoder().encode(message);
  const sigBytes = nacl.sign.detached(msgBytes, kp.secretKey);
  const signature = bs58.encode(sigBytes);

  // 3) verify
  const vr = await fetch(`${BASE}/auth/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      pubkey,
      signature,
      nonce: ch.challenge.nonce,
      domain: ch.challenge.domain,
    }),
  }).then(r => r.json());
  if (!vr.ok) throw new Error(JSON.stringify(vr));

  console.log("SESSION:", vr.session);

  // 4) session endpoint
  const ss = await fetch(`${BASE}/auth/session`, {
    headers: { authorization: `Bearer ${vr.session.token}` },
  }).then(r => r.json());
  console.log("SESSION CHECK:", ss);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
