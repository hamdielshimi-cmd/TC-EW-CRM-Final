// api/whatsapp-webhook.js
import crypto from "crypto";

export const config = { api: { bodyParser: false } };

const readRaw = (req) =>
  new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });

export default async function handler(req, res) {
  if (req.method === "GET") {
    const { "hub.mode": mode, "hub.verify_token": token, "hub.challenge": challenge } = req.query;
    if (mode === "subscribe" && token === process.env.WHATSAPP_VERIFY_TOKEN) {
      return res.status(200).send(challenge);
    }
    return res.status(403).send("Forbidden");
  }

  if (req.method === "POST") {
    const raw = await readRaw(req);
    const sig = req.headers["x-hub-signature-256"] ?? "";
    const expected = "sha256=" + crypto.createHmac("sha256", process.env.META_APP_SECRET ?? "").update(raw).digest("hex");
    if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
      return res.status(401).send("Bad signature");
    }

    const body = JSON.parse(raw);
    for (const entry of body.entry ?? []) {
      for (const change of entry.changes ?? []) {
        const v = change.value ?? {};
        for (const m of v.messages ?? []) {
          // m.from, m.type, m.text?.body, m.timestamp -> TODO: insert into Supabase
        }
        for (const s of v.statuses ?? []) {
          // s.id, s.status
        }
      }
    }
    return res.status(200).send("OK");
  }

  return res.status(405).send("Method Not Allowed");
}
