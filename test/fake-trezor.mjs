// Test-only software stand-in for a Trezor, for tests that can't use the
// emulator (CI). Speaks the protocol v1 messages the IdP uses, at message level:
// SignIdentity keys are derived from a fixed seed and the identity, and every
// signature is "confirmed" automatically. Not a security model of the device.

import { createECDH, createHmac, createPrivateKey, sign } from "node:crypto";
import { createServer } from "node:http";
import { MessageType, MessageName, encode, decode } from "../js/proto.js";

const b64u = (b) => Buffer.from(b).toString("base64url");

export class FakeTrezor {
  constructor(seed = "fake-trezor-test-seed") {
    this.seed = seed;
    this.pending = null; // SignIdentity waiting for ButtonAck
    this.signCount = 0;
  }

  keyFor(identity) {
    const label = `${identity.proto}://${identity.user}@${identity.host}${identity.port ? ":" + identity.port : ""}${identity.path || ""}#${identity.index ?? 0}`;
    const d = createHmac("sha256", this.seed).update(label).digest();
    const ecdh = createECDH("prime256v1");
    ecdh.setPrivateKey(d);
    const pub = ecdh.getPublicKey(null, "uncompressed");
    const key = createPrivateKey({
      format: "jwk",
      key: { kty: "EC", crv: "P-256", d: b64u(d), x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33)) },
    });
    return { key, compressed: new Uint8Array(ecdh.getPublicKey(null, "compressed")) };
  }

  /** Handle one request message; returns the response message. */
  handle(type, data) {
    const name = MessageName[type];
    const msg = decode(name, data);
    const reply = (n, o = {}) => ({ type: MessageType[n], data: encode(n, o) });
    switch (name) {
      case "Initialize":
        return reply("Features", { vendor: "trezor.io", major_version: 2, minor_version: 8, patch_version: 0, model: "T", initialized: true, unlocked: true, session_id: new Uint8Array(32).fill(7) });
      case "SignIdentity":
        this.pending = msg;
        return reply("ButtonRequest", { code: 8 });
      case "ButtonAck": {
        const req = this.pending;
        this.pending = null;
        if (!req) return reply("Failure", { code: 1, message: "Unexpected message" });
        const { key, compressed } = this.keyFor(req.identity);
        const sig = sign("sha256", req.challenge_hidden, { key, dsaEncoding: "ieee-p1363" });
        this.signCount++;
        return reply("SignedIdentity", { public_key: compressed, signature: new Uint8Array([0, ...sig]) });
      }
      case "Cancel":
        this.pending = null;
        return reply("Failure", { code: 4, message: "Cancelled" });
      default:
        return reply("Failure", { code: 1, message: `Unexpected message ${name}` });
    }
  }

  /** In-process message transport for TrezorClient. */
  transport() {
    let next;
    return {
      sendMessage: (type, data) => { next = this.handle(type, data); },
      receiveMessage: async () => next,
      close: async () => {},
    };
  }
}

/** Minimal Trezor Bridge HTTP API in front of a FakeTrezor. */
export function fakeBridge(device, { origin = "https://python.trezor.io" } = {}) {
  let session = null;
  const server = createServer(async (req, res) => {
    const send = (code, body) => { res.writeHead(code, { "content-type": "application/json" }); res.end(typeof body === "string" ? body : JSON.stringify(body)); };
    if (req.headers.origin !== origin) return send(403, { error: "Origin not allowed" });
    let body = "";
    for await (const c of req) body += c;
    const parts = req.url.split("/").filter(Boolean);
    if (req.method !== "POST") return send(405, { error: "POST only" });
    if (!parts.length) return send(200, { version: "2.0.33" });
    if (parts[0] === "enumerate") return send(200, [{ path: "1", session, product: 0x53c1, vendor: 0x1209, debug: false, debugSession: null }]);
    if (parts[0] === "acquire") { session = String(Number(session ?? 0) + 1); return send(200, { session }); }
    if (parts[0] === "release") { session = null; return send(200, {}); }
    if (parts[0] === "call") {
      if (parts[1] !== session) return send(400, { error: "wrong previous session" });
      const msg = Buffer.from(body, "hex");
      const r = device.handle(msg.readUInt16BE(0), new Uint8Array(msg.subarray(6, 6 + msg.readUInt32BE(2))));
      const out = Buffer.alloc(6 + r.data.length);
      out.writeUInt16BE(r.type, 0);
      out.writeUInt32BE(r.data.length, 2);
      Buffer.from(r.data).copy(out, 6);
      res.writeHead(200, { "content-type": "text/plain" });
      return res.end(out.toString("hex"));
    }
    send(404, { error: "not found" });
  });
  return server;
}
