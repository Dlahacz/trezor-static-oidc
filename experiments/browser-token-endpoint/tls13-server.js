// Minimal TLS 1.3 server on WebCrypto, for running an HTTPS endpoint inside a
// browser tab. Experimental: one cipher suite (TLS_AES_128_GCM_SHA256), X25519
// or P-256 key exchange (with HelloRetryRequest), ECDSA P-256 server key, no
// PSK/resumption, no client certificates, no 0-RTT.
//
//   const tls = new Tls13Server({ certChain, sign, send, onData, onClose, alpn });
//   tls.feed(bytes)      // bytes from the network
//   await tls.write(b)   // application data to the client
//   await tls.close()    // close_notify
//
// `sign(content)` must return a 64-byte r||s ECDSA P-256 signature over
// SHA-256(content); the Trezor's SignIdentity "ssh" mode does exactly that.

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

const CT = { CCS: 20, ALERT: 21, HANDSHAKE: 22, APP: 23 };
const HS = { CLIENT_HELLO: 1, SERVER_HELLO: 2, ENCRYPTED_EXTENSIONS: 8, CERTIFICATE: 11, CERTIFICATE_VERIFY: 15, FINISHED: 20, MESSAGE_HASH: 254 };
const EXT = { SERVER_NAME: 0, SUPPORTED_GROUPS: 10, SIG_ALGS: 13, ALPN: 16, SUPPORTED_VERSIONS: 43, KEY_SHARE: 51 };
const GROUP = { X25519: 0x001d, P256: 0x0017 };
const TLS_AES_128_GCM_SHA256 = 0x1301;
const ECDSA_P256_SHA256 = 0x0403;
// SHA-256("HelloRetryRequest"), RFC 8446 4.1.3
const HRR_RANDOM = Uint8Array.from("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c".match(/../g), (h) => parseInt(h, 16));

export class TlsAlert extends Error {
  constructor(code, msg) { super(msg); this.code = code; }
}
const ALERT = { UNEXPECTED_MESSAGE: 10, BAD_RECORD_MAC: 20, HANDSHAKE_FAILURE: 40, ILLEGAL_PARAMETER: 47, DECODE_ERROR: 50, DECRYPT_ERROR: 51, PROTOCOL_VERSION: 70, INTERNAL_ERROR: 80, MISSING_EXTENSION: 109, CLOSE_NOTIFY: 0 };

// ---------------------------------------------------------------- bytes
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const u8 = (n) => Uint8Array.of(n & 0xff);
const u16 = (n) => Uint8Array.of((n >> 8) & 0xff, n & 0xff);
const u24 = (n) => Uint8Array.of((n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
const vec8 = (b) => concat(u8(b.length), b);
const vec16 = (b) => concat(u16(b.length), b);
const vec24 = (b) => concat(u24(b.length), b);

class Reader {
  constructor(b) { this.b = b; this.i = 0; }
  left() { return this.b.length - this.i; }
  need(n) { if (this.left() < n) throw new TlsAlert(ALERT.DECODE_ERROR, "truncated message"); }
  u8() { this.need(1); return this.b[this.i++]; }
  u16() { this.need(2); const v = (this.b[this.i] << 8) | this.b[this.i + 1]; this.i += 2; return v; }
  u24() { this.need(3); const v = (this.b[this.i] << 16) | (this.b[this.i + 1] << 8) | this.b[this.i + 2]; this.i += 3; return v; }
  bytes(n) { this.need(n); const v = this.b.subarray(this.i, this.i + n); this.i += n; return v; }
  vec8() { return this.bytes(this.u8()); }
  vec16() { return this.bytes(this.u16()); }
}

// ---------------------------------------------------------------- crypto
const sha256 = async (b) => new Uint8Array(await subtle.digest("SHA-256", b));
async function hmac(key, data) {
  const k = await subtle.importKey("raw", key.length ? key : new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, data));
}
const hkdfExtract = (salt, ikm) => hmac(salt.length ? salt : new Uint8Array(32), ikm);
async function hkdfExpandLabel(secret, label, context, length) {
  const full = enc.encode("tls13 " + label);
  const info = concat(u16(length), vec8(full), vec8(context));
  let t = new Uint8Array(0), out = new Uint8Array(0);
  for (let i = 1; out.length < length; i++) {
    t = await hmac(secret, concat(t, info, u8(i)));
    out = concat(out, t);
  }
  return out.subarray(0, length);
}
const deriveSecret = (secret, label, transcriptHash) => hkdfExpandLabel(secret, label, transcriptHash, 32);

async function trafficKeys(secret) {
  const key = await hkdfExpandLabel(secret, "key", new Uint8Array(0), 16);
  const iv = await hkdfExpandLabel(secret, "iv", new Uint8Array(0), 12);
  return { key: await subtle.importKey("raw", key, "AES-GCM", false, ["encrypt", "decrypt"]), iv, seq: 0n, secret };
}
function nonceFor(k) {
  const n = new Uint8Array(k.iv);
  let s = k.seq;
  for (let i = 11; i >= 4; i--) { n[i] ^= Number(s & 0xffn); s >>= 8n; }
  k.seq += 1n;
  return n;
}

/** r||s (64 bytes) -> DER ECDSA-Sig-Value */
export function ecdsaRawToDer(raw) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.subarray(i);
    if (b[0] & 0x80) b = concat(Uint8Array.of(0), b);
    return concat(Uint8Array.of(0x02, b.length), b);
  };
  const body = concat(int(raw.subarray(0, 32)), int(raw.subarray(32)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

// ---------------------------------------------------------------- server
export class Tls13Server {
  constructor({ certChain, sign, send, onData, onClose, onEvent, alpn = ["http/1.1"] }) {
    Object.assign(this, { certChain, sign, send, onData, onClose, onEvent, alpn });
    this.inbuf = new Uint8Array(0);
    this.hsbuf = new Uint8Array(0);
    this.transcript = [];
    this.state = "WAIT_CH";
    this.read = null;   // traffic keys for decrypting client records
    this.write_ = null; // traffic keys for encrypting our records
    this.queue = Promise.resolve();
    this.closed = false;
    this.info = {};
  }

  event(name, data) { this.onEvent?.(name, data); }

  /** Feed raw bytes from the network; processing is serialized. */
  feed(bytes) {
    this.queue = this.queue.then(() => this.#process(bytes)).catch((e) => this.#fail(e));
    return this.queue;
  }

  async write(data) {
    if (this.state !== "CONNECTED") throw new Error("TLS not connected");
    for (let o = 0; o < data.length; o += 16384) await this.#sendRecord(CT.APP, data.subarray(o, o + 16384));
  }

  async close() {
    if (this.closed) return;
    try { await this.#sendRecord(CT.ALERT, Uint8Array.of(1, ALERT.CLOSE_NOTIFY)); } catch {}
    this.closed = true;
    this.onClose?.();
  }

  async #fail(e) {
    if (this.closed) return;
    const code = e instanceof TlsAlert ? e.code : ALERT.INTERNAL_ERROR;
    this.event("error", e.message);
    try { await this.#sendRecord(CT.ALERT, Uint8Array.of(2, code)); } catch {}
    this.closed = true;
    this.onClose?.(e);
  }

  async #process(bytes) {
    if (this.closed) return;
    this.inbuf = concat(this.inbuf, bytes);
    while (this.inbuf.length >= 5) {
      const type = this.inbuf[0];
      const len = (this.inbuf[3] << 8) | this.inbuf[4];
      if (len > 16384 + 256) throw new TlsAlert(ALERT.DECODE_ERROR, "record too long");
      if (this.inbuf.length < 5 + len) break;
      const header = this.inbuf.subarray(0, 5);
      const body = this.inbuf.subarray(5, 5 + len);
      this.inbuf = this.inbuf.subarray(5 + len);
      await this.#record(type, header, body);
      if (this.closed) return;
    }
  }

  async #record(type, header, body) {
    if (type === CT.CCS) return; // middlebox compatibility; ignored
    if (this.read && type === CT.APP) {
      const pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonceFor(this.read), additionalData: header }, this.read.key, body)
        .catch(() => { throw new TlsAlert(ALERT.BAD_RECORD_MAC, "record decryption failed"); }));
      let end = pt.length - 1;
      while (end >= 0 && pt[end] === 0) end--;
      if (end < 0) throw new TlsAlert(ALERT.UNEXPECTED_MESSAGE, "empty inner plaintext");
      type = pt[end];
      body = pt.subarray(0, end);
    } else if (this.read) {
      throw new TlsAlert(ALERT.UNEXPECTED_MESSAGE, "plaintext record after keys were set");
    }
    if (type === CT.ALERT) {
      if (body[1] === ALERT.CLOSE_NOTIFY) { this.event("close_notify"); await this.close(); return; }
      this.event("error", `client sent alert ${body[1]}`);
      this.closed = true;
      this.onClose?.(new Error(`client sent alert ${body[1]}`));
      return;
    }
    if (type === CT.HANDSHAKE) {
      this.hsbuf = concat(this.hsbuf, body);
      while (this.hsbuf.length >= 4) {
        const mlen = (this.hsbuf[1] << 16) | (this.hsbuf[2] << 8) | this.hsbuf[3];
        if (this.hsbuf.length < 4 + mlen) break;
        const msg = this.hsbuf.subarray(0, 4 + mlen);
        this.hsbuf = this.hsbuf.subarray(4 + mlen);
        await this.#handshake(msg[0], msg.subarray(4), msg);
      }
      return;
    }
    if (type === CT.APP) {
      if (this.state !== "CONNECTED") throw new TlsAlert(ALERT.UNEXPECTED_MESSAGE, "application data before handshake end");
      if (body.length) await this.onData?.(body);
      return;
    }
    throw new TlsAlert(ALERT.UNEXPECTED_MESSAGE, `unexpected record type ${type}`);
  }

  async #transcriptHash() { return sha256(concat(...this.transcript)); }

  async #sendRecord(type, data) {
    if (!this.write_) {
      return this.send(concat(u8(type), u16(0x0303), u16(data.length), data));
    }
    const inner = concat(data, u8(type));
    const header = concat(u8(CT.APP), u16(0x0303), u16(inner.length + 16));
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonceFor(this.write_), additionalData: header }, this.write_.key, inner));
    return this.send(concat(header, ct));
  }

  async #sendHandshake(type, body) {
    const msg = concat(u8(type), u24(body.length), body);
    this.transcript.push(msg);
    await this.#sendRecord(CT.HANDSHAKE, msg);
    return msg;
  }

  async #handshake(type, body, raw) {
    if (this.state === "WAIT_CH" || this.state === "WAIT_CH2") {
      if (type !== HS.CLIENT_HELLO) throw new TlsAlert(ALERT.UNEXPECTED_MESSAGE, "expected ClientHello");
      return this.#clientHello(body, raw);
    }
    if (this.state === "WAIT_FINISHED") {
      if (type !== HS.FINISHED) throw new TlsAlert(ALERT.UNEXPECTED_MESSAGE, "expected Finished");
      const fk = await hkdfExpandLabel(this.clientHsSecret, "finished", new Uint8Array(0), 32);
      const expected = await hmac(fk, await this.#transcriptHash());
      if (expected.length !== body.length || expected.some((b, i) => b !== body[i])) throw new TlsAlert(ALERT.DECRYPT_ERROR, "client Finished does not verify");
      this.transcript.push(raw);
      this.read = await trafficKeys(this.clientApSecret);
      this.state = "CONNECTED";
      this.event("connected", this.info);
      return;
    }
    if (this.state === "CONNECTED") {
      // NewSessionTicket/KeyUpdate from a client are not expected in this use; ignore KeyUpdate requests safely.
      throw new TlsAlert(ALERT.UNEXPECTED_MESSAGE, `unexpected post-handshake message ${type}`);
    }
    throw new TlsAlert(ALERT.UNEXPECTED_MESSAGE, `unexpected handshake message ${type} in ${this.state}`);
  }

  async #clientHello(body, raw) {
    const r = new Reader(body);
    r.u16(); // legacy_version
    r.bytes(32); // random
    const sessionId = r.vec8();
    const suites = r.vec16();
    r.vec8(); // compression
    const exts = new Map();
    if (r.left()) {
      const er = new Reader(r.vec16());
      while (er.left()) { const t = er.u16(); exts.set(t, er.vec16()); }
    }
    const has16 = (list, v) => { for (let i = 0; i + 1 < list.length; i += 2) if (((list[i] << 8) | list[i + 1]) === v) return true; return false; };

    if (!has16(suites, TLS_AES_128_GCM_SHA256)) throw new TlsAlert(ALERT.HANDSHAKE_FAILURE, "client does not offer TLS_AES_128_GCM_SHA256");
    const sv = exts.get(EXT.SUPPORTED_VERSIONS);
    if (!sv || !has16(sv.subarray(1), 0x0304)) throw new TlsAlert(ALERT.PROTOCOL_VERSION, "client does not offer TLS 1.3");
    const sigs = exts.get(EXT.SIG_ALGS);
    if (!sigs || !has16(sigs.subarray(2), ECDSA_P256_SHA256)) throw new TlsAlert(ALERT.HANDSHAKE_FAILURE, "client does not accept ecdsa_secp256r1_sha256");

    // key shares
    const shares = new Map();
    const ks = exts.get(EXT.KEY_SHARE);
    if (!ks) throw new TlsAlert(ALERT.MISSING_EXTENSION, "no key_share");
    const kr = new Reader(new Reader(ks).vec16());
    while (kr.left()) { const g = kr.u16(); shares.set(g, kr.vec16()); }
    const groups = exts.get(EXT.SUPPORTED_GROUPS)?.subarray(2) ?? new Uint8Array(0);

    // SNI and ALPN, for routing information and EncryptedExtensions
    const sni = exts.get(EXT.SERVER_NAME);
    if (sni) { const sr = new Reader(new Reader(sni).vec16()); sr.u8(); this.info.sni = new TextDecoder().decode(sr.vec16()); }
    let alpn = null;
    const al = exts.get(EXT.ALPN);
    if (al) {
      const ar = new Reader(new Reader(al).vec16());
      const offered = [];
      while (ar.left()) offered.push(new TextDecoder().decode(ar.vec8()));
      alpn = this.alpn.find((p) => offered.includes(p)) ?? null;
      this.info.alpnOffered = offered;
      if (!alpn) throw new TlsAlert(120, `no common ALPN protocol (client offered ${offered.join(",")})`);
    }
    this.info.alpn = alpn;
    this.info.groupsOffered = [...shares.keys()].map((g) => "0x" + g.toString(16));

    let group = shares.has(GROUP.X25519) ? GROUP.X25519 : shares.has(GROUP.P256) ? GROUP.P256 : null;
    if (group === null) {
      if (this.state === "WAIT_CH2") throw new TlsAlert(ALERT.ILLEGAL_PARAMETER, "second ClientHello without a usable key share");
      const want = has16(groups, GROUP.X25519) ? GROUP.X25519 : has16(groups, GROUP.P256) ? GROUP.P256 : null;
      if (want === null) throw new TlsAlert(ALERT.HANDSHAKE_FAILURE, "no common key exchange group");
      // HelloRetryRequest: transcript restarts with message_hash(CH1)
      const ch1Hash = await sha256(raw);
      this.transcript = [concat(u8(HS.MESSAGE_HASH), u24(32), ch1Hash)];
      const hrrExts = concat(u16(EXT.SUPPORTED_VERSIONS), vec16(u16(0x0304)), u16(EXT.KEY_SHARE), vec16(u16(want)));
      await this.#sendHandshake(HS.SERVER_HELLO, concat(u16(0x0303), HRR_RANDOM, vec8(sessionId), u16(TLS_AES_128_GCM_SHA256), u8(0), vec16(hrrExts)));
      await this.#sendRecord(CT.CCS, Uint8Array.of(1));
      this.sentCcs = true;
      this.state = "WAIT_CH2";
      this.info.helloRetry = true;
      this.event("hello_retry", { group: want });
      return;
    }
    this.transcript.push(raw);
    this.info.group = group === GROUP.X25519 ? "x25519" : "secp256r1";

    // ECDHE
    let ourPub, shared;
    if (group === GROUP.X25519) {
      const kp = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
      ourPub = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
      const peer = await subtle.importKey("raw", shares.get(group), { name: "X25519" }, false, []);
      shared = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: peer }, kp.privateKey, 256));
    } else {
      const kp = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
      ourPub = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
      const peer = await subtle.importKey("raw", shares.get(group), { name: "ECDH", namedCurve: "P-256" }, false, []);
      shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: peer }, kp.privateKey, 256));
    }

    // ServerHello
    const shExts = concat(
      u16(EXT.SUPPORTED_VERSIONS), vec16(u16(0x0304)),
      u16(EXT.KEY_SHARE), vec16(concat(u16(group), vec16(ourPub))),
    );
    const random = crypto.getRandomValues(new Uint8Array(32));
    await this.#sendHandshake(HS.SERVER_HELLO, concat(u16(0x0303), random, vec8(sessionId), u16(TLS_AES_128_GCM_SHA256), u8(0), vec16(shExts)));
    if (!this.sentCcs) await this.#sendRecord(CT.CCS, Uint8Array.of(1));

    // handshake keys
    const zeros = new Uint8Array(32);
    const emptyHash = await sha256(new Uint8Array(0));
    const early = await hkdfExtract(new Uint8Array(0), zeros);
    const hs = await hkdfExtract(await deriveSecret(early, "derived", emptyHash), shared);
    const helloHash = await this.#transcriptHash();
    this.clientHsSecret = await deriveSecret(hs, "c hs traffic", helloHash);
    const serverHs = await deriveSecret(hs, "s hs traffic", helloHash);
    this.write_ = await trafficKeys(serverHs);
    this.read = await trafficKeys(this.clientHsSecret);

    // EncryptedExtensions, Certificate, CertificateVerify, Finished
    const ee = alpn ? concat(u16(EXT.ALPN), vec16(vec16(vec8(enc.encode(alpn))))) : new Uint8Array(0);
    await this.#sendHandshake(HS.ENCRYPTED_EXTENSIONS, vec16(ee));
    const certList = concat(...this.certChain.map((der) => concat(vec24(der), u16(0))));
    await this.#sendHandshake(HS.CERTIFICATE, concat(u8(0), vec24(certList)));

    const cvContent = concat(new Uint8Array(64).fill(0x20), enc.encode("TLS 1.3, server CertificateVerify"), u8(0), await this.#transcriptHash());
    const t0 = Date.now();
    const raw64 = await this.sign(cvContent);
    this.info.signMs = Date.now() - t0;
    await this.#sendHandshake(HS.CERTIFICATE_VERIFY, concat(u16(ECDSA_P256_SHA256), vec16(ecdsaRawToDer(raw64))));

    const sfk = await hkdfExpandLabel(serverHs, "finished", new Uint8Array(0), 32);
    await this.#sendHandshake(HS.FINISHED, await hmac(sfk, await this.#transcriptHash()));

    // application secrets (transcript through server Finished)
    const master = await hkdfExtract(await deriveSecret(hs, "derived", emptyHash), zeros);
    const finHash = await this.#transcriptHash();
    this.clientApSecret = await deriveSecret(master, "c ap traffic", finHash);
    this.write_ = await trafficKeys(await deriveSecret(master, "s ap traffic", finHash));
    this.state = "WAIT_FINISHED";
  }
}
