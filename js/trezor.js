// Trezor protocol v1 client (Model One, Model T, Safe 3, Safe 5).
// Transport-agnostic: anything with async write(Uint8Array[64]) / read() -> Uint8Array[64],
// or, for transports that carry whole messages (Trezor Bridge), async
// sendMessage(type, data) / receiveMessage() -> { type, data }.
// Safe 7 (and other THP-only firmware) is not supported by this POC.

import { MessageType, MessageName, encode, decode } from "./proto.js";

const PACKET = 64;

export class TrezorFailure extends Error {
  constructor(code, message) {
    super(message || `Trezor failure ${code}`);
    this.code = code;
  }
}
export const FailureType = { ActionCancelled: 4, PinCancelled: 6, PinInvalid: 7, DataError: 3 };

export class TrezorClient {
  /**
   * @param transport {write(pkt), read()}
   * @param handlers {
   *   onButton?(req),                       // device is waiting for a button press
   *   onPin?(req) -> Promise<string|null>,  // Model One: matrix-encoded PIN, null cancels
   *   onPassphrase?(features) -> Promise<{passphrase?: string, onDevice?: boolean}|null>,
   * }
   */
  constructor(transport, handlers = {}) {
    this.t = transport;
    this.h = handlers;
    this.features = null;
    this.sessionId = undefined;
  }

  async send(name, obj) {
    const data = encode(name, obj);
    const type = MessageType[name];
    if (this.t.sendMessage) return this.t.sendMessage(type, data);
    const msg = new Uint8Array(8 + data.length);
    msg[0] = 0x23; msg[1] = 0x23; // "##"
    msg[2] = type >> 8; msg[3] = type & 0xff;
    new DataView(msg.buffer).setUint32(4, data.length);
    msg.set(data, 8);
    for (let off = 0; off < msg.length; off += PACKET - 1) {
      const pkt = new Uint8Array(PACKET);
      pkt[0] = 0x3f; // "?"
      pkt.set(msg.subarray(off, off + PACKET - 1), 1);
      await this.t.write(pkt);
    }
  }

  async receive() {
    if (this.t.receiveMessage) {
      const { type, data } = await this.t.receiveMessage();
      return this.decodeMessage(type, data);
    }
    let pkt;
    // skip any stray continuation packets until a message header appears
    for (let tries = 0; ; tries++) {
      pkt = await this.t.read();
      if (pkt[0] === 0x3f && pkt[1] === 0x23 && pkt[2] === 0x23) break;
      if (tries > 64) throw new Error("no message header from device");
    }
    const dv = new DataView(pkt.buffer, pkt.byteOffset, pkt.byteLength);
    const type = dv.getUint16(3);
    const len = dv.getUint32(5);
    const data = new Uint8Array(len);
    let have = Math.min(len, PACKET - 9);
    data.set(pkt.subarray(9, 9 + have));
    while (have < len) {
      pkt = await this.t.read();
      if (pkt[0] !== 0x3f) throw new Error("bad continuation packet");
      const n = Math.min(len - have, PACKET - 1);
      data.set(pkt.subarray(1, 1 + n), have);
      have += n;
    }
    return this.decodeMessage(type, data);
  }

  decodeMessage(type, data) {
    const name = MessageName[type];
    if (!name) throw new Error(`unexpected message type ${type}`);
    return { name, message: decode(name, data) };
  }

  /** Send a request and drive the interaction loop until a final response. */
  async call(name, obj, expect) {
    await this.send(name, obj);
    for (;;) {
      const { name: rname, message } = await this.receive();
      switch (rname) {
        case "ButtonRequest":
          this.h.onButton?.(message);
          await this.send("ButtonAck", {});
          break;
        case "PinMatrixRequest": {
          const pin = this.h.onPin ? await this.h.onPin(message) : null;
          if (pin == null) await this.send("Cancel", {});
          else await this.send("PinMatrixAck", { pin });
          break;
        }
        case "PassphraseRequest": {
          const r = this.h.onPassphrase ? await this.h.onPassphrase(this.features) : { passphrase: "" };
          if (r == null) await this.send("Cancel", {});
          else if (r.onDevice) await this.send("PassphraseAck", { on_device: true });
          else await this.send("PassphraseAck", { passphrase: r.passphrase ?? "" });
          break;
        }
        case "Failure":
          throw new TrezorFailure(message.code, message.message);
        default:
          if (expect && rname !== expect) throw new Error(`expected ${expect}, got ${rname}`);
          return message;
      }
    }
  }

  async initialize() {
    this.features = await this.call("Initialize", { session_id: this.sessionId }, "Features");
    if (this.features.session_id) this.sessionId = this.features.session_id;
    return this.features;
  }

  /**
   * SLIP-0013 SignIdentity. With identity.proto === "ssh" the device signs
   * sha256(challengeHidden) (ECDSA curves) or challengeHidden itself (ed25519),
   * which is exactly JWS ES256 / ES256K / EdDSA over the signing input.
   * Returns { publicKey: Uint8Array(33), signature: Uint8Array(64) }.
   */
  async signIdentity({ identity, challengeHidden, challengeVisual = "", curve = "nist256p1" }) {
    const r = await this.call(
      "SignIdentity",
      {
        identity,
        challenge_hidden: challengeHidden,
        challenge_visual: challengeVisual,
        ecdsa_curve_name: curve,
      },
      "SignedIdentity",
    );
    if (!r.signature || r.signature.length !== 65) throw new Error("unexpected signature length");
    return { publicKey: r.public_key, signature: r.signature.subarray(1) };
  }
}

/** Model One shows a scrambled 3x3 grid; the host sends positions using this layout. */
export const PIN_MATRIX_LAYOUT = [7, 8, 9, 4, 5, 6, 1, 2, 3];
