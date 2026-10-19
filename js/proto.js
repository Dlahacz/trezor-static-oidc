// Minimal protobuf codec for the handful of Trezor wire messages this IdP needs.
// Field numbers come from trezor-firmware/common/protob/*.proto.

export const MessageType = {
  Initialize: 0,
  Failure: 3,
  Features: 17,
  PinMatrixRequest: 18,
  PinMatrixAck: 19,
  Cancel: 20,
  ButtonRequest: 26,
  ButtonAck: 27,
  PassphraseRequest: 41,
  PassphraseAck: 42,
  SignIdentity: 53,
  SignedIdentity: 54,
};

export const MessageName = Object.fromEntries(
  Object.entries(MessageType).map(([k, v]) => [v, k]),
);

// field number -> [name, type]; type is uint | bool | string | bytes | msg:<Name>
const SCHEMAS = {
  Initialize: { 1: ["session_id", "bytes"] },
  Failure: { 1: ["code", "uint"], 2: ["message", "string"] },
  Features: {
    1: ["vendor", "string"],
    2: ["major_version", "uint"],
    3: ["minor_version", "uint"],
    4: ["patch_version", "uint"],
    6: ["device_id", "string"],
    7: ["pin_protection", "bool"],
    8: ["passphrase_protection", "bool"],
    10: ["label", "string"],
    12: ["initialized", "bool"],
    16: ["unlocked", "bool"],
    21: ["model", "string"],
    35: ["session_id", "bytes"],
    36: ["passphrase_always_on_device", "bool"],
    44: ["internal_model", "string"],
  },
  PinMatrixRequest: { 1: ["type", "uint"] },
  PinMatrixAck: { 1: ["pin", "string"] },
  Cancel: {},
  ButtonRequest: { 1: ["code", "uint"], 2: ["pages", "uint"] },
  ButtonAck: {},
  PassphraseRequest: {},
  PassphraseAck: { 1: ["passphrase", "string"], 3: ["on_device", "bool"] },
  IdentityType: {
    1: ["proto", "string"],
    2: ["user", "string"],
    3: ["host", "string"],
    4: ["port", "string"],
    5: ["path", "string"],
    6: ["index", "uint"],
  },
  SignIdentity: {
    1: ["identity", "msg:IdentityType"],
    2: ["challenge_hidden", "bytes"],
    3: ["challenge_visual", "string"],
    4: ["ecdsa_curve_name", "string"],
  },
  SignedIdentity: {
    1: ["address", "string"],
    2: ["public_key", "bytes"],
    3: ["signature", "bytes"],
  },
};

const utf8 = new TextEncoder();
const utf8d = new TextDecoder();

function pushVarint(out, n) {
  n = Number(n);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`bad varint ${n}`);
  while (n > 0x7f) {
    out.push((n % 0x80) | 0x80);
    n = Math.floor(n / 0x80);
  }
  out.push(n);
}

export function encode(name, obj = {}) {
  const schema = SCHEMAS[name];
  if (!schema) throw new Error(`no schema for ${name}`);
  const out = [];
  const fields = Object.keys(schema).map(Number).sort((a, b) => a - b);
  for (const no of fields) {
    const [key, type] = schema[no];
    const v = obj[key];
    if (v === undefined || v === null) continue;
    if (type === "uint" || type === "bool") {
      pushVarint(out, (no << 3) | 0);
      pushVarint(out, type === "bool" ? (v ? 1 : 0) : v);
    } else {
      let bytes;
      if (type === "string") bytes = utf8.encode(String(v));
      else if (type === "bytes") bytes = v instanceof Uint8Array ? v : new Uint8Array(v);
      else if (type.startsWith("msg:")) bytes = encode(type.slice(4), v);
      else throw new Error(`bad type ${type}`);
      pushVarint(out, (no << 3) | 2);
      pushVarint(out, bytes.length);
      for (const b of bytes) out.push(b);
    }
  }
  return new Uint8Array(out);
}

export function decode(name, buf) {
  const schema = SCHEMAS[name] || {};
  const res = {};
  let i = 0;
  const varint = () => {
    let n = 0, mul = 1, b;
    do {
      if (i >= buf.length) throw new Error("truncated varint");
      b = buf[i++];
      n += (b & 0x7f) * mul;
      mul *= 0x80;
    } while (b & 0x80);
    return n;
  };
  while (i < buf.length) {
    const tag = varint();
    const no = Math.floor(tag / 8), wt = tag & 7;
    let raw;
    if (wt === 0) raw = varint();
    else if (wt === 2) {
      const len = varint();
      raw = buf.subarray(i, i + len);
      i += len;
    } else if (wt === 1) { i += 8; continue; }
    else if (wt === 5) { i += 4; continue; }
    else throw new Error(`unsupported wire type ${wt}`);
    const def = schema[no];
    if (!def) continue;
    const [key, type] = def;
    if (type === "uint") res[key] = raw;
    else if (type === "bool") res[key] = raw !== 0;
    else if (type === "string") res[key] = utf8d.decode(raw);
    else if (type === "bytes") res[key] = new Uint8Array(raw);
    else if (type.startsWith("msg:")) res[key] = decode(type.slice(4), raw);
  }
  return res;
}
