// Tiny DER writer, enough to build a PKCS#10 CSR for a P-256 key whose
// signature comes from the Trezor. Shows the Let's Encrypt path works with a
// key that never leaves the device.
import { ecdsaRawToDer } from "./tls13-server.js";

const concat = (...p) => { const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
const len = (n) => n < 128 ? Uint8Array.of(n) : n < 256 ? Uint8Array.of(0x81, n) : Uint8Array.of(0x82, n >> 8, n & 255);
const tlv = (tag, c) => concat(Uint8Array.of(tag), len(c.length), c);
const seq = (...c) => tlv(0x30, concat(...c));
const set = (...c) => tlv(0x31, concat(...c));
const oid = (s) => {
  const a = s.split(".").map(Number);
  const out = [40 * a[0] + a[1]];
  for (const n of a.slice(2)) {
    const b = [n & 0x7f];
    for (let v = n >> 7; v; v >>= 7) b.unshift((v & 0x7f) | 0x80);
    out.push(...b);
  }
  return tlv(0x06, Uint8Array.from(out));
};
const utf8 = (s) => tlv(0x0c, new TextEncoder().encode(s));

/** Build and sign a CSR. `sign(bytes)` returns raw r||s over SHA-256(bytes). */
export async function buildCsr({ spki, dnsName, sign }) {
  const subject = seq(set(seq(oid("2.5.4.3"), utf8(dnsName))));
  const san = seq(tlv(0x82, new TextEncoder().encode(dnsName)));
  const extReq = seq(oid("1.2.840.113549.1.9.14"), set(seq(seq(oid("2.5.29.17"), tlv(0x04, san)))));
  const info = seq(Uint8Array.of(0x02, 0x01, 0x00), subject, spki, tlv(0xa0, extReq));
  const sig = ecdsaRawToDer(await sign(info));
  return { csr: seq(info, seq(oid("1.2.840.10045.4.3.2")), tlv(0x03, concat(Uint8Array.of(0), sig))), infoLength: info.length };
}
