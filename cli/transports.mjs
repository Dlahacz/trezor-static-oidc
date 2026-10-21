// Node transports for the command-line tool. All of them feed js/trezor.js.
//
//   bridge  Trezor Bridge (trezord, or the bridge built into Trezor Suite) over HTTP.
//           No native modules; works while Suite is running.
//   usb     Direct USB through the optional "usb" package (libusb), using the
//           same WebUSB code path as the browser. Trezor Suite must be closed.
//   udp     Trezor emulator (protocol v1 over UDP), for development.

import dgram from "node:dgram";
import { WebUsbTransport, TREZOR_FILTERS } from "../js/webusb.js";

export const DEFAULT_BRIDGE_URL = "http://127.0.0.1:21325";
// Bridge only answers known origins; this is the one trezorlib (trezorctl) uses.
const BRIDGE_ORIGIN = "https://python.trezor.io";

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const unhex = (s) => new Uint8Array(Buffer.from(s, "hex"));

export class BridgeTransport {
  constructor(url, session) {
    this.url = url;
    this.session = session;
    this.pending = null;
  }

  static async post(url, path, body) {
    let r;
    try {
      r = await fetch(url + path, { method: "POST", headers: { Origin: BRIDGE_ORIGIN }, body });
    } catch (e) {
      throw new Error(`Trezor Bridge is not reachable at ${url}.`, { cause: e });
    }
    const text = await r.text();
    if (!r.ok) {
      let msg = text;
      try { msg = JSON.parse(text).error; } catch {}
      throw new Error(`Trezor Bridge ${path}: ${msg || r.status}`);
    }
    return text;
  }

  static async available(url = DEFAULT_BRIDGE_URL) {
    try {
      await BridgeTransport.post(url, "/", "");
      return true;
    } catch {
      return false;
    }
  }

  static async open(url = DEFAULT_BRIDGE_URL) {
    const devices = JSON.parse(await BridgeTransport.post(url, "/enumerate", ""));
    if (!devices.length) throw new Error("No Trezor found. Connect and unlock it, then try again.");
    const dev = devices[0];
    const { session } = JSON.parse(await BridgeTransport.post(url, `/acquire/${dev.path}/${dev.session ?? "null"}`, ""));
    return new BridgeTransport(url, session);
  }

  // Bridge calls are request/response, so a send starts the call and the next receive awaits it.
  sendMessage(type, data) {
    const msg = new Uint8Array(6 + data.length);
    const dv = new DataView(msg.buffer);
    dv.setUint16(0, type);
    dv.setUint32(2, data.length);
    msg.set(data, 6);
    this.pending = BridgeTransport.post(this.url, `/call/${this.session}`, hex(msg));
    this.pending.catch(() => {}); // surfaced by receiveMessage
  }

  async receiveMessage() {
    if (!this.pending) throw new Error("receive without a pending call");
    const msg = unhex((await this.pending).trim());
    this.pending = null;
    const dv = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
    const len = dv.getUint32(2);
    return { type: dv.getUint16(0), data: msg.subarray(6, 6 + len) };
  }

  async close() {
    try { await BridgeTransport.post(this.url, `/release/${this.session}`, ""); } catch {}
  }
}

export async function openUsb() {
  let usb;
  try {
    usb = await import("usb");
  } catch {
    throw new Error('Direct USB needs the optional "usb" package (run npm install in this repository), or start Trezor Suite / Trezor Bridge and use the bridge transport.');
  }
  const webusb = new usb.WebUSB({ allowAllDevices: true });
  const all = await webusb.getDevices();
  const device = all.find((d) => TREZOR_FILTERS.some((f) => d.vendorId === f.vendorId && d.productId === f.productId))
    ?? all.find((d) => d.vendorId === 0x1209 && d.productId === 0x53c0);
  if (!device) throw new Error("No Trezor found over USB. Connect and unlock it, then try again.");
  try {
    return await WebUsbTransport.open(device);
  } catch (e) {
    if (/Another app/.test(e.message)) {
      throw new Error("Another app is using your Trezor. Close Trezor Suite, or use --transport bridge while it runs.", { cause: e });
    }
    throw e;
  }
}

/** Trezor emulator: 64-byte protocol v1 packets over UDP. */
export class UdpTransport {
  constructor(port = 21324, host = "127.0.0.1") {
    this.port = port;
    this.host = host;
    this.sock = dgram.createSocket("udp4");
    this.queue = [];
    this.waiters = [];
    this.sock.on("message", (m) => {
      const pkt = new Uint8Array(m);
      const w = this.waiters.shift();
      if (w) w(pkt);
      else this.queue.push(pkt);
    });
  }
  write(pkt) {
    return new Promise((res, rej) => this.sock.send(pkt, this.port, this.host, (e) => (e ? rej(e) : res())));
  }
  read(timeoutMs = 30000) {
    if (this.queue.length) return Promise.resolve(this.queue.shift());
    return new Promise((res, rej) => {
      const t = setTimeout(() => rej(new Error("UDP read timeout")), timeoutMs);
      this.waiters.push((p) => { clearTimeout(t); res(p); });
    });
  }
  close() { this.sock.close(); }
}

/**
 * spec: "auto" (bridge if it answers, else usb), "bridge", "usb", "udp" or "udp:<port>".
 */
export async function openTransport(spec = "auto", { bridgeUrl = DEFAULT_BRIDGE_URL } = {}) {
  if (spec === "bridge") return BridgeTransport.open(bridgeUrl);
  if (spec === "usb") return openUsb();
  if (spec === "udp" || spec.startsWith("udp:")) return new UdpTransport(Number(spec.split(":")[1] || 21324));
  if (spec !== "auto") throw new Error(`Unknown transport "${spec}". Use auto, bridge, usb or udp[:port].`);
  return (await BridgeTransport.available(bridgeUrl)) ? BridgeTransport.open(bridgeUrl) : openUsb();
}
