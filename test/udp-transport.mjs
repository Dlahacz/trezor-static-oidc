// Test-only transport: talks to the Trezor emulator over UDP (protocol v1) and
// presses "confirm" through DebugLink, standing in for a person and WebUSB.
import dgram from "node:dgram";

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

/** Send DebugLinkDecision(button=YES) on the DebugLink port (message type 100). */
export async function debugConfirm(port = 21325) {
  const dbg = new UdpTransport(port);
  const pkt = new Uint8Array(64);
  pkt.set([0x3f, 0x23, 0x23, 0x00, 100, 0, 0, 0, 2, 0x08, 0x01]);
  await new Promise((r) => setTimeout(r, 250));
  await dbg.write(pkt);
  dbg.close();
}
