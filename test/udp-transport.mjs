// Test helpers for the Trezor emulator: the UDP transport (shared with the CLI)
// and a DebugLink "confirm", standing in for a person and WebUSB.
import { UdpTransport } from "../cli/transports.mjs";

export { UdpTransport };

/** Send DebugLinkDecision(button=YES) on the DebugLink port (message type 100). */
export async function debugConfirm(port = 21325) {
  const dbg = new UdpTransport(port);
  const pkt = new Uint8Array(64);
  pkt.set([0x3f, 0x23, 0x23, 0x00, 100, 0, 0, 0, 2, 0x08, 0x01]);
  await new Promise((r) => setTimeout(r, 250));
  await dbg.write(pkt);
  dbg.close();
}
