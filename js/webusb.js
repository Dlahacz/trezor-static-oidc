// WebUSB transport for Trezor devices in normal (firmware) mode.

export const TREZOR_FILTERS = [{ vendorId: 0x1209, productId: 0x53c1 }];
const BOOTLOADER = { vendorId: 0x1209, productId: 0x53c0 };

export function webUsbAvailable() {
  return typeof navigator !== "undefined" && "usb" in navigator && window.isSecureContext;
}

/** Reuse an already-paired device, or show the browser's device picker (needs a user gesture). */
export async function pickTrezor({ forcePicker = false } = {}) {
  if (!forcePicker) {
    const paired = (await navigator.usb.getDevices()).filter(
      (d) => d.vendorId === 0x1209 && (d.productId === 0x53c1 || d.productId === BOOTLOADER.productId),
    );
    if (paired.length) return paired[0];
  }
  return navigator.usb.requestDevice({ filters: [...TREZOR_FILTERS, BOOTLOADER] });
}

export class WebUsbTransport {
  constructor(device, iface, epIn, epOut) {
    this.device = device;
    this.iface = iface;
    this.epIn = epIn;
    this.epOut = epOut;
  }

  static async open(device) {
    if (device.productId === BOOTLOADER.productId) {
      throw new Error("Your Trezor is in bootloader mode. Reconnect it without touching the screen or buttons.");
    }
    if (!device.opened) await device.open();
    if (device.configuration === null) await device.selectConfiguration(1);
    // Interface 0 is the main wire interface; 1 is DebugLink, 2 is U2F (HID).
    const iface = device.configuration.interfaces.find((i) => i.interfaceNumber === 0);
    const alt = iface.alternate;
    const epIn = alt.endpoints.find((e) => e.direction === "in").endpointNumber;
    const epOut = alt.endpoints.find((e) => e.direction === "out").endpointNumber;
    try {
      await device.claimInterface(0);
    } catch (e) {
      throw new Error(
        "Another app is using your Trezor. Close Trezor Suite and other tabs that use it, then try again.",
        { cause: e },
      );
    }
    return new this(device, 0, epIn, epOut);
  }

  async write(pkt) {
    const r = await this.device.transferOut(this.epOut, pkt);
    if (r.status !== "ok") throw new Error(`USB write ${r.status}`);
  }

  async read() {
    const r = await this.device.transferIn(this.epIn, 64);
    if (r.status !== "ok") throw new Error(`USB read ${r.status}`);
    return new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength);
  }

  async close() {
    try { await this.device.releaseInterface(this.iface); } catch {}
    try { await this.device.close(); } catch {}
  }
}
