// navigator.usb stand-in that relays packets to the Trezor emulator through Playwright
(() => {
  const b64 = (u8) => btoa(String.fromCharCode(...u8));
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const dev = {
    vendorId: 0x1209, productId: 0x53c1, productName: "Trezor (emulator)", opened: false,
    configuration: null,
    async open() { this.opened = true; },
    async close() { this.opened = false; },
    async selectConfiguration() {
      this.configuration = { interfaces: [{ interfaceNumber: 0, alternate: { endpoints: [
        { direction: "in", endpointNumber: 1 }, { direction: "out", endpointNumber: 1 } ] } }] };
    },
    async claimInterface() {}, async releaseInterface() {},
    async transferOut(ep, data) { await window.__usbOut(b64(new Uint8Array(data))); return { status: "ok", bytesWritten: data.length }; },
    async transferIn(ep, len) { const u8 = unb64(await window.__usbIn()); return { status: "ok", data: new DataView(u8.buffer) }; },
  };
  const usb = { async getDevices() { return [dev]; }, async requestDevice() { return dev; } };
  Object.defineProperty(Navigator.prototype, "usb", { get: () => usb, configurable: true });
})();
