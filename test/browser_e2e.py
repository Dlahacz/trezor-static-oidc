#!/usr/bin/env python3
"""
Browser end-to-end test: real pages in Chromium, with navigator.usb replaced by
a shim that relays USB packets to the Trezor emulator over UDP. DebugLink
presses "confirm" whenever the device asks for a button.

  python3 test/browser_e2e.py [base_url] [screenshot_dir]
"""
import base64, socket, sys, threading, time, json, os
from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
SHOTS = sys.argv[2] if len(sys.argv) > 2 else "shots"
os.makedirs(SHOTS, exist_ok=True)

main = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
main.settimeout(30)
EMU = ("127.0.0.1", 21324)
DBG = ("127.0.0.1", 21325)
button_requests = 0

def debug_confirm():
    time.sleep(0.4)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pkt = bytes([0x3F, 0x23, 0x23, 0x00, 100, 0, 0, 0, 2, 0x08, 0x01]).ljust(64, b"\0")
    s.sendto(pkt, DBG)
    s.close()

def usb_out(b64):
    main.sendto(base64.b64decode(b64), EMU)

def usb_in():
    global button_requests
    pkt, _ = main.recvfrom(64)
    if pkt[:3] == b"?##" and int.from_bytes(pkt[3:5], "big") == 26:  # ButtonRequest
        button_requests += 1
        threading.Thread(target=debug_confirm, daemon=True).start()
    return base64.b64encode(pkt).decode()

SHIM = """
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
"""

results = {}
def check(name, cond, detail=""):
    results[name] = bool(cond)
    print(f"  {'ok  ' if cond else 'FAIL'}  {name}{(': ' + detail) if detail and not cond else ''}")

with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(viewport={"width": 1100, "height": 900})
    ctx.expose_function("__usbOut", usb_out)
    ctx.expose_function("__usbIn", usb_in)
    ctx.add_init_script(SHIM)
    page = ctx.new_page()
    logs = []
    page.on("console", lambda m: logs.append(f"[{m.type}] {m.text}"))
    page.on("pageerror", lambda e: logs.append(f"[pageerror] {e}"))

    print("demo app -> authorize -> device -> back")
    page.goto(f"{BASE}/rp/")
    page.screenshot(path=f"{SHOTS}/1-rp-signed-out.png", full_page=True)
    page.click("#signin")
    page.wait_for_selector("#consent:not([hidden])", timeout=15000)
    check("authorize page shows consent", page.inner_text("#title").startswith("Sign in to"))
    page.screenshot(path=f"{SHOTS}/2-authorize-consent.png", full_page=True)

    page.click("#go")
    page.wait_for_selector("#signed-in:not([hidden])", timeout=60000)
    hello = page.inner_text("#hello")
    check("returned to demo app signed in", "Alice Example" in hello, hello)
    check("token removed from address bar", "#" not in page.url, page.url)
    claims = page.inner_text("#claims")
    check("claims include name and nonce", "name" in claims and "nonce" in claims)
    check("device asked for confirmation", button_requests >= 1, str(button_requests))
    token = page.inner_text("#raw").strip()
    page.screenshot(path=f"{SHOTS}/3-rp-signed-in.png", full_page=True)

    print("\nerror handling")
    page.goto(f"{BASE}/authorize.html?client_id=demo-rp&redirect_uri=https://evil.example/cb&response_type=id_token&scope=openid&nonce=x")
    page.wait_for_selector("#fatal:not([hidden])", timeout=10000)
    check("unregistered redirect_uri stays on the IdP", page.url.startswith(BASE))
    page.screenshot(path=f"{SHOTS}/4-authorize-bad-redirect.png", full_page=True)

    page.goto(f"{BASE}/authorize.html?client_id=demo-rp&redirect_uri={BASE}/rp/&response_type=id_token&scope=openid&state=s1")
    page.wait_for_url(f"{BASE}/rp/*", timeout=10000)
    page.wait_for_selector("#error:not([hidden])", timeout=10000)
    err = page.inner_text("#error-msg")
    check("missing nonce: error returned to app", "invalid_request" in err or "state mismatch" in err, err)

    # cancel returns access_denied with state
    page.goto(f"{BASE}/rp/")
    page.click("#signin")
    page.wait_for_selector("#consent:not([hidden])")
    page.click("#cancel")
    page.wait_for_selector("#error:not([hidden])", timeout=10000)
    err = page.inner_text("#error-msg")
    check("cancel returns access_denied", "access_denied" in err, err)

    print("\nsetup page")
    page.goto(f"{BASE}/setup.html")
    page.fill("#user", "carol")
    page.fill("#name", "Carol Example")
    page.screenshot(path=f"{SHOTS}/5-setup.png", full_page=True)
    page.click("#go")
    page.wait_for_selector("#result:not([hidden])", timeout=60000)
    files_text = page.inner_text("#files")
    check("setup outputs config/accounts.json", "config/accounts.json" in files_text)
    check("setup merged carol into published accounts", '"sub": "alice"' in files_text and '"sub": "carol"' in files_text)
    check("setup used the deployed issuer, path included", page.input_value("#issuer") == BASE and f'"path": "{BASE.split(":8080")[1]}"' in files_text if "/" in BASE.split(":8080")[1] else True)
    page.screenshot(path=f"{SHOTS}/6-setup-result.png", full_page=True)

    dark = browser.new_context(viewport={"width": 420, "height": 900}, color_scheme="dark")
    dark.expose_function("__usbOut", usb_out)
    dark.expose_function("__usbIn", usb_in)
    dark.add_init_script(SHIM)
    dp = dark.new_page()
    dp.goto(f"{BASE}/authorize.html?client_id=demo-rp&redirect_uri={BASE}/rp/&response_type=id_token&scope=openid%20profile&state=s&nonce=n")
    dp.wait_for_selector("#consent:not([hidden])")
    dp.screenshot(path=f"{SHOTS}/7-authorize-mobile-dark.png", full_page=True)

    errors = [l for l in logs if "pageerror" in l or "[error]" in l]
    # expected noise: blocked Google Fonts in this sandbox
    errors = [l for l in errors if "fonts.g" not in l and "ERR_" not in l]
    check("no unexpected page errors", not errors, "\n".join(errors))
    browser.close()

with open(os.path.join(SHOTS, "token.txt"), "w") as f:
    f.write(token)
print(f"\n{sum(results.values())} passed, {len(results) - sum(results.values())} failed")
sys.exit(0 if all(results.values()) else 1)
