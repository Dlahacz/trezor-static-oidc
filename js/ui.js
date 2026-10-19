// Shared UI bits: device-screen preview, PIN matrix, passphrase prompt, progress, errors.
import { TrezorClient, TrezorFailure, FailureType, PIN_MATRIX_LAYOUT } from "./trezor.js";
import { WebUsbTransport, pickTrezor, webUsbAvailable } from "./webusb.js";
import { identityLabel } from "./oidc.js";

export const $ = (sel, root = document) => root.querySelector(sel);

export function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== false) n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c != null) n.append(c);
  return n;
}

/** What the Trezor will display for SignIdentity (Model T / Safe wording). */
export function renderDevice(container, { identity, visual }) {
  const who = identityLabel(identity);
  container.replaceChildren(
    el("div", { class: "device__body", "aria-hidden": "true" },
      el("div", { class: "device__screen" },
        el("b", {}, "Sign SSH"),
        el("span", {}, visual),
        el("span", { class: "dim" }, who),
      ),
    ),
    el("p", { class: "device__caption" },
      "Your Trezor will ask you to sign as ",
      el("strong", {}, who),
      ". The SSH label is expected: it is the signing mode that produces a standard ID token.",
    ),
  );
}

export function setSteps(list, activeIndex) {
  [...list.children].forEach((li, i) => {
    li.dataset.state = i < activeIndex ? "done" : i === activeIndex ? "active" : "";
  });
}

// ---------------------------------------------------------------- dialogs
function pinDialog(type) {
  return new Promise((resolve) => {
    let pin = "";
    const display = el("div", { class: "pin-display", "aria-live": "polite" });
    const title = type === 2 ? "Enter a new PIN" : type === 3 ? "Enter the new PIN again" : "Enter your PIN";
    const grid = el("div", { class: "pin-grid" },
      PIN_MATRIX_LAYOUT.map((n) =>
        el("button", { type: "button", "aria-label": `Position ${n}`, onclick: () => { if (pin.length < 50) { pin += n; display.textContent = "•".repeat(pin.length); } } }, "•"),
      ),
    );
    const dlg = el("dialog", { "aria-labelledby": "pin-title" },
      el("h2", { id: "pin-title" }, title),
      el("p", { class: "hint" }, "The numbers are scrambled on your Trezor's screen. Click the positions that match your PIN."),
      display,
      grid,
      el("div", { class: "row" },
        el("button", { type: "button", class: "primary", onclick: () => close(pin || null) }, "Enter PIN"),
        el("button", { type: "button", class: "quiet", onclick: () => { pin = ""; display.textContent = ""; } }, "Clear"),
        el("button", { type: "button", class: "quiet", onclick: () => close(null) }, "Cancel"),
      ),
    );
    const close = (v) => { dlg.close(); dlg.remove(); resolve(v); };
    dlg.addEventListener("cancel", (e) => { e.preventDefault(); close(null); });
    document.body.append(dlg);
    dlg.showModal();
  });
}

function passphraseDialog(features) {
  return new Promise((resolve) => {
    const input = el("input", { type: "password", id: "pp", autocomplete: "off" });
    const canOnDevice = features && features.major_version >= 2;
    const dlg = el("dialog", { "aria-labelledby": "pp-title" },
      el("h2", { id: "pp-title" }, "Passphrase"),
      el("p", { class: "hint" }, "Use the same passphrase as during setup. A different passphrase gives a different key, and sign-in will fail."),
      el("div", { class: "field" }, el("label", { for: "pp" }, "Passphrase"), input),
      el("div", { class: "row" },
        el("button", { type: "button", class: "primary", onclick: () => close({ passphrase: input.value }) }, "Continue"),
        canOnDevice ? el("button", { type: "button", class: "quiet", onclick: () => close({ onDevice: true }) }, "Enter on Trezor") : null,
        el("button", { type: "button", class: "quiet", onclick: () => close(null) }, "Cancel"),
      ),
    );
    const close = (v) => { dlg.close(); dlg.remove(); resolve(v); };
    dlg.addEventListener("cancel", (e) => { e.preventDefault(); close(null); });
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") close({ passphrase: input.value }); });
    document.body.append(dlg);
    dlg.showModal();
    input.focus();
  });
}

// ---------------------------------------------------------------- connect
/** Connect over WebUSB and return an initialized client. Must run from a click. */
export async function connectTrezor({ onButton, forcePicker = false } = {}) {
  if (!webUsbAvailable()) {
    throw new Error("This browser cannot talk to USB devices. Open this page in Chrome, Edge or Brave over HTTPS (or localhost).");
  }
  const device = await pickTrezor({ forcePicker });
  const transport = await WebUsbTransport.open(device);
  const client = new TrezorClient(transport, {
    onButton,
    onPin: (req) => pinDialog(req.type),
    onPassphrase: (features) => passphraseDialog(features),
  });
  try {
    const f = await client.initialize();
    if (!f.initialized) throw new Error("This Trezor has no wallet yet. Set it up in Trezor Suite first.");
    if (f.major_version === 1 && (f.minor_version < 12 || (f.minor_version === 12 && f.patch_version < 1))) {
      throw new Error(`Trezor Model One firmware ${f.major_version}.${f.minor_version}.${f.patch_version} is too old. Update to 1.12.1 or newer.`);
    }
  } catch (e) {
    await transport.close();
    throw e;
  }
  return { client, transport };
}

export function explainError(e) {
  if (e instanceof TrezorFailure) {
    if (e.code === FailureType.ActionCancelled) return "You cancelled on the Trezor.";
    if (e.code === FailureType.PinCancelled) return "PIN entry was cancelled.";
    if (e.code === FailureType.PinInvalid) return "That PIN was wrong. Try again; the Trezor waits longer after each wrong PIN.";
    return `The Trezor refused: ${e.message}`;
  }
  if (e && e.name === "NotFoundError") return "No Trezor was selected. Connect it, unlock it, and choose it in the browser's device list.";
  if (e && e.name === "SecurityError") return "The browser blocked USB access on this page.";
  if (e && e.name === "NetworkError") return "The Trezor was disconnected. Reconnect it and try again.";
  return e?.message || String(e);
}

export const LOCK_ICON = () => {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", "22"); svg.setAttribute("height", "22"); svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.innerHTML = '<rect x="4" y="10" width="16" height="11" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3" fill="none" stroke="currentColor" stroke-width="2"/>';
  return svg;
};
