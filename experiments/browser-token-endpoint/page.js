// Experiment page: the sign-in tab acting as the OAuth token endpoint over a blind relay.
// Driven by test/run.py through window.spike.
import { TrezorClient } from "../../js/trezor.js";
import { WebUsbTransport, pickTrezor } from "../../js/webusb.js";
import { p256JwkFromCompressed, b64u } from "../../js/oidc.js";
import { enrollAccount, signIdToken } from "../../js/flows.js";
import { CodeStore } from "./token-endpoint.js";
import { connectWebRTC, connectWebSocket, serveTokenEndpoint } from "./tunnel.js";
import { buildCsr } from "./csr.js";

const events = [];
const logEl = document.getElementById("log");
const log = (name, data) => {
  events.push({ t: Math.round(performance.now()), name, ...data });
  logEl.textContent += `${name} ${JSON.stringify(data)}\n`;
};
const b64 = (u8) => btoa(String.fromCharCode(...u8));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

let client, store = new CodeStore(), tlsKey, tunnel;
// one device call at a time (an ID token and a TLS handshake may overlap)
let deviceQueue = Promise.resolve();
const onDevice = (fn) => (deviceQueue = deviceQueue.then(fn, fn));

window.spike = {
  events,

  async connect() {
    const device = await pickTrezor();
    client = new TrezorClient(await WebUsbTransport.open(device), {
      onButton: () => log("device_confirm", {}),
      onPassphrase: async () => ({ passphrase: "" }),
    });
    const f = await client.initialize();
    return { model: f.model, version: `${f.major_version}.${f.minor_version}.${f.patch_version}` };
  },

  /** mode "webcrypto": key in browser memory (non-extractable). mode "trezor": key on the device. */
  async setupKey(mode, dnsName) {
    if (mode === "webcrypto") {
      const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
      const spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
      tlsKey = { mode, spki, sign: async (c) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, c)) };
      return { spki: b64(spki) };
    }
    // Trezor: SLIP-0013 identity dedicated to the TLS key
    const identity = { proto: "ssh", host: dnsName, user: "tls", index: 0 };
    const sign = (content) => onDevice(async () => {
      const t0 = performance.now();
      const { signature } = await client.signIdentity({ identity, challengeHidden: content, challengeVisual: "Token request" });
      log("device_sign", { purpose: "tls", bytes: content.length, ms: Math.round(performance.now() - t0) });
      return signature;
    });
    const probe = await onDevice(() => client.signIdentity({ identity, challengeHidden: crypto.getRandomValues(new Uint8Array(32)), challengeVisual: "Export TLS key" }));
    const jwk = p256JwkFromCompressed(probe.publicKey);
    const pub = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pub));
    const { csr, infoLength } = await buildCsr({ spki, dnsName, sign });
    tlsKey = { mode, spki, sign };
    return { spki: b64(spki), csr: b64(csr), csrInfoBytes: infoLength };
  },

  /** relay: { kind: "webrtc", ip, port, certhash } or { kind: "websocket", url } */
  async startTunnel(relay, host, leafB64) {
    tunnel?.close();
    const t0 = performance.now();
    const link = relay.kind === "webrtc" ? await connectWebRTC(relay, host) : await connectWebSocket(relay.url, host);
    log("relay_connected", { link: link.kind, ms: Math.round(performance.now() - t0) });
    tunnel = serveTokenEndpoint({ link, certChain: [unb64(leafB64)], sign: tlsKey.sign, store, onEvent: log });
    return { link: link.kind, ms: Math.round(performance.now() - t0) };
  },

  /** Is a plain ws:// connection even allowed from this page? (Not from an HTTPS page.) */
  tryInsecureWebSocket(url) {
    try { new WebSocket(url).close(); return "allowed"; } catch (e) { return `blocked: ${e.name}`; }
  },

  async enroll(issuer, user) {
    const { account } = await onDevice(() => enrollAccount(client, { issuer, user }));
    window.spike.account = account;
    window.spike.config = { issuer, token_ttl: 300 };
    return account;
  },

  /** What authorize.html would do for a code-flow request: sign the ID token, keep it here, hand out a code. */
  async authorize({ clientId, clientName, redirectUri, nonce, codeChallenge }) {
    const req = { client: { name: clientName }, clientId, redirectUri, nonce, scope: ["openid"], state: "s" };
    const t0 = performance.now();
    const { idToken } = await onDevice(() => signIdToken(client, { config: window.spike.config, account: window.spike.account, req }));
    log("device_sign", { purpose: "id_token", ms: Math.round(performance.now() - t0) });
    return { code: store.issue({ idToken, clientId, redirectUri, codeChallenge }), idToken };
  },
};
document.getElementById("status").textContent = "ready";
