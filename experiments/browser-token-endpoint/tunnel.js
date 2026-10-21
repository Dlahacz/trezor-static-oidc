// Tab side of the relay: one link to the relay, one TLS server per forwarded connection.
//
// Two links are supported:
//   connectWebRTC({ ip, port, certhash }, host)  signaling-free WebRTC data channel (no relay certificate/domain)
//   connectWebSocket(url, host)                  WebSocket (needs wss:// and a relay certificate on HTTPS pages)
import { Tls13Server } from "./tls13-server.js";
import { httpConnection } from "./token-endpoint.js";

const T = { OPEN: 1, DATA: 2, CLOSE: 3, REGISTER: 16 };
const frame = (type, conn, payload = new Uint8Array(0)) => {
  const f = new Uint8Array(5 + payload.length);
  f[0] = type;
  new DataView(f.buffer).setUint32(1, conn);
  f.set(payload, 5);
  return f;
};

// ---------------------------------------------------------------- links
export function connectWebSocket(relayUrl, host) {
  const ws = new WebSocket(`${relayUrl}?host=${encodeURIComponent(host)}`);
  ws.binaryType = "arraybuffer";
  const link = { send: (b) => ws.send(b), onMessage: null, close: () => ws.close(), kind: "websocket" };
  ws.onmessage = (ev) => link.onMessage?.(new Uint8Array(ev.data));
  return new Promise((res, rej) => { ws.onopen = () => res(link); ws.onerror = () => rej(new Error("relay unreachable")); });
}

const ICE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const randomUfrag = (n = 32) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => ICE_CHARS[b % ICE_CHARS.length]).join("");

/**
 * WebRTC data channel to a relay known only by IP, UDP port and certificate
 * fingerprint ("sha-256 AB:CD:…"). No signaling: the relay's answer is built here.
 */
export async function connectWebRTC({ ip, port, certhash }, host, { timeoutMs = 10000 } = {}) {
  const pc = new RTCPeerConnection();
  const dc = pc.createDataChannel("tunnel", { negotiated: true, id: 0, ordered: true });
  dc.binaryType = "arraybuffer";

  const ufrag = randomUfrag();
  const offer = await pc.createOffer();
  const sdp = offer.sdp
    .replace(/a=ice-ufrag:[^\r\n]*/g, `a=ice-ufrag:${ufrag}`)
    .replace(/a=ice-pwd:[^\r\n]*/g, `a=ice-pwd:${ufrag}`);
  await pc.setLocalDescription({ type: "offer", sdp });

  const [hashAlg, hashValue] = certhash.split(" ");
  const answer = [
    "v=0", `o=- 0 0 IN IP4 ${ip}`, "s=-", "t=0 0", "a=group:BUNDLE 0", "a=ice-lite",
    `m=application ${port} UDP/DTLS/SCTP webrtc-datachannel`, `c=IN IP4 ${ip}`, "a=mid:0",
    `a=ice-ufrag:${ufrag}`, `a=ice-pwd:${ufrag}`, `a=fingerprint:${hashAlg} ${hashValue}`,
    "a=setup:passive", "a=sctp-port:5000", "a=max-message-size:262144",
    `a=candidate:1 1 UDP 2130706431 ${ip} ${port} typ host`, "a=end-of-candidates", "",
  ].join("\r\n");
  await pc.setRemoteDescription({ type: "answer", sdp: answer });

  await new Promise((res, rej) => {
    const timer = setTimeout(() => rej(new Error(`relay ${ip}:${port} did not answer over WebRTC`)), timeoutMs);
    dc.onopen = () => { clearTimeout(timer); res(); };
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === "failed") { clearTimeout(timer); rej(new Error("WebRTC connection to relay failed")); }
    };
  });
  const link = { send: (b) => dc.send(b), onMessage: null, close: () => pc.close(), kind: "webrtc", pc };
  dc.onmessage = (ev) => link.onMessage?.(new Uint8Array(ev.data));
  link.send(frame(T.REGISTER, 0, new TextEncoder().encode(host)));
  return link;
}

// ---------------------------------------------------------------- token endpoint over a link
/**
 * @param link      from connectWebRTC / connectWebSocket
 * @param certChain DER certificates, leaf first
 * @param sign      async (content) => 64-byte r||s ECDSA P-256 over SHA-256(content)
 * @param store     CodeStore
 */
export function serveTokenEndpoint({ link, certChain, sign, store, onEvent = () => {} }) {
  const conns = new Map();
  link.onMessage = (msg) => {
    const type = msg[0], conn = new DataView(msg.buffer, msg.byteOffset).getUint32(1), payload = msg.subarray(5);
    if (type === T.OPEN) {
      const meta = JSON.parse(new TextDecoder().decode(payload));
      const started = performance.now();
      const http = httpConnection(store, { onRequest: (r) => onEvent("request", { conn, ...r }) });
      const tls = new Tls13Server({
        certChain,
        sign,
        send: (b) => link.send(frame(T.DATA, conn, b)),
        onClose: () => { link.send(frame(T.CLOSE, conn)); conns.delete(conn); },
        onEvent: (name, data) => {
          if (name === "connected") onEvent("handshake", { conn, ms: Math.round(performance.now() - started), link: link.kind, ...data });
          if (name === "error") onEvent("tls_error", { conn, message: data });
        },
        onData: async (bytes) => {
          const res = await http(bytes, (b) => tls.write(b));
          if (res) { await tls.write(res); await tls.close(); }
        },
      });
      conns.set(conn, tls);
      onEvent("open", { conn, ...meta });
    } else if (type === T.DATA) {
      conns.get(conn)?.feed(payload.slice());
    } else if (type === T.CLOSE) {
      conns.delete(conn);
    }
  };
  return { close: () => link.close() };
}
