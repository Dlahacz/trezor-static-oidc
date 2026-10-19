#!/usr/bin/env node
// Blind relay: accepts TLS connections, reads only the SNI host name from the
// unencrypted ClientHello, and forwards the raw byte stream to the browser tab
// that registered for that host over a WebSocket. It never holds a key, so it
// sees ciphertext only.
//
//   node relay.mjs [--tls-port 8443] [--ws-port 8090] [--capture file]
//
// Tunnel frames (binary WebSocket messages): [type u8][conn u32][payload]
//   1 OPEN  relay->tab  payload: JSON {sni, remote}
//   2 DATA  both ways   payload: raw TLS bytes
//   3 CLOSE both ways

import net from "node:net";
import http from "node:http";
import crypto from "node:crypto";
import { appendFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";

const { values: opt } = parseArgs({
  options: {
    "tls-port": { type: "string", default: "8443" },
    "ws-port": { type: "string", default: "8090" },
    capture: { type: "string" },
  },
});
const T = { OPEN: 1, DATA: 2, CLOSE: 3 };
const tabs = new Map(); // host -> websocket wrapper
const log = (...a) => console.log(new Date().toISOString().slice(11, 23), ...a);
if (opt.capture) writeFileSync(opt.capture, "");
const capture = (dir, conn, buf) => opt.capture && appendFileSync(opt.capture, `${dir} ${conn} ${buf.toString("base64")}\n`);

// ---------------------------------------------------------------- WebSocket (RFC 6455, server side, minimal)
function wsAccept(req, socket) {
  const key = req.headers["sec-websocket-key"];
  const accept = crypto.createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
  socket.setNoDelay(true);
  const ws = { socket, onMessage: null, onClose: null, closed: false };
  let buf = Buffer.alloc(0), frag = [];
  ws.send = (data) => {
    if (ws.closed) return;
    const len = data.length;
    const head = len < 126 ? Buffer.from([0x82, len])
      : len < 65536 ? Buffer.from([0x82, 126, len >> 8, len & 255])
      : Buffer.concat([Buffer.from([0x82, 127]), (() => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(len)); return b; })()]);
    socket.write(Buffer.concat([head, data]));
  };
  socket.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      if (buf.length < 2) return;
      const fin = buf[0] & 0x80, op = buf[0] & 0x0f, masked = buf[1] & 0x80;
      let len = buf[1] & 0x7f, off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      const mask = masked ? buf.subarray(off, off + 4) : null;
      if (masked) off += 4;
      if (buf.length < off + len) return;
      const payload = Buffer.from(buf.subarray(off, off + len));
      if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      buf = buf.subarray(off + len);
      if (op === 0x8) { ws.closed = true; socket.end(); ws.onClose?.(); return; }
      if (op === 0x9) { socket.write(Buffer.concat([Buffer.from([0x8a, payload.length]), payload])); continue; }
      if (op === 0x2 || op === 0x0) {
        frag.push(payload);
        if (fin) { const msg = Buffer.concat(frag); frag = []; ws.onMessage?.(msg); }
      }
    }
  });
  socket.on("close", () => { if (!ws.closed) { ws.closed = true; ws.onClose?.(); } });
  socket.on("error", () => {});
  return ws;
}

const frame = (type, conn, payload = Buffer.alloc(0)) => {
  const h = Buffer.alloc(5);
  h[0] = type;
  h.writeUInt32BE(conn, 1);
  return Buffer.concat([h, payload]);
};

// ---------------------------------------------------------------- tab registration
const wsServer = http.createServer((req, res) => { res.writeHead(404); res.end(); });
wsServer.on("upgrade", (req, socket) => {
  const url = new URL(req.url, "http://relay");
  const host = url.searchParams.get("host");
  if (url.pathname !== "/tunnel" || !host) { socket.destroy(); return; }
  const ws = wsAccept(req, socket);
  ws.conns = new Map();
  tabs.set(host, ws);
  log(`tab registered for ${host}`);
  ws.onMessage = (msg) => {
    const type = msg[0], conn = msg.readUInt32BE(1), payload = msg.subarray(5);
    const c = ws.conns.get(conn);
    if (!c) return;
    if (type === T.DATA) { capture("out", conn, payload); c.write(payload); }
    else if (type === T.CLOSE) c.end();
  };
  ws.onClose = () => {
    if (tabs.get(host) === ws) tabs.delete(host);
    for (const c of ws.conns.values()) c.destroy();
    log(`tab for ${host} disconnected`);
  };
});

// ---------------------------------------------------------------- TLS ingress
/** Return the SNI host name from a buffered first TLS record, null if none, undefined if incomplete. */
function readSni(buf) {
  if (buf.length < 5) return undefined;
  if (buf[0] !== 22) return null;
  const recLen = buf.readUInt16BE(3);
  if (buf.length < 5 + recLen) return undefined;
  let p = 5;
  if (buf[p] !== 1) return null; // ClientHello
  p += 4 + 2 + 32;
  p += 1 + buf[p];                     // session id
  p += 2 + buf.readUInt16BE(p);        // cipher suites
  p += 1 + buf[p];                     // compression
  const extEnd = p + 2 + buf.readUInt16BE(p);
  p += 2;
  while (p + 4 <= extEnd) {
    const type = buf.readUInt16BE(p), len = buf.readUInt16BE(p + 2);
    if (type === 0) {
      const nameLen = buf.readUInt16BE(p + 4 + 2 + 1);
      return buf.subarray(p + 4 + 2 + 3, p + 4 + 2 + 3 + nameLen).toString("ascii").toLowerCase();
    }
    p += 4 + len;
  }
  return null;
}

let nextConn = 1;
const ingress = net.createServer((sock) => {
  sock.setNoDelay(true);
  let head = Buffer.alloc(0), routed = false;
  sock.on("error", () => {});
  sock.on("data", function onFirst(chunk) {
    if (routed) return;
    head = Buffer.concat([head, chunk]);
    const sni = readSni(head);
    if (sni === undefined) return;
    routed = true;
    sock.off("data", onFirst);
    const ws = sni && tabs.get(sni);
    if (!ws) { log(`no tab for ${sni ?? "(no SNI)"}; dropping`); sock.destroy(); return; }
    const conn = nextConn++;
    ws.conns.set(conn, sock);
    log(`conn ${conn}: ${sock.remoteAddress} -> ${sni}`);
    ws.send(frame(T.OPEN, conn, Buffer.from(JSON.stringify({ sni, remote: sock.remoteAddress }))));
    capture("in", conn, head);
    ws.send(frame(T.DATA, conn, head));
    sock.on("data", (d) => { capture("in", conn, d); ws.send(frame(T.DATA, conn, d)); });
    sock.on("close", () => { ws.conns.delete(conn); ws.send(frame(T.CLOSE, conn)); log(`conn ${conn} closed`); });
  });
});

ingress.listen(Number(opt["tls-port"]), () => log(`TLS ingress on :${opt["tls-port"]}`));
wsServer.listen(Number(opt["ws-port"]), () => log(`tab tunnel on :${opt["ws-port"]}/tunnel?host=…`));
