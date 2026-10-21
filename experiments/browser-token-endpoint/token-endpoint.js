// OAuth token endpoint served from the sign-in tab. Codes are opaque random
// handles; the signed ID token never leaves this tab except in the token response.
import { b64u, randomToken } from "../../js/oidc.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

export class CodeStore {
  constructor() { this.codes = new Map(); }

  /** Register a freshly signed ID token and return the authorization code for it. */
  issue({ idToken, clientId, redirectUri, codeChallenge, ttl = 60 }) {
    const code = randomToken(32);
    this.codes.set(code, { idToken, clientId, redirectUri, codeChallenge, exp: Date.now() + ttl * 1000, used: false });
    return code;
  }

  /** RFC 6749 4.1.3 + RFC 7636 4.6. Returns [status, json]. */
  async redeem(form, basicClientId) {
    const err = (status, error, error_description) => [status, { error, error_description }];
    if (form.get("grant_type") !== "authorization_code") return err(400, "unsupported_grant_type", "Only authorization_code is supported.");
    const clientId = basicClientId ?? form.get("client_id");
    const code = form.get("code");
    const entry = code && this.codes.get(code);
    if (!entry) return err(400, "invalid_grant", "Unknown code.");
    if (entry.used) { this.codes.delete(code); return err(400, "invalid_grant", "Code was already used."); }
    entry.used = true;
    if (Date.now() > entry.exp) return err(400, "invalid_grant", "Code has expired.");
    if (clientId !== entry.clientId) return err(401, "invalid_client", "Code was issued to another client.");
    if (form.get("redirect_uri") !== entry.redirectUri) return err(400, "invalid_grant", "redirect_uri does not match the authorization request.");
    const verifier = form.get("code_verifier");
    if (entry.codeChallenge) {
      if (!verifier) return err(400, "invalid_grant", "code_verifier is required.");
      const h = b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(verifier))));
      if (h !== entry.codeChallenge) return err(400, "invalid_grant", "code_verifier does not match.");
    } else if (verifier) {
      return err(400, "invalid_grant", "code_verifier sent but no code_challenge was used.");
    }
    return [200, {
      access_token: randomToken(32), // opaque; some clients (Go's x/oauth2) insist on one
      token_type: "Bearer",
      expires_in: 60,
      scope: "openid",
      id_token: entry.idToken,
    }];
  }
}

/** Per-connection HTTP/1.1 handler: feed decrypted bytes, get response bytes once a request is complete. */
export function httpConnection(store, { onRequest } = {}) {
  let buf = new Uint8Array(0);
  let sentContinue = false;
  return async function onBytes(bytes, write) {
    const merged = new Uint8Array(buf.length + bytes.length);
    merged.set(buf); merged.set(bytes, buf.length);
    buf = merged;
    const text = dec.decode(buf);
    const headEnd = text.indexOf("\r\n\r\n");
    if (headEnd < 0) return null;
    const [requestLine, ...headerLines] = text.slice(0, headEnd).split("\r\n");
    const headers = Object.fromEntries(headerLines.map((l) => { const i = l.indexOf(":"); return [l.slice(0, i).trim().toLowerCase(), l.slice(i + 1).trim()]; }));
    const [method, path] = requestLine.split(" ");
    const bodyStart = enc.encode(text.slice(0, headEnd + 4)).length;
    const length = Number(headers["content-length"] || 0);
    if (headers.expect?.toLowerCase() === "100-continue" && !sentContinue && buf.length - bodyStart < length) {
      sentContinue = true;
      await write(enc.encode("HTTP/1.1 100 Continue\r\n\r\n"));
    }
    if (buf.length - bodyStart < length) return null;
    const body = dec.decode(buf.subarray(bodyStart, bodyStart + length));

    let status = 404, json = { error: "not_found" };
    if (method === "POST" && path.split("?")[0].endsWith("/token")) {
      let basicClientId;
      const auth = headers.authorization;
      if (auth?.startsWith("Basic ")) basicClientId = decodeURIComponent(atob(auth.slice(6)).split(":")[0]);
      [status, json] = await store.redeem(new URLSearchParams(body), basicClientId);
    }
    onRequest?.({ method, path, status, error: json.error });
    const out = JSON.stringify(json);
    const reason = { 200: "OK", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found" }[status];
    return enc.encode(
      `HTTP/1.1 ${status} ${reason}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nPragma: no-cache\r\n` +
      `Content-Length: ${enc.encode(out).length}\r\nConnection: close\r\n\r\n${out}`,
    );
  };
}
