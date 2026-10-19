// OIDC helpers shared by the IdP pages, the demo RP and the tests.
// Implicit flow only (response_type=id_token): a static site has no token endpoint.

export const MAX_SIGNING_INPUT = 512; // SignIdentity.challenge_hidden limit (Trezor One, enforced)

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------- base64url
export function b64u(input) {
  const bytes = typeof input === "string" ? enc.encode(input) : input;
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function b64uDecode(s) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
export const b64uJson = (o) => b64u(JSON.stringify(o));
export const fromB64uJson = (s) => JSON.parse(dec.decode(b64uDecode(s)));

export function randomToken(nBytes = 16) {
  return b64u(crypto.getRandomValues(new Uint8Array(nBytes)));
}

// ---------------------------------------------------------------- keys
const P256 = {
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
};
function modpow(base, exp, mod) {
  let r = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return r;
}
const bigFrom = (bytes) => BigInt("0x" + [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(""));
const bytesFrom = (n, len = 32) => Uint8Array.from(n.toString(16).padStart(len * 2, "0").match(/../g), (h) => parseInt(h, 16));

/** Trezor returns a 33-byte compressed P-256 point; WebCrypto and JWKS want x and y. */
export function p256JwkFromCompressed(pub) {
  if (pub.length !== 33 || (pub[0] !== 2 && pub[0] !== 3)) throw new Error("expected compressed P-256 key");
  const { p, b } = P256;
  const x = bigFrom(pub.subarray(1));
  const y2 = (((x * x * x - 3n * x + b) % p) + p) % p;
  let y = modpow(y2, (p + 1n) / 4n, p);
  if ((y * y) % p !== y2) throw new Error("point not on curve");
  if (Number(y & 1n) !== (pub[0] & 1)) y = p - y;
  return { kty: "EC", crv: "P-256", x: b64u(bytesFrom(x)), y: b64u(bytesFrom(y)) };
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url). */
export async function jwkThumbprint(jwk) {
  const canon = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(canon))));
}

export const sameKey = (a, b) => a && b && a.kty === b.kty && a.crv === b.crv && a.x === b.x && a.y === b.y;

// ---------------------------------------------------------------- IdP config
/**
 * idp-config.json:
 * {
 *   issuer, token_ttl,
 *   accounts: [{ sub, name, kid, jwk, identity: {proto:"ssh", host, user, index} }]
 * }
 */
export function discoveryDocument(issuer) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize.html`,
    jwks_uri: `${issuer}/jwks.json`,
    response_types_supported: ["id_token"],
    response_modes_supported: ["fragment", "form_post"],
    grant_types_supported: ["implicit"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256"],
    scopes_supported: ["openid", "profile"],
    claims_supported: ["iss", "sub", "aud", "exp", "iat", "nonce", "name", "preferred_username"],
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
    claims_parameter_supported: false,
  };
}

export function jwksDocument(accounts) {
  return { keys: accounts.map((a) => ({ ...a.jwk, kid: a.kid, alg: "ES256", use: "sig" })) };
}

/**
 * SLIP-0013 identity for an account: ssh://<user>@<issuer host><issuer path>.
 * The path keeps keys apart for different sites on one host (e.g. two
 * project pages on the same github.io account).
 */
export function slip13Identity(issuer, user, index = 0) {
  const u = new URL(issuer);
  const path = u.pathname.replace(/\/+$/, "");
  return { proto: "ssh", host: u.host, ...(path ? { path } : {}), user, index };
}

/** "user@host/path" as the device shows it. */
export const identityLabel = (id) => `${id.user}@${id.host}${id.port ? ":" + id.port : ""}${id.path || ""}`;

// ---------------------------------------------------------------- authorization request
export class AuthError extends Error {
  /** fatal=true: never redirect (unknown client / redirect_uri). */
  constructor(error, description, fatal = false) {
    super(description);
    this.error = error;
    this.fatal = fatal;
  }
}

export function parseAuthRequest(params, clients) {
  const p = (k) => params.get(k) ?? undefined;
  const clientId = p("client_id");
  const redirectUri = p("redirect_uri");
  if (!clientId) throw new AuthError("invalid_request", "The sign-in link is missing client_id.", true);
  const client = clients[clientId];
  if (!client) throw new AuthError("unauthorized_client", `"${clientId}" is not a registered app on this sign-in service.`, true);
  if (!redirectUri || !client.redirect_uris.includes(redirectUri)) {
    throw new AuthError("invalid_request", `The return address for "${client.name || clientId}" is not registered.`, true);
  }
  const responseMode = p("response_mode") || "fragment";
  const req = {
    client, clientId, redirectUri, responseMode,
    state: p("state"),
    nonce: p("nonce"),
    scope: (p("scope") || "").split(" ").filter(Boolean),
    loginHint: p("login_hint"),
    prompt: p("prompt"),
  };
  if (!["fragment", "form_post"].includes(responseMode)) {
    req.responseMode = "fragment";
    throw Object.assign(new AuthError("invalid_request", "response_mode must be fragment or form_post."), { req });
  }
  const rt = p("response_type");
  if (rt !== "id_token") {
    throw Object.assign(
      new AuthError("unsupported_response_type", "Only response_type=id_token (implicit flow) is supported."),
      { req },
    );
  }
  if (!req.scope.includes("openid")) throw Object.assign(new AuthError("invalid_scope", "scope must include openid."), { req });
  if (!req.nonce) throw Object.assign(new AuthError("invalid_request", "nonce is required for the implicit flow."), { req });
  if (req.prompt && req.prompt.split(" ").includes("none")) {
    throw Object.assign(new AuthError("interaction_required", "Signing in always needs a confirmation on the Trezor."), { req });
  }
  return req;
}

// ---------------------------------------------------------------- ID token
/**
 * Build the JWS signing input, dropping optional profile claims if needed to
 * stay within the device's 512-byte limit.
 */
export function buildSigningInput({ issuer, account, req, ttl = 300, now = Math.floor(Date.now() / 1000) }) {
  const header = { alg: "ES256", typ: "JWT", kid: account.kid };
  const required = { iss: issuer, sub: account.sub, aud: req.clientId, iat: now, exp: now + ttl, nonce: req.nonce };
  const optional = [];
  if (req.scope.includes("profile")) {
    if (account.name) optional.push(["name", account.name]);
    optional.push(["preferred_username", account.identity.user]);
  }
  const make = (claims) => `${b64uJson(header)}.${b64uJson(claims)}`;
  const claims = { ...required };
  for (const [k, v] of optional) {
    const tryClaims = { ...claims, [k]: v };
    if (make(tryClaims).length <= MAX_SIGNING_INPUT) claims[k] = v;
  }
  const si = make(claims);
  if (si.length > MAX_SIGNING_INPUT) {
    throw new AuthError(
      "server_error",
      `The ID token would be ${si.length} bytes; the Trezor can sign at most ${MAX_SIGNING_INPUT}. Use a shorter nonce or client_id.`,
    );
  }
  return { signingInput: si, header, claims };
}

export const assembleJwt = (signingInput, sig64) => `${signingInput}.${b64u(sig64)}`;

// ---------------------------------------------------------------- response
export function authResponse(req, fields) {
  const params = Object.entries({ ...fields, state: req.state }).filter(([, v]) => v !== undefined);
  if (req.responseMode === "form_post") return { method: "POST", action: req.redirectUri, fields: params };
  const frag = new URLSearchParams(params).toString();
  return { method: "GET", url: `${req.redirectUri}#${frag}` };
}

export function sendAuthResponse(doc, resp) {
  if (resp.method === "GET") return doc.location.assign(resp.url);
  const form = doc.createElement("form");
  form.method = "POST";
  form.action = resp.action;
  for (const [k, v] of resp.fields) {
    const input = doc.createElement("input");
    input.type = "hidden";
    input.name = k;
    input.value = v;
    form.append(input);
  }
  doc.body.append(form);
  form.submit();
}

// ---------------------------------------------------------------- verification (RP side)
export async function verifyIdToken(token, jwks, { issuer, audience, nonce, now = Math.floor(Date.now() / 1000), leeway = 60 }) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("ID token is not a compact JWS");
  const header = fromB64uJson(parts[0]);
  const claims = fromB64uJson(parts[1]);
  if (header.alg !== "ES256") throw new Error(`unexpected alg ${header.alg}`);
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error(`no key with kid ${header.kid} in JWKS`);
  const key = await crypto.subtle.importKey(
    "jwk", { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"],
  );
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, key, b64uDecode(parts[2]), enc.encode(`${parts[0]}.${parts[1]}`),
  );
  if (!ok) throw new Error("signature does not verify");
  if (claims.iss !== issuer) throw new Error(`iss is ${claims.iss}, expected ${issuer}`);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(audience)) throw new Error(`aud does not include ${audience}`);
  if (nonce !== undefined && claims.nonce !== nonce) throw new Error("nonce does not match");
  if (typeof claims.exp !== "number" || claims.exp + leeway < now) throw new Error("token has expired");
  if (typeof claims.iat === "number" && claims.iat - leeway > now) throw new Error("token is issued in the future");
  return { header, claims };
}
