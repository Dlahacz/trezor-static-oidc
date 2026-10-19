// End-to-end test against the Trezor emulator: enroll -> site files -> RP
// builds an auth request -> IdP signs ID token on device -> RP verifies.
import { writeFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { TrezorClient } from "../js/trezor.js";
import { parseAuthRequest, authResponse, verifyIdToken, randomToken, AuthError, buildSigningInput } from "../js/oidc.js";
import { enrollAccount, buildSiteFiles, signIdToken } from "../js/flows.js";
import { UdpTransport, debugConfirm } from "./udp-transport.mjs";

const ISSUER = process.env.ISSUER || "http://localhost:8080";
const RP_REDIRECT = `${ISSUER}/rp/`;
let passed = 0, failed = 0;
const check = async (name, fn) => {
  try { await fn(); console.log(`  ok    ${name}`); passed++; }
  catch (e) { console.log(`  FAIL  ${name}: ${e.message}`); failed++; }
};
const expectThrow = async (fn, match) => {
  try { await fn(); } catch (e) { if (!match || match.test(e.message) || match.test(e.error || "")) return e; throw new Error(`wrong error: ${e.message}`); }
  throw new Error("expected an error");
};

const transport = new UdpTransport();
const buttons = [];
const client = new TrezorClient(transport, {
  onButton: (req) => { buttons.push(req.code); debugConfirm(); },
  onPassphrase: async () => ({ passphrase: "" }),
});

const features = await client.initialize();
console.log(`device: ${features.vendor} model ${features.model} fw ${features.major_version}.${features.minor_version}.${features.patch_version}, initialized=${features.initialized}`);

// ---------------------------------------------------------------- setup
console.log("\nsetup");
const { account, selfTest } = await enrollAccount(client, { issuer: ISSUER, user: "alice", name: "Alice Example" });
const { account: bob } = await enrollAccount(client, { issuer: ISSUER, user: "bob", index: 0 });
const clients = { "demo-rp": { name: "Demo app", redirect_uris: [RP_REDIRECT] } };
const files = buildSiteFiles({ issuer: ISSUER, accounts: [account, bob], clients });
await check("enrollment self-test signature verified on device key", async () => { if (!selfTest) throw new Error("no self test"); });
await check("account kid and JWK present", async () => { if (!account.kid || account.jwk.crv !== "P-256") throw new Error(JSON.stringify(account)); });
await check("two accounts derive different keys", async () => { if (account.jwk.x === bob.jwk.x) throw new Error("same key"); });
await check("sites on the same host with different paths derive different keys", async () => {
  const other = new URL(ISSUER).pathname.length > 1 ? new URL(ISSUER).origin : `${ISSUER}/other-site`;
  const { account: a2 } = await enrollAccount(client, { issuer: other, user: "alice" });
  if (a2.jwk.x === account.jwk.x) throw new Error("same key for different paths");
});

// EMIT_CONFIG=<dir>: write the enrolled accounts and apps as a config folder,
// ready for scripts/build-site.mjs --config <dir>.
if (process.env.EMIT_CONFIG) {
  const dir = new URL(`file://${process.env.EMIT_CONFIG.startsWith("/") ? "" : process.cwd() + "/"}${process.env.EMIT_CONFIG}/`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(new URL("accounts.json", dir), JSON.stringify(files["idp-config.json"].accounts, null, 2) + "\n");
  writeFileSync(new URL("clients.json", dir), JSON.stringify({ "demo-rp": { name: "Demo app", redirect_uris: ["{{ISSUER}}/rp/"] } }, null, 2) + "\n");
  writeFileSync(new URL("site.json", dir), JSON.stringify({ issuer: ISSUER, token_ttl: 300 }, null, 2) + "\n");
  console.log("  wrote test config to", process.env.EMIT_CONFIG, "(emulator test seed: never deploy)");
}

// ---------------------------------------------------------------- authorize
console.log("\nauthorize");
const config = files["idp-config.json"];
const jwks = files["jwks.json"];
const state = randomToken(), nonce = randomToken();
const authUrl = new URL(files[".well-known/openid-configuration"].authorization_endpoint);
Object.entries({ client_id: "demo-rp", redirect_uri: RP_REDIRECT, response_type: "id_token", scope: "openid profile", state, nonce })
  .forEach(([k, v]) => authUrl.searchParams.set(k, v));

const req = parseAuthRequest(authUrl.searchParams, clients);
const { idToken, claims } = await signIdToken(client, { config, account, req });
const resp = authResponse(req, { id_token: idToken });
console.log(`  token: ${idToken.length} chars, claims: ${Object.keys(claims).join(", ")}`);

let fragToken;
await check("fragment response returns to registered redirect_uri", async () => {
  const u = new URL(resp.url);
  if (`${u.origin}${u.pathname}` !== RP_REDIRECT) throw new Error(resp.url);
  const frag = new URLSearchParams(u.hash.slice(1));
  if (frag.get("state") !== state) throw new Error("state lost");
  fragToken = frag.get("id_token");
});
await check("RP verifies token with WebCrypto against published JWKS", async () => {
  const { claims: c } = await verifyIdToken(fragToken, jwks, { issuer: ISSUER, audience: "demo-rp", nonce });
  if (c.sub !== "alice" || c.name !== "Alice Example") throw new Error(JSON.stringify(c));
});
await check("PyJWT verifies the same token via the JWKS", async () => {
  const py = `
import json, sys, jwt
jwks = json.loads(sys.argv[1]); tok = sys.argv[2]
kid = jwt.get_unverified_header(tok)["kid"]
key = jwt.PyJWK(next(k for k in jwks["keys"] if k["kid"] == kid))
c = jwt.decode(tok, key, algorithms=["ES256"], audience="demo-rp", issuer=sys.argv[3])
print(c["sub"])`;
  const out = execFileSync("python3", ["-c", py, JSON.stringify(jwks), fragToken, ISSUER]).toString().trim();
  if (out !== "alice") throw new Error(out);
});
await check("tampered payload is rejected", async () => {
  const [h, , s] = fragToken.split(".");
  const forged = Buffer.from(JSON.stringify({ ...claims, sub: "mallory" })).toString("base64url");
  await expectThrow(() => verifyIdToken(`${h}.${forged}.${s}`, jwks, { issuer: ISSUER, audience: "demo-rp", nonce }), /signature/);
});
await check("replay with a different nonce is rejected", async () => {
  await expectThrow(() => verifyIdToken(fragToken, jwks, { issuer: ISSUER, audience: "demo-rp", nonce: "other" }), /nonce/);
});
await check("token for another client is rejected", async () => {
  await expectThrow(() => verifyIdToken(fragToken, jwks, { issuer: ISSUER, audience: "evil-rp", nonce }), /aud/);
});
await check("expired token is rejected", async () => {
  await expectThrow(() => verifyIdToken(fragToken, jwks, { issuer: ISSUER, audience: "demo-rp", nonce, now: claims.exp + 3600 }), /expired/);
});
await check("form_post response carries id_token and state", async () => {
  const r = authResponse({ ...req, responseMode: "form_post" }, { id_token: idToken });
  const f = Object.fromEntries(r.fields);
  if (r.method !== "POST" || r.action !== RP_REDIRECT || f.state !== state || !f.id_token) throw new Error(JSON.stringify(r));
});

// ---------------------------------------------------------------- request validation
console.log("\nrequest validation");
const base = { client_id: "demo-rp", redirect_uri: RP_REDIRECT, response_type: "id_token", scope: "openid", nonce: "n" };
const qp = (o) => new URLSearchParams({ ...base, ...o });
await check("unregistered redirect_uri is fatal (never redirected)", async () => {
  const e = await expectThrow(() => parseAuthRequest(qp({ redirect_uri: "https://evil.example/cb" }), clients));
  if (!e.fatal) throw new Error("not fatal");
});
await check("unknown client is fatal", async () => {
  const e = await expectThrow(() => parseAuthRequest(qp({ client_id: "nope" }), clients));
  if (!e.fatal) throw new Error("not fatal");
});
await check("missing nonce returns invalid_request to the app", async () => {
  const p = qp({}); p.delete("nonce");
  const e = await expectThrow(() => parseAuthRequest(p, clients));
  if (e.fatal || e.error !== "invalid_request" || !e.req) throw new Error(e.error);
});
await check("response_type=code returns unsupported_response_type", async () => {
  const e = await expectThrow(() => parseAuthRequest(qp({ response_type: "code" }), clients));
  if (e.error !== "unsupported_response_type") throw new Error(e.error);
});
await check("prompt=none returns interaction_required", async () => {
  const e = await expectThrow(() => parseAuthRequest(qp({ prompt: "none" }), clients));
  if (e.error !== "interaction_required") throw new Error(e.error);
});
await check("long nonce drops optional profile claims to fit 512 bytes", async () => {
  const r = parseAuthRequest(qp({ scope: "openid profile", nonce: "x".repeat(210) }), clients);
  const { signingInput, claims: c } = buildSigningInput({ issuer: ISSUER, account, req: r });
  if (signingInput.length > 512 || c.name) throw new Error(`${signingInput.length} ${JSON.stringify(c)}`);
});
await check("oversized nonce is refused before touching the device", async () => {
  const r = parseAuthRequest(qp({ nonce: "x".repeat(400) }), clients);
  await expectThrow(() => buildSigningInput({ issuer: ISSUER, account, req: r }), /at most 512/);
});

// ---------------------------------------------------------------- device-side checks
console.log("\ndevice checks");
await check("longest allowed token (512-byte signing input) is signed and verifies", async () => {
  let n = 1;
  let r;
  for (;;) {
    r = parseAuthRequest(qp({ nonce: "y".repeat(n + 1) }), clients);
    try { buildSigningInput({ issuer: ISSUER, account, req: r }); n++; } catch { break; }
  }
  r = parseAuthRequest(qp({ nonce: "y".repeat(n) }), clients);
  const { signingInput } = buildSigningInput({ issuer: ISSUER, account, req: r });
  const { idToken: t } = await signIdToken(client, { config, account, req: r });
  await verifyIdToken(t, jwks, { issuer: ISSUER, audience: "demo-rp", nonce: r.nonce });
  console.log(`        (signing input ${signingInput.length} bytes)`);
});
await check("key mismatch is detected (account registered with another identity)", async () => {
  const wrong = { ...account, identity: { ...account.identity, index: 7 } };
  await expectThrow(() => signIdToken(client, { config, account: wrong, req }), /different key/);
});
await check("device asked for a confirmation on every signature", async () => {
  if (buttons.length < 5) throw new Error(`only ${buttons.length} button requests`);
});

transport.close();
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
