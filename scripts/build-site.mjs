#!/usr/bin/env node
// Build the deployable static site: copy the pages and generate the OIDC
// documents (discovery, JWKS, idp-config, clients) from config/, after
// checking that every account key and app registration is usable.
//
//   node scripts/build-site.mjs [--issuer URL] [--config DIR] [--out DIR]
//
// Settings are taken from, highest priority first:
//   command-line flags
//   environment: OIDC_ISSUER, OIDC_TOKEN_TTL, OIDC_ACCOUNTS (JSON), OIDC_CLIENTS (JSON)
//   files: <config>/site.json, <config>/accounts.json, <config>/clients.json

import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, appendFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import {
  discoveryDocument, jwksDocument, jwkThumbprint, buildSigningInput, MAX_SIGNING_INPUT, b64uDecode,
  slip13Identity, identityLabel,
} from "../js/oidc.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const STATIC = ["index.html", "authorize.html", "setup.html", "rp", "css", "js"];
const GH = !!process.env.GITHUB_ACTIONS;

const { values: args } = parseArgs({
  options: {
    issuer: { type: "string" },
    config: { type: "string", default: join(ROOT, "config") },
    out: { type: "string", default: join(ROOT, "_site") },
  },
});

const errors = [], warnings = [];
const fail = (msg) => errors.push(msg);
const warn = (msg) => warnings.push(msg);
const env = (k) => (process.env[k] && process.env[k].trim() !== "" ? process.env[k].trim() : undefined);

function readJson(label, envName, file, fallback) {
  const raw = env(envName);
  const source = raw !== undefined ? `${envName} variable` : relative(ROOT, file) || file;
  try {
    if (raw !== undefined) return { value: JSON.parse(raw), source };
    if (!existsSync(file)) return { value: fallback, source: `${source} (missing, using default)` };
    return { value: JSON.parse(readFileSync(file, "utf8")), source };
  } catch (e) {
    fail(`${label}: ${source} is not valid JSON (${e.message}).`);
    return { value: fallback, source };
  }
}

// ---------------------------------------------------------------- settings
const site = readJson("Site settings", "__none__", join(args.config, "site.json"), {}).value;
const issuerRaw = args.issuer || env("OIDC_ISSUER") || site.issuer;
let issuer, issuerHost;
if (!issuerRaw) {
  fail("No issuer. Set OIDC_ISSUER, pass --issuer, or set \"issuer\" in config/site.json. In GitHub Actions it comes from the Pages URL.");
} else {
  issuer = String(issuerRaw).replace(/\/+$/, "");
  try {
    const u = new URL(issuer);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
    if (u.protocol !== "https:" && !(local && u.protocol === "http:")) fail(`Issuer ${issuer} must use https (http is allowed only for localhost).`);
    if (u.search || u.hash) fail(`Issuer ${issuer} must not have a query or fragment.`);
    issuerHost = u.host;
  } catch {
    fail(`Issuer "${issuerRaw}" is not a valid URL.`);
  }
}

const ttlRaw = env("OIDC_TOKEN_TTL") ?? site.token_ttl ?? 300;
const tokenTtl = Number(ttlRaw);
if (!Number.isInteger(tokenTtl) || tokenTtl < 60 || tokenTtl > 3600) fail(`Token lifetime ${ttlRaw} must be a whole number of seconds between 60 and 3600.`);

const accountsIn = readJson("Accounts", "OIDC_ACCOUNTS", join(args.config, "accounts.json"), []);
const clientsIn = readJson("Apps", "OIDC_CLIENTS", join(args.config, "clients.json"), {});

// ---------------------------------------------------------------- accounts
const accounts = [];
if (!Array.isArray(accountsIn.value)) fail(`Accounts in ${accountsIn.source} must be a JSON array.`);
else {
  const subs = new Set(), kids = new Set();
  for (const [i, a] of accountsIn.value.entries()) {
    const where = `Account ${a?.sub ? `"${a.sub}"` : `#${i + 1}`} in ${accountsIn.source}`;
    if (!a || typeof a !== "object") { fail(`${where} is not an object.`); continue; }
    const before = errors.length;
    if (typeof a.sub !== "string" || !/^[A-Za-z0-9._-]{1,32}$/.test(a.sub)) fail(`${where}: "sub" must be 1-32 letters, digits, dots, dashes or underscores.`);
    else if (subs.has(a.sub)) fail(`${where}: "sub" is used by another account.`);
    if (a.name !== undefined && (typeof a.name !== "string" || a.name.length > 40)) fail(`${where}: "name" must be text of at most 40 characters.`);
    const id = a.identity || {};
    if (id.proto !== "ssh") fail(`${where}: identity.proto must be "ssh"; register the account again with setup.html.`);
    if (typeof id.user !== "string" || !id.user) fail(`${where}: identity.user is missing.`);
    if (!Number.isInteger(id.index ?? 0) || (id.index ?? 0) < 0 || (id.index ?? 0) > 0xffffffff) fail(`${where}: identity.index must be a 32-bit unsigned integer.`);
    if (issuerHost) {
      const want = slip13Identity(issuer, id.user || "", 0);
      if (id.host !== want.host || (id.path || "") !== (want.path || "")) {
        const was = `${id.host}${id.path || ""}`, now = `${want.host}${want.path || ""}`;
        fail(`${where} was registered for ${was}, but the site is served from ${now}. The address is part of the key, so register this account again with setup.html on ${issuer}.`);
      }
    }
    const jwk = a.jwk || {};
    if (jwk.kty !== "EC" || jwk.crv !== "P-256") fail(`${where}: jwk must be an EC P-256 key.`);
    else {
      try {
        if (b64uDecode(jwk.x).length !== 32 || b64uDecode(jwk.y).length !== 32) throw new Error("coordinates must be 32 bytes");
        await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
        const expectedKid = (await jwkThumbprint(jwk)).slice(0, 12);
        if (a.kid !== expectedKid) fail(`${where}: kid is "${a.kid}" but the key's thumbprint gives "${expectedKid}". Copy the account from setup.html unchanged.`);
        else if (kids.has(a.kid)) fail(`${where}: the same key is registered twice.`);
      } catch (e) {
        fail(`${where}: jwk is not a valid P-256 public key (${e.message}).`);
      }
    }
    if (errors.length === before) {
      subs.add(a.sub);
      kids.add(a.kid);
      accounts.push({
        sub: a.sub,
        ...(a.name ? { name: a.name } : {}),
        kid: a.kid,
        jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
        identity: { proto: "ssh", host: id.host, ...(id.path ? { path: id.path } : {}), user: id.user, index: id.index ?? 0 },
      });
    }
  }
  if (accountsIn.value.length === 0) warn("No accounts are registered yet. After this deploy, open setup.html on the site, then add the account it gives you to config/accounts.json.");
}

// ---------------------------------------------------------------- clients
const clients = {};
if (!clientsIn.value || typeof clientsIn.value !== "object" || Array.isArray(clientsIn.value)) {
  fail(`Apps in ${clientsIn.source} must be a JSON object keyed by app ID.`);
} else {
  for (const [cid, c] of Object.entries(clientsIn.value)) {
    const where = `App "${cid}" in ${clientsIn.source}`;
    const before = errors.length;
    if (!/^[A-Za-z0-9._:-]{1,64}$/.test(cid)) fail(`${where}: the app ID may only contain letters, digits and . _ : - (at most 64).`);
    if (!c || typeof c !== "object") { fail(`${where} is not an object.`); continue; }
    if (c.name !== undefined && (typeof c.name !== "string" || c.name.length > 48)) fail(`${where}: "name" must be text of at most 48 characters.`);
    const uris = Array.isArray(c.redirect_uris) ? c.redirect_uris : [];
    if (!uris.length) fail(`${where}: "redirect_uris" must list at least one return address.`);
    const resolved = uris.map((u) => String(u).replaceAll("{{ISSUER}}", issuer ?? ""));
    for (const u of issuer ? resolved : []) {
      try {
        const url = new URL(u);
        const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
        if (url.protocol !== "https:" && !(local && url.protocol === "http:")) fail(`${where}: return address ${u} must use https (http only for localhost).`);
        if (url.hash) fail(`${where}: return address ${u} must not contain a fragment.`);
      } catch {
        fail(`${where}: return address "${u}" is not an absolute URL.`);
      }
    }
    if (errors.length === before) clients[cid] = { ...(c.name ? { name: c.name } : {}), redirect_uris: resolved };
  }
  if (!Object.keys(clients).length && !errors.length) warn("No apps are registered, so nobody can sign in. Add one to config/clients.json.");
}

// ---------------------------------------------------------------- size check
// Typical request: 22-43 character nonce. Warn if an account/app pair leaves no room.
if (issuer && !errors.length) {
  for (const a of accounts) {
    for (const [cid, c] of Object.entries(clients)) {
      const req = { clientId: cid, client: c, nonce: "x".repeat(43), scope: ["openid", "profile"] };
      try {
        const { signingInput, claims } = buildSigningInput({ issuer, account: a, req, ttl: tokenTtl, now: 2_000_000_000 });
        if (!claims.name && a.name) warn(`Tokens for "${a.sub}" at "${cid}" are close to the ${MAX_SIGNING_INPUT}-byte limit (${signingInput.length}); the name claim will be left out.`);
      } catch {
        fail(`Tokens for "${a.sub}" at "${cid}" would exceed the Trezor's ${MAX_SIGNING_INPUT}-byte limit even with a 43-character nonce. Use a shorter issuer, app ID or username.`);
      }
    }
  }
}

// ---------------------------------------------------------------- report / write
const report = (level, msgs) => msgs.forEach((m) => console.log(GH ? `::${level}::${m}` : `${level}: ${m}`));
report("warning", warnings);
if (errors.length) {
  report("error", errors);
  console.log(`\nBuild failed with ${errors.length} problem${errors.length > 1 ? "s" : ""}.`);
  process.exit(1);
}

const out = resolve(args.out);
if (out === ROOT || ROOT.startsWith(out + "/")) { console.error("Refusing to write over the source folder."); process.exit(1); }
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

const inject = (text) => text.replaceAll("%%ISSUER%%", issuer).replaceAll("%%ISSUER_HOST%%", issuerHost);
function copy(rel) {
  const src = join(ROOT, rel), dst = join(out, rel);
  if (statSync(src).isDirectory()) {
    mkdirSync(dst, { recursive: true });
    for (const f of readdirSync(src)) copy(join(rel, f));
  } else if (rel.endsWith(".html")) {
    writeFileSync(dst, inject(readFileSync(src, "utf8")));
  } else {
    cpSync(src, dst);
  }
}
STATIC.forEach(copy);

const config = { issuer, token_ttl: tokenTtl, accounts };
const files = {
  ".well-known/openid-configuration": discoveryDocument(issuer),
  "jwks.json": jwksDocument(accounts),
  "idp-config.json": config,
  "clients.json": clients,
};
for (const [p, body] of Object.entries(files)) {
  mkdirSync(dirname(join(out, p)), { recursive: true });
  writeFileSync(join(out, p), JSON.stringify(body, null, 2) + "\n");
}
writeFileSync(join(out, ".nojekyll"), "");

const summary = [
  `## Trezor sign-in site`,
  ``,
  `Issuer: \`${issuer}\``,
  ``,
  `Discovery: ${issuer}/.well-known/openid-configuration`,
  ``,
  `| Account | Key ID | Device identity |`,
  `|---|---|---|`,
  ...accounts.map((a) => `| ${a.sub}${a.name ? ` (${a.name})` : ""} | \`${a.kid}\` | \`ssh://${identityLabel(a.identity)}\` #${a.identity.index} |`),
  ...(accounts.length ? [] : [`| none yet: open ${issuer}/setup.html | | |`]),
  ``,
  `| App ID | Name | Return addresses |`,
  `|---|---|---|`,
  ...Object.entries(clients).map(([id, c]) => `| \`${id}\` | ${c.name ?? ""} | ${c.redirect_uris.join("<br>")} |`),
  ``,
  `Sources: ${accountsIn.source}, ${clientsIn.source}. Token lifetime ${tokenTtl}s.`,
].join("\n");
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary + "\n");
console.log(`Built ${relative(process.cwd(), out) || out} for ${issuer}: ${accounts.length} account(s), ${Object.keys(clients).length} app(s).`);
