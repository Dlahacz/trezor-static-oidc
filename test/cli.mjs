// Command-line tool test, no hardware needed: a software Trezor behind a fake
// Trezor Bridge, the real site build served locally, and a fake AWS STS.
//
//   node test/cli.mjs
import { execFile } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";
import { TrezorClient } from "../js/trezor.js";
import { enrollAccount } from "../js/flows.js";
import { verifyIdToken, fromB64uJson } from "../js/oidc.js";
import { FakeTrezor, fakeBridge } from "./fake-trezor.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "cli/trezor-oidc.mjs");
const work = mkdtempSync(join(tmpdir(), "trezor-oidc-cli-"));
let passed = 0, failed = 0;
const check = async (name, fn) => {
  try { await fn(); console.log(`  ok    ${name}`); passed++; }
  catch (e) { console.log(`  FAIL  ${name}: ${e.message}`); failed++; }
};
const assert = (cond, msg) => { if (!cond) throw new Error(msg); };
const listen = (server) => new Promise((r) => server.listen(0, "127.0.0.1", () => r(server.address().port)));
const run = (cmd, args, env = {}) => new Promise((res) => {
  execFile(cmd, args, { env: { ...process.env, ...env }, timeout: 20000 }, (err, stdout, stderr) =>
    res({ code: err ? (err.code ?? 1) : 0, stdout, stderr }));
});

// ---------------------------------------------------------------- site
const site = createServer(async (req, res) => {
  try {
    const body = await readFile(join(work, "site", decodeURIComponent(new URL(req.url, "http://x").pathname)));
    res.writeHead(200, { "content-type": "application/json" });
    res.end(body);
  } catch {
    res.writeHead(404);
    res.end();
  }
});
const issuer = `http://127.0.0.1:${await listen(site)}`;

const device = new FakeTrezor();
const enroll = (user) => enrollAccount(new TrezorClient(device.transport()), { issuer, user });
const { account: alice } = await enroll("alice");
const { account: bob } = await enroll("bob");

const cfg = join(work, "config");
mkdirSync(cfg);
writeFileSync(join(cfg, "accounts.json"), JSON.stringify([alice, bob]));
writeFileSync(join(cfg, "site.json"), JSON.stringify({ token_ttl: 300 }));

console.log("build");
await check("rejects an app without return addresses or cli", async () => {
  writeFileSync(join(cfg, "clients.json"), JSON.stringify({ bad: { name: "Bad" } }));
  const r = await run("node", [join(ROOT, "scripts/build-site.mjs"), "--issuer", issuer, "--config", cfg, "--out", join(work, "site")]);
  assert(r.code !== 0 && /set "cli": true/.test(r.stdout), r.stdout);
});
await check("accepts a command-line-only app and publishes cli: true", async () => {
  writeFileSync(join(cfg, "clients.json"), JSON.stringify({
    "demo-rp": { name: "Demo app", redirect_uris: ["{{ISSUER}}/rp/"] },
    aws: { name: "AWS", cli: true },
  }));
  const r = await run("node", [join(ROOT, "scripts/build-site.mjs"), "--issuer", issuer, "--config", cfg, "--out", join(work, "site")]);
  assert(r.code === 0, r.stdout + r.stderr);
  const clients = JSON.parse(await readFile(join(work, "site/clients.json"), "utf8"));
  assert(clients.aws.cli === true && clients.aws.redirect_uris.length === 0, JSON.stringify(clients.aws));
  assert(clients["demo-rp"].cli === undefined, "demo-rp must not be a cli app");
});

// ---------------------------------------------------------------- token
const bridge = fakeBridge(device);
const bridgeUrl = `http://127.0.0.1:${await listen(bridge)}`;
const jwks = JSON.parse(await readFile(join(work, "site/jwks.json"), "utf8"));
const cache = join(work, "cache");
const env = { TREZOR_OIDC_ISSUER: issuer, TREZOR_OIDC_CLIENT: "aws", XDG_CACHE_HOME: cache };
const cli = (...args) => run("node", [CLI, ...args, "--transport", "bridge", "--bridge-url", bridgeUrl], env);

console.log("\ntoken");
await check("prints a verifiable ID token on stdout and nothing else", async () => {
  const r = await cli("token", "--account", "alice", "--nonce", "n-123");
  assert(r.code === 0, r.stderr);
  const token = r.stdout.trim();
  assert(r.stdout === token + "\n" && token.split(".").length === 3, `stdout: ${r.stdout}`);
  const { claims } = await verifyIdToken(token, jwks, { issuer, audience: "aws", nonce: "n-123" });
  assert(claims.sub === "alice" && claims.exp - claims.iat === 300, JSON.stringify(claims));
});
await check("--profile adds preferred_username", async () => {
  const r = await cli("token", "--account", "bob", "--profile");
  assert(r.code === 0, r.stderr);
  const claims = fromB64uJson(r.stdout.trim().split(".")[1]);
  assert(claims.sub === "bob" && claims.preferred_username === "bob" && claims.nonce, JSON.stringify(claims));
});
await check("asks for --account when several are registered", async () => {
  const r = await cli("token");
  assert(r.code === 2 && /--account: alice, bob/.test(r.stderr), r.stderr);
});
await check("refuses apps that are not enabled for the command line", async () => {
  const r = await run("node", [CLI, "token", "--account", "alice", "--client", "demo-rp", "--transport", "bridge", "--bridge-url", bridgeUrl], env);
  assert(r.code === 2 && /not enabled for command-line/.test(r.stderr) && !r.stdout, r.stderr);
});
await check("refuses a key that doesn't match the registered one", async () => {
  const other = fakeBridge(new FakeTrezor("another-wallet"));
  const url = `http://127.0.0.1:${await listen(other)}`;
  const r = await run("node", [CLI, "token", "--account", "alice", "--transport", "bridge", "--bridge-url", url], env);
  other.close();
  assert(r.code === 1 && /different key/.test(r.stderr) && !r.stdout, r.stderr);
});
await check("reports a wrong issuer", async () => {
  const r = await run("node", [CLI, "token", "--account", "alice", "--issuer", `${issuer}/nope`, "--transport", "bridge", "--bridge-url", bridgeUrl], env);
  assert(r.code === 1 && /Could not load/.test(r.stderr), r.stderr);
});

// ---------------------------------------------------------------- aws-credentials
const stsCalls = [];
let stsFail = false;
const sts = createServer(async (req, res) => {
  let body = "";
  for await (const c of req) body += c;
  const p = new URLSearchParams(body);
  stsCalls.push(p);
  if (stsFail) {
    res.writeHead(400, { "content-type": "text/xml" });
    return res.end(`<ErrorResponse><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>Incorrect token audience &amp; stuff</Message></Error></ErrorResponse>`);
  }
  const exp = new Date(Date.now() + Number(p.get("DurationSeconds")) * 1000).toISOString();
  res.writeHead(200, { "content-type": "text/xml" });
  res.end(`<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>
<AccessKeyId>ASIATEST</AccessKeyId><SecretAccessKey>secret/key+1</SecretAccessKey><SessionToken>tok/en+=</SessionToken><Expiration>${exp}</Expiration>
</Credentials><SubjectFromWebIdentityToken>${p.get("RoleSessionName")}</SubjectFromWebIdentityToken></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`);
});
env.AWS_ENDPOINT_URL_STS = `http://127.0.0.1:${await listen(sts)}`;
const role = "arn:aws:iam::123456789012:role/example";

console.log("\naws-credentials");
await check("exchanges the token and prints credential_process JSON", async () => {
  const before = device.signCount;
  const r = await cli("aws-credentials", "--account", "alice", "--role-arn", role);
  assert(r.code === 0, r.stderr);
  const c = JSON.parse(r.stdout);
  assert(c.Version === 1 && c.AccessKeyId === "ASIATEST" && c.SecretAccessKey === "secret/key+1" && c.SessionToken === "tok/en+=" && Date.parse(c.Expiration), r.stdout);
  const call = stsCalls.at(-1);
  assert(call.get("Action") === "AssumeRoleWithWebIdentity" && call.get("RoleArn") === role, call.toString());
  assert(call.get("RoleSessionName") === "trezor-alice" && call.get("DurationSeconds") === "3600", call.toString());
  await verifyIdToken(call.get("WebIdentityToken"), jwks, { issuer, audience: "aws" });
  assert(device.signCount === before + 1, "expected one signature");
});
await check("serves cached credentials without the Trezor", async () => {
  const before = device.signCount, calls = stsCalls.length;
  const r = await cli("aws-credentials", "--account", "alice", "--role-arn", role);
  assert(r.code === 0 && JSON.parse(r.stdout).AccessKeyId === "ASIATEST", r.stderr);
  assert(device.signCount === before && stsCalls.length === calls, "cache was not used");
  const files = readdirSync(join(cache, "trezor-oidc"));
  assert(files.length === 1 && files[0].startsWith("aws-"), files.join());
});
await check("--no-cache signs again; short sessions are not reused", async () => {
  let before = device.signCount;
  let r = await cli("aws-credentials", "--account", "alice", "--role-arn", role, "--no-cache");
  assert(r.code === 0 && device.signCount === before + 1, r.stderr);
  before = device.signCount;
  r = await cli("aws-credentials", "--account", "bob", "--role-arn", role, "--duration", "900");
  assert(r.code === 0, r.stderr);
  r = await cli("aws-credentials", "--account", "bob", "--role-arn", role, "--duration", "900");
  assert(r.code === 0 && device.signCount === before + 2, "15-minute credentials should not be served from cache");
});
await check("passes STS errors through", async () => {
  stsFail = true;
  const r = await cli("aws-credentials", "--account", "alice", "--role-arn", role, "--no-cache");
  stsFail = false;
  assert(r.code === 1 && /InvalidIdentityToken: Incorrect token audience & stuff/.test(r.stderr) && !r.stdout, r.stderr);
});
await check("requires --role-arn", async () => {
  const r = await cli("aws-credentials", "--account", "alice");
  assert(r.code === 2 && /--role-arn is required/.test(r.stderr), r.stderr);
});

[site, bridge, sts].forEach((s) => s.close());
rmSync(work, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
