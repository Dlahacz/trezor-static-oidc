// Command-line tool test, no hardware needed: a software Trezor behind a fake
// Trezor Bridge, the real site build served locally, and a fake AWS STS for
// the examples/aws glue script.
//
//   node test/cli.mjs
import { execFile } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
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
const env = { TREZOR_OIDC_ISSUER: issuer, TREZOR_OIDC_CLIENT: "aws" };
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

// ---------------------------------------------------------------- AWS CLI glue
// examples/aws/trezor-aws-credentials.sh as a real AWS CLI credential_process,
// with a fake STS. Skipped when the aws command isn't installed.
const stsCalls = [];
const sts = createServer(async (req, res) => {
  let body = "";
  for await (const c of req) body += c;
  const p = new URLSearchParams(body);
  stsCalls.push({ params: p, signed: !!req.headers.authorization });
  const exp = new Date(Date.now() + Number(p.get("DurationSeconds")) * 1000).toISOString();
  res.writeHead(200, { "content-type": "text/xml" });
  res.end(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult>
<Credentials><AccessKeyId>ASIATEST</AccessKeyId><SecretAccessKey>secret/key+1</SecretAccessKey><SessionToken>tok/en+=</SessionToken><Expiration>${exp}</Expiration></Credentials>
<SubjectFromWebIdentityToken>alice</SubjectFromWebIdentityToken>
<AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/example/${p.get("RoleSessionName")}</Arn><AssumedRoleId>AROATEST:${p.get("RoleSessionName")}</AssumedRoleId></AssumedRoleUser>
</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`);
});
const stsUrl = `http://127.0.0.1:${await listen(sts)}`;
const role = "arn:aws:iam::123456789012:role/example";
const hasAws = (await run("aws", ["--version"])).code === 0;

console.log("\nAWS CLI credential_process (examples/aws)");
if (!hasAws) console.log("  skip  aws command not installed");
else await check("token is piped into STS and reshaped into credential_process JSON", async () => {
  const bin = join(work, "bin");
  mkdirSync(bin);
  symlinkSync(CLI, join(bin, "trezor-oidc"));
  const awsConfig = join(work, "aws-config");
  writeFileSync(awsConfig, `[profile trezor]
credential_process = ${join(ROOT, "examples/aws/trezor-aws-credentials.sh")} ${role} --issuer ${issuer} --client aws --account alice --transport bridge --bridge-url ${bridgeUrl}
region = eu-central-1
`);
  const r = await run("aws", ["configure", "export-credentials", "--profile", "trezor"], {
    PATH: `${bin}:${process.env.PATH}`,
    AWS_CONFIG_FILE: awsConfig,
    AWS_SHARED_CREDENTIALS_FILE: join(work, "none"),
    AWS_PROFILE: "trezor", // the inner aws call must not resolve this profile again
    AWS_ENDPOINT_URL_STS: stsUrl,
    USER: "tester",
  });
  assert(r.code === 0, r.stderr);
  const c = JSON.parse(r.stdout);
  assert(c.AccessKeyId === "ASIATEST" && c.SecretAccessKey === "secret/key+1" && c.SessionToken === "tok/en+=", r.stdout);
  assert(stsCalls.length === 1, `expected one STS call, got ${stsCalls.length}`);
  const { params, signed } = stsCalls[0];
  assert(!signed, "STS request should be unsigned");
  assert(params.get("RoleArn") === role && params.get("RoleSessionName") === "trezor-tester" && params.get("DurationSeconds") === "3600", params.toString());
  const token = params.get("WebIdentityToken");
  assert(!/\s/.test(token), "token reached STS with whitespace");
  const { claims } = await verifyIdToken(token, jwks, { issuer, audience: "aws" });
  assert(claims.sub === "alice", JSON.stringify(claims));
});

[site, bridge, sts].forEach((s) => s.close());
rmSync(work, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
