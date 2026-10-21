#!/usr/bin/env node
// Command-line ID tokens: sign on the Trezor without a browser and print to stdout.
//
//   trezor-oidc token           --issuer URL --client ID [--account SUB]
//   trezor-oidc aws-credentials --issuer URL --client ID --role-arn ARN
//
// Run with --help for all options.

import { parseArgs } from "node:util";
import { TrezorClient, TrezorFailure, FailureType, PIN_MATRIX_LAYOUT } from "../js/trezor.js";
import { randomToken, identityLabel } from "../js/oidc.js";
import { signIdToken } from "../js/flows.js";
import { openTransport, DEFAULT_BRIDGE_URL } from "./transports.mjs";
import { say, promptHidden } from "./tty.mjs";
import { assumeRoleWithWebIdentity, credentialCache } from "./aws.mjs";

const HELP = `Usage:
  trezor-oidc token [options]
      Sign an ID token on your Trezor and print it to stdout.
  trezor-oidc aws-credentials --role-arn ARN [options]
      Exchange the token with AWS STS (AssumeRoleWithWebIdentity) and print
      credentials in the AWS CLI credential_process format. Cached until
      15 minutes before they expire.

Options:
  --issuer URL             Sign-in site address            [env TREZOR_OIDC_ISSUER]
  --client ID              App ID from clients.json, which
                           must have "cli": true           [env TREZOR_OIDC_CLIENT]
  --account SUB            Account to sign as; needed if the
                           site has more than one          [env TREZOR_OIDC_ACCOUNT]
  --profile                Add the name and preferred_username claims
  --nonce VALUE            Nonce claim (default: random)
  --passphrase-on-device   Enter the wallet passphrase on the Trezor
  --transport T            auto (default), bridge, usb or udp[:port]
                           auto uses Trezor Bridge / Suite if it runs, else USB
  --bridge-url URL         Default ${DEFAULT_BRIDGE_URL}

aws-credentials options:
  --role-arn ARN           Role to assume                  [env TREZOR_OIDC_AWS_ROLE_ARN]
  --session-name NAME      Role session name (default: trezor-<account>)
  --duration SECONDS       Session length, up to the role's maximum (default 3600)
  --region REGION          STS region (default: AWS_REGION, else the global endpoint)
  --no-cache               Always sign a new token

Prompts and device messages go to the terminal (/dev/tty), never to stdout.`;

const { values: opt, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    issuer: { type: "string", default: process.env.TREZOR_OIDC_ISSUER },
    client: { type: "string", default: process.env.TREZOR_OIDC_CLIENT },
    account: { type: "string", default: process.env.TREZOR_OIDC_ACCOUNT },
    profile: { type: "boolean", default: false },
    nonce: { type: "string" },
    "passphrase-on-device": { type: "boolean", default: false },
    transport: { type: "string", default: "auto" },
    "bridge-url": { type: "string", default: DEFAULT_BRIDGE_URL },
    "role-arn": { type: "string", default: process.env.TREZOR_OIDC_AWS_ROLE_ARN },
    "session-name": { type: "string" },
    duration: { type: "string", default: "3600" },
    region: { type: "string", default: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION },
    "no-cache": { type: "boolean", default: false },
    help: { type: "boolean", short: "h", default: false },
  },
});

class UsageError extends Error {}

async function loadSite(issuer) {
  const get = async (name) => {
    const url = `${issuer}/${name}`;
    let r;
    try {
      r = await fetch(url, { cache: "no-store" });
    } catch (e) {
      throw new Error(`Could not load ${url} (${e.cause?.code || e.message}).`);
    }
    if (!r.ok) throw new Error(`Could not load ${url} (HTTP ${r.status}). Is --issuer the sign-in site's address?`);
    return r.json();
  };
  const [config, clients] = await Promise.all([get("idp-config.json"), get("clients.json")]);
  if (config.issuer !== issuer) throw new Error(`The site at ${issuer} says its issuer is ${config.issuer}. Use that as --issuer.`);
  return { config, clients };
}

function pickAccount(config, wanted) {
  const accounts = config.accounts || [];
  if (!accounts.length) throw new Error("No accounts are registered on this sign-in site yet.");
  if (wanted) {
    const a = accounts.find((x) => x.sub === wanted || x.identity.user === wanted);
    if (!a) throw new UsageError(`No account "${wanted}". Registered: ${accounts.map((x) => x.sub).join(", ")}.`);
    return a;
  }
  if (accounts.length > 1) throw new UsageError(`Choose an account with --account: ${accounts.map((x) => x.sub).join(", ")}.`);
  return accounts[0];
}

function pickClient(clients, clientId) {
  const client = clients[clientId];
  if (!client) throw new UsageError(`"${clientId}" is not a registered app. Registered: ${Object.keys(clients).join(", ") || "none"}.`);
  if (client.cli !== true) {
    throw new UsageError(`App "${clientId}" is not enabled for command-line sign-in. Set "cli": true for it in config/clients.json.`);
  }
  return client;
}

async function pinFromTerminal(req) {
  const what = req.type === 2 ? "new PIN" : req.type === 3 ? "new PIN again" : "PIN";
  say(
    `Your Trezor shows a scrambled number grid. Type the positions of your PIN digits using this layout:\n` +
    [0, 3, 6].map((i) => "    " + PIN_MATRIX_LAYOUT.slice(i, i + 3).join(" ")).join("\n"),
  );
  for (;;) {
    const pin = await promptHidden(`Enter ${what} positions: `);
    if (/^[1-9]{1,50}$/.test(pin)) return pin;
    say("Use the digits 1-9 only.");
  }
}

async function issueToken() {
  if (!opt.issuer) throw new UsageError("--issuer is required (or set TREZOR_OIDC_ISSUER).");
  if (!opt.client) throw new UsageError("--client is required (or set TREZOR_OIDC_CLIENT).");
  const issuer = opt.issuer.replace(/\/+$/, "");
  const { config, clients } = await loadSite(issuer);
  const account = pickAccount(config, opt.account);
  const client = pickClient(clients, opt.client);
  const appName = client.name || opt.client;
  const req = {
    clientId: opt.client,
    client,
    nonce: opt.nonce || randomToken(16),
    scope: ["openid", ...(opt.profile ? ["profile"] : [])],
  };

  const transport = await openTransport(opt.transport, { bridgeUrl: opt["bridge-url"] });
  let prompted = false;
  const trezor = new TrezorClient(transport, {
    onButton: () => {
      if (prompted) return;
      prompted = true;
      say(`Confirm on your Trezor: "Sign in to ${appName}" as ${identityLabel(account.identity)}`);
    },
    onPin: pinFromTerminal,
    onPassphrase: async () => {
      if (opt["passphrase-on-device"]) return { onDevice: true };
      return { passphrase: await promptHidden("Wallet passphrase (empty for none): ") };
    },
  });
  try {
    await trezor.initialize();
    const { idToken } = await signIdToken(trezor, { config, account, req });
    return { idToken, account };
  } finally {
    await transport.close();
  }
}

async function awsCredentials() {
  const roleArn = opt["role-arn"];
  if (!roleArn) throw new UsageError("--role-arn is required (or set TREZOR_OIDC_AWS_ROLE_ARN).");
  const durationSeconds = Number(opt.duration);
  if (!Number.isInteger(durationSeconds) || durationSeconds < 900 || durationSeconds > 43200) {
    throw new UsageError("--duration must be a whole number of seconds between 900 and 43200.");
  }
  const cache = credentialCache([opt.issuer, opt.client, opt.account, roleArn, opt["session-name"], opt.region]);
  const cached = !opt["no-cache"] && cache.read();
  if (cached) return cached;

  const { idToken, account } = await issueToken();
  const sessionName = opt["session-name"] || `trezor-${account.sub}`.slice(0, 64);
  const creds = await assumeRoleWithWebIdentity({ roleArn, sessionName, token: idToken, durationSeconds, region: opt.region });
  if (!opt["no-cache"]) cache.write(creds);
  return creds;
}

function explain(e) {
  if (e instanceof TrezorFailure) {
    if (e.code === FailureType.ActionCancelled) return "Cancelled on the Trezor.";
    if (e.code === FailureType.PinInvalid) return "Wrong PIN.";
    if (e.code === FailureType.PinCancelled) return "PIN entry was cancelled.";
    return `The Trezor refused: ${e.message}`;
  }
  return e.message;
}

const command = positionals[0];
if (opt.help || !command) {
  console.log(HELP);
  process.exit(opt.help ? 0 : 2);
}
try {
  if (command === "token") {
    const { idToken } = await issueToken();
    process.stdout.write(idToken + "\n");
  } else if (command === "aws-credentials") {
    process.stdout.write(JSON.stringify(await awsCredentials()) + "\n");
  } else {
    throw new UsageError(`Unknown command "${command}". Use token or aws-credentials.`);
  }
  process.exit(0);
} catch (e) {
  process.stderr.write(`trezor-oidc: ${explain(e)}\n`);
  if (process.env.TREZOR_OIDC_DEBUG) console.error(e);
  process.exit(e instanceof UsageError ? 2 : 1);
}
