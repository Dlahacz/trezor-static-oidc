// Exchange an ID token for temporary AWS credentials (STS AssumeRoleWithWebIdentity)
// and cache them, so an AWS CLI credential_process doesn't need the Trezor on every call.
// AssumeRoleWithWebIdentity is an unsigned call: no AWS credentials are needed for it.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// The AWS CLI refreshes credential_process credentials that expire within 15 minutes.
const MIN_REMAINING_MS = 15 * 60 * 1000;

export function stsEndpoint(region) {
  if (process.env.AWS_ENDPOINT_URL_STS) return process.env.AWS_ENDPOINT_URL_STS.replace(/\/+$/, "");
  return region ? `https://sts.${region}.amazonaws.com` : "https://sts.amazonaws.com";
}

const xmlText = (xml, tag) => {
  const m = xml.match(new RegExp(`<${tag}>([^<]*)</${tag}>`));
  return m && m[1]
    .replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&quot;", '"').replaceAll("&apos;", "'").replaceAll("&amp;", "&");
};

export async function assumeRoleWithWebIdentity({ roleArn, sessionName, token, durationSeconds, region }) {
  const body = new URLSearchParams({
    Action: "AssumeRoleWithWebIdentity",
    Version: "2011-06-15",
    RoleArn: roleArn,
    RoleSessionName: sessionName,
    WebIdentityToken: token,
    ...(durationSeconds ? { DurationSeconds: String(durationSeconds) } : {}),
  });
  const endpoint = stsEndpoint(region);
  const r = await fetch(endpoint + "/", { method: "POST", body });
  const xml = await r.text();
  if (!r.ok) {
    const code = xmlText(xml, "Code") || `HTTP ${r.status}`;
    throw new Error(`AWS STS (${endpoint}) refused the token: ${code}: ${xmlText(xml, "Message") || xml.slice(0, 200)}`);
  }
  const creds = {
    Version: 1,
    AccessKeyId: xmlText(xml, "AccessKeyId"),
    SecretAccessKey: xmlText(xml, "SecretAccessKey"),
    SessionToken: xmlText(xml, "SessionToken"),
    Expiration: xmlText(xml, "Expiration"),
  };
  if (!creds.AccessKeyId || !creds.SecretAccessKey || !creds.SessionToken) throw new Error("AWS STS returned no credentials.");
  return creds;
}

/** Credentials cache in $XDG_CACHE_HOME/trezor-oidc (default ~/.cache/trezor-oidc), readable only by you. */
export function credentialCache(keyParts) {
  const dir = join(process.env.XDG_CACHE_HOME || join(homedir(), ".cache"), "trezor-oidc");
  const file = join(dir, `aws-${createHash("sha256").update(JSON.stringify(keyParts)).digest("hex").slice(0, 32)}.json`);
  return {
    read() {
      try {
        const c = JSON.parse(readFileSync(file, "utf8"));
        if (Date.parse(c.Expiration) - Date.now() > MIN_REMAINING_MS) return c;
      } catch {}
      return null;
    },
    write(c) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      writeFileSync(file, JSON.stringify(c), { mode: 0o600 });
    },
    clear() { rmSync(file, { force: true }); },
  };
}
