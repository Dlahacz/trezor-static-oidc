// Device flows shared by setup.html, authorize.html and the tests.
import {
  b64u, b64uJson, jwkThumbprint, p256JwkFromCompressed, sameKey, slip13Identity,
  buildSigningInput, assembleJwt, verifyIdToken, discoveryDocument, jwksDocument,
} from "./oidc.js";

const enc = new TextEncoder();

/**
 * Setup: derive the account's signing key from the device and prove it signs
 * valid ES256 JWTs (one confirmation on the Trezor).
 */
export async function enrollAccount(client, { issuer, user, name, index = 0 }) {
  const identity = slip13Identity(issuer, user, index);
  const now = Math.floor(Date.now() / 1000);
  const testSi = `${b64uJson({ alg: "ES256", typ: "JWT" })}.${b64uJson({ iss: issuer, sub: user, aud: "setup-self-test", iat: now })}`;
  const { publicKey, signature } = await client.signIdentity({
    identity,
    challengeHidden: enc.encode(testSi),
    challengeVisual: "Set up sign-in key",
  });
  const jwk = p256JwkFromCompressed(publicKey);
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, enc.encode(testSi));
  if (!ok) throw new Error("The device's test signature did not verify as ES256. Check the firmware version.");
  const thumb = await jwkThumbprint(jwk);
  return {
    account: { sub: user, name: name || undefined, kid: thumb.slice(0, 12), jwk, identity },
    selfTest: `${testSi}.${b64u(signature)}`,
  };
}

/** Files the static host must serve. */
export function buildSiteFiles({ issuer, accounts, clients, tokenTtl = 300 }) {
  return {
    ".well-known/openid-configuration": discoveryDocument(issuer),
    "jwks.json": jwksDocument(accounts),
    "idp-config.json": { issuer, token_ttl: tokenTtl, accounts },
    "clients.json": clients,
  };
}

/**
 * Authorize: sign an ID token for `req` with the account's device key.
 * Refuses to return a token if the device produced a different key (wrong
 * device, wrong passphrase, or wrong identity), since nobody could verify it.
 */
export async function signIdToken(client, { config, account, req, now }) {
  const { signingInput, claims } = buildSigningInput({ issuer: config.issuer, account, req, ttl: config.token_ttl, now });
  const visual = `Sign in to ${req.client.name || req.clientId}`.slice(0, 64);
  const { publicKey, signature } = await client.signIdentity({
    identity: account.identity,
    challengeHidden: enc.encode(signingInput),
    challengeVisual: visual,
  });
  const jwk = p256JwkFromCompressed(publicKey);
  if (!sameKey(jwk, account.jwk)) {
    const err = new Error(
      "This Trezor produced a different key than the one registered for this account. " +
      "Use the same device and passphrase you used during setup.",
    );
    err.keyMismatch = true;
    throw err;
  }
  const idToken = assembleJwt(signingInput, signature);
  // self-check before handing it to the app
  await verifyIdToken(idToken, jwksDocument([account]), {
    issuer: config.issuer, audience: req.clientId, nonce: req.nonce, now: claims.iat,
  });
  return { idToken, claims };
}
