# Trezor sign-in: a static OpenID Connect provider

A proof of concept OIDC provider made only of static files and deployed with
GitHub Pages. Your Trezor signs the ID tokens over WebUSB, using SLIP-0013
`SignIdentity` in its `ssh` mode, which produces a standard ES256 JWS. No
server, no token endpoint, no secrets in the repository.

```
app ──(authorize link)──▶ authorize.html ──WebUSB──▶ Trezor  (confirm on device)
 ▲                              │
 └──── #id_token=… (or form_post) ◀──┘     app verifies against jwks.json
```

## Repository layout

| Path | Purpose |
|---|---|
| `config/accounts.json` | Registered accounts: username, public key, SLIP-0013 identity. Produced by `setup.html` |
| `config/clients.json` | Apps allowed to sign in and their exact return addresses |
| `config/site.json` | Optional issuer override and token lifetime |
| `scripts/build-site.mjs` | Checks the config and builds the deployable site into `_site/` |
| `.github/workflows/pages.yml` | Builds on every push to `main` and deploys to GitHub Pages |
| `authorize.html` | Authorization endpoint: checks the request, shows consent, signs on the Trezor, returns the token |
| `setup.html` | Registers an account: derives its key on the Trezor and gives you the updated `config/accounts.json` |
| `rp/` | Demo app that signs in and verifies the token in the browser |
| `cli/` | `trezor-oidc` command-line tool: signs a token without a browser and prints it |
| `examples/aws/` | AWS IAM federation: identity provider, role, example bucket, AWS CLI profile |
| `js/` | Dependency-free Trezor protocol v1 client over WebUSB, OIDC helpers, page scripts |

The build generates these files on the site; they are not in the repository:

| Published path | Contents |
|---|---|
| `.well-known/openid-configuration` | Discovery document for the issuer |
| `jwks.json` | Public keys of all accounts |
| `idp-config.json` | Issuer, token lifetime and accounts, read by the pages |
| `clients.json` | Registered apps, with `{{ISSUER}}` resolved |

## Deploy to GitHub Pages

1. Push this folder to a GitHub repository with `main` as the default branch.
2. In the repository, open **Settings → Pages** and set **Source** to **GitHub Actions**.
3. Run the **Deploy sign-in site to GitHub Pages** workflow (it also runs on every push to `main`).
   The first deploy has no accounts yet; the run shows a warning saying so.
4. Open `https://<owner>.github.io/<repo>/setup.html` in Chrome, Edge or Brave, with Trezor Suite closed.
5. Enter a username, click **Register with Trezor** and confirm on the device.
6. Copy the JSON it shows into `config/accounts.json` (there's a link to GitHub's editor) and commit to `main`.
7. When the workflow finishes, open `https://<owner>.github.io/<repo>/rp/` and sign in.

Register more people the same way: setup starts from the accounts already published
and adds or replaces the one you register.

### Configuration

Everything the site publishes comes from `config/`. Repository variables
(**Settings → Secrets and variables → Actions → Variables**) override it:

| Variable | Default | Meaning |
|---|---|---|
| `OIDC_ISSUER` | The repository's Pages URL, custom domain included | Public address of the site |
| `OIDC_TOKEN_TTL` | `token_ttl` in `config/site.json`, else 300 | ID token lifetime in seconds (60–3600) |
| `OIDC_ACCOUNTS` | `config/accounts.json` | JSON array of accounts, if you'd rather not commit them |
| `OIDC_CLIENTS` | `config/clients.json` | JSON object of apps |

Register your own apps in `config/clients.json`. `{{ISSUER}}` in a return address
is replaced with the issuer, which keeps the demo app working wherever the site lives:

```json
{
  "demo-rp": { "name": "Demo app", "redirect_uris": ["{{ISSUER}}/rp/"] },
  "my-app": { "name": "My app", "redirect_uris": ["https://my-app.example/callback"] },
  "aws": { "name": "AWS", "cli": true }
}
```

| App setting | Meaning |
|---|---|
| `name` | Shown on the consent page and on the Trezor ("Sign in to <name>"), at most 48 characters |
| `redirect_uris` | Exact return addresses for browser sign-in. Optional when `cli` is true |
| `cli` | `true` lets the command-line tool issue tokens for this app (no browser, no redirect) |

### What the build checks

The workflow fails, with a message naming the account or app, if:

- an account was registered for a different site address than the issuer (the address is part of the key);
- an account's key is not a valid P-256 point, or its `kid` doesn't match the key's thumbprint;
- two accounts share a username or key;
- an app ID is malformed, has no return address and isn't a `cli` app, or a return address isn't an absolute `https` URL (`http` is allowed for localhost) or contains a fragment;
- an account and app pair would produce tokens over the Trezor's 512-byte limit;
- the issuer isn't `https`, or the token lifetime is out of range.

After deploying, the workflow fetches the published discovery document and
JWKS and checks the issuer matches. Each run's summary lists the accounts and apps.

### Changing the address

Account keys are derived from the full issuer address, host and path. Adding a
custom domain, renaming the repository or moving to another site changes the
issuer, so the build will reject the existing accounts until you register them
again with setup on the new address. Two sites on the same `github.io` host
get different keys because their paths differ.

## For apps (relying parties)

- Discovery: `<issuer>/.well-known/openid-configuration`. For project sites the
  issuer has a path (`https://owner.github.io/repo`); give libraries the full discovery URL.
- `response_type=id_token`, `scope=openid` (optionally `profile`), `nonce` required, `state` recommended.
- `response_mode=fragment` (default) or `form_post`. No code flow, no access tokens, no userinfo.
- Tokens are ES256 with a `kid` from `jwks.json`, valid for 5 minutes by default.
- Claims: `iss`, `sub` (the registered username), `aud`, `iat`, `exp`, `nonce`, and with `profile`, `name` and `preferred_username`.
- GitHub Pages serves JSON with `Access-Control-Allow-Origin: *`, so browser apps on other origins can fetch discovery and keys.

## Command-line tokens

`cli/trezor-oidc.mjs` signs an ID token on the Trezor without a browser and
prints it to stdout, for scripts and tools that accept an OIDC token. The app
must have `"cli": true` in `config/clients.json`.

```sh
npm install && npm link    # optional: "usb" package for direct USB, trezor-oidc on PATH
trezor-oidc token --issuer https://owner.github.io/repo --client aws [--account alice] [--profile]
```

- It reads `idp-config.json` and `clients.json` from the issuer, so it uses
  exactly the accounts and apps the site publishes.
- Device access: through Trezor Bridge or Trezor Suite when they run, else
  directly over USB (Suite closed). `--transport bridge|usb|udp[:port]` forces one;
  `udp` is the emulator.
- Confirmation messages and PIN / passphrase prompts go to the terminal
  (`/dev/tty`), never to stdout. Model One PINs use the scrambled-grid
  positions, as in the browser.
- Same checks as the browser: the token is refused if the device's key doesn't
  match the registered one, and verified before it's printed.
- The `cli` flag is a convenience, not a security boundary: whoever holds a
  registered Trezor can sign tokens for any audience. Relying parties must check
  `aud` and `sub`.

The tool stops at the token. To use it with AWS, pipe it into
`aws sts assume-role-with-web-identity`. [examples/aws](examples/aws/README.md)
shows the identity provider, the role, and an AWS CLI profile built on that pipeline.

## Supported devices and browsers

- Trezor Model One (firmware 1.12.1+), Model T, Safe 3, Safe 5: protocol v1 over WebUSB.
- Not supported: Safe 7 and other devices that only speak the newer encrypted host protocol (THP).
- Chromium-based browsers (WebUSB). Firefox and Safari don't support WebUSB.
- On Linux, install Trezor's udev rules so the browser can open the device.
- PIN: Model One uses the scrambled matrix dialog; newer models ask on the device.
- Passphrase: entered in the page or on the device. A different passphrase gives a different key, and the page refuses to issue a token that wouldn't verify.

## How it works

- Each account's key is derived from the wallet seed at the SLIP-0013 path for
  `ssh://<username>@<issuer host><issuer path>` with the chosen key number.
  Changing the site address, username, key number or passphrase changes the key.
- With `proto: "ssh"` and curve `nist256p1`, the firmware signs
  `sha256(challenge_hidden)`. Putting the JWS signing input in `challenge_hidden`
  yields an ES256 signature; the page drops the leading zero byte of the 65-byte result.
- `challenge_hidden` is limited to 512 bytes on the Model One. The page drops
  optional profile claims to fit and refuses oversized requests before touching
  the device. The longest token tested is 512 bytes of signing input.
- The device shows "Sign SSH", the account (`user@host/path`) and "Sign in to <app>".
  The app name comes from this page, so it helps the user but is not proof.

## Security notes (proof of concept)

- Claims are self-asserted by whoever controls the registered Trezor. Apps should key accounts on `iss` + `sub`.
- Whoever can push to `main` or edit the repository variables can add keys or apps.
  Protect `main` with branch rules and review changes to `config/`.
- Implicit flow puts the token in the browser. Tokens are short-lived and audience- and nonce-bound, but this is weaker than code flow with PKCE.
- `authorize.html` refuses to run in a frame and sends no referrer. GitHub Pages can't set CSP headers, so a meta CSP is used; it cannot block framing on its own.
- No replay cache: an app must check `nonce`, `aud` and `exp`, as the demo does.

## Local development and tests

```sh
# Build for local serving (issuer must match the address you open)
node scripts/build-site.mjs --issuer http://localhost:8080 --out _site
(cd _site && python3 -m http.server 8080)
```

The device code is tested against the Trezor One emulator (built from
trezor-firmware with `EMULATOR=1 DEBUG_LINK=1`), which DebugLink confirms automatically.

```sh
# 0. command-line tool, no hardware: software Trezor behind a fake Bridge, fake AWS STS
node test/cli.mjs

# 1. protocol, OIDC logic and key derivation (22 checks). EMIT_CONFIG writes the
#    emulator-derived accounts as a config folder for the build.
ISSUER=http://localhost:8080/trezor-oidc EMIT_CONFIG=/tmp/testcfg node test/e2e.mjs
node scripts/build-site.mjs --config /tmp/testcfg --out /tmp/www/trezor-oidc

# 2. real pages in Chromium, navigator.usb shimmed to the emulator (12 checks)
(cd /tmp/www && python3 -m http.server 8080) &
python3 test/browser_e2e.py http://localhost:8080/trezor-oidc shots/
```

The emulator uses the public test seed. Never put accounts from a test config
into `config/accounts.json`.

## Experiments

`experiments/browser-token-endpoint/` tests whether the sign-in tab itself can
act as the OAuth token endpoint, so apps that only support the authorization
code flow (like Grafana) can use this provider without a server that can read
tokens. A blind relay forwards encrypted TLS to the tab over a signaling-free
WebRTC data channel, and the tab terminates TLS with a key that can live on the
Trezor. See its README for results and what is still untested. It is not part
of the deployed site.
