# Experiment: the sign-in tab as the OAuth token endpoint

Question: can a static site support the authorization code flow, for apps like
Grafana that only speak it, without any server that can read tokens?

Idea: the app's backend POSTs to the token endpoint as usual. A **blind relay**
forwards the encrypted TLS stream, routed only by the SNI host name, to the
**sign-in tab**, which terminates TLS itself in JavaScript and answers the
token request. The TLS private key can live **on the Trezor**. The tab reaches
the relay over a **WebRTC data channel without a signaling server**, so the
relay needs no domain and no certificate.

```
Grafana backend ──TLS──▶ relay (sees only SNI + ciphertext) ──WebRTC──▶ sign-in tab
                         IP + UDP port + pinned fingerprint            │  TLS 1.3 server (WebCrypto)
                                                                       │  CertificateVerify signed by Trezor
                                                                       └─ token endpoint: code → ID token
```

## Result: it works

`test/run.py` runs the real page in Chromium, served over HTTPS like GitHub
Pages, with the Trezor One emulator behind a `navigator.usb` shim and real
HTTPS clients as "apps". Over WebRTC, 22 of 22 checks pass:

| Check | Result |
|---|---|
| Tab connects to the relay over WebRTC from an HTTPS page, knowing only IP, port and fingerprint | connects in 64–69 ms, no signaling server |
| Relay presenting a different certificate than the pinned fingerprint | refused |
| Plain `ws://` to a relay from an HTTPS page (why WebSocket would need a relay certificate) | blocked by Chrome |
| Token exchange through the relay: curl (OpenSSL 3.0), Python, Node, Go (Grafana's TLS stack, x/oauth2-style Basic auth) | all succeed, ID token verifies |
| Same, with the TLS key on the Trezor (every handshake signed by the device) | all succeed |
| Replayed code, wrong PKCE verifier, code used by another client | rejected |
| Trezor-signed CSR (what Let's Encrypt would receive), 162-byte body | valid signature, right SAN and key |
| Go client during an 8-second button press in the handshake | waits and succeeds |
| Relay capture (about 36 KB per run) contains codes, verifiers, tokens or HTTP text | none; only the SNI host name |

The earlier WebSocket variant (`relay.mjs`, `--transport websocket`) passed the
same token-endpoint checks; it works only from `localhost` or with a `wss://`
relay certificate.

`test/direct.mjs` also checks the TLS server alone against curl (with HTTP/2
offered, and with a HelloRetryRequest to P-256), Python, Node and Go: all pass.

Timings on the emulator (DebugLink presses after 0.4 s):

| | TLS handshake in the tab | Client total |
|---|---|---|
| Key in browser memory (WebCrypto, non-extractable) | 5–10 ms | 15–117 ms |
| Key on the Trezor | ~430 ms, almost all of it the button press | 440–510 ms |
| Key on the Trezor, 8 s press | 8.0 s | 8.0 s |

With a real person, the Trezor-key variant costs one extra press per sign-in,
during the app's connection.

## How the signaling-free WebRTC link works

This is the approach libp2p calls WebRTC Direct.

1. The relay publishes `{ ip, port, certhash }`; its DTLS certificate is
   self-signed and long-lived, and `certhash` is its SHA-256 fingerprint.
2. The tab creates an offer, replaces its ICE username fragment and password
   with one random 32-character value `U`, and builds the relay's answer itself:
   ICE-lite, ufrag and password `U`, the pinned fingerprint, `setup:passive`, and
   a single host candidate at the published IP and port.
3. The browser sends STUN checks with username `U:U`. The relay's UDP mux sees
   an unknown `U`, creates a peer connection with credentials `U`/`U` and a
   fabricated copy of the browser's offer, and hands it the packet.
4. The browser is the DTLS client and checks the relay's certificate against the
   pinned fingerprint. The data channel is pre-negotiated (id 0), so nothing
   else needs exchanging. The tab then sends a "register this host" frame.

## What's in here

| File | Purpose |
|---|---|
| `tls13-server.js` | TLS 1.3 server on WebCrypto: TLS_AES_128_GCM_SHA256, X25519 or P-256 (with HelloRetryRequest), ECDSA P-256 server key, ALPN http/1.1. No resumption, 0-RTT or client certificates |
| `relay-webrtc/` | Go relay (Pion): ICE-lite, pinned DTLS certificate, UDP mux that accepts unknown ufrags, TLS passthrough by SNI |
| `relay.mjs` | Earlier WebSocket relay, kept for comparison. No dependencies |
| `tunnel.js` | Tab side: `connectWebRTC`, `connectWebSocket`, and the token endpoint served over either link |
| `token-endpoint.js` | Opaque single-use codes, PKCE S256, client and redirect_uri checks, RFC 6749 token response |
| `csr.js` | DER writer for a PKCS#10 CSR signed by the Trezor |
| `page.html`, `page.js` | Experiment page driven by the test |
| `testca.py` | Test CA standing in for Let's Encrypt |
| `test/run.py` | End-to-end run in Chromium with the emulator |
| `test/direct.mjs` | TLS server alone against real clients |
| `results-*.json` | Raw results of the runs |

Run (needs the Trezor One emulator from trezor-firmware built with
`EMULATOR=1 DEBUG_LINK=1`, Playwright and Go):

```sh
(cd relay-webrtc && go mod tidy && go build)
node test/direct.mjs
python3 test/run.py --emulator /path/to/trezor.elf --emu-dir /path/to/emulator/state
python3 test/run.py --transport websocket ...   # earlier variant
```

Running the relay for real: `relay-webrtc -ip <public IPv4> -udp 4443 -tls :443 -state /var/lib/relay`.
Publish the contents of `relay-info.json` in the site config, and point the
token endpoint's DNS name at the relay's IP.

## Not tested yet

- **The tab staying alive in real use.** Here the test drives a single tab. In a
  real sign-in the tab must keep its relay connection until the app's backend
  has called the token endpoint, a second or two after the redirect. The plan is
  to open the app's return address in a new tab at the "Sign in" click and let
  the sign-in tab finish and close itself. Desktop browsers should keep a
  background tab's data channel working for that long; mobile browsers may suspend it.
- **Networks that block UDP.** WebRTC needs UDP to the relay. The usual fallback,
  TURN over TLS, would bring a certificate back.
- **Other browsers.** Only Chromium was tested. Firefox should work (libp2p uses
  the same approach there); Safari is unknown.
- **Registration is not authenticated.** Anyone who can reach the relay can claim
  a host name and break sign-ins for it (they still can't read anything). The tab
  should prove it holds the TLS key by signing a challenge from the relay.
- **A real Grafana.** The Go client mimics how golang.org/x/oauth2 sends the
  token request, but Grafana may also call a userinfo endpoint or need extra
  token fields.
- **Let's Encrypt itself.** The CSR is accepted by a test CA; ACME account
  handling, the HTTP-01 or TLS-ALPN-01 challenge through the relay, and the CAA
  `accounturi` restriction are not built.
- **Security review.** The TLS server and the relay's UDP mux are new, unaudited
  code. They implement only what the handshake needs, but haven't been fuzzed or
  checked against test suites.
- **Concurrent sign-ins.** The relay routes by host name only, so one tab answers
  for the host. That fits a personal sign-in site, not a shared one.
