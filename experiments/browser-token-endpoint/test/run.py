#!/usr/bin/env python3
"""
End-to-end experiment: the sign-in tab (real Chromium) answers OAuth token
requests from ordinary HTTPS clients, through a blind relay, with TLS
terminated inside the tab. The Trezor is the emulator, reached through a
navigator.usb shim; DebugLink presses "confirm".

  python3 test/run.py [--emulator PATH] [--out DIR]
"""
import argparse, base64, hashlib, json, os, secrets, socket, subprocess, sys, threading, time
from pathlib import Path
from playwright.sync_api import sync_playwright
import jwt  # PyJWT

HERE = Path(__file__).resolve().parent.parent
ROOT = HERE.parent.parent  # repository root, served over HTTP
ap = argparse.ArgumentParser()
ap.add_argument("--emulator", default="/root/src/trezor-firmware/legacy/firmware/trezor.elf")
ap.add_argument("--emu-dir", default="/root/jwtemu/emu")
ap.add_argument("--out", default=str(HERE / "results"))
ap.add_argument("--transport", choices=["webrtc", "websocket"], default="webrtc")
ap.add_argument("--relay-ip", default=None, help="non-loopback IPv4 of this machine (WebRTC)")
args = ap.parse_args()
OUT = Path(args.out); OUT.mkdir(parents=True, exist_ok=True)

HOST, TLS_PORT, WS_PORT, HTTP_PORT, UDP_PORT = "token.test", 8443, 8090, 8444, 4443
ISSUER = f"https://localhost:{HTTP_PORT}/trezor-oidc-test"
RELAY_IP = args.relay_ip or subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split()[0]
CLIENT_ID, REDIRECT = "grafana", "https://grafana.example/login/generic_oauth"
NOPROXY = {**os.environ, "HTTPS_PROXY": "", "https_proxy": "", "HTTP_PROXY": "", "http_proxy": "", "NO_PROXY": "*", "no_proxy": "*"}

procs = []
def start(cmd, **kw):
    p = subprocess.Popen(cmd, stdout=open(OUT / f"{Path(cmd[1] if cmd[0] in ('node','python3') else cmd[0]).stem}.log", "w"), stderr=subprocess.STDOUT, **kw)
    procs.append(p); return p

def wait_port(port, udp=False, t=10):
    end = time.time() + t
    while time.time() < end:
        try:
            if udp: return True
            socket.create_connection(("127.0.0.1", port), 0.5).close(); return True
        except OSError: time.sleep(0.2)
    raise SystemExit(f"port {port} did not open")

# ---------------------------------------------------------------- infrastructure
start([args.emulator], cwd=args.emu_dir, env={**os.environ, "SDL_VIDEODRIVER": "dummy"}); time.sleep(1.5)
capture = OUT / "relay-capture.txt"
ca_dir = OUT / "ca"
subprocess.run(["python3", str(HERE / "testca.py"), "init", str(ca_dir)], check=True, capture_output=True)
CA = str(ca_dir / "ca.pem")
if args.transport == "webrtc":
    state = OUT / "relay-state"; state.mkdir(exist_ok=True)
    relay_bin = HERE / "relay-webrtc" / "relay-webrtc"
    if not relay_bin.exists():
        subprocess.run(["go", "build", "-o", str(relay_bin), "."], cwd=str(relay_bin.parent), check=True)
    start([str(relay_bin), "-ip", RELAY_IP, "-udp", str(UDP_PORT), "-tls", f":{TLS_PORT}", "-state", str(state), "-capture", str(capture)])
    wait_port(TLS_PORT)
    RELAY = {"kind": "webrtc", **json.loads((state / "relay-info.json").read_text())}
else:
    start(["node", str(HERE / "relay.mjs"), "--tls-port", str(TLS_PORT), "--ws-port", str(WS_PORT), "--capture", str(capture)]); wait_port(WS_PORT)
    RELAY = {"kind": "websocket", "url": f"ws://localhost:{WS_PORT}/tunnel"}

# the sign-in page is served over HTTPS, as on GitHub Pages (certificate from the test CA)
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives import serialization as _ser
_k = _ec.generate_private_key(_ec.SECP256R1())
_spki = base64.b64encode(_k.public_key().public_bytes(_ser.Encoding.DER, _ser.PublicFormat.SubjectPublicKeyInfo)).decode()
_leaf = subprocess.run(["python3", str(HERE / "testca.py"), "issue", str(ca_dir), _spki, "localhost"], capture_output=True, text=True, check=True).stdout.strip()
(OUT / "site.pem").write_text("-----BEGIN CERTIFICATE-----\n" + _leaf + "\n-----END CERTIFICATE-----\n")
(OUT / "site.key").write_bytes(_k.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption()))
start(["python3", "-c", f"""
import http.server, ssl, functools
h = functools.partial(http.server.SimpleHTTPRequestHandler, directory={str(ROOT)!r})
s = http.server.ThreadingHTTPServer(("127.0.0.1", {HTTP_PORT}), h)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain({str(OUT / "site.pem")!r}, {str(OUT / "site.key")!r})
s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()"""]); wait_port(HTTP_PORT)

# ---------------------------------------------------------------- emulator bridge for navigator.usb
main = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); main.settimeout(60)
confirm_delay = [0.4]
def debug_confirm():
    time.sleep(confirm_delay[0])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(bytes([0x3F, 0x23, 0x23, 0x00, 100, 0, 0, 0, 2, 0x08, 0x01]).ljust(64, b"\0"), ("127.0.0.1", 21325)); s.close()
def usb_out(b64): main.sendto(base64.b64decode(b64), ("127.0.0.1", 21324))
def usb_in():
    pkt, _ = main.recvfrom(64)
    if pkt[:3] == b"?##" and int.from_bytes(pkt[3:5], "big") == 26:
        threading.Thread(target=debug_confirm, daemon=True).start()
    return base64.b64encode(pkt).decode()
SHIM = (Path(__file__).parent / "usb_shim.js").read_text()

# ---------------------------------------------------------------- HTTPS clients (the "apps")
GO_CLIENT = OUT / "client.go"
GO_CLIENT.write_text("""package main
// Token request the way golang.org/x/oauth2 (used by Grafana) sends it: client id in HTTP Basic auth.
import ("crypto/tls";"crypto/x509";"encoding/json";"fmt";"net/http";"net/url";"os";"strings";"time")
func main(){ pool:=x509.NewCertPool(); pem,_:=os.ReadFile(os.Args[1]); pool.AppendCertsFromPEM(pem)
 dial:="127.0.0.1:"+os.Args[2]
 tr:=&http.Transport{TLSClientConfig:&tls.Config{RootCAs:pool}, Proxy:nil}
 tr.DialContext=nil; tr.DialTLSContext=nil
 tr.TLSClientConfig.ServerName="token.test"
 c:=&http.Client{Transport:&rewrite{tr,dial}}
 form:=url.Values{"grant_type":{"authorization_code"},"code":{os.Args[3]},"redirect_uri":{os.Args[4]},"code_verifier":{os.Args[5]}}
 req,_:=http.NewRequest("POST","https://token.test/token",strings.NewReader(form.Encode()))
 req.Header.Set("Content-Type","application/x-www-form-urlencoded"); req.SetBasicAuth("grafana","unused-secret")
 t0:=time.Now(); r,err:=c.Do(req); if err!=nil { fmt.Println(`{"client_error":"`+err.Error()+`"}`); os.Exit(0) }
 var out map[string]any; json.NewDecoder(r.Body).Decode(&out); out["_status"]=r.StatusCode; out["_ms"]=time.Since(t0).Milliseconds()
 b,_:=json.Marshal(out); fmt.Println(string(b)) }
type rewrite struct{ t *http.Transport; addr string }
func (r *rewrite) RoundTrip(q *http.Request)(*http.Response,error){ q2:=q.Clone(q.Context()); q2.URL.Host=r.addr; q2.Host="token.test"; return r.t.RoundTrip(q2) }
""")
subprocess.run(["go", "build", "-o", str(OUT / "goclient"), str(GO_CLIENT)], check=True, env={**NOPROXY, "GOTOOLCHAIN": "local", "GO111MODULE": "off"})

def token_request(kind, code, verifier, redirect=REDIRECT, client=CLIENT_ID):
    url = f"https://{HOST}:{TLS_PORT}/token"
    form = f"grant_type=authorization_code&code={code}&redirect_uri={redirect}&client_id={client}&code_verifier={verifier}"
    t0 = time.time()
    if kind == "curl":
        r = subprocess.run(["curl", "-sS", "--noproxy", "*", "--cacert", CA, "--resolve", f"{HOST}:{TLS_PORT}:127.0.0.1",
                            "-w", "\n%{http_code} %{time_appconnect}", "-d", form, url], capture_output=True, text=True, env=NOPROXY, timeout=120)
        body, meta = r.stdout.rsplit("\n", 1) if "\n" in r.stdout else (r.stdout, "0 0")
        status, tls_s = meta.split()
        out = json.loads(body) if body.strip().startswith("{") else {"client_error": r.stderr.strip()}
        out["_status"], out["_tls_ms"] = int(status), round(float(tls_s) * 1000)
    elif kind == "python":
        r = subprocess.run(["python3", "-c", f"""
import json, ssl, socket, urllib.request, urllib.error
ctx = ssl.create_default_context(cafile={CA!r})
orig = socket.getaddrinfo
socket.getaddrinfo = lambda h, *a, **k: orig("127.0.0.1" if h == {HOST!r} else h, *a, **k)
try:
    r = urllib.request.urlopen(urllib.request.Request({url!r}, data={form.encode()!r}), context=ctx, timeout=120)
    out = json.loads(r.read()); out["_status"] = r.status
except urllib.error.HTTPError as e:
    out = json.loads(e.read()); out["_status"] = e.code
print(json.dumps(out))"""], capture_output=True, text=True, env=NOPROXY, timeout=150)
        out = json.loads(r.stdout or json.dumps({"client_error": r.stderr[-300:]}))
    elif kind == "node":
        r = subprocess.run(["node", "-e", f"""
const https=require("https"),fs=require("fs");
const q=https.request({{host:"127.0.0.1",port:{TLS_PORT},path:"/token",method:"POST",servername:{json.dumps(HOST)},ca:fs.readFileSync({json.dumps(CA)}),headers:{{"content-type":"application/x-www-form-urlencoded"}}}},
 res=>{{let d="";res.on("data",c=>d+=c);res.on("end",()=>{{const o=JSON.parse(d);o._status=res.statusCode;console.log(JSON.stringify(o))}})}});
q.on("error",e=>console.log(JSON.stringify({{client_error:e.message}})));q.end({json.dumps(form)});"""], capture_output=True, text=True, env=NOPROXY, timeout=150)
        out = json.loads(r.stdout or json.dumps({"client_error": r.stderr[-300:]}))
    elif kind == "go":
        r = subprocess.run([str(OUT / "goclient"), CA, str(TLS_PORT), code, redirect, verifier], capture_output=True, text=True, env=NOPROXY, timeout=150)
        out = json.loads(r.stdout or json.dumps({"client_error": r.stderr[-300:]}))
    out["_wall_ms"] = round((time.time() - t0) * 1000)
    return out

def pumped(page, fn, *a, **k):
    """Run a blocking client call in a thread while Playwright keeps serving the page's USB calls."""
    box = {}
    t = threading.Thread(target=lambda: box.update(r=fn(*a, **k)), daemon=True)
    t.start()
    while t.is_alive():
        page.wait_for_timeout(20)
    return box["r"]

def pkce():
    v = secrets.token_urlsafe(48)
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()

# ---------------------------------------------------------------- run
results, secrets_seen = {"checks": [], "timings": []}, []
def check(name, ok, detail=""):
    results["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}" + (f": {detail}" if detail and not ok else ""))

with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(ignore_https_errors=True)
    ctx.expose_function("__usbOut", usb_out); ctx.expose_function("__usbIn", usb_in)
    ctx.add_init_script(SHIM)
    page = ctx.new_page()
    page.on("console", lambda m: m.type == "error" and print("   [page]", m.text))
    page.goto(f"https://localhost:{HTTP_PORT}/experiments/browser-token-endpoint/page.html")
    check("plain ws:// to a relay is blocked from the HTTPS page (why WebSocket would need a relay certificate)", page.evaluate("(u) => spike.tryInsecureWebSocket(u)", f"ws://{RELAY_IP}:{WS_PORT}/tunnel").startswith("blocked"))
    page.wait_for_function("window.spike !== undefined")
    dev = page.evaluate("spike.connect()")
    print(f"device: model {dev['model']} firmware {dev['version']}")
    account = page.evaluate("([i,u]) => spike.enroll(i,u)", [ISSUER, "alice"])
    jwk = jwt.PyJWK({**account["jwk"], "alg": "ES256", "kid": account["kid"]})

    for mode in ["webcrypto", "trezor"]:
        print(f"\n[{mode} TLS key]")
        key = page.evaluate("([m,h]) => spike.setupKey(m,h)", [mode, HOST])
        if mode == "trezor":
            v = json.loads(subprocess.run(["python3", str(HERE / "testca.py"), "verify-csr", key["csr"]], capture_output=True, text=True).stdout)
            check("Trezor-signed CSR verifies (what Let's Encrypt would receive)", v["signature_valid"] and v["san"] == [HOST] and v["public_key"] == key["spki"],
                  json.dumps(v))
            print(f"        (CSR body {key['csrInfoBytes']} bytes, within the 512-byte SignIdentity limit)")
        leaf = subprocess.run(["python3", str(HERE / "testca.py"), "issue", str(ca_dir), key["spki"], HOST], capture_output=True, text=True, check=True).stdout.strip()
        if RELAY["kind"] == "webrtc" and mode == "webcrypto":
            bad = {**RELAY, "certhash": RELAY["certhash"][:-2] + ("00" if not RELAY["certhash"].endswith("00") else "11")}
            err = page.evaluate("async ([r,h]) => { const { connectWebRTC } = await import('./tunnel.js'); try { await connectWebRTC(r, h, { timeoutMs: 5000 }); return 'connected'; } catch (e) { return String(e); } }", [bad, "attacker.test"])
            check("relay with a different certificate than the pinned fingerprint is refused", err != "connected", err)
        tun = page.evaluate("([r,h,l]) => spike.startTunnel(r,h,l)", [RELAY, HOST, leaf])
        check(f"tab connected to relay over {tun['link']} from an HTTPS page, no signaling server", tun["link"] == RELAY["kind"])
        results["timings"].append({"mode": mode, "relay_link": tun["link"], "connect_ms": tun["ms"]})

        for kind in ["curl", "python", "node", "go"]:
            verifier, challenge = pkce()
            nonce = secrets.token_urlsafe(16)
            a = page.evaluate("(o) => spike.authorize(o)", {"clientId": CLIENT_ID, "clientName": "Grafana", "redirectUri": REDIRECT, "nonce": nonce, "codeChallenge": challenge})
            secrets_seen += [a["code"], verifier, a["idToken"].split(".")[1][:40]]
            out = pumped(page, token_request, kind, a["code"], verifier)
            ok = out.get("_status") == 200 and out.get("id_token") == a["idToken"] and out.get("access_token")
            claims = {}
            if ok:
                claims = jwt.decode(out["id_token"], jwk, algorithms=["ES256"], audience=CLIENT_ID, issuer=ISSUER)
            check(f"{kind}: token exchange through relay, ID token verifies", ok and claims.get("nonce") == nonce, json.dumps(out)[:300])
            results["timings"].append({"mode": mode, "client": kind, "wall_ms": out["_wall_ms"], "tls_ms": out.get("_tls_ms")})
            if kind == "curl":
                again = pumped(page, token_request, "curl", a["code"], verifier)
                check("replayed code is rejected", again.get("_status") == 400 and again.get("error") == "invalid_grant", json.dumps(again))
                v2, c2 = pkce()
                b = page.evaluate("(o) => spike.authorize(o)", {"clientId": CLIENT_ID, "clientName": "Grafana", "redirectUri": REDIRECT, "nonce": "n", "codeChallenge": c2})
                bad = pumped(page, token_request, "curl", b["code"], "wrong-" + v2)
                check("wrong PKCE verifier is rejected", bad.get("_status") == 400 and bad.get("error") == "invalid_grant", json.dumps(bad))
                c3 = page.evaluate("(o) => spike.authorize(o)", {"clientId": CLIENT_ID, "clientName": "Grafana", "redirectUri": REDIRECT, "nonce": "n", "codeChallenge": c2})
                other = pumped(page, token_request, "curl", c3["code"], v2, client="someone-else")
                check("code issued to another client is rejected", other.get("_status") in (400, 401), json.dumps(other))

        if mode == "trezor":
            verifier, challenge = pkce()
            a = page.evaluate("(o) => spike.authorize(o)", {"clientId": CLIENT_ID, "clientName": "Grafana", "redirectUri": REDIRECT, "nonce": "slow", "codeChallenge": challenge})
            confirm_delay[0] = 8.0
            out = pumped(page, token_request, "go", a["code"], verifier)
            check("Go client waits through an 8 s button press during the handshake", out.get("_status") == 200, json.dumps(out)[:200])
            results["timings"].append({"mode": "trezor, 8 s press", "client": "go", "wall_ms": out["_wall_ms"]})
            confirm_delay[0] = 0.4

    events = page.evaluate("spike.events")
    browser.close()

# ---------------------------------------------------------------- blindness of the relay
raw = b"".join(base64.b64decode(line.split()[2]) for line in capture.read_text().splitlines() if line.strip())
leaks = [s for s in secrets_seen if s.encode() in raw] + [m for m in [b"grant_type", b"HTTP/1.1", b"id_token", b"code_verifier"] if m in raw]
check(f"relay saw {len(raw)} bytes and none of the codes, verifiers, tokens or HTTP text", not leaks, repr(leaks[:3]))
check("relay could read the SNI host name (expected: used for routing)", HOST.encode() in raw)

hs = [e for e in events if e["name"] == "handshake"]
for e in hs:
    results["timings"].append({"handshake_ms": e["ms"], "group": e.get("group"), "sign_ms": e.get("signMs"), "alpn": e.get("alpn")})
results["events"] = events
(OUT / "results.json").write_text(json.dumps(results, indent=2))
print("\ntimings (ms):")
for t in results["timings"]:
    print("  ", t)
for p_ in procs: p_.terminate()
failed = [c for c in results["checks"] if not c["ok"]]
print(f"\n{len(results['checks']) - len(failed)} passed, {len(failed)} failed")
sys.exit(1 if failed else 0)
