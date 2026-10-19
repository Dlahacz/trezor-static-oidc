// Step 1: the JS TLS 1.3 server behind a plain Node TCP socket (no relay, no browser),
// with a WebCrypto P-256 key, answered by curl / Go / Python / Node clients.
import net from "node:net";
import { execFileSync, execFile } from "node:child_process";
import { promisify } from "node:util";
const execFileP = promisify(execFile);
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Tls13Server } from "../tls13-server.js";

const dir = mkdtempSync(join(tmpdir(), "tls13-"));
const HERE = new URL("..", import.meta.url).pathname;
execFileSync("python3", [join(HERE, "testca.py"), "init", dir]);

const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
const spki = Buffer.from(await crypto.subtle.exportKey("spki", kp.publicKey)).toString("base64");
const leaf = Buffer.from(execFileSync("python3", [join(HERE, "testca.py"), "issue", dir, spki, "token.test"]).toString().trim(), "base64");
const sign = async (content) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, content));

const server = net.createServer((sock) => {
  let req = "";
  const tls = new Tls13Server({
    certChain: [new Uint8Array(leaf)],
    sign,
    send: (b) => sock.write(b),
    onEvent: (n, d) => n === "connected" && (sock.info = d),
    onClose: () => sock.end(),
    onData: async (d) => {
      req += new TextDecoder().decode(d);
      if (!req.includes("\r\n\r\n")) return;
      const body = JSON.stringify({ ok: true, group: sock.info.group, hrr: !!sock.info.helloRetry, alpn: sock.info.alpn });
      await tls.write(new TextEncoder().encode(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`));
      await tls.close();
    },
  });
  sock.on("data", (b) => tls.feed(new Uint8Array(b)));
  sock.on("error", () => {});
});
await new Promise((r) => server.listen(9443, "127.0.0.1", r));

const goSrc = join(dir, "client.go");
writeFileSync(goSrc, `package main
import ("crypto/tls";"crypto/x509";"fmt";"io";"net/http";"os";"strings")
func main(){ pool:=x509.NewCertPool(); pem,_:=os.ReadFile(os.Args[1]); pool.AppendCertsFromPEM(pem)
 tr:=&http.Transport{TLSClientConfig:&tls.Config{RootCAs:pool, ServerName:"token.test"}}
 if len(os.Args)>3 && os.Args[3]=="p256only" { tr.TLSClientConfig.CurvePreferences=[]tls.CurveID{tls.CurveP256} }
 c:=&http.Client{Transport:tr}
 r,err:=c.Post(os.Args[2],"application/x-www-form-urlencoded",strings.NewReader("grant_type=authorization_code"))
 if err!=nil { fmt.Println("ERR",err); os.Exit(1) }
 b,_:=io.ReadAll(r.Body); fmt.Println(string(b)) }`);

const run = async (name, cmd, args, env) => {
  const t0 = Date.now();
  try {
    const { stdout } = await execFileP(cmd, args, { env: { ...process.env, HTTPS_PROXY: "", https_proxy: "", HTTP_PROXY: "", http_proxy: "", NO_PROXY: "*", no_proxy: "*", ...env }, timeout: 60000 });
    console.log(`  ok    ${name.padEnd(30)} ${String(Date.now() - t0).padStart(5)} ms  ${stdout.trim().split("\n").pop()}`);
  } catch (e) {
    console.log(`  FAIL  ${name.padEnd(30)} ${(e.stdout || "").toString().trim()} ${(e.stderr || "").toString().trim().split("\n").slice(-2).join(" ")}`);
  }
};
const url = "https://token.test:9443/token";
const ca = join(dir, "ca.pem");
await run("curl (OpenSSL 3.0)", "curl", ["-sS", "--cacert", ca, "--resolve", "token.test:9443:127.0.0.1", "-d", "grant_type=x", url]);
await run("curl, X448 first (HelloRetry)", "curl", ["-sS", "--cacert", ca, "--resolve", "token.test:9443:127.0.0.1", "--curves", "X448:P-256", "-d", "x=1", url]);
await run("curl, HTTP/2 offered", "curl", ["-sS", "--http2", "--cacert", ca, "--resolve", "token.test:9443:127.0.0.1", "-d", "x=1", url]);
await run("python urllib", "python3", ["-c", `
import ssl, urllib.request, socket
ctx = ssl.create_default_context(cafile="${ca}")
orig = socket.getaddrinfo
socket.getaddrinfo = lambda h, *a, **k: orig("127.0.0.1" if h == "token.test" else h, *a, **k)
print(urllib.request.urlopen(urllib.request.Request("${url}", data=b"grant_type=x"), context=ctx).read().decode())`]);
await run("node https", "node", ["-e", `
const https=require("https");const fs=require("fs");
const r=https.request({host:"127.0.0.1",port:9443,path:"/token",method:"POST",servername:"token.test",ca:fs.readFileSync("${ca}"),headers:{"content-type":"application/x-www-form-urlencoded"}},res=>{let d="";res.on("data",c=>d+=c);res.on("end",()=>console.log(d))});
r.on("error",e=>{console.log("ERR",e.message);process.exit(1)});r.end("grant_type=x")`]);
await run("go net/http (Grafana's stack)", "go", ["run", goSrc, ca, "https://127.0.0.1:9443/token"], { GOFLAGS: "-mod=mod", GOTOOLCHAIN: "local" });
await run("go, P-256 only", "go", ["run", goSrc, ca, "https://127.0.0.1:9443/token", "p256only"], { GOTOOLCHAIN: "local" });
server.close();
