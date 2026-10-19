// Blind relay with a signaling-free WebRTC link to the sign-in tab.
//
// The relay has no domain and no CA certificate. Tabs reach it at a published
// IP:port and pin its self-signed DTLS certificate by fingerprint. Apps reach
// it over TCP; it reads only the SNI host name from each TLS ClientHello and
// forwards the encrypted stream to the tab registered for that host.
//
// How the WebRTC side works without a signaling server (the libp2p
// "WebRTC Direct" approach):
//   - The tab picks a random ICE ufrag U, uses U as its own ufrag and password,
//     and builds the relay's answer itself from the published IP, port and
//     fingerprint, with ufrag/password U as well.
//   - The relay is ICE-lite. Its UDP mux reads the STUN USERNAME "U:U" of the
//     first packet from an unknown address, creates a peer connection with
//     credentials U/U and a fabricated remote offer, and hands it that packet.
//   - The browser verifies the relay's DTLS certificate against the pinned
//     fingerprint. The relay doesn't need to verify the browser.
//
// Usage: relay-webrtc -ip 203.0.113.7 [-udp 4443] [-tls :8443] [-state DIR] [-capture FILE]
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"github.com/pion/webrtc/v4"
)

const (
	frameOpen     = 1
	frameData     = 2
	frameClose    = 3
	frameRegister = 16 // tab -> relay: payload is the host name
)

var (
	flagIP      = flag.String("ip", "", "IP address tabs connect to (published in the site config)")
	flagUDP     = flag.Int("udp", 4443, "UDP port for tabs (WebRTC)")
	flagTLS     = flag.String("tls", ":8443", "TCP address for apps (TLS passthrough)")
	flagState   = flag.String("state", ".", "directory holding the relay's DTLS certificate")
	flagCapture = flag.String("capture", "", "append every forwarded byte (base64) to this file, for tests")
)

// ---------------------------------------------------------------- certificate
func loadOrCreateCert(dir string) (webrtc.Certificate, string, error) {
	keyPath, certPath := filepath.Join(dir, "relay-key.pem"), filepath.Join(dir, "relay-cert.pem")
	var key *ecdsa.PrivateKey
	var cert *x509.Certificate
	if kb, err := os.ReadFile(keyPath); err == nil {
		cb, err := os.ReadFile(certPath)
		if err != nil {
			return webrtc.Certificate{}, "", err
		}
		kp, _ := pem.Decode(kb)
		cp, _ := pem.Decode(cb)
		if key, err = x509.ParseECPrivateKey(kp.Bytes); err != nil {
			return webrtc.Certificate{}, "", err
		}
		if cert, err = x509.ParseCertificate(cp.Bytes); err != nil {
			return webrtc.Certificate{}, "", err
		}
	} else {
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: "trezor-oidc relay"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().AddDate(10, 0, 0), // pinned by fingerprint, so a long life is fine
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return webrtc.Certificate{}, "", err
		}
		cert, _ = x509.ParseCertificate(der)
		kder, _ := x509.MarshalECPrivateKey(key)
		_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
		_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	}
	wc := webrtc.CertificateFromX509(key, cert)
	fps, err := wc.GetFingerprints()
	if err != nil {
		return webrtc.Certificate{}, "", err
	}
	for _, fp := range fps {
		if fp.Algorithm == "sha-256" {
			return wc, "sha-256 " + strings.ToUpper(fp.Value), nil
		}
	}
	return webrtc.Certificate{}, "", errors.New("no sha-256 fingerprint")
}

// ---------------------------------------------------------------- UDP mux
// A minimal ice.UDPMux that, unlike Pion's default, reports unknown ufrags so a
// peer connection can be created on the fly.
type packet struct {
	data []byte
	addr net.Addr
}

type udpMux struct {
	sock       *net.UDPConn
	advertised *net.UDPAddr
	mu         sync.Mutex
	byUfrag    map[string]*vconn
	byAddr     map[string]*vconn
	onNew      func(ufrag string)
}

func (m *udpMux) loop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := m.sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		data := append([]byte(nil), buf[:n]...)
		m.mu.Lock()
		c := m.byAddr[addr.String()]
		m.mu.Unlock()
		if c == nil {
			if !stun.IsMessage(data) {
				continue
			}
			msg := &stun.Message{Raw: append([]byte(nil), data...)}
			if msg.Decode() != nil {
				continue
			}
			var user stun.Username
			if user.GetFrom(msg) != nil {
				continue
			}
			ufrag := strings.SplitN(string(user), ":", 2)[0]
			if len(ufrag) < 16 {
				continue // too little entropy to be one of ours
			}
			m.mu.Lock()
			c = m.byUfrag[ufrag]
			isNew := c == nil
			if isNew {
				c = m.newConn(ufrag)
			}
			m.byAddr[addr.String()] = c
			m.mu.Unlock()
			if isNew {
				go m.onNew(ufrag)
			}
		}
		select {
		case c.in <- packet{data, addr}:
		default: // queue full, drop like the network would
		}
	}
}

func (m *udpMux) newConn(ufrag string) *vconn {
	c := &vconn{m: m, ufrag: ufrag, in: make(chan packet, 256), closed: make(chan struct{})}
	m.byUfrag[ufrag] = c
	return c
}

func (m *udpMux) GetConn(ufrag string, _ net.Addr) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.byUfrag[ufrag]; c != nil {
		return c, nil
	}
	return m.newConn(ufrag), nil
}

func (m *udpMux) RemoveConnByUfrag(ufrag string) {
	m.mu.Lock()
	c := m.byUfrag[ufrag]
	delete(m.byUfrag, ufrag)
	for a, v := range m.byAddr {
		if v == c {
			delete(m.byAddr, a)
		}
	}
	m.mu.Unlock()
	if c != nil {
		c.closeOnce()
	}
}

func (m *udpMux) GetListenAddresses() []net.Addr { return []net.Addr{m.advertised} }
func (m *udpMux) Close() error                   { return m.sock.Close() }

type vconn struct {
	m        *udpMux
	ufrag    string
	in       chan packet
	closed   chan struct{}
	once     sync.Once
	deadline atomic.Value // time.Time
}

func (c *vconn) closeOnce() { c.once.Do(func() { close(c.closed) }) }

func (c *vconn) ReadFrom(p []byte) (int, net.Addr, error) {
	var timer <-chan time.Time
	if d, ok := c.deadline.Load().(time.Time); ok && !d.IsZero() {
		t := time.NewTimer(time.Until(d))
		defer t.Stop()
		timer = t.C
	}
	select {
	case pk := <-c.in:
		return copy(p, pk.data), pk.addr, nil
	case <-c.closed:
		return 0, nil, io.EOF
	case <-timer:
		return 0, nil, os.ErrDeadlineExceeded
	}
}
func (c *vconn) WriteTo(p []byte, addr net.Addr) (int, error) { return c.m.sock.WriteTo(p, addr) }
func (c *vconn) Close() error                                 { c.m.RemoveConnByUfrag(c.ufrag); return nil }
func (c *vconn) LocalAddr() net.Addr                          { return c.m.advertised }
func (c *vconn) SetDeadline(t time.Time) error                { c.deadline.Store(t); return nil }
func (c *vconn) SetReadDeadline(t time.Time) error            { c.deadline.Store(t); return nil }
func (c *vconn) SetWriteDeadline(time.Time) error             { return nil }

var _ ice.UDPMux = (*udpMux)(nil)

// ---------------------------------------------------------------- tabs
type tab struct {
	dc    *webrtc.DataChannel
	host  string
	mu    sync.Mutex
	conns map[uint32]net.Conn
}

var (
	tabsMu   sync.Mutex
	tabs     = map[string]*tab{}
	nextConn atomic.Uint32
	capMu    sync.Mutex
)

func capture(dir string, conn uint32, b []byte) {
	if *flagCapture == "" {
		return
	}
	capMu.Lock()
	defer capMu.Unlock()
	f, err := os.OpenFile(*flagCapture, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %d %s\n", dir, conn, base64.StdEncoding.EncodeToString(b))
}

func frame(t byte, conn uint32, payload []byte) []byte {
	f := make([]byte, 5+len(payload))
	f[0] = t
	binary.BigEndian.PutUint32(f[1:], conn)
	copy(f[5:], payload)
	return f
}

// fabricatedOffer stands in for the browser's offer, which the relay never receives.
func fabricatedOffer(ufrag string) string {
	fp := strings.TrimSuffix(strings.Repeat("00:", 32), ":") // not verified: the relay doesn't authenticate tabs at this layer
	return strings.Join([]string{
		"v=0", "o=- 0 0 IN IP4 0.0.0.0", "s=-", "t=0 0", "a=group:BUNDLE 0",
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel", "c=IN IP4 0.0.0.0", "a=mid:0",
		"a=ice-ufrag:" + ufrag, "a=ice-pwd:" + ufrag, "a=fingerprint:sha-256 " + fp,
		"a=setup:actpass", "a=sctp-port:5000", "a=max-message-size:262144", "",
	}, "\r\n")
}

func newPeer(mux *udpMux, cert webrtc.Certificate, ufrag string) {
	se := webrtc.SettingEngine{}
	se.SetLite(true)
	se.SetICEUDPMux(mux)
	se.SetICECredentials(ufrag, ufrag)
	se.DisableCertificateFingerprintVerification(true)
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	if err := se.SetAnsweringDTLSRole(webrtc.DTLSRoleServer); err != nil {
		log.Println("dtls role:", err)
		return
	}
	api := webrtc.NewAPI(webrtc.WithSettingEngine(se))
	pc, err := api.NewPeerConnection(webrtc.Configuration{Certificates: []webrtc.Certificate{cert}})
	if err != nil {
		log.Println("peer:", err)
		return
	}
	negotiated, id := true, uint16(0)
	dc, err := pc.CreateDataChannel("tunnel", &webrtc.DataChannelInit{Negotiated: &negotiated, ID: &id})
	if err != nil {
		log.Println("datachannel:", err)
		return
	}
	t := &tab{dc: dc, conns: map[uint32]net.Conn{}}
	dc.OnMessage(func(m webrtc.DataChannelMessage) { t.onMessage(m.Data) })
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		log.Printf("peer %s…: %s", ufrag[:6], s)
		if s == webrtc.PeerConnectionStateFailed || s == webrtc.PeerConnectionStateClosed || s == webrtc.PeerConnectionStateDisconnected {
			t.drop()
			_ = pc.Close()
		}
	})
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: fabricatedOffer(ufrag)}); err != nil {
		log.Println("remote description:", err)
		return
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		log.Println("answer:", err)
		return
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		log.Println("local description:", err)
	}
}

func (t *tab) onMessage(msg []byte) {
	if len(msg) < 5 {
		return
	}
	kind, conn, payload := msg[0], binary.BigEndian.Uint32(msg[1:5]), msg[5:]
	switch kind {
	case frameRegister:
		host := strings.ToLower(string(payload))
		tabsMu.Lock()
		t.host = host
		tabs[host] = t // latest registration wins (see README: should be authenticated)
		tabsMu.Unlock()
		log.Printf("tab registered for %s", host)
	case frameData:
		t.mu.Lock()
		c := t.conns[conn]
		t.mu.Unlock()
		if c != nil {
			capture("out", conn, payload)
			_, _ = c.Write(payload)
		}
	case frameClose:
		t.mu.Lock()
		c := t.conns[conn]
		delete(t.conns, conn)
		t.mu.Unlock()
		if c != nil {
			_ = c.Close()
		}
	}
}

func (t *tab) drop() {
	tabsMu.Lock()
	if tabs[t.host] == t {
		delete(tabs, t.host)
	}
	tabsMu.Unlock()
	t.mu.Lock()
	for _, c := range t.conns {
		_ = c.Close()
	}
	t.conns = map[uint32]net.Conn{}
	t.mu.Unlock()
}

// ---------------------------------------------------------------- TLS ingress
// readSNI returns the SNI from a complete first TLS record; ok=false means "need more bytes".
func readSNI(b []byte) (sni string, ok bool, err error) {
	if len(b) < 5 {
		return "", false, nil
	}
	if b[0] != 22 {
		return "", true, errors.New("not a TLS handshake")
	}
	n := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+n {
		return "", false, nil
	}
	p := b[5 : 5+n]
	defer func() {
		if recover() != nil {
			sni, ok, err = "", true, errors.New("malformed ClientHello")
		}
	}()
	if p[0] != 1 {
		return "", true, errors.New("not a ClientHello")
	}
	i := 4 + 2 + 32
	i += 1 + int(p[i])
	i += 2 + int(binary.BigEndian.Uint16(p[i:]))
	i += 1 + int(p[i])
	end := i + 2 + int(binary.BigEndian.Uint16(p[i:]))
	i += 2
	for i+4 <= end {
		typ, l := binary.BigEndian.Uint16(p[i:]), int(binary.BigEndian.Uint16(p[i+2:]))
		if typ == 0 {
			nl := int(binary.BigEndian.Uint16(p[i+4+3:]))
			return strings.ToLower(string(p[i+4+5 : i+4+5+nl])), true, nil
		}
		i += 4 + l
	}
	return "", true, errors.New("no SNI")
}

func serveApp(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 16384)
	var sni string
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := c.Read(tmp)
		if err != nil {
			return
		}
		buf = append(buf, tmp[:n]...)
		s, ok, perr := readSNI(buf)
		if perr != nil {
			log.Println("drop:", perr)
			return
		}
		if ok {
			sni = s
			break
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	tabsMu.Lock()
	t := tabs[sni]
	tabsMu.Unlock()
	if t == nil {
		log.Printf("no tab for %s", sni)
		return
	}
	id := nextConn.Add(1)
	t.mu.Lock()
	t.conns[id] = c
	t.mu.Unlock()
	log.Printf("conn %d: %s -> %s", id, c.RemoteAddr(), sni)
	meta, _ := json.Marshal(map[string]string{"sni": sni, "remote": c.RemoteAddr().String()})
	_ = t.dc.Send(frame(frameOpen, id, meta))
	capture("in", id, buf)
	_ = t.dc.Send(frame(frameData, id, buf))
	for {
		n, err := c.Read(tmp)
		if n > 0 {
			capture("in", id, tmp[:n])
			_ = t.dc.Send(frame(frameData, id, append([]byte(nil), tmp[:n]...)))
		}
		if err != nil {
			break
		}
	}
	t.mu.Lock()
	delete(t.conns, id)
	t.mu.Unlock()
	_ = t.dc.Send(frame(frameClose, id, nil))
	log.Printf("conn %d closed", id)
}

func main() {
	flag.Parse()
	if *flagCapture != "" {
		_ = os.WriteFile(*flagCapture, nil, 0o644)
	}
	ip := net.ParseIP(*flagIP)
	if ip == nil || ip.To4() == nil {
		log.Fatal("-ip must be the IPv4 address tabs use to reach this relay")
	}
	cert, fingerprint, err := loadOrCreateCert(*flagState)
	if err != nil {
		log.Fatal(err)
	}
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{Port: *flagUDP})
	if err != nil {
		log.Fatal(err)
	}
	mux := &udpMux{sock: sock, advertised: &net.UDPAddr{IP: ip, Port: *flagUDP}, byUfrag: map[string]*vconn{}, byAddr: map[string]*vconn{}}
	mux.onNew = func(ufrag string) { newPeer(mux, cert, ufrag) }
	go mux.loop()

	info, _ := json.Marshal(map[string]any{"ip": ip.String(), "port": *flagUDP, "certhash": fingerprint})
	_ = os.WriteFile(filepath.Join(*flagState, "relay-info.json"), info, 0o644)
	log.Printf("tabs: WebRTC %s:%d, %s", ip, *flagUDP, fingerprint)

	ln, err := net.Listen("tcp", *flagTLS)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("apps: TLS passthrough on %s", *flagTLS)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go serveApp(c)
	}
}
