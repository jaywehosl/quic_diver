package cip_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/ipv4"

	"quicdiver/internal/transport/cip"
)

func selfSigned(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "qd-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	server = &tls.Config{Certificates: []tls.Certificate{cert}}
	client = &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}
	return server, client
}

// startProxy поднимает узел connect-ip и возвращает endpoint (host:port), template
// и канал установленных туннельных соединений.
func startProxy(t *testing.T, serverTLS *tls.Config) (endpoint string, tmpl *uritemplate.Template, conns <-chan *connectip.Conn) {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	tmpl = uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/connect-ip", port))

	ch := make(chan *connectip.Conn, 1)
	h := cip.ProxyHandler("/connect-ip", tmpl, func(c *connectip.Conn) { ch <- c })
	srv := &http3.Server{Handler: h, EnableDatagrams: true, TLSConfig: serverTLS}
	go func() { _ = srv.Serve(udp) }()
	t.Cleanup(func() { srv.Close(); udp.Close() })

	return udp.LocalAddr().String(), tmpl, ch
}

// ipv4Packet собирает валидный IPv4-пакет src→dst с заданным TTL.
func ipv4Packet(t *testing.T, src, dst net.IP, ttl int) []byte {
	t.Helper()
	hdr := &ipv4.Header{
		Version:  4,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen,
		TTL:      ttl,
		Protocol: 17, // UDP
		Src:      src,
		Dst:      dst,
	}
	b, err := hdr.Marshal()
	if err != nil {
		t.Fatalf("marshal ipv4: %v", err)
	}
	return b
}

// setup поднимает узел и клиента, настраивает адреса/маршруты так, чтобы пакеты
// src=192.168.1.1 dst=* проходили (как в TestTTLs самого connect-ip-go).
func setup(t *testing.T, ctx context.Context) (client *cip.Client, server *connectip.Conn, clientSrc net.IP) {
	t.Helper()
	serverTLS, clientTLS := selfSigned(t)
	endpoint, tmpl, conns := startProxy(t, serverTLS)

	client, rsp, err := cip.Dial(ctx, endpoint, tmpl, clientTLS)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if rsp.StatusCode != 200 {
		t.Fatalf("connect-ip status: %d", rsp.StatusCode)
	}
	t.Cleanup(func() { client.Close() })

	select {
	case server = <-conns:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not establish tunnel")
	}

	if err := server.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("192.168.1.1/32")}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := server.AdvertiseRoute(ctx, []connectip.IPRoute{
		{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")},
	}); err != nil {
		t.Fatalf("advertise: %v", err)
	}

	// Клиент получает назначенный адрес (блокируется до ADDRESS_ASSIGN).
	prefs, err := client.LocalPrefixes(ctx)
	if err != nil {
		t.Fatalf("local prefixes: %v", err)
	}
	if len(prefs) != 1 || prefs[0].String() != "192.168.1.1/32" {
		t.Fatalf("unexpected assigned prefixes: %v", prefs)
	}
	return client, server, net.IPv4(192, 168, 1, 1)
}

// sendExpect гонит один IP-пакет клиент→узел и проверяет приём (TTL декрементирован).
func sendExpect(t *testing.T, client *cip.Client, server *connectip.Conn, src net.IP, ttl int) {
	t.Helper()
	pkt := ipv4Packet(t, src, net.IPv4(8, 8, 8, 8), ttl)
	icmp, err := client.WritePacket(pkt)
	if err != nil {
		t.Fatalf("write packet: %v", err)
	}
	if len(icmp) != 0 {
		t.Fatalf("unexpected icmp: %x", icmp)
	}
	buf := make([]byte, 1500)
	n, err := server.ReadPacket(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	got, err := ipv4.ParseHeader(buf[:n])
	if err != nil {
		t.Fatalf("parse received: %v", err)
	}
	if !got.Dst.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Fatalf("dst mismatch: got %v", got.Dst)
	}
	if got.TTL != ttl-1 {
		t.Fatalf("TTL not decremented: got %d want %d", got.TTL, ttl-1)
	}
}

func TestConnectIPRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, server, src := setup(t, ctx)
	sendExpect(t, client, server, src, 42)
	t.Log("connect-ip: IP-пакет прошёл клиент→узел, TTL декрементирован")
}

// TestConnectIPSurvivesMigration — полный стек B (connect-ip/http3/quic) переживает
// смену локального сокета клиента (arch4).
func TestConnectIPSurvivesMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, server, src := setup(t, ctx)
	sendExpect(t, client, server, src, 42) // до миграции

	mctx, mcancel := context.WithTimeout(ctx, 8*time.Second)
	defer mcancel()
	if err := client.Migrate(mctx, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	sendExpect(t, client, server, src, 42) // после миграции — туннель жив
	t.Log("connect-ip: туннель пережил миграцию пути")
}
