package quicconn_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"quicdiver/internal/uplink"
	"quicdiver/internal/uplink/quicconn"
)

// selfSigned выдаёт TLS-конфиги сервера и клиента с общим ALPN. Клиент не
// проверяет цепочку (loopback-тест).
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
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	server = &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{quicconn.ALPN}}
	client = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{quicconn.ALPN}}
	return server, client
}

// startEcho поднимает узел-эхо: датаграммы отражаются, потоки копируются назад.
func startEcho(t *testing.T, serverTLS *tls.Config) *quic.Listener {
	t.Helper()
	ln, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go echoConn(conn)
		}
	}()
	return ln
}

func echoConn(conn *quic.Conn) {
	ctx := conn.Context()
	go func() {
		for {
			b, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			_ = conn.SendDatagram(b)
		}
	}()
	for {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func(s *quic.Stream) {
			_, _ = io.Copy(s, s)
			_ = s.Close()
		}(s)
	}
}

func dial(t *testing.T, ctx context.Context, addr string, clientTLS *tls.Config) uplink.Conn {
	t.Helper()
	uc, err := quicconn.Dialer{TLS: clientTLS}.Dial(ctx, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return uc
}

// datagramRT шлёт payload и ждёт эхо, возвращает RTT.
func datagramRT(t *testing.T, ctx context.Context, uc uplink.Conn, payload []byte) time.Duration {
	t.Helper()
	start := time.Now()
	if err := uc.SendDatagram(payload); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
	got, err := uc.RecvDatagram(ctx)
	if err != nil {
		t.Fatalf("recv datagram: %v", err)
	}
	rtt := time.Since(start)
	if !bytes.Equal(got, payload) {
		t.Fatalf("datagram mismatch: got %q want %q", got, payload)
	}
	return rtt
}

func TestDatagramRoundTrip(t *testing.T) {
	serverTLS, clientTLS := selfSigned(t)
	ln := startEcho(t, serverTLS)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	uc := dial(t, ctx, ln.Addr().String(), clientTLS)
	defer uc.Close()

	const n = 50
	var total time.Duration
	for i := 0; i < n; i++ {
		total += datagramRT(t, ctx, uc, []byte(fmt.Sprintf("datagram-payload-%04d", i)))
	}
	t.Logf("datagram RTT avg over %d msgs: %v", n, total/n)
	t.Logf("MaxDatagramSize = %d", uc.MaxDatagramSize())
}

func TestStreamRoundTrip(t *testing.T) {
	serverTLS, clientTLS := selfSigned(t)
	ln := startEcho(t, serverTLS)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	uc := dial(t, ctx, ln.Addr().String(), clientTLS)
	defer uc.Close()

	s, err := uc.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	msg := []byte("stream ping over quic")
	if _, err := s.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.Close(); err != nil { // закрыть write-сторону → сервер увидит EOF
		t.Fatalf("close write: %v", err)
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("stream mismatch: got %q want %q", got, msg)
	}
}

// TestMigration проверяет arch4: смена локального сокета без разрыва сессии.
func TestMigration(t *testing.T) {
	serverTLS, clientTLS := selfSigned(t)
	ln := startEcho(t, serverTLS)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	uc := dial(t, ctx, ln.Addr().String(), clientTLS)
	defer uc.Close()

	// До миграции.
	rtt1 := datagramRT(t, ctx, uc, []byte("before-migration"))

	c, ok := uc.(*quicconn.Conn)
	if !ok {
		t.Fatalf("expected *quicconn.Conn, got %T", uc)
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, 8*time.Second)
	defer probeCancel()
	if err := c.Migrate(probeCtx, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// После миграции — сессия жива, датаграммы ходят по новому пути.
	rtt2 := datagramRT(t, ctx, uc, []byte("after-migration"))
	t.Logf("RTT before=%v after=%v (session survived path switch)", rtt1, rtt2)
}
