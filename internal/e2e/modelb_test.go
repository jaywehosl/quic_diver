package e2e

import (
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
	"net/netip"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"quicdiver/internal/server/netstack"
	"quicdiver/internal/transport/cip"
)

const clientAddr = "192.168.1.1" // адрес, который узел назначает клиенту

// --- helpers ---

func selfSigned(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "qd-e2e"},
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
	return &tls.Config{Certificates: []tls.Certificate{cert}},
		&tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}
}

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()
	return ln.Addr().String()
}

// redirectDialer игнорирует dst и всегда идёт в target (echo) — изолирует тест от
// реального интернета; на VM тут будет реальный direct/chain.
type redirectDialer struct{ target string }

func (d redirectDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.target)
}
func (d redirectDialer) DialUDP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "udp", d.target)
}

// clientStackGen — клиентский gVisor-стек, эмулирующий приложения за туннелем.
func clientStackGen(t *testing.T) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(512, 1500, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("client nic: %v", err)
	}
	addr := tcpip.AddrFrom4([4]byte(net.ParseIP(clientAddr).To4()))
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("client addr: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return s, ep
}

func ipProto(b0 byte) (tcpip.NetworkProtocolNumber, bool) {
	switch b0 >> 4 {
	case 4:
		return header.IPv4ProtocolNumber, true
	case 6:
		return header.IPv6ProtocolNumber, true
	default:
		return 0, false
	}
}

// bridgeClient качает пакеты между клиентским стеком (cep) и connect-ip клиентом.
func bridgeClient(ctx context.Context, cep *channel.Endpoint, c *cip.Client) {
	go func() { // стек → туннель
		for {
			pkt := cep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			b := pkt.ToBuffer()
			_, _ = c.WritePacket(b.Flatten())
			pkt.DecRef()
		}
	}()
	go func() { // туннель → стек
		buf := make([]byte, 2048)
		for {
			n, err := c.ReadPacket(buf)
			if err != nil {
				return
			}
			proto, ok := ipProto(buf[0])
			if !ok {
				continue
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
			cep.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}()
}

// startNode поднимает узел: connect-ip прокси, на каждый туннель — назначение
// адреса/маршрута и gVisor-forwarder в echo.
func startNode(t *testing.T, echoAddr string, serverTLS *tls.Config) (endpoint string, tmpl *uritemplate.Template) {
	t.Helper()
	udpc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("node listen: %v", err)
	}
	port := udpc.LocalAddr().(*net.UDPAddr).Port
	tmpl = uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/connect-ip", port))

	handler := cip.ProxyHandler("/connect-ip", tmpl, func(conn *connectip.Conn) {
		ctx := context.Background()
		if err := conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix(clientAddr + "/32")}); err != nil {
			return
		}
		if err := conn.AdvertiseRoute(ctx, []connectip.IPRoute{
			{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")},
		}); err != nil {
			return
		}
		ns, err := netstack.New(redirectDialer{target: echoAddr})
		if err != nil {
			return
		}
		go ns.Run(ctx, conn) // connectip.Conn удовлетворяет netstack.Tunnel
	})

	srv := &http3.Server{Handler: handler, EnableDatagrams: true, TLSConfig: serverTLS}
	go func() { _ = srv.Serve(udpc) }()
	t.Cleanup(func() { srv.Close(); udpc.Close() })

	return udpc.LocalAddr().String(), tmpl
}

// TestModelBEndToEnd — вся вертикаль модели B локально: приложение клиента →
// gVisor(клиент) → connect-ip → gVisor-forwarder(узел) → реальный сокет → назад.
func TestModelBEndToEnd(t *testing.T) {
	echoAddr := startEcho(t)
	serverTLS, clientTLS := selfSigned(t)
	endpoint, tmpl := startNode(t, echoAddr, serverTLS)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, rsp, err := cip.Dial(ctx, endpoint, tmpl, clientTLS)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if rsp.StatusCode != 200 {
		t.Fatalf("connect-ip status: %d", rsp.StatusCode)
	}
	t.Cleanup(func() { client.Close() })

	// Дождаться назначенного узлом адреса (синхронизация с AssignAddresses).
	prefs, err := client.LocalPrefixes(ctx)
	if err != nil {
		t.Fatalf("local prefixes: %v", err)
	}
	if len(prefs) != 1 || prefs[0].Addr().String() != clientAddr {
		t.Fatalf("unexpected assigned prefixes: %v", prefs)
	}

	// Клиентский стек-генератор + мост в туннель.
	cs, cep := clientStackGen(t)
	bridgeClient(ctx, cep, client)

	// Приложение клиента коннектится к произвольному dst — узел редиректит в echo.
	dst := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{8, 8, 8, 8}), Port: 80}
	conn, err := gonet.DialContextTCP(ctx, cs, dst, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("app dial through tunnel: %v", err)
	}
	defer conn.Close()

	msg := []byte("full model-B path: client app -> tunnel -> node -> socket")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
	t.Log("модель B: полная вертикаль клиент→connect-ip→forwarder→сокет прошла")
}
