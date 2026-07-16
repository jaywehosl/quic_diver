package netstack_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

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
)

// redirectDialer игнорирует запрошенный dst и всегда соединяется с target
// (реальным echo-сервером). Так тест проверяет прокладку forwarder'а, не завися
// от реальной маршрутизации в интернет.
type redirectDialer struct{ target string }

func (d redirectDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.target)
}
func (d redirectDialer) DialUDP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "udp", d.target)
}

// chanTunnel мостит серверный netstack.Tunnel к channel-endpoint клиентского
// стека: исходящие клиента → ingress сервера, ответы сервера → клиенту.
type chanTunnel struct {
	ctx context.Context
	cep *channel.Endpoint
}

func (t *chanTunnel) ReadPacket(b []byte) (int, error) {
	pkt := t.cep.ReadContext(t.ctx)
	if pkt == nil {
		return 0, io.EOF
	}
	data := pkt.ToBuffer()
	n := copy(b, data.Flatten())
	pkt.DecRef()
	return n, nil
}

func (t *chanTunnel) WritePacket(b []byte) ([]byte, error) {
	var proto tcpip.NetworkProtocolNumber
	switch b[0] >> 4 {
	case 4:
		proto = header.IPv4ProtocolNumber
	case 6:
		proto = header.IPv6ProtocolNumber
	default:
		return nil, nil
	}
	data := make([]byte, len(b))
	copy(data, b)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
	t.cep.InjectInbound(proto, pkt)
	pkt.DecRef()
	return nil, nil
}

// startEcho поднимает реальный TCP echo-сервер.
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

// newClientStack строит gVisor-стек, эмулирующий приложение за туннелем.
func newClientStack(t *testing.T) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(512, 1500, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("client nic: %v", err)
	}
	addr := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("client addr: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return s, ep
}

// TestTCPForward: клиентский стек открывает TCP через серверный forwarder, тот
// проксирует на реальный echo — данные ходят в обе стороны.
func TestTCPForward(t *testing.T) {
	echoAddr := startEcho(t)

	srv, err := netstack.New(redirectDialer{target: echoAddr})
	if err != nil {
		t.Fatalf("server stack: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cs, cep := newClientStack(t)
	tun := &chanTunnel{ctx: ctx, cep: cep}
	go func() { _ = srv.Run(ctx, tun) }()

	// Клиент коннектится к произвольному публичному dst — forwarder редиректит на echo.
	dst := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{8, 8, 8, 8}), Port: 80}
	conn, err := gonet.DialContextTCP(ctx, cs, dst, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial through netstack: %v", err)
	}
	defer conn.Close()

	msg := []byte("ping through gvisor forwarder")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
	t.Log("netstack: TCP-флоу прошёл клиент→forwarder→реальный сокет и обратно")
}
