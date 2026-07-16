// Package netstack — серверный конец модели B: gVisor netstack узла.
//
// Разворачивает сырые IP-пакеты из connect-ip туннеля, терминирует TCP/UDP в
// userspace-стеке и форвардит наружу — напрямую в интернет (direct) или в
// upstream-узел (chain). Обратный трафик стек сериализует в IP-пакеты и пишет
// назад в туннель. Это единственное место на узле, где живёт полноценный TCP/IP.
//
// NIC работает в promiscuous+spoofing режиме и держит маршрут по умолчанию, чтобы
// принимать соединения на ЛЮБОЙ адрес назначения (клиент ходит в произвольные
// хосты). Выбор direct/chain делает Dialer — туда позже придёт routing.Router.
package netstack

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID = 1
	// channelMTU занижен до 1280 (IPv6 min MTU): узел объявляет MSS ≤1240 и
	// клиенту, и удалённым серверам, поэтому ни один сегмент не превышает ёмкость
	// connect-ip датаграммы (QUIC datagram). Иначе крупные пакеты отбрасываются.
	channelMTU  = 1280
	maxInFlight = 2048
	dialTimeout = 15 * time.Second
)

// Tunnel — двусторонний канал сырых IP-пакетов (серверный connect-ip Conn).
type Tunnel interface {
	ReadPacket(b []byte) (int, error)
	WritePacket(b []byte) (icmp []byte, err error)
}

// Dialer выходит наружу с узла: direct (реальная сеть) или chain (upstream-узел).
type Dialer interface {
	DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
}

// Stack — netstack узла.
type Stack struct {
	stack  *stack.Stack
	ep     *channel.Endpoint
	dialer Dialer
	mtu    int
}

// New поднимает стек с TCP/UDP-форвардерами, направляющими трафик через d.
func New(d Dialer) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6,
		},
	})
	ep := channel.New(512, channelMTU, "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create nic: %v", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("promiscuous: %v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("spoofing: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	st := &Stack{stack: s, ep: ep, dialer: d, mtu: channelMTU}

	tcpFwd := tcp.NewForwarder(s, 0, maxInFlight, st.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, st.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return st, nil
}

// Run гоняет обмен туннель↔стек до отмены ctx. ingress держит горутину вызова,
// egress — отдельную.
func (s *Stack) Run(ctx context.Context, t Tunnel) error {
	go s.egress(ctx, t)
	return s.ingress(ctx, t)
}

// ingress: IP-пакеты из туннеля → стек.
func (s *Stack) ingress(ctx context.Context, t Tunnel) error {
	buf := make([]byte, s.mtu+header.IPv4MaximumHeaderSize)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := t.ReadPacket(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		var proto tcpip.NetworkProtocolNumber
		switch buf[0] >> 4 {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			continue
		}
		// Копия: buf переиспользуется на следующей итерации.
		data := make([]byte, n)
		copy(data, buf[:n])
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(data),
		})
		s.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

// egress: IP-пакеты из стека → туннель (ответы клиенту).
func (s *Stack) egress(ctx context.Context, t Tunnel) {
	for {
		pkt := s.ep.ReadContext(ctx)
		if pkt == nil {
			return // ctx отменён / стек закрыт
		}
		b := pkt.ToBuffer()
		if _, err := t.WritePacket(b.Flatten()); err != nil {
			pkt.DecRef()
			return
		}
		pkt.DecRef()
	}
}

// handleTCP терминирует TCP-соединение в стеке и склеивает его с реальным
// исходящим соединением (direct/chain).
func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := netip.AddrPortFrom(toNetip(id.LocalAddress), id.LocalPort)

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	outbound, err := s.dialer.DialTCP(ctx, dst)
	cancel()
	if err != nil {
		r.Complete(true) // RST инициатору
		return
	}

	var wq waiter.Queue
	ep, tcperr := r.CreateEndpoint(&wq)
	if tcperr != nil {
		outbound.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)

	inbound := gonet.NewTCPConn(&wq, ep)
	go pipe(inbound, outbound)
}

// handleUDP терминирует UDP-флоу и склеивает с реальным исходящим сокетом.
func (s *Stack) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dst := netip.AddrPortFrom(toNetip(id.LocalAddress), id.LocalPort)

	outbound, err := s.dialer.DialUDP(context.Background(), dst)
	if err != nil {
		return // дроп
	}
	var wq waiter.Queue
	ep, tcperr := r.CreateEndpoint(&wq)
	if tcperr != nil {
		outbound.Close()
		return
	}
	inbound := gonet.NewUDPConn(s.stack, &wq, ep)
	go pipe(inbound, outbound)
}

// pipe качает данные в обе стороны и корректно закрывает половинки.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

func toNetip(a tcpip.Address) netip.Addr {
	if a.Len() == 4 {
		return netip.AddrFrom4(a.As4())
	}
	return netip.AddrFrom16(a.As16())
}

// NetDialer — прямой выход в реальную сеть узла (direct). Chain-реализация Dialer
// добавится отдельно (dial в upstream-узел).
type NetDialer struct {
	D net.Dialer
}

func (n NetDialer) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return n.D.DialContext(ctx, "tcp", dst.String())
}

func (n NetDialer) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return n.D.DialContext(ctx, "udp", dst.String())
}

var _ Dialer = NetDialer{}
