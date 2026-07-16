// Command qdhybrid — изолирует клиентскую половину гибрида БЕЗ WinDivert.
//
// Тот же путь, что у qd-client: приложение → gVisor-терминатор → CONNECT-стрим →
// узел → benchsrv. Разница одна: источником пакетов вместо WinDivert работает
// второй gVisor-стек (генератор).
//
// Если тут download ~600+, значит режет WinDivert-петля; если ~300 — виноват
// gVisor-терминатор, и копать надо в нём.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"strconv"
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

	"quicdiver/internal/client/connectdial"
	"quicdiver/internal/server"
	"quicdiver/internal/server/netstack"
	"quicdiver/internal/transport/cip"
)

func main() {
	srv := flag.String("server", "localhost:8443", "endpoint узла")
	authority := flag.String("authority", "localhost:8443", "authority connect-ip")
	target := flag.String("target", "localhost:8080", "benchsrv")
	dur := flag.Duration("d", 12*time.Second, "длительность")
	pprofAddr := flag.String("pprof", "localhost:6062", "pprof")
	flag.Parse()

	go func() { log.Println(http.ListenAndServe(*pprofAddr, nil)) }()
	ctx := context.Background()

	// Туннель к узлу (как в qd-client).
	host, _, _ := net.SplitHostPort(*srv)
	client, _, err := cip.Dial(ctx, *srv, server.Template(*authority, "/connect-ip"),
		&tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		log.Fatalf("cip.Dial: %v", err)
	}
	defer client.Close()

	// Терминатор: ровно то, что делает гибрид на клиенте.
	ns, err := netstack.NewWithMTU(connectdial.Dialer{CC: client.H3Conn()}, 1500)
	if err != nil {
		log.Fatalf("netstack: %v", err)
	}

	// Генератор: играет роль приложения+ОС (вместо WinDivert-перехвата).
	gen, genEP := genStack()
	go ns.Run(ctx, &wire{ctx: ctx, ep: genEP})

	httpc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			h, ps, _ := net.SplitHostPort(addr)
			ip, _ := netip.ParseAddr(h)
			port, _ := strconv.Atoi(ps)
			return gonet.DialContextTCP(ctx, gen, tcpip.FullAddress{
				NIC: 1, Addr: tcpip.AddrFrom4(ip.As4()), Port: uint16(port),
			}, ipv4.ProtocolNumber)
		},
	}}

	req, _ := http.NewRequest(http.MethodGet, "http://"+*target+"/zero", nil)
	resp, err := httpc.Do(req)
	if err != nil {
		log.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	log.Printf("benchsrv %s — качаю %v (netstack+CONNECT, без WinDivert)", resp.Status, *dur)

	buf := make([]byte, 256*1024)
	var total, last int64
	start := time.Now()
	deadline := start.Add(*dur)
	lastT := start
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf)
		total += int64(n)
		if now := time.Now(); now.Sub(lastT) >= 2*time.Second {
			log.Printf("  %.1f Mbps", float64(total-last)*8/now.Sub(lastT).Seconds()/1e6)
			last, lastT = total, now
		}
		if err != nil {
			log.Printf("read: %v", err)
			break
		}
	}
	el := time.Since(start)
	log.Printf("ИТОГ: %.1f Mbps (%d МБ за %v)", float64(total)*8/el.Seconds()/1e6,
		total/1024/1024, el.Round(time.Millisecond))
	log.Printf("→ сравни: connectdial без netstack ~680, полный тракт с WinDivert ~300")
}

// wire — провод между генератором и терминатором (вместо WinDivert).
type wire struct {
	ctx context.Context
	ep  *channel.Endpoint
}

func (w *wire) ReadPacket(b []byte) (int, error) {
	pkt := w.ep.ReadContext(w.ctx)
	if pkt == nil {
		return 0, context.Canceled
	}
	data := pkt.ToBuffer()
	n := copy(b, data.Flatten())
	pkt.DecRef()
	return n, nil
}

func (w *wire) WritePacket(b []byte) ([]byte, error) {
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
	w.ep.InjectInbound(proto, pkt)
	pkt.DecRef()
	return nil, nil
}

func genStack() (*stack.Stack, *channel.Endpoint) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(4096, 1500, "")
	ep.LinkEPCapabilities = stack.CapabilityRXChecksumOffload
	if err := s.CreateNIC(1, ep); err != nil {
		log.Fatalf("gen nic: %v", err)
	}
	addr := tcpip.AddrFrom4([4]byte{192, 168, 31, 108}) // как реальный клиент
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		log.Fatalf("gen addr: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return s, ep
}
