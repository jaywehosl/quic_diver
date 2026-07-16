// Command qdbench — автономный бенчмарк пропускной способности туннеля БЕЗ
// WinDivert (не требует администратора). Клиентский gVisor-стек с назначенным
// узлом адресом ходит через connect-ip туннель к benchsrv на VM и меряет
// download/upload. Встроенный pprof (localhost:6060) для профилирования.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"strconv"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/buffer"

	"quicdiver/internal/server"
	"quicdiver/internal/transport/cip"
)

func main() {
	srv := flag.String("server", "localhost:8443", "endpoint узла")
	authority := flag.String("authority", "localhost:8443", "authority connect-ip")
	target := flag.String("target", "localhost:8080", "benchsrv (host:port)")
	mode := flag.String("mode", "down", "down | up")
	dur := flag.Duration("d", 15*time.Second, "длительность")
	pprofAddr := flag.String("pprof", "localhost:6060", "адрес pprof")
	flag.Parse()

	go func() { log.Println(http.ListenAndServe(*pprofAddr, nil)) }()

	ctx := context.Background()
	host, _, _ := net.SplitHostPort(*srv)
	tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: host}
	tmpl := server.Template(*authority, "/connect-ip")

	client, rsp, err := cip.Dial(ctx, *srv, tmpl, tlsConf)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer client.Close()
	log.Printf("туннель ok (status %d)", rsp.StatusCode)

	prefs, err := client.LocalPrefixes(ctx)
	if err != nil || len(prefs) == 0 {
		log.Fatalf("no assigned addr: %v", err)
	}
	src := prefs[0].Addr()
	log.Printf("assigned %s", src)

	cs, cep := clientStack(src)
	bridge(ctx, cep, client)

	httpc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			h, ps, _ := net.SplitHostPort(addr)
			ip, err := netip.ParseAddr(h)
			if err != nil {
				return nil, err
			}
			port, _ := strconv.Atoi(ps)
			log.Printf("gVisor dial %s через туннель...", addr)
			conn, err := gonet.DialContextTCP(ctx, cs, tcpip.FullAddress{
				NIC: 1, Addr: tcpip.AddrFrom4(ip.As4()), Port: uint16(port),
			}, ipv4.ProtocolNumber)
			if err != nil {
				log.Printf("gVisor dial %s FAILED: %v", addr, err)
			} else {
				log.Printf("gVisor dial %s OK", addr)
			}
			return conn, err
		},
	}}

	switch *mode {
	case "down":
		benchDown(httpc, *target, *dur)
	case "up":
		benchUp(httpc, *target, *dur)
	default:
		log.Fatalf("mode: down|up")
	}
}

func benchDown(c *http.Client, target string, d time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), d+10*time.Second)
	defer cancel()
	log.Printf("GET http://%s/zero ...", target)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target+"/zero", nil)
	resp, err := c.Do(req)
	if err != nil {
		log.Fatalf("GET /zero: %v", err)
	}
	defer resp.Body.Close()
	log.Printf("ответ %s — качаю %v", resp.Status, d)

	buf := make([]byte, 256*1024)
	var total int64
	start := time.Now()
	deadline := start.Add(d)
	lastLog := start
	var lastTotal int64
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf)
		total += int64(n)
		if now := time.Now(); now.Sub(lastLog) >= 2*time.Second {
			mbps := float64(total-lastTotal) * 8 / now.Sub(lastLog).Seconds() / 1e6
			log.Printf("download: %.1f Mbps (инст.)", mbps)
			lastLog, lastTotal = now, total
		}
		if err != nil {
			log.Printf("read: %v", err)
			break
		}
	}
	el := time.Since(start)
	log.Printf("ИТОГ download: %.1f Mbps (%d МБ за %v)", float64(total)*8/el.Seconds()/1e6, total/1024/1024, el.Round(time.Millisecond))
}

func benchUp(c *http.Client, target string, d time.Duration) {
	pr, pw := io.Pipe()
	go func() {
		buf := make([]byte, 256*1024)
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			if _, err := pw.Write(buf); err != nil {
				break
			}
		}
		pw.Close()
	}()
	start := time.Now()
	resp, err := c.Post("http://"+target+"/sink", "application/octet-stream", pr)
	if err != nil {
		log.Fatalf("POST /sink: %v", err)
	}
	resp.Body.Close()
	log.Printf("ИТОГ upload за %v", time.Since(start).Round(time.Millisecond))
}

func clientStack(src netip.Addr) (*stack.Stack, *channel.Endpoint) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(2048, 1500, "")
	if err := s.CreateNIC(1, ep); err != nil {
		log.Fatalf("nic: %v", err)
	}
	addr := tcpip.AddrFrom4(src.As4())
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		log.Fatalf("addr: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return s, ep
}

func bridge(ctx context.Context, cep *channel.Endpoint, c *cip.Client) {
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
			var proto tcpip.NetworkProtocolNumber
			switch buf[0] >> 4 {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
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
