// Command qdudp — проверка серверного UDP-форвардинга через connect-ip туннель.
//
// Собираем сырой IP/UDP-пакет (DNS-запрос к 8.8.8.8:53), шлём в туннель как это
// делает реальный клиент после WinDivert+NAT, и ждём ответ обратно. Так виден
// именно путь UDP: клиент → connect-ip → gVisor узла → dial наружу → ответ.
//
// Гоняем N запросов подряд: теряются ли ответы, растёт ли задержка. Без прав
// администратора (WinDivert не нужен — пакет собираем сами).
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"log"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"quicdiver/internal/server"
	"quicdiver/internal/transport/cip"
)

func main() {
	srv := flag.String("server", "localhost:8443", "endpoint узла")
	authority := flag.String("authority", "localhost:8443", "authority")
	token := flag.String("token", "", "токен (для узла с БД)")
	dstStr := flag.String("dst", "8.8.8.8:53", "UDP-адрес назначения (DNS-сервер)")
	n := flag.Int("n", 30, "сколько запросов")
	gap := flag.Duration("gap", 50*time.Millisecond, "пауза между запросами")
	oneFlow := flag.Bool("oneflow", true, "один src-порт (как реальное приложение); false — новый порт на запрос")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	host, _, _ := net.SplitHostPort(*srv)
	tmpl := server.Template(*authority, "/connect-ip")
	client, _, err := cip.DialAuth(ctx, *srv, tmpl,
		&tls.Config{InsecureSkipVerify: true, ServerName: host},
		*token, "https://"+*authority+"/qd-auth")
	if err != nil {
		log.Fatalf("cip.DialAuth: %v", err)
	}
	defer client.Close()

	prefs, err := client.LocalPrefixes(ctx)
	if err != nil || len(prefs) == 0 {
		log.Fatalf("нет назначенного адреса: %v", err)
	}
	src := prefs[0].Addr()
	dst := netip.MustParseAddrPort(*dstStr)
	log.Printf("src=%s dst=%s — шлю %d UDP DNS-запросов через туннель", src, dst, *n)

	var mu sync.Mutex
	sent := make(map[uint16]time.Time)
	got := make(map[uint16]time.Duration)

	// читатель: фиксируем RTT В МОМЕНТ ПРИЁМА, а не при разборе позже —
	// иначе ответ, ждущий в очереди, даёт мнимо большую задержку.
	go func() {
		buf := make([]byte, 2048)
		for {
			nn, err := client.ReadPacket(buf)
			if err != nil {
				return
			}
			if id, ok := parseDNSReplyID(buf[:nn], src); ok {
				now := time.Now()
				mu.Lock()
				if t0, known := sent[id]; known {
					if _, dup := got[id]; !dup {
						got[id] = now.Sub(t0)
					}
				}
				mu.Unlock()
			}
		}
	}()

	for i := 0; i < *n; i++ {
		id := uint16(1000 + i)
		sport := uint16(40000)
		if !*oneFlow {
			sport = uint16(40000 + i)
		}
		pkt := buildDNSPacket(src, dst, id, sport)
		mu.Lock()
		sent[id] = time.Now()
		mu.Unlock()
		if _, err := client.WritePacket(pkt); err != nil {
			log.Printf("запрос %d: WritePacket: %v", i, err)
		}
		time.Sleep(*gap)
	}
	time.Sleep(2 * time.Second) // добрать хвост ответов

	mu.Lock()
	var rtts []time.Duration
	for _, d := range got {
		rtts = append(rtts, d)
	}
	mu.Unlock()

	report(*n, got, rtts)
}

// report печатает потери и задержки.
func report(n int, got map[uint16]time.Duration, rtts []time.Duration) {
	lost := n - len(got)
	log.Printf("=== серверный UDP-форвардинг ===")
	log.Printf("отправлено %d, получено %d, ПОТЕРЯНО %d (%.1f%%)",
		n, len(got), lost, float64(lost)*100/float64(n))
	if len(rtts) == 0 {
		log.Printf("→ UDP-форвардинг НЕ работает вовсе: ни одного ответа")
		return
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	log.Printf("RTT UDP через туннель: min %v, med %v, p95 %v, max %v",
		rtts[0].Round(time.Millisecond),
		rtts[len(rtts)/2].Round(time.Millisecond),
		rtts[min(len(rtts)-1, len(rtts)*95/100)].Round(time.Millisecond),
		rtts[len(rtts)-1].Round(time.Millisecond))
	if lost > n/10 {
		log.Printf("→ потери >10%%: UDP-форвардинг теряет пакеты — вот почему YouTube/Discord рвутся")
	} else if lost > 0 {
		log.Printf("→ потери есть, но умеренные")
	} else {
		log.Printf("→ UDP-форвардинг работает чисто")
	}
}

// buildDNSPacket собирает IPv4+UDP+DNS-запрос example.com A.
func buildDNSPacket(src netip.Addr, dst netip.AddrPort, id, sport uint16) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{
		Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	})
	dnsMsg, _ := b.Finish()

	srcB := src.As4()
	dstB := dst.Addr().As4()
	udpLen := 8 + len(dnsMsg)
	totalLen := 20 + udpLen

	pkt := make([]byte, totalLen)
	// IPv4
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(totalLen))
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], srcB[:])
	copy(pkt[16:20], dstB[:])
	binary.BigEndian.PutUint16(pkt[10:], ipChecksum(pkt[:20]))
	// UDP
	binary.BigEndian.PutUint16(pkt[20:], sport)      // src port
	binary.BigEndian.PutUint16(pkt[22:], dst.Port()) // dst port
	binary.BigEndian.PutUint16(pkt[24:], uint16(udpLen))
	copy(pkt[28:], dnsMsg)
	binary.BigEndian.PutUint16(pkt[26:], udpChecksum(pkt))
	return pkt
}

// parseDNSReplyID достаёт ID из входящего IP/UDP/DNS-пакета, адресованного src.
func parseDNSReplyID(pkt []byte, src netip.Addr) (uint16, bool) {
	if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != 17 {
		return 0, false
	}
	dstIP := netip.AddrFrom4([4]byte(pkt[16:20]))
	if dstIP != src {
		return 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	dns := pkt[ihl+8:]
	if len(dns) < 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(dns), true
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// udpChecksum считает контрольную сумму UDP с псевдозаголовком IPv4.
func udpChecksum(pkt []byte) uint16 {
	udp := pkt[20:]
	var sum uint32
	// псевдозаголовок: src, dst, proto, udpLen
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	sum += 17
	sum += uint32(len(udp))
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i:]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	c := ^uint16(sum)
	if c == 0 {
		c = 0xffff
	}
	return c
}
