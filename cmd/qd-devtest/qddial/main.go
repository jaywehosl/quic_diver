// Command qddial — dev-проверка транспорта и реального выхода в интернет через
// узел, БЕЗ WinDivert (не требует администратора).
//
// Устанавливает connect-ip туннель к узлу, берёт назначенный адрес, отправляет
// через туннель настоящий DNS-запрос к 8.8.8.8 и ждёт ответ — доказывает, что
// узел форвардит трафик в реальную сеть (весь серверный путь модели B).
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"quicdiver/internal/server"
	"quicdiver/internal/transport/cip"
)

func main() {
	srv := flag.String("server", "localhost:8443", "endpoint узла")
	authority := flag.String("authority", "localhost:8443", "authority в connect-ip URI")
	domain := flag.String("domain", "example.com", "домен для DNS-запроса через туннель")
	token := flag.String("token", "", "клиентский токен (узел с БД без него не пустит)")
	hold := flag.Duration("hold", 0, "держать туннель открытым после запроса (для проверки учёта)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second+*hold)
	defer cancel()

	host, _, _ := net.SplitHostPort(*srv)
	tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: host}
	tmpl := server.Template(*authority, "/connect-ip")

	log.Printf("dial %s (authority %s)...", *srv, *authority)
	client, rsp, err := cip.DialAuth(ctx, *srv, tmpl, tlsConf, *token, "https://"+*authority+"/qd-auth")
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer client.Close()
	log.Printf("туннель установлен, status %d", rsp.StatusCode)

	prefs, err := client.LocalPrefixes(ctx)
	if err != nil {
		log.Fatalf("local prefixes: %v", err)
	}
	if len(prefs) == 0 {
		log.Fatal("узел не назначил адрес")
	}
	src := prefs[0].Addr()
	log.Printf("узел назначил: %v (src=%s)", prefs, src)

	// DNS-запрос через туннель.
	dst := netip.MustParseAddr("8.8.8.8")
	query := buildDNSQuery(src, dst, 40000, *domain)
	if _, err := client.WritePacket(query); err != nil {
		log.Fatalf("write packet: %v", err)
	}
	log.Printf("DNS-запрос %s → 8.8.8.8 отправлен через туннель, жду ответ...", *domain)

	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := client.ReadPacket(buf)
			if err != nil {
				return
			}
			if ip, ok := parseDNSReply(buf[:n]); ok {
				got <- ip
				return
			}
		}
	}()

	select {
	case ip := <-got:
		log.Printf("УСПЕХ: %s → %s (через узел в реальный интернет)", *domain, ip)
	case <-ctx.Done():
		log.Fatalf("таймаут: ответ из туннеля не пришёл (%v)", ctx.Err())
	}

	// Учёт трафика узел сливает в базу не на каждый пакет, а раз в интервал:
	// туннель, закрытый сразу, до этого слива не доживёт.
	if *hold > 0 {
		log.Printf("держу туннель ещё %s", *hold)
		time.Sleep(*hold)
	}
}

// buildDNSQuery собирает IPv4/UDP/DNS-пакет с корректными контрольными суммами.
func buildDNSQuery(src, dst netip.Addr, sport uint16, domain string) []byte {
	dns := dnsQuestion(domain)
	udpLen := 8 + len(dns)
	total := 20 + udpLen
	pkt := make([]byte, total)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(total))
	pkt[8] = 64
	pkt[9] = 17 // UDP
	s4, d4 := src.As4(), dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	setIPv4Checksum(pkt)

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], 53)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	copy(udp[8:], dns)
	setUDPChecksum(pkt)
	return pkt
}

func dnsQuestion(domain string) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], 0x1234) // id
	binary.BigEndian.PutUint16(b[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(b[4:], 1)      // qdcount
	for _, label := range strings.Split(domain, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)       // root
	b = append(b, 0, 1)    // qtype A
	b = append(b, 0, 1)    // qclass IN
	return b
}

func setIPv4Checksum(pkt []byte) {
	pkt[10], pkt[11] = 0, 0
	binary.BigEndian.PutUint16(pkt[10:], ^onesSum(pkt[:20]))
}

func setUDPChecksum(pkt []byte) {
	udp := pkt[20:]
	udp[6], udp[7] = 0, 0
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], pkt[12:16])
	copy(pseudo[4:8], pkt[16:20])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(udp)))
	c := ^onesSum(append(pseudo, udp...))
	if c == 0 {
		c = 0xFFFF
	}
	binary.BigEndian.PutUint16(udp[6:], c)
}

func onesSum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s > 0xFFFF {
		s = (s & 0xFFFF) + (s >> 16)
	}
	return uint16(s)
}

// parseDNSReply проверяет, что пакет — IPv4/UDP DNS-ответ, и извлекает первую
// A-запись.
func parseDNSReply(pkt []byte) (string, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 17 {
		return "", false
	}
	ihl := int(pkt[0]&0x0F) * 4
	udp := pkt[ihl:]
	if len(udp) < 8 || binary.BigEndian.Uint16(udp[0:]) != 53 {
		return "", false // не от DNS-порта
	}
	dns := udp[8:]
	if len(dns) < 12 {
		return "", false
	}
	an := binary.BigEndian.Uint16(dns[6:8])
	if an == 0 {
		return "", false
	}
	off := 12
	for off < len(dns) && dns[off] != 0 { // skip qname
		off += int(dns[off]) + 1
	}
	off += 5 // null + qtype + qclass
	for i := 0; i < int(an) && off+12 <= len(dns); i++ {
		if dns[off]&0xC0 == 0xC0 {
			off += 2
		} else {
			for off < len(dns) && dns[off] != 0 {
				off += int(dns[off]) + 1
			}
			off++
		}
		if off+10 > len(dns) {
			break
		}
		typ := binary.BigEndian.Uint16(dns[off:])
		rdlen := int(binary.BigEndian.Uint16(dns[off+8:]))
		off += 10
		if typ == 1 && rdlen == 4 && off+4 <= len(dns) {
			return net.IP(dns[off : off+4]).String(), true
		}
		off += rdlen
	}
	return "", false
}
