// Command qdstun — проверка UDP-роутинга по меткам: каким внешним адресом узел
// выпускает UDP-флоу.
//
// DNS-ответ не показывает, откуда вышел пакет, поэтому берём STUN (RFC 5389):
// сервер отвечает XOR-MAPPED-ADDRESS — тем адресом, который увидел. Пакет
// собираем сами и шлём в connect-ip туннель ровно как реальный клиент после
// WinDivert+NAT, подставляя src из подсети нужного выхода: узел роутит UDP по
// src-адресу, значит метка едет именно в нём.
//
// direct → должен вернуть адрес самого узла, chain → адрес upstream-узла.
// Прав администратора не нужно (WinDivert не участвует).
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	"quicdiver/internal/server"
	"quicdiver/internal/transport/cip"
)

func main() {
	srv := flag.String("server", "localhost:8443", "endpoint узла")
	authority := flag.String("authority", "", "authority (по умолчанию host из -server)")
	token := flag.String("token", "", "токен доступа к узлу")
	route := flag.String("route", "", "метка выхода (пусто → первый доступный)")
	stunHost := flag.String("stun", "74.125.250.129:19302", "STUN-сервер (IP:port, google)")
	wait := flag.Duration("wait", 6*time.Second, "сколько ждать ответ")
	flag.Parse()

	auth := *authority
	if auth == "" {
		h, _, _ := net.SplitHostPort(*srv)
		auth = h
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	sni, _, _ := net.SplitHostPort(*srv)
	client, _, err := cip.DialAuth(ctx, *srv, server.Template(auth, "/connect-ip"),
		&tls.Config{InsecureSkipVerify: true, ServerName: sni}, *token, "https://"+auth+"/qd-auth")
	if err != nil {
		log.Fatalf("туннель: %v", err)
	}
	defer client.Close()

	prefs, err := client.LocalPrefixes(ctx)
	if err != nil {
		log.Fatalf("назначенные адреса: %v", err)
	}
	log.Printf("узел назначил: %v", prefs)

	src, label := pickSrc(ctx, client, auth, prefs, *route)
	log.Printf("выход %q → шлём с src %v", label, src)

	dst, err := netip.ParseAddrPort(*stunHost)
	if err != nil {
		log.Fatalf("-stun: %v", err)
	}

	req, txid := stunRequest()
	pkt := buildUDPv4(src, dst.Addr(), 34567, dst.Port(), req)
	if _, err := client.WritePacket(pkt); err != nil {
		log.Fatalf("отправка: %v", err)
	}

	deadline := time.Now().Add(*wait)
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		n, err := client.ReadPacket(buf)
		if err != nil {
			log.Fatalf("чтение: %v", err)
		}
		payload, ok := udpPayload(buf[:n])
		if !ok {
			continue
		}
		ext, ok := stunMapped(payload, txid)
		if !ok {
			continue
		}
		fmt.Printf("\nВЫХОД %q → внешний адрес %s\n", label, ext)
		return
	}
	log.Fatalf("ответ STUN не пришёл за %v (метка %q)", *wait, label)
}

// pickSrc выбирает src-адрес из подсети нужного выхода: узел роутит UDP по нему.
func pickSrc(ctx context.Context, c *cip.Client, authority string, prefs []netip.Prefix, want string) (netip.Addr, string) {
	obs := fetchOutbounds(ctx, c, authority)
	for _, o := range obs {
		if want != "" && o.Label != want {
			continue
		}
		sub, err := netip.ParsePrefix(o.Subnet)
		if err != nil {
			continue
		}
		for _, p := range prefs {
			if sub.Contains(p.Addr()) && p.Addr().Is4() {
				return p.Addr(), o.Label
			}
		}
	}
	if want != "" {
		log.Fatalf("выход %q не найден (доступны: %v)", want, labels(obs))
	}
	for _, p := range prefs { // узел без выходов — единственный адрес
		if p.Addr().Is4() {
			return p.Addr(), "(по умолчанию)"
		}
	}
	log.Fatal("нет IPv4-адреса от узла")
	return netip.Addr{}, ""
}

func fetchOutbounds(ctx context.Context, c *cip.Client, authority string) []server.PublicOutbound {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+authority+"/qd-outbounds", nil)
	resp, err := c.H3Conn().RoundTrip(req)
	if err != nil {
		log.Printf("выходы узла недоступны: %v", err)
		return nil
	}
	defer resp.Body.Close()
	var obs []server.PublicOutbound
	if err := json.NewDecoder(resp.Body).Decode(&obs); err != nil {
		log.Printf("разбор выходов: %v", err)
		return nil
	}
	log.Printf("выходы узла: %v", labels(obs))
	return obs
}

func labels(obs []server.PublicOutbound) []string {
	out := make([]string, 0, len(obs))
	for _, o := range obs {
		out = append(out, o.Label+"="+o.Subnet)
	}
	return out
}

// --- STUN (RFC 5389) ---

const stunMagic = 0x2112A442

func stunRequest() ([]byte, [12]byte) {
	var txid [12]byte
	rand.Read(txid[:])
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(b[2:], 0)      // без атрибутов
	binary.BigEndian.PutUint32(b[4:], stunMagic)
	copy(b[8:], txid[:])
	return b, txid
}

// stunMapped достаёт XOR-MAPPED-ADDRESS из ответа (адрес хранится в XOR с magic).
func stunMapped(b []byte, txid [12]byte) (netip.AddrPort, bool) {
	if len(b) < 20 || binary.BigEndian.Uint16(b[0:]) != 0x0101 ||
		binary.BigEndian.Uint32(b[4:]) != stunMagic || [12]byte(b[8:20]) != txid {
		return netip.AddrPort{}, false
	}
	attrs := b[20:]
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:])
		l := int(binary.BigEndian.Uint16(attrs[2:]))
		if len(attrs) < 4+l {
			return netip.AddrPort{}, false
		}
		v := attrs[4 : 4+l]
		if typ == 0x0020 && len(v) >= 8 && v[1] == 0x01 { // XOR-MAPPED-ADDRESS, IPv4
			port := binary.BigEndian.Uint16(v[2:]) ^ uint16(stunMagic>>16)
			var ip [4]byte
			binary.BigEndian.PutUint32(ip[:], binary.BigEndian.Uint32(v[4:])^stunMagic)
			return netip.AddrPortFrom(netip.AddrFrom4(ip), port), true
		}
		pad := (4 - l%4) % 4
		attrs = attrs[4+l+pad:]
	}
	return netip.AddrPort{}, false
}

// --- сборка/разбор пакетов (как это делает клиент после NAT) ---

func buildUDPv4(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	pkt := make([]byte, 20+udpLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(20+udpLen))
	pkt[8] = 64
	pkt[9] = 17
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:], csum(pkt[:20]))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	copy(udp[8:], payload)

	var sum uint32
	for _, p := range [][]byte{s[:], d[:]} {
		for i := 0; i+1 < len(p); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(p[i:]))
		}
	}
	sum += 17 + uint32(udpLen)
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i:]))
	}
	if udpLen%2 == 1 {
		sum += uint32(udp[udpLen-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	c := ^uint16(sum)
	if c == 0 {
		c = 0xFFFF
	}
	binary.BigEndian.PutUint16(udp[6:], c)
	return pkt
}

func udpPayload(pkt []byte) ([]byte, bool) {
	if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != 17 {
		return nil, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl+8 {
		return nil, false
	}
	udp := pkt[ihl:]
	ulen := int(binary.BigEndian.Uint16(udp[4:]))
	if ulen < 8 || ulen > len(udp) {
		return nil, false
	}
	return udp[8:ulen], true
}

func csum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
