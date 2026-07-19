// Command qdstun — проверка UDP-роутинга: каким внешним адресом узел выпускает
// UDP-флоу.
//
// DNS-ответ не показывает точку выхода, поэтому берём STUN (RFC 5389): сервер
// возвращает XOR-MAPPED-ADDRESS — тот адрес, который увидел.
//
// Флоу открывается CONNECT-UDP (RFC 9298), метка выхода едет заголовком — ровно
// как у TCP. Прежняя версия собирала IP-пакет вручную и метила выход src-адресом
// из нарезки пула; теперь этого нет, и инструмент проверяет именно новый путь.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	"quicdiver/internal/client/routing"
	"quicdiver/internal/server"
	"quicdiver/internal/transport/cip"
	"quicdiver/internal/transport/connectudp"
)

func main() {
	srv := flag.String("server", "localhost:8443", "endpoint узла")
	authority := flag.String("authority", "", "authority (по умолчанию host из -server)")
	token := flag.String("token", "", "токен доступа к узлу")
	route := flag.String("route", "", "метка выхода (пусто → выход по умолчанию)")
	stunHost := flag.String("stun", "74.125.250.129:19302", "STUN-сервер (IP:port)")
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

	dst, err := netip.ParseAddrPort(*stunHost)
	if err != nil {
		log.Fatalf("-stun: %v", err)
	}

	// Метка выхода — тем же заголовком, что у TCP.
	var hdr http.Header
	if *route != "" && *route != "direct" {
		hdr = http.Header{routing.RouteHeaderName: []string{*route}}
	}
	label := *route
	if label == "" {
		label = "(по умолчанию)"
	}
	log.Printf("открываю UDP-флоу к %s, метка выхода %q", dst, label)

	dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
	conn, err := connectudp.Dialer{CC: client.H3Conn(), Authority: auth, Header: hdr}.Dial(dctx, dst)
	dcancel()
	if err != nil {
		log.Fatalf("CONNECT-UDP: %v", err)
	}
	defer conn.Close()

	req, txid := stunRequest()
	if _, err := conn.Write(req); err != nil {
		log.Fatalf("отправка: %v", err)
	}

	deadline := time.Now().Add(*wait)
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if err != nil {
			log.Fatalf("чтение: %v", err)
		}
		ext, ok := stunMapped(buf[:n], txid)
		if !ok {
			continue // не наш ответ — ждём дальше
		}
		fmt.Printf("\nВЫХОД %q → внешний адрес %s\n", label, ext)
		return
	}
	log.Fatalf("ответ STUN не пришёл за %v (метка %q)", *wait, label)
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

// stunMapped достаёт XOR-MAPPED-ADDRESS (адрес хранится в XOR с magic).
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
