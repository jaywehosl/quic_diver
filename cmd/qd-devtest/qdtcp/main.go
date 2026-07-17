// Command qdtcp — проверка TCP-выхода узла (в т.ч. через цепочку).
//
// Открывает CONNECT-стрим через узел к HTTP-хосту и делает GET, печатая ответ
// (например, свой внешний IP от ipify). Через узел с -upstream так виден проход
// TCP по цепочке A→B→наружу.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	"quicdiver/internal/client/connectdial"
	"quicdiver/internal/server"
	"quicdiver/internal/transport/cip"
)

func main() {
	srv := flag.String("server", "localhost:19444", "endpoint узла")
	authority := flag.String("authority", "", "authority (пусто → host из -server)")
	token := flag.String("token", "", "токен доступа")
	hostHdr := flag.String("host", "api.ipify.org", "Host для HTTP-запроса")
	dstStr := flag.String("dst", "", "TCP dst host:port (пусто → резолв -host:80)")
	flag.Parse()

	if *authority == "" {
		h, _, _ := net.SplitHostPort(*srv)
		*authority = h
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sni, _, _ := net.SplitHostPort(*srv)
	client, _, err := cip.DialAuth(ctx, *srv, server.Template(*authority, "/connect-ip"),
		&tls.Config{InsecureSkipVerify: true, ServerName: sni},
		*token, "https://"+*authority+"/qd-auth")
	if err != nil {
		log.Fatalf("cip.DialAuth: %v", err)
	}
	defer client.Close()

	dst := *dstStr
	if dst == "" {
		ips, err := net.LookupIP(*hostHdr)
		if err != nil || len(ips) == 0 {
			log.Fatalf("резолв %s: %v", *hostHdr, err)
		}
		dst = netip.AddrPortFrom(netip.MustParseAddr(ips[0].String()), 80).String()
	}
	dstAP, err := netip.ParseAddrPort(dst)
	if err != nil {
		log.Fatalf("bad dst: %v", err)
	}

	start := time.Now()
	conn, err := connectdial.Dialer{CC: client.H3Conn()}.DialTCP(ctx, dstAP)
	if err != nil {
		log.Fatalf("CONNECT %s через узел: %v", dstAP, err)
	}
	defer conn.Close()
	log.Printf("CONNECT %s открыт за %v", dstAP, time.Since(start).Round(time.Millisecond))

	// HTTP GET поверх стрима
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+*hostHdr+"\r\nConnection: close\r\n\r\n"); err != nil {
		log.Fatalf("запрос: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		log.Fatalf("ответ: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	log.Printf("HTTP %s | тело: %s", resp.Status, string(body))
	log.Printf("→ TCP-выход узла работает (через цепочку, если у узла -upstream)")
}
