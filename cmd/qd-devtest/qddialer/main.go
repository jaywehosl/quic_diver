// Command qddialer — проверка клиентского пути гибрида БЕЗ WinDivert: тот же
// cip.Client + connectdial.Dialer, что использует qd-client. Открывает
// CONNECT-стрим до benchsrv и качает. Изолирует Dialer от netstack/перехвата.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
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
	srv := flag.String("server", "localhost:8443", "endpoint узла")
	authority := flag.String("authority", "localhost:8443", "authority connect-ip")
	target := flag.String("target", "localhost:8080", "benchsrv")
	dur := flag.Duration("d", 10*time.Second, "длительность")
	flag.Parse()

	ctx := context.Background()
	host, _, _ := net.SplitHostPort(*srv)
	tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: host}
	tmpl := server.Template(*authority, "/connect-ip")

	// Точно как в qd-client: connect-ip туннель, поверх него — CONNECT-стримы.
	client, rsp, err := cip.Dial(ctx, *srv, tmpl, tlsConf)
	if err != nil {
		log.Fatalf("cip.Dial: %v", err)
	}
	defer client.Close()
	log.Printf("connect-ip туннель ok (status %d)", rsp.StatusCode)

	if client.H3Conn() == nil {
		log.Fatal("H3Conn() == nil — гибрид не сможет открыть CONNECT")
	}
	log.Print("H3Conn() получен")

	d := connectdial.Dialer{CC: client.H3Conn()}
	dst, err := netip.ParseAddrPort(*target)
	if err != nil {
		log.Fatalf("target: %v", err)
	}

	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, err := d.DialTCP(dctx, dst)
	cancel()
	if err != nil {
		log.Fatalf("DialTCP (CONNECT): %v  ← ВОТ ОНА, ПРИЧИНА", err)
	}
	defer conn.Close()
	log.Printf("DialTCP OK → %s", conn.RemoteAddr())

	if _, err := fmt.Fprintf(conn, "GET /zero HTTP/1.1\r\nHost: %s\r\n\r\n", *target); err != nil {
		log.Fatalf("write: %v", err)
	}
	br := bufio.NewReaderSize(conn, 256*1024)
	inner, err := http.ReadResponse(br, nil)
	if err != nil {
		log.Fatalf("inner response: %v", err)
	}
	log.Printf("benchsrv ответил %s — качаю %v", inner.Status, *dur)

	buf := make([]byte, 256*1024)
	var total int64
	start := time.Now()
	deadline := start.Add(*dur)
	for time.Now().Before(deadline) {
		n, err := inner.Body.Read(buf)
		total += int64(n)
		if err != nil {
			log.Printf("read: %v", err)
			break
		}
	}
	el := time.Since(start)
	log.Printf("ИТОГ через connectdial: %.1f Mbps (%d МБ за %v)",
		float64(total)*8/el.Seconds()/1e6, total/1024/1024, el.Round(time.Millisecond))
}
