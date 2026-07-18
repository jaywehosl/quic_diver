// quicprobe сравнивает достижимость узла по TCP-TLS и по QUIC/HTTP3 с одной
// машины. Кейс: googlevideo ACKает наш TCP ClientHello, но ServerHello не
// приходит. Если DPI режет открытый TLS ServerHello — QUIC (рукопожатие
// зашифровано целиком, открытого ServerHello нет) должен пройти. Если узел
// молчит и по QUIC — троттлинг по source-IP на стороне Google.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

const sni = "rr1---sn-4g5ednse.googlevideo.com"

func tcpTLS(ip string) (bool, time.Duration, string) {
	start := time.Now()
	d := net.Dialer{Timeout: 6 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", ip+":443",
		&tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		return false, time.Since(start), err.Error()
	}
	conn.Close()
	return true, time.Since(start), ""
}

func quicHS(ip string) (bool, time.Duration, string) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ip+":443",
		&tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"h3"}},
		&quic.Config{HandshakeIdleTimeout: 6 * time.Second})
	if err != nil {
		return false, time.Since(start), err.Error()
	}
	conn.CloseWithError(0, "")
	return true, time.Since(start), ""
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func main() {
	for _, ip := range os.Args[1:] {
		tok, tt, terr := tcpTLS(ip)
		qok, qt, qerr := quicHS(ip)
		ts, qs := "МЁРТВ", "МЁРТВ"
		if tok {
			ts = "ЖИВ"
		}
		if qok {
			qs = "ЖИВ"
		}
		fmt.Printf("%-16s TCP-TLS=%-5s %4dms | QUIC-h3=%-5s %4dms | t:%s q:%s\n",
			ip, ts, tt.Milliseconds(), qs, qt.Milliseconds(), short(terr, 22), short(qerr, 30))
	}
}
