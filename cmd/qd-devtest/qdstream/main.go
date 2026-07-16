// Command qdstream — проверка гипотезы гибрида: TCP-флоу через НАДЁЖНЫЙ QUIC-стрим
// (HTTP/3 CONNECT, RFC 9114) вместо ненадёжных датаграмм.
//
// Ретрансмит делает QUIC, поэтому потери туннеля не доходят до TCP. Если stream
// даёт заметно больше, чем connect-ip datagram (~115 Мбит) — гибрид оправдан.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	srv := flag.String("server", "localhost:8443", "endpoint узла")
	sni := flag.String("sni", "localhost:8443", "TLS ServerName")
	target := flag.String("target", "localhost:8080", "benchsrv (host:port) — куда CONNECT")
	dur := flag.Duration("d", 15*time.Second, "длительность")
	flag.Parse()

	ctx := context.Background()
	qconn, err := quic.DialAddr(ctx, *srv, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         *sni,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		log.Fatalf("quic dial: %v", err)
	}
	defer qconn.CloseWithError(0, "")

	tr := &http3.Transport{EnableDatagrams: true}
	defer tr.Close()
	cc := tr.NewClientConn(qconn)

	// CONNECT-туннель до benchsrv через узел.
	pr, pw := io.Pipe()
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: *target},
		Host:   *target,
		Header: make(http.Header),
		Body:   pr,
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		log.Fatalf("CONNECT: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("CONNECT status: %d", resp.StatusCode)
	}
	log.Printf("CONNECT-туннель до %s открыт (200)", *target)

	// Внутри туннеля — обычный HTTP-запрос к benchsrv.
	if _, err := fmt.Fprintf(pw, "GET /zero HTTP/1.1\r\nHost: %s\r\n\r\n", *target); err != nil {
		log.Fatalf("write request: %v", err)
	}
	br := bufio.NewReaderSize(resp.Body, 256*1024)
	inner, err := http.ReadResponse(br, nil)
	if err != nil {
		log.Fatalf("inner response: %v", err)
	}
	log.Printf("benchsrv ответил %s — качаю %v через СТРИМ", inner.Status, *dur)

	buf := make([]byte, 256*1024)
	var total, lastTotal int64
	var samples []float64
	start := time.Now()
	deadline := start.Add(*dur)
	lastT := start
	for time.Now().Before(deadline) {
		n, err := inner.Body.Read(buf)
		total += int64(n)
		if now := time.Now(); now.Sub(lastT) >= time.Second {
			mbps := float64(total-lastTotal) * 8 / now.Sub(lastT).Seconds() / 1e6
			samples = append(samples, mbps)
			log.Printf("  %6.1f Mbps", mbps)
			lastTotal, lastT = total, now
		}
		if err != nil {
			log.Printf("read: %v", err)
			break
		}
	}
	el := time.Since(start)

	avg := float64(total) * 8 / el.Seconds() / 1e6
	log.Printf("=== TCP через НАДЁЖНЫЙ СТРИМ (CONNECT) ===")
	log.Printf("throughput: avg %.1f Mbps, stddev %.1f Mbps (%.0f%% от среднего), %d МБ за %v",
		avg, stddev(samples), stddev(samples)*100/math.Max(avg, 1), total/1024/1024, el.Round(time.Millisecond))
	log.Printf("→ сравни: connect-ip datagram давал ~115 Mbps, чистый транспорт ~560 Mbps")
}

func stddev(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))
	var v float64
	for _, x := range xs {
		v += (x - mean) * (x - mean)
	}
	return math.Sqrt(v / float64(len(xs)))
}
