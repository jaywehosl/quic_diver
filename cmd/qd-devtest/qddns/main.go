// Command qddns — проверка резолва через узел (DoH внутри туннеля), без админа.
// Показывает разницу с системным DNS: провайдер подменяет ответы на заглушку.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"quicdiver/internal/client/dnsforward"
	"quicdiver/internal/client/dnsproxy"
	"quicdiver/internal/client/nat46"
	"quicdiver/internal/server"
	"quicdiver/internal/transport/cip"
)

func main() {
	srv := flag.String("server", "localhost:8443", "endpoint узла")
	authority := flag.String("authority", "localhost:8443", "authority")
	domain := flag.String("domain", "instagram.com", "что резолвить")
	v6 := flag.Bool("aaaa", false, "спрашивать AAAA (IPv6) вместо A")
	listen := flag.String("listen", "", "поднять локальный DNS-listener на этом адресе и ждать (напр. 127.0.0.1:5353); проверка боевого пути без прав админа")
	withNAT46 := flag.Bool("nat46", false, "включить синтез A для v6-only хостов (как в бою)")
	flag.Parse()

	timeout := 25 * time.Second
	if *listen != "" {
		timeout = time.Hour
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	host, _, _ := net.SplitHostPort(*srv)
	client, _, err := cip.Dial(ctx, *srv, server.Template(*authority, "/connect-ip"),
		&tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		log.Fatalf("cip.Dial: %v", err)
	}
	defer client.Close()

	fwd := dnsforward.New(client.H3Conn(), "https://"+*authority+"/dns-query")

	// Режим listener'а: тот же путь, что и в бою (приложение → наш listener →
	// DoH → узел), только на нестандартном порту и без подмены системного DNS —
	// поэтому не нужен админ. Проверять: nslookup example.com 127.0.0.1 -port=5353
	if *listen != "" {
		var ex dnsproxy.Exchanger = traced{fwd}
		if *withNAT46 {
			tbl := nat46.NewTable(nat46.DefaultPool, nat46.DefaultTTL)
			ex = nat46.NewResolver(ex, tbl)
			log.Printf("NAT46 включён: v6-only хосты получат адрес из %s", tbl.Pool())
		}
		p, err := dnsproxy.New(dnsproxy.Config{Addrs: []string{*listen}, Exchange: ex})
		if err != nil {
			log.Fatalf("listener: %v", err)
		}
		log.Printf("DNS-listener на %v (проверка: nslookup %s %s)", p.Addrs(), *domain, *listen)
		if err := p.Run(ctx); err != nil {
			log.Fatalf("listener: %v", err)
		}
		return
	}

	qtype := dnsmessage.TypeA
	if *v6 {
		qtype = dnsmessage.TypeAAAA
	}
	start := time.Now()
	resp, err := fwd.Query(ctx, buildQuery(*domain, qtype))
	if err != nil {
		log.Fatalf("резолв через узел: %v", err)
	}
	log.Printf("резолв через узел за %v:", time.Since(start).Round(time.Millisecond))
	printAnswers(resp)

	// второй раз — должен прилететь из кеша узла (заметно быстрее)
	start = time.Now()
	if _, err := fwd.Query(ctx, buildQuery(*domain, qtype)); err != nil {
		log.Fatalf("повтор: %v", err)
	}
	log.Printf("повтор (кеш узла) за %v", time.Since(start).Round(time.Millisecond))

	// для сравнения — что отдаёт системный DNS (через провайдера)
	if ips, err := net.LookupHost(*domain); err == nil && len(ips) > 0 {
		log.Printf("системный DNS отдаёт: %v", ips)
	}
}

// traced печатает каждый запрос, прошедший через listener: видно, что именно
// шлёт системный резолвер и чем мы ответили.
type traced struct{ inner *dnsforward.Forwarder }

func (t traced) Query(ctx context.Context, wire []byte) ([]byte, error) {
	var p dnsmessage.Parser
	var name, qtype string
	if _, err := p.Start(wire); err == nil {
		if q, err := p.Question(); err == nil {
			name, qtype = q.Name.String(), q.Type.String()
		}
	}
	start := time.Now()
	resp, err := t.inner.Query(ctx, wire)
	if err != nil {
		log.Printf("← %s %s: ОШИБКА %v", qtype, name, err)
		return nil, err
	}
	log.Printf("← %s %s: %d байт за %v", qtype, name, len(resp), time.Since(start).Round(time.Millisecond))
	return resp, nil
}

func buildQuery(domain string, t dnsmessage.Type) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(domain + "."),
		Type:  t,
		Class: dnsmessage.ClassINET,
	})
	msg, err := b.Finish()
	if err != nil {
		log.Fatalf("сборка запроса: %v", err)
	}
	return msg
}

func printAnswers(resp []byte) {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		log.Fatalf("разбор ответа: %v", err)
	}
	_ = p.SkipAllQuestions()
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, _ := p.AResource()
			log.Printf("  A    %s (TTL %ds)", net.IP(r.A[:]), h.TTL)
		case dnsmessage.TypeAAAA:
			r, _ := p.AAAAResource()
			log.Printf("  AAAA %s (TTL %ds)", net.IP(r.AAAA[:]), h.TTL)
		case dnsmessage.TypeCNAME:
			r, _ := p.CNAMEResource()
			log.Printf("  CNAME %s", r.CNAME)
		default:
			_ = p.SkipAnswer()
		}
	}
}
