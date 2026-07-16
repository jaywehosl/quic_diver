// Command qdv6 — проверка IPv6-выхода узла: просим узел дозвониться до v6-адреса
// через CONNECT-стрим и сделать HTTP-запрос. Отвечает на вопрос «есть ли у узла
// IPv6 наружу», не требуя доступа на саму машину.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
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
	srv := flag.String("server", "localhost:8443", "endpoint узла")
	authority := flag.String("authority", "localhost:8443", "authority")
	target := flag.String("target", "[2a02:e00:ffec:4b8::1]:443", "куда узел должен дозвониться")
	host := flag.String("host", "ntc.party", "Host/SNI для запроса")
	get := flag.String("get", "", "сделать GET этого пути и напечатать тело (напр. / для ipify — покажет v6-адрес узла)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sni, _, _ := net.SplitHostPort(*srv)
	client, _, err := cip.Dial(ctx, *srv, server.Template(*authority, "/connect-ip"),
		&tls.Config{InsecureSkipVerify: true, ServerName: sni})
	if err != nil {
		log.Fatalf("cip.Dial: %v", err)
	}
	defer client.Close()

	d := connectdial.Dialer{CC: client.H3Conn()}
	addr, err := netip.ParseAddrPort(*target)
	if err != nil {
		log.Fatalf("bad -target %q: %v", *target, err)
	}

	start := time.Now()
	conn, err := d.DialTCP(ctx, addr)
	if err != nil {
		log.Fatalf("узел НЕ смог дозвониться до %s: %v\n(значит у узла нет IPv6 наружу)", *target, err)
	}
	defer conn.Close()
	log.Printf("узел дозвонился до %s за %v — IPv6-выход есть", *target, time.Since(start).Round(time.Millisecond))

	// дедлайн на самом соединении: ctx не прерывает Read/Write, и без него
	// чтение тела висит вечно, если хост не закрыл поток
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	// поверх — настоящий TLS+HTTP, чтобы убедиться, что это рабочий путь, а не
	// просто открытый сокет
	tc := tls.Client(conn, &tls.Config{ServerName: *host})
	if err := tc.HandshakeContext(ctx); err != nil {
		log.Fatalf("TLS: %v", err)
	}
	method, path := http.MethodHead, "/"
	if *get != "" {
		method, path = http.MethodGet, *get
	}
	req, _ := http.NewRequest(method, "https://"+*host+path, nil)
	req.Header.Set("Connection", "close")
	if err := req.Write(tc); err != nil {
		log.Fatalf("запрос: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		log.Fatalf("ответ: %v", err)
	}
	defer resp.Body.Close()
	fmt.Printf("%s по IPv6 через узел: HTTP %d\n", *host, resp.StatusCode)
	if *get != "" {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		fmt.Printf("тело: %s\n", body)
	}
}
