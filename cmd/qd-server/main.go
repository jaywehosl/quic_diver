// Command qd-server — узел QUIC Diver. master = slave: роль определяется
// конфигом/наличием БД, не кодовой базой. Единый admin-токен коннектится к любому
// узлу; узел может дозваниваться до upstream-узла как chain-аутбаунд.
//
// Пока: боевой connect-ip узел с gVisor-forwarder (direct-выход) и decoy. TLS —
// self-signed для локали (-authority localhost:8443). БД/auth/chain — следующие
// кирпичи.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"time"

	connectip "github.com/quic-go/connect-ip-go"

	"quicdiver/internal/server"
	"quicdiver/internal/server/dns"
	"quicdiver/internal/server/netstack"
)

func main() {
	listen := flag.String("listen", ":8443", "UDP-адрес прослушивания QUIC")
	authority := flag.String("authority", "localhost:8443", "host:port в connect-ip URI (совпадает с клиентом)")
	assign := flag.String("assign", "10.7.0.2/32", "адрес, назначаемый клиенту")
	certFile := flag.String("cert", "", "TLS cert (PEM); пусто → self-signed dev")
	keyFile := flag.String("key", "", "TLS key (PEM)")
	pprofAddr := flag.String("pprof", "", "адрес pprof (напр. localhost:6060); пусто → выкл")
	dnsUpstream := flag.String("dns", "https://dns.google/dns-query",
		"upstream DNS узла: https://... (DoH), tls://host:853 (DoT) или udp://host:53 (plain)")
	dnsCache := flag.Int("dns-cache", 4096, "размер DNS-кеша в записях (0 — выключить)")
	dnsTTL := flag.Duration("dns-ttl", 0, "принудительный TTL кеша (0 — брать из ответа)")
	dnsMinTTL := flag.Duration("dns-min-ttl", 5*time.Second, "не кешировать короче")
	dnsMaxTTL := flag.Duration("dns-max-ttl", time.Hour, "не кешировать дольше")
	dnsGC := flag.Duration("dns-gc", time.Minute, "период мягкой очистки кеша (выброс протухшего)")
	flag.Parse()

	log.SetPrefix("qd-server: ")

	if *pprofAddr != "" {
		go func() { log.Printf("pprof: %v", http.ListenAndServe(*pprofAddr, nil)) }()
	}

	tlsConf, err := loadTLS(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	pfx, err := netip.ParsePrefix(*assign)
	if err != nil {
		log.Fatalf("bad -assign: %v", err)
	}

	up, err := parseUpstream(*dnsUpstream)
	if err != nil {
		log.Fatalf("dns upstream: %v", err)
	}
	resolver := dns.New(dns.Config{
		Upstream:    up,
		CacheSize:   *dnsCache,
		TTLOverride: *dnsTTL,
		MinTTL:      *dnsMinTTL,
		MaxTTL:      *dnsMaxTTL,
	})
	log.Printf("DNS: upstream %s, кеш %d записей", up, *dnsCache)

	cfg := server.Config{
		Listen:        *listen,
		Authority:     *authority,
		ConnectIPPath: "/connect-ip",
		Resolver:      resolver,
		DNSPath:       "/dns-query",
		DNSGCEvery:    *dnsGC,
		TLS:           tlsConf,
		Assign:        []netip.Prefix{pfx},
		Routes: []connectip.IPRoute{
			{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")},
			{StartIP: netip.MustParseAddr("::"), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		},
		Dialer: netstack.NetDialer{},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	log.Printf("узел на %s (authority=%s, назначаю клиенту %s)", *listen, *authority, *assign)
	if err := server.Run(ctx, cfg); err != nil && ctx.Err() == nil {
		log.Fatalf("run: %v", err)
	}
	log.Print("остановлен")
}

// parseUpstream разбирает адрес upstream-DNS: схема выбирает транспорт (arch —
// «DNS, DoT, DoH на выбор»).
func parseUpstream(s string) (dns.Upstream, error) {
	switch {
	case strings.HasPrefix(s, "https://"):
		return dns.NewDoH(s), nil
	case strings.HasPrefix(s, "tls://"):
		addr := strings.TrimPrefix(s, "tls://")
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("tls:// ждёт host:port: %w", err)
		}
		return dns.NewDoT(addr, host), nil
	case strings.HasPrefix(s, "udp://"):
		return dns.NewPlain(strings.TrimPrefix(s, "udp://")), nil
	default:
		return nil, fmt.Errorf("неизвестная схема %q (нужно https://, tls:// или udp://)", s)
	}
}

// loadTLS берёт серт из файлов (реальный домен) или генерит self-signed (dev).
func loadTLS(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return server.DevTLS()
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}
