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
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"time"

	connectip "github.com/quic-go/connect-ip-go"

	"quicdiver/internal/server"
	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/chain"
	"quicdiver/internal/server/db"
	"quicdiver/internal/server/dns"
	"quicdiver/internal/server/netstack"
	"quicdiver/internal/transport/cip"
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
	dbPath := flag.String("db", "", "файл БД токенов (пусто → узел ОТКРЫТ, любой клиент проходит — только для dev)")
	poolCIDR := flag.String("pool", "10.7.0.0/16", "пул адресов клиентов (IPv4); каждому токену — стабильный адрес")
	upstreamAddr := flag.String("upstream", "", "выход через upstream-узел host:port (цепочка); пусто → direct")
	upstreamAuthority := flag.String("upstream-authority", "", "authority upstream-узла (пусто → host из -upstream)")
	upstreamToken := flag.String("upstream-token", "", "node-токен для upstream-узла")
	adminToken := flag.String("admin-token", "", "admin-токен сети из деплоя: его хеш кладётся в БД (пусто → не трогать)")
	nodeToken := flag.String("node-token", "", "node-токен этого узла из деплоя: его хеш кладётся в БД (пусто → не трогать)")
	addUser := flag.Bool("add-user", false, "сгенерировать клиентский токен, записать в БД и выйти (нужен -db)")
	userLabel := flag.String("label", "", "имя клиента для -add-user")
	flag.Parse()

	log.SetPrefix("qd-server: ")

	// Управляющие команды (генерация токенов) — заготовка кнопок будущей панели.
	if *addUser {
		if err := cmdAddUser(*dbPath, *userLabel); err != nil {
			log.Fatalf("add-user: %v", err)
		}
		return
	}

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

	up, err := dns.ParseUpstream(*dnsUpstream)
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

	// БД токенов. Пусто → узел открыт (dev/e2e). В бою обязательна: иначе туннель
	// — открытый прокси.
	var store *db.SQLite
	if *dbPath != "" {
		store, err = db.Open(*dbPath)
		if err != nil {
			log.Fatalf("db: %v", err)
		}
		defer store.Close()
		// Секреты сети из деплой-параметров → хеши в БД. Открытый секрет в БД не
		// попадает; при репликации хеши разнесутся по узлам сети (arch2).
		seedNetworkToken(store, *adminToken, auth.RoleAdmin)
		seedNetworkToken(store, *nodeToken, auth.RoleNode)
		if counts, err := store.CountByRole(context.Background()); err == nil {
			log.Printf("БД: %s (user=%d admin=%d node=%d)", *dbPath,
				counts[auth.RoleUser], counts[auth.RoleAdmin], counts[auth.RoleNode])
		}
	} else {
		log.Print("ВНИМАНИЕ: -db не задан — узел ОТКРЫТ, авторизации нет (только dev)")
	}

	cfg := server.Config{
		Listen:             *listen,
		Authority:          *authority,
		ConnectIPPath:      "/connect-ip",
		Resolver:           resolver,
		DNSPath:            "/dns-query",
		DNSGCEvery:         *dnsGC,
		AuthPath:           "/qd-auth",
		AdminPath:          "/qd-admin/dns",
		AdminOutboundsPath: "/qd-admin/outbounds",
		Store:              storeOrNil(store),
		Pool:               poolFor(store, *poolCIDR),
		TLS:                tlsConf,
		Assign:             []netip.Prefix{pfx},
		Routes: []connectip.IPRoute{
			{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")},
			{StartIP: netip.MustParseAddr("::"), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		},
		Dialer: netstack.NetDialer{},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Выходы узла (arch: роутинг/цепочки). direct + chain-выходы из БД; admin
	// перенастраивает через API. Пул делится на подсети (по одной на выход); клиент
	// шлёт с src нужной подсети (UDP) или ставит метку Qd-Route (TCP).
	if store != nil {
		obs := server.NewOutbounds(cfg.Pool, netstack.NetDialer{}, chainDialer(ctx))
		defer obs.Close()

		// Разовый выход из флага -upstream — сеем в БД как chain "chain" (обратная
		// совместимость + удобно поднять стенд одной командой).
		if *upstreamAddr != "" {
			auth := *upstreamAuthority
			if auth == "" {
				h, _, _ := net.SplitHostPort(*upstreamAddr)
				auth = h
			}
			if err := store.PutOutbound(ctx, db.OutboundRow{
				Label: "chain", Type: db.OutChain, Addr: *upstreamAddr,
				Authority: auth, Token: *upstreamToken, Enabled: true,
			}); err != nil {
				log.Printf("seed outbound: %v", err)
			}
		}
		if err := obs.Reload(ctx, store); err != nil {
			log.Fatalf("выходы: %v", err)
		}
		cfg.Outbounds = obs
		cfg.OutboundStore = store
		log.Printf("выходы: %v", obs.Labels())
	}

	log.Printf("узел на %s (authority=%s, назначаю клиенту %s)", *listen, *authority, *assign)
	if err := server.Run(ctx, cfg); err != nil && ctx.Err() == nil {
		log.Fatalf("run: %v", err)
	}
	log.Print("остановлен")
}

// chainDialer — фабрика chain-выходов для менеджера outbounds. Живёт в main, а не
// в server: cip импортирует server (Template), прямой импорт дал бы цикл.
func chainDialer(base context.Context) server.ChainDialer {
	return func(_ context.Context, addr, authority, token string) (netstack.Dialer, io.Closer, error) {
		if authority == "" {
			h, _, _ := net.SplitHostPort(addr)
			authority = h
		}
		tmpl := server.Template(authority, "/connect-ip")
		sni, _, _ := net.SplitHostPort(addr)
		tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: sni}
		// base-контекст (жизнь узла), а не dctx запроса: цепочка живёт долго.
		client, _, err := cip.DialAuth(base, addr, tmpl, tlsConf, token, "https://"+authority+"/qd-auth")
		if err != nil {
			return nil, nil, err
		}
		return chain.New(client.H3Conn()), client, nil
	}
}

// storeOrNil отдаёт nil-интерфейс, если БД нет: server.Config.Store — интерфейс,
// а типизированный nil-указатель в нём != nil и сломал бы проверку «узел открыт».
func storeOrNil(s *db.SQLite) db.Store {
	if s == nil {
		return nil
	}
	return s
}

// poolFor разбирает пул адресов. Без БД пул не нужен (клиент получает статический
// Assign) — возвращаем невалидный префикс.
func poolFor(s *db.SQLite, cidr string) netip.Prefix {
	if s == nil {
		return netip.Prefix{}
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		log.Fatalf("bad -pool: %v", err)
	}
	log.Printf("пул адресов клиентов: %s", p)
	return p
}

// seedNetworkToken кладёт хеш admin/node-секрета из деплой-параметров в БД. Сам
// секрет в БД не хранится — только хеш, поэтому утечка реплики его не выдаёт.
func seedNetworkToken(store *db.SQLite, token string, role auth.Role) {
	if token == "" {
		return
	}
	if err := store.PutToken(context.Background(), auth.Hash(token), role, string(role)+"-сети"); err != nil {
		log.Fatalf("seed %s: %v", role, err)
	}
}

// cmdAddUser генерирует клиентский токен, пишет его хеш в БД и печатает открытый
// токен ОДИН раз. Заготовка кнопки «добавить клиента» будущей веб-панели.
func cmdAddUser(dbPath, label string) error {
	if dbPath == "" {
		return fmt.Errorf("нужен -db")
	}
	store, err := db.Open(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	token, err := auth.Generate()
	if err != nil {
		return err
	}
	if err := store.PutToken(context.Background(), auth.Hash(token), auth.RoleUser, label); err != nil {
		return err
	}
	fmt.Printf("клиентский токен создан (показывается один раз):\n\n  %s\n\n", token)
	fmt.Printf("метка: %q\nв БД лежит только хеш; передайте токен клиенту флагом -token.\n", label)
	return nil
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
