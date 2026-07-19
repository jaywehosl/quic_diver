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
	masterAddr := flag.String("master", "",
		"адрес мастер-узла host:port при первой установке (дальше сеть узнаётся сама)")
	masterSNI := flag.String("master-sni", "", "имя мастера для TLS/:authority (пусто → host из -master)")
	beatEvery := flag.Duration("beat-every", time.Minute,
		"как часто узел отмечается живым у мастера")
	replicaEvery := flag.Duration("replica-every", 15*time.Minute,
		"как часто реплика забирает базу у мастера (0 — не реплицировать)")
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
	// live — та же база, но с возможностью горячей подмены: реплика применяет
	// снимок мастера, не перезапуская узел. Перезапуск рвал бы все туннели, а
	// обновляемся мы регулярно.
	var live *db.Live
	if *dbPath != "" {
		// Восстановление из снимка применяется здесь, до открытия базы: подменить
		// её на ходу нельзя, поэтому админ загружает файл, а подхватывает его
		// следующий запуск. Прежняя база отодвигается в .prev — если в снимке
		// окажется не то, есть куда вернуться.
		if applied, err := db.ApplyPendingRestore(*dbPath); err != nil {
			log.Fatalf("восстановление базы: %v", err)
		} else if applied {
			log.Printf("база восстановлена из снимка (прежняя сохранена как %s.prev)", *dbPath)
		}
		live, err = db.NewLive(*dbPath)
		if err != nil {
			log.Fatalf("db: %v", err)
		}
		defer live.Close()
		// Для разовых операций старта база нужна напрямую. Долго этот указатель
		// держать нельзя (подмена его обесценит) — в конфиг уходит live.
		store = live.DB()
		// Секреты сети из деплой-параметров → хеши в БД. Открытый секрет в БД не
		// попадает; при репликации хеши разнесутся по узлам сети (arch2).
		seedNetworkToken(store, *adminToken, auth.RoleAdmin)
		seedNetworkToken(store, *nodeToken, auth.RoleNode)
		// Кто мастер — говорит администратор при установке, один раз. Дальше узел
		// узнаёт сеть из снимков сам, поэтому флаг на уже работающем узле ничего
		// не переписывает (смена мастера — дело admin-API, осознанно).
		if *masterAddr != "" {
			sni := *masterSNI
			if sni == "" {
				sni, _, _ = net.SplitHostPort(*masterAddr)
			}
			done, err := store.BootstrapMaster(context.Background(), db.Node{
				ID: sni, Addr: *masterAddr, SNI: sni, Enabled: true,
				Label: "мастер (из установки)",
			})
			if err != nil {
				log.Printf("мастер из установки: %v", err)
			} else if done {
				log.Printf("мастер сети: %s (%s) — базу забираю у него", sni, *masterAddr)
			}
		}
		if counts, err := store.CountByRole(context.Background()); err == nil {
			log.Printf("БД: %s (user=%d admin=%d node=%d)", *dbPath,
				counts[auth.RoleUser], counts[auth.RoleAdmin], counts[auth.RoleNode])
		}
	} else {
		log.Print("ВНИМАНИЕ: -db не задан — узел ОТКРЫТ, авторизации нет (только dev)")
	}

	// Идентификатор узла в сети: по нему он понимает, он ли выход из метки.
	nodeID := *authority
	if h, _, err := net.SplitHostPort(nodeID); err == nil {
		nodeID = h
	}

	cfg := server.Config{
		Listen:             *listen,
		NodeID:             nodeID,
		Authority:          *authority,
		ConnectIPPath:      "/connect-ip",
		Resolver:           resolver,
		DNSPath:            "/dns-query",
		DNSGCEvery:         *dnsGC,
		AuthPath:           "/qd-auth",
		AdminPath:          "/qd-admin/dns",
		AdminOutboundsPath: "/qd-admin/outbounds",
		AdminUsersPath:     "/qd-admin/users",
		AdminSessionsPath:  "/qd-admin/sessions",
		AdminStatsPath:     "/qd-admin/stats",
		AdminBackupPath:    "/qd-admin/backup",
		AdminPowerPath:     "/qd-admin/power",
		AdminNodesPath:     "/qd-admin/nodes",
		AdminClusterPath:   "/qd-admin/cluster",
		ReplicaPath:        server.ReplicaPath,
		HeartbeatPath:      server.HeartbeatPath,
		OutboundsPath:      "/qd-outbounds",
		Store:              storeOrNil(live),
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

		// Связи с соседними узлами из реестра. Поднимаются по мере надобности:
		// держать соединение к каждому узлу сети незачем, а вот молча не иметь
		// пути к нему — значит выпустить флоу не там, где просил клиент.
		links := server.NewNodeLinks(cfg.NodeID, *nodeToken, nodeDialer(ctx))
		defer links.Close()
		if err := links.Reload(ctx, store); err != nil {
			log.Printf("реестр узлов: %v", err)
		}
		cfg.Links = links
		if n := len(links.Nodes()); n > 0 {
			log.Printf("соседей в реестре: %d", n)
		}

		// Репликация базы с мастера. Реплика узнаёт о новых узлах и клиентах
		// сама — без неё каждый узел пришлось бы регистрировать руками на всех
		// остальных, что и делали до сих пор.
		rep := &server.Replicator{
			Live: live, SelfID: cfg.NodeID, SelfToken: *nodeToken,
			RT: nodeRoundTripper(ctx), Every: *replicaEvery,
			// После подмены перечитываем то, что построено по базе: иначе
			// свежий реестр лежал бы в базе, а узел ходил бы по старому.
			OnUpdate: func(c context.Context) {
				fresh := live.DB()
				if err := links.Reload(c, fresh); err != nil {
					log.Printf("реестр узлов после репликации: %v", err)
				}
				if err := obs.Reload(c, fresh); err != nil {
					log.Printf("выходы после репликации: %v", err)
				}
			},
		}
		if *replicaEvery > 0 {
			go rep.Run(ctx)
			log.Printf("репликация базы: раз в %s", *replicaEvery)
		}
		// Отметки живости. Идут своим темпом: узел, о котором не слышно три
		// минуты, считается мёртвым, а снимок ходит куда реже.
		go (&server.Beater{
			Live: live, SelfID: cfg.NodeID, SelfToken: *nodeToken,
			RT: nodeRoundTripper(ctx), Every: *beatEvery,
		}).Run(ctx)
	}

	log.Printf("узел на %s (authority=%s, назначаю клиенту %s)", *listen, *authority, *assign)
	if err := server.Run(ctx, cfg); err != nil && ctx.Err() == nil {
		log.Fatalf("run: %v", err)
	}
	log.Print("остановлен")
}

// nodeRoundTripper — HTTP-доступ к соседнему узлу для репликации.
//
// Отдельная сессия, а не связь из NodeLinks: репликация ходит раз в четверть
// часа, и держать ради неё соединение с мастером постоянно смысла нет, а вот
// зависеть от состояния кэша транзитных связей — лишний риск.
func nodeRoundTripper(base context.Context) server.NodeRoundTripper {
	return func(ctx context.Context, node db.Node, selfToken string) (http.RoundTripper, io.Closer, error) {
		authority := node.Authority()
		sni, _, _ := net.SplitHostPort(node.Addr)
		if sni == "" {
			sni = authority
		}
		tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: sni}
		link, err := cip.DialLink(ctx, node.Addr, tlsConf, selfToken,
			"https://"+authority+"/qd-auth")
		if err != nil {
			return nil, nil, err
		}
		return link.H3Conn(), link, nil
	}
}

// nodeDialer — фабрика связей с соседними узлами из реестра.
//
// Узел предъявляет СВОЙ токен, а сосед сверяет его с хешем из общей реплики:
// чужих секретов ни у кого нет, поэтому утечка одного узла не открывает
// остальные, и копировать токены между машинами не нужно.
func nodeDialer(base context.Context) server.NodeDialer {
	return func(_ context.Context, node db.Node, selfToken string) (netstack.Dialer, io.Closer, error) {
		authority := node.Authority()
		sni, _, _ := net.SplitHostPort(node.Addr)
		if sni == "" {
			sni = authority
		}
		tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: sni}
		// Связь без connect-ip: сосед ходит стримами, и туннель ему только выделил
		// бы адрес из клиентского пула, которым он не пользуется.
		// base-контекст (жизнь узла), а не контекст запроса: связь переживает
		// отдельные флоу.
		link, err := cip.DialLink(base, node.Addr, tlsConf, selfToken,
			"https://"+authority+"/qd-auth")
		if err != nil {
			return nil, nil, err
		}
		return chain.New(link.H3Conn(), authority), link, nil
	}
}

// chainDialer — фабрика chain-выходов для менеджера outbounds. Живёт в main, а не
// в server: cip импортирует server (Template), прямой импорт дал бы цикл.
func chainDialer(base context.Context) server.ChainDialer {
	return func(_ context.Context, addr, authority, token string) (netstack.Dialer, io.Closer, error) {
		if authority == "" {
			h, _, _ := net.SplitHostPort(addr)
			authority = h
		}
		sni, _, _ := net.SplitHostPort(addr)
		tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: sni}
		// Без connect-ip: и TCP, и UDP уходят стримами, а туннель только выделил
		// бы узлу адрес из клиентского пула, которым он не пользуется.
		// base-контекст (жизнь узла), а не dctx запроса: цепочка живёт долго.
		link, err := cip.DialLink(base, addr, tlsConf, token, "https://"+authority+"/qd-auth")
		if err != nil {
			return nil, nil, err
		}
		return chain.New(link.H3Conn(), authority), link, nil
	}
}

// storeOrNil отдаёт nil-интерфейс, если БД нет: server.Config.Store — интерфейс,
// а типизированный nil-указатель в нём != nil и сломал бы проверку «узел открыт».
func storeOrNil(s *db.Live) db.Store {
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
