// Package server — сборка узла QUIC Diver (master=slave: роль из конфига, не кода).
//
// Узел слушает QUIC/HTTP3, отдаёт connect-ip на служебном пути (валидный клиент →
// туннель), а на прочих путях — decoy («under construction»), поэтому снаружи
// выглядит обычным HTTPS-сайтом. Каждый установленный туннель получает адрес из
// пула и маршруты, дальше обслуживается gVisor-forwarder'ом (выход direct/chain).
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/chain"
	"quicdiver/internal/server/db"
	"quicdiver/internal/server/decoy"
	"quicdiver/internal/server/dns"
	"quicdiver/internal/server/netstack"
)

// Config — параметры узла.
type Config struct {
	// Listen — UDP-адрес прослушивания QUIC, напр. ":8443".
	Listen string
	// NodeID — идентификатор этого узла в сети. По нему узел понимает, он ли
	// выход, указанный в метке маршрута. Пусто → берётся Authority.
	NodeID string
	// Authority — host[:port] в connect-ip URI (должен совпадать с :authority,
	// который шлёт клиент). Напр. "localhost:8443".
	Authority string
	// ConnectIPPath — путь connect-ip эндпоинта, напр. "/connect-ip".
	ConnectIPPath string
	// TLS — серверный TLS (реальный серт по домену; self-signed для локали).
	TLS *tls.Config
	// Assign — статический адрес клиента для dev-режима (без БД). С БД адрес
	// берётся из Pool по токену.
	Assign []netip.Prefix
	// Pool — диапазон адресов клиентов (IPv4). Валиден только вместе со Store:
	// каждому токену выделяется стабильный адрес из пула.
	Pool netip.Prefix
	// Routes — рекламируемые клиенту маршруты (обычно весь IPv4/IPv6).
	Routes []connectip.IPRoute
	// Dialer — выход по умолчанию (dev/один выход): direct или chain. Используется,
	// когда Outbounds == nil.
	Dialer netstack.Dialer
	// Outbounds — живой набор выходов с роутингом (из БД, перенастраивается admin).
	// nil → один Dialer без роутинга.
	Outbounds *Outbounds
	// OutboundStore — БД для admin-API выходов (Reload после изменения). Обычно =
	// Store.
	OutboundStore db.Store
	// Resolver — DNS узла (кеш + upstream). nil → эндпоинт /dns-query не поднимается.
	// Резолв обязан идти здесь: у клиента провайдер подменяет ответы на заглушку.
	Resolver *dns.Resolver
	// DNSPath — путь DoH-эндпоинта (RFC 8484), обычно "/dns-query".
	DNSPath string
	// DNSGCEvery — период мягкой очистки кеша (протухшее). 0 → минута.
	DNSGCEvery time.Duration
	// Store — хранилище токенов. nil → узел открыт (dev): любой клиент проходит.
	// В бою обязателен, иначе туннель — открытый прокси.
	Store db.Store
	// AuthPath — путь эндпоинта авторизации сессии, обычно "/qd-auth". Клиент
	// предъявляет туда токен до connect-ip; сессия помечается доверенной.
	AuthPath string
	// AdminPath — путь admin-API (управление резолвером), обычно "/qd-admin/dns".
	// Пусто → не поднимается. Доступ строго по admin-токену.
	AdminPath string
	// AdminOutboundsPath — путь admin-API выходов, обычно "/qd-admin/outbounds".
	AdminOutboundsPath string
	// AdminUsersPath — путь admin-API учёта клиентов, обычно "/qd-admin/users".
	AdminUsersPath string
	// AdminSessionsPath — путь admin-API живых сессий, обычно "/qd-admin/sessions".
	AdminSessionsPath string
	// AdminStatsPath — путь admin-API состояния узла, обычно "/qd-admin/stats".
	AdminStatsPath string
	// AdminBackupPath — путь admin-API снимков базы, обычно "/qd-admin/backup".
	AdminBackupPath string
	// AdminPowerPath — путь admin-API перезапуска/питания, обычно "/qd-admin/power".
	AdminPowerPath string
	// AdminNodesPath — путь admin-API реестра узлов, обычно "/qd-admin/nodes".
	AdminNodesPath string
	// OutboundsPath — путь публикации выходов клиенту (метка+подсеть),
	// обычно "/qd-outbounds". Доступ авторизованному клиенту, секреты не отдаются.
	OutboundsPath string
}

// Template строит URI Template connect-ip эндпоинта. Клиент и узел обязаны
// использовать одинаковый (authority + path совпадают).
func Template(authority, path string) *uritemplate.Template {
	return uritemplate.MustNew(fmt.Sprintf("https://%s%s", authority, path))
}

// Run поднимает узел и блокируется до отмены ctx или фатальной ошибки.
func Run(ctx context.Context, cfg Config) error {
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("resolve listen: %w", err)
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	defer udp.Close()
	// UDP-буферы: покрыть BDP с запасом, но НЕ раздувать — длинная очередь даёт
	// bufferbloat (RTT под нагрузкой растёт). ОС урежет до net.core.rmem_max.
	_ = udp.SetReadBuffer(2 << 20)
	_ = udp.SetWriteBuffer(2 << 20)

	// Идентификатор узла: по нему он понимает, он ли выход из метки маршрута.
	if cfg.NodeID == "" {
		cfg.NodeID = cfg.Authority
	}
	tmpl := Template(cfg.Authority, cfg.ConnectIPPath)
	proxy := &connectip.Proxy{}

	// Роутер выхода: живой набор outbound'ов (выбор по src) либо один Dialer.
	var router netstack.Router
	if cfg.Outbounds != nil {
		router = cfg.Outbounds
		log.Printf("роутинг по src: выходы %v", cfg.Outbounds.Labels())
	} else {
		router = netstack.Single(cfg.Dialer)
	}

	// Витрина одна на оба транспорта. Общий экземпляр принципиален: таблица
	// лимита у него внутри, а браузер после Alt-Svc уходит на HTTP/3 — с
	// отдельными экземплярами лимит обходился бы простой сменой протокола.
	site := decoy.NewSite(udpAddr.Port)

	mux := http.NewServeMux()
	mux.Handle("/", site) // всё прочее — витрина (та же, что на TCP: лимит общий)

	// UDP-флоу клиента (RFC 9298). Префиксом, а не точным путём: целевой адрес
	// лежит в самом пути. Метка маршрута едет тем же заголовком, что у TCP —
	// одна модель маршрутизации на оба протокола.
	mux.Handle(ConnectUDPPrefix, serveConnectUDP(cfg))

	// DoH (RFC 8484) в том же HTTP/3-соединении, что и туннель: DNS клиента едет
	// внутри QUIC, провайдеру его не видно и подменить нечего.
	if cfg.Resolver != nil && cfg.DNSPath != "" {
		doh := dns.Handler(cfg.Resolver)
		mux.Handle(cfg.DNSPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// DNS — только для своих: иначе узел станет открытым DoH-резолвером.
			if !sessionAllowed(r.Context(), cfg) {
				site.ServeHTTP(w, r)
				return
			}
			doh.ServeHTTP(w, r)
		}))
		go cfg.Resolver.RunGC(ctx, cfg.DNSGCEvery)
		log.Printf("DoH на %s", cfg.DNSPath)

		// Admin-API управления резолвером (upstream/кеш/TTL/flush) по admin-токену.
		if cfg.AdminPath != "" {
			mux.Handle(cfg.AdminPath, adminDNS(cfg))
			log.Printf("admin-API DNS на %s", cfg.AdminPath)
		}
	}

	// Admin-API управления выходами (outbounds CRUD + горячий Reload).
	if cfg.AdminOutboundsPath != "" && cfg.Outbounds != nil {
		mux.Handle(cfg.AdminOutboundsPath, adminOutbounds(cfg))
		log.Printf("admin-API выходов на %s", cfg.AdminOutboundsPath)
	}

	// Учёт клиентов: раньше жил только в CLI узла, то есть требовал ssh. Панель
	// должна уметь то же удалённо — и через туннель, а не отдельным портом.
	if cfg.AdminUsersPath != "" && cfg.Store != nil {
		mux.Handle(cfg.AdminUsersPath, adminUsers(cfg))
		log.Printf("admin-API клиентов на %s", cfg.AdminUsersPath)
	}
	if cfg.AdminSessionsPath != "" && cfg.Store != nil {
		mux.Handle(cfg.AdminSessionsPath, adminSessions(cfg))
		log.Printf("admin-API сессий на %s", cfg.AdminSessionsPath)
	}
	if cfg.AdminStatsPath != "" {
		mux.Handle(cfg.AdminStatsPath, adminStats(cfg))
		log.Printf("admin-API состояния на %s", cfg.AdminStatsPath)
	}
	// Снимок базы и восстановление (arch3): переезд узла на другую машину с тем
	// же доменом не должен ничего менять для клиентов.
	if cfg.AdminBackupPath != "" && cfg.Store != nil {
		mux.Handle(cfg.AdminBackupPath, adminBackup(cfg))
		log.Printf("admin-API снимков базы на %s", cfg.AdminBackupPath)
	}
	if cfg.AdminPowerPath != "" {
		mux.Handle(cfg.AdminPowerPath, adminPower(cfg))
		log.Printf("admin-API питания на %s", cfg.AdminPowerPath)
	}
	// Реестр узлов: кто есть в сети и кто из них вход, кто выход. Аутбаундов
	// (ручных связей между узлами) здесь нет — маршрут живёт в метке трафика.
	if cfg.AdminNodesPath != "" && cfg.Store != nil {
		mux.Handle(cfg.AdminNodesPath, adminNodes(cfg))
		log.Printf("admin-API узлов на %s", cfg.AdminNodesPath)
	}
	// Уборка сессий, о которых давно не слышно: узел мог умереть, не закрыв их,
	// и тогда «активные сессии» превратились бы в кладбище, а лимит
	// одновременных подключений заклинило бы навсегда.
	if store, ok := cfg.Store.(*db.SQLite); ok {
		go sweepSessions(ctx, store)
	}

	// Публикация выходов клиенту (метка+подсеть, без секретов) — по ним клиент
	// строит соответствие «метка правила → src/Qd-Route». Доступ любому своему
	// (авторизованному), не только admin: клиенту это нужно для роутинга.
	if cfg.OutboundsPath != "" && cfg.Outbounds != nil {
		mux.HandleFunc(cfg.OutboundsPath, func(w http.ResponseWriter, r *http.Request) {
			if !sessionAllowed(r.Context(), cfg) {
				site.ServeHTTP(w, r)
				return
			}
			writeJSON(w, cfg.Outbounds.Public())
		})
		log.Printf("выходы клиенту на %s", cfg.OutboundsPath)
	}
	// Авторизация сессии: клиент предъявляет токен ДО connect-ip. Проверяем один
	// раз на QUIC-сессию — connect-ip и все CONNECT-стримы идут по ней же и
	// наследуют доверие. Нет/битый токен → decoy (не 401 — не выдавать себя).
	if cfg.AuthPath != "" {
		mux.HandleFunc(cfg.AuthPath, func(w http.ResponseWriter, r *http.Request) {
			// Узел без БД (dev) открыт — принимаем любую сессию. Иначе проверяем
			// токен; нет/битый/отозван → decoy (не 401, не выдавать себя).
			if cfg.Store == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			sess := auth.SessionFrom(r.Context())
			tok := auth.TokenFromRequest(r)
			if sess == nil || tok == "" || !authorize(r.Context(), cfg, sess, tok) {
				site.ServeHTTP(w, r)
				return
			}
			// Отпечаток машины клиент шлёт именно здесь; туннель поднимается
			// следующим запросом, где заголовка уже не будет — запоминаем.
			sess.SetHWID(hwidFrom(r))
			w.WriteHeader(http.StatusNoContent)
		})
	}

	mux.HandleFunc(cfg.ConnectIPPath, func(w http.ResponseWriter, r *http.Request) {
		if !sessionAllowed(r.Context(), cfg) {
			site.ServeHTTP(w, r)
			return
		}
		assign, err := assignFor(r.Context(), cfg)
		if err != nil {
			// пул исчерпан или БД сбоит — не выдаём себя, роняем как decoy
			site.ServeHTTP(w, r)
			return
		}
		req, err := connectip.ParseRequest(r, tmpl)
		if err != nil {
			// не валидный connect-ip запрос → decoy, не выдавать себя
			site.ServeHTTP(w, r)
			return
		}
		conn, err := proxy.Proxy(w, req)
		if err != nil {
			return
		}
		// Учёт заводим здесь: тут ещё виден запрос (адрес клиента, отпечаток
		// машины), а в serveTunnel остаётся только сам туннель.
		acct := beginSession(r.Context(), cfg, sessionHash(r.Context()), sessionHWID(r.Context()), remoteIPFrom(r))
		go serveTunnel(ctx, conn, cfg, assign, router, acct)
	})

	// Обычный CONNECT (RFC 9114) — надёжный stream для TCP-флоу гибрида: ретрансмит
	// делает QUIC, поэтому внутренний TCP клиента потерь туннеля не видит.
	//
	// Ловим ДО mux: у такого запроса URL в authority-form (host:port), а ServeMux
	// роутит по path и вернул бы 404.
	//
	// Отличать от Extended CONNECT (RFC 9220), которым установлен connect-ip: у
	// него есть :protocol и НЕПУСТОЙ :path (/connect-ip) — он должен уйти в mux.
	// У обычного CONNECT :path пустой (см. requestFromHeaders в http3).
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isPlainConnect := r.Method == http.MethodConnect &&
			r.URL != nil && r.URL.Path == "" && r.Host != ""
		if isPlainConnect {
			// CONNECT-стрим идёт по уже авторизованной сессии; если нет — рвём
			// (decoy бессмыслен для authority-form, снаружи это просто отказ).
			if !sessionAllowed(r.Context(), cfg) {
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			serveConnect(w, r, cfg)
			return
		}
		mux.ServeHTTP(w, r)
	})

	srv := &http3.Server{
		Handler:         handler,
		EnableDatagrams: true,
		TLSConfig:       cfg.TLS,
		// Вешаем свежую auth-сессию на каждое QUIC-соединение: значение доходит до
		// всех его хендлеров (request ctx наследует conn ctx), поэтому проверять
		// токен достаточно один раз, а не на каждом стриме.
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
			return auth.NewSessionContext(ctx)
		},
		QUICConfig: &quic.Config{
			// В гибриде КАЖДЫЙ TCP-флоу клиента — отдельный CONNECT-стрим, а
			// браузер с мессенджером легко держат сотни соединений. Дефолт
			// quic-go (100) исчерпывается мгновенно: новые CONNECT молча ждут
			// разрешения и отваливаются по таймауту — снаружи это выглядит как
			// «интернет упал».
			MaxIncomingStreams: 4096,
			EnableDatagrams:    true,
			// Idle согласуем с клиентом (см. quicconn.DefaultConfig): у него связь
			// рвётся между роутером и провайдером на десятки секунд, и сессию всё
			// это время убивать нельзя — оборвались бы все TCP приложений. Стороны
			// берут минимум из двух значений, поэтому короткий таймаут здесь
			// обесценил бы длинный у клиента.
			MaxIdleTimeout:  45 * time.Second,
			KeepAlivePeriod: 15 * time.Second,
			// Окна чуть выше BDP и не больше — см. quicconn.DefaultConfig:
			// раздутые окна дают bufferbloat (RTT p95 3.4 с, throughput ×5 вниз).
			InitialStreamReceiveWindow:     2 << 20,
			MaxStreamReceiveWindow:         6 << 20,
			InitialConnectionReceiveWindow: 3 << 20,
			MaxConnectionReceiveWindow:     15 << 20,
		},
	}
	// Витрина на TCP: тот же порт, тот же сертификат, та же страница. Без неё узел
	// слушает только UDP — а домен, чей HTTPS не отвечает по TCP при живом QUIC,
	// сам себя выдаёт при активном пробинге (см. decoy.Site).
	tcpSrv, tcpErr := serveDecoyTCP(ctx, cfg, site)

	go func() {
		<-ctx.Done()
		srv.Close()
		if tcpSrv != nil {
			tcpSrv.Close()
		}
	}()

	err = srv.Serve(udp)
	// Ошибка витрины интересна, только если она уронила узел раньше QUIC.
	select {
	case terr := <-tcpErr:
		if err == nil && terr != nil {
			return terr
		}
	default:
	}
	return err
}

// serveDecoyTCP поднимает HTTPS-витрину (H1+H2) на TCP того же порта.
//
// Узел работает и без неё (возвращаем nil при ошибке — обычно порт занят), но
// тогда остаётся маркер: QUIC на порту есть, TCP молчит. Поэтому неудачу
// логируем громко, а не глотаем.
func serveDecoyTCP(ctx context.Context, cfg Config, site *decoy.Site) (*http.Server, <-chan error) {
	errc := make(chan error, 1)
	if cfg.TLS == nil {
		log.Print("витрина TCP: нет TLS-конфига, пропускаю (узел виден только по UDP)")
		return nil, errc
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Printf("витрина TCP на %s не поднялась: %v (узел виден только по UDP — палево при пробинге)", cfg.Listen, err)
		return nil, errc
	}

	// ALPN у витрины свой: h3 живёт на UDP, здесь — обычные H2/HTTP1.1.
	// Сертификат тот же, поэтому TLS сходится и по IP с нашим SNI.
	tlsConf := cfg.TLS.Clone()
	tlsConf.NextProtos = []string{"h2", "http/1.1"}

	srv := &http.Server{
		Handler:           site,
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0), // сканеры шумят битым TLS — не засорять журнал
	}
	go func() {
		err := srv.ServeTLS(ln, "", "")
		if err != nil && ctx.Err() == nil {
			log.Printf("витрина TCP остановилась: %v", err)
		}
		errc <- err
	}()
	log.Printf("витрина на TCP %s (H1+H2, лимит общий с HTTP/3)", cfg.Listen)
	return srv, errc
}

// authorize проверяет предъявленный токен по БД и, если он живой, помечает
// сессию доверенной. Возвращает false молча — вызывающий покажет decoy.
func authorize(ctx context.Context, cfg Config, sess *auth.Session, token string) bool {
	if cfg.Store == nil {
		return false
	}
	info, err := cfg.Store.Lookup(ctx, auth.Hash(token))
	if err != nil {
		return false // нет токена, отозван или ошибка БД — не пускаем
	}
	sess.Authorize(info.Role, auth.Hash(token))
	return true
}

// sessionAllowed — доверенная ли текущая сессия. Если Store не задан (dev-режим,
// узел открыт), пускаем всех — так локальный e2e работает без БД.
func sessionAllowed(ctx context.Context, cfg Config) bool {
	if cfg.Store == nil {
		return true
	}
	sess := auth.SessionFrom(ctx)
	return sess != nil && sess.Authorized()
}

// assignFor выбирает адрес(а), которые получит клиент. С БД — стабильный адрес из
// пула по токену (для роутинга по клиенту и логов). Без БД (dev) — статический
// Assign из конфига.
func assignFor(ctx context.Context, cfg Config) ([]netip.Prefix, error) {
	if cfg.Store == nil || !cfg.Pool.IsValid() {
		return cfg.Assign, nil
	}
	sess := auth.SessionFrom(ctx)
	if sess == nil {
		return nil, fmt.Errorf("нет сессии")
	}
	_, hash, ok := sess.Status()
	if !ok {
		return nil, fmt.Errorf("сессия не авторизована")
	}
	addr, err := cfg.Store.AllocateAddress(ctx, hash, cfg.Pool)
	if err != nil {
		return nil, err
	}
	// Без роутинга — один /32 (как раньше). С выходами — тот же хост-номер во всех
	// outbound-подсетях: клиент шлёт с нужного src, узел роутит по подсети.
	if cfg.Outbounds == nil {
		return []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}, nil
	}
	host := hostFromAddr(cfg.Outbounds.BaseSubnet(), addr)
	return cfg.Outbounds.AddrsForHost(host), nil
}

// serveConnect обслуживает CONNECT-туннель одного TCP-флоу: соединяется с
// запрошенным адресом (direct; chain придёт сюда же через Dialer) и склеивает
// поток с QUIC-стримом.
// liveConnects — сколько CONNECT-стримов сейчас открыто. Если счётчик только
// растёт при простое — стримы утекают (флоу закончился, а стрим не закрыт).
var liveConnects atomic.Int64

func serveConnect(w http.ResponseWriter, r *http.Request, cfg Config) {
	dst, err := netip.ParseAddrPort(r.Host)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// hop-limit: транзитный CONNECT (от другого узла) несёт остаток, клиентский —
	// нет (полный лимит). Ноль у транзита — петля, обрываем decoy'ем, не выдавая
	// себя. Вниз в Dialer передаём уменьшенный остаток — для следующего узла.
	hops, fromClient := chain.HopsFromRequest(r)
	if !fromClient && hops <= 0 {
		// Петля между узлами: отвечаем как обычной странице, не выдавая себя.
		// Лимит витрины тут не нужен — это внутренний путь, не публичный.
		decoy.Handler().ServeHTTP(w, r)
		return
	}
	n := liveConnects.Add(1)
	defer liveConnects.Add(-1)
	if n%256 == 0 {
		log.Printf("CONNECT-стримов живо: %d", n)
	}
	// Выход для этого флоу: TCP идёт CONNECT-стримом (мимо IP-слоя), поэтому метка
	// маршрута едет заголовком, а не src-адресом (как у датаграмм). Клиент ставит
	// Qd-Route по своему правилу; пусто/неизвестно → выход по умолчанию (direct).
	dialer, rctx := routeFlow(r.Context(), cfg, r, hops)
	ctx, cancel := context.WithTimeout(rctx, 15*time.Second)
	out, err := dialer.DialTCP(ctx, dst)
	cancel()
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer out.Close()

	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush() // отдать 200 сразу, не дожидаясь данных
	}

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(out, r.Body) // клиент → внешний хост
		if cw, ok := out.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(flushWriter{w}, out) // внешний хост → клиент
	<-done
}

// flushWriter флашит стрим после каждой записи — иначе HTTP/3 придержит данные
// в буфере и получится рваная доставка.
type flushWriter struct{ w http.ResponseWriter }

func (fw flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

// serveTunnel назначает клиенту адрес(а)/маршруты и запускает forwarder. assign —
// адреса именно этого клиента (по одному на выход при роутинге). router выбирает
// выход по src-адресу пакета.
func serveTunnel(ctx context.Context, conn *connectip.Conn, cfg Config, assign []netip.Prefix, router netstack.Router, acct *accountant) {
	if err := conn.AssignAddresses(ctx, assign); err != nil {
		conn.Close()
		return
	}
	if err := conn.AdvertiseRoute(ctx, cfg.Routes); err != nil {
		conn.Close()
		return
	}
	ns, err := netstack.NewRouted(router)
	if err != nil {
		conn.Close()
		return
	}

	// Туннель считаем сквозь обёртку, а учёт живёт ровно столько же, сколько
	// сессия: свой контекст гасим при выходе, и запись снимается с учёта.
	tun := &countingTunnel{inner: conn}
	tctx, stop := context.WithCancel(ctx)
	defer stop()
	go acct.run(tctx, tun.totals)

	_ = ns.Run(ctx, tun) // до закрытия туннеля
}
