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
	// когда Outbounds пуст.
	Dialer netstack.Dialer
	// Outbounds — несколько выходов с роутингом по src-адресу. Клиент получает
	// адрес в подсети каждого выхода и шлёт с нужного src. Пусто → один Dialer.
	Outbounds []Outbound
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

	tmpl := Template(cfg.Authority, cfg.ConnectIPPath)
	proxy := &connectip.Proxy{}

	// Роутер выхода: несколько outbound'ов → выбор по src-адресу; иначе один Dialer.
	var router netstack.Router
	if len(cfg.Outbounds) > 0 {
		router = newRouter(cfg.Outbounds)
		log.Printf("роутинг по src: %d выход(ов)", len(cfg.Outbounds))
	} else {
		router = netstack.Single(cfg.Dialer)
	}

	mux := http.NewServeMux()
	mux.Handle("/", decoy.Handler()) // всё прочее — decoy

	// DoH (RFC 8484) в том же HTTP/3-соединении, что и туннель: DNS клиента едет
	// внутри QUIC, провайдеру его не видно и подменить нечего.
	if cfg.Resolver != nil && cfg.DNSPath != "" {
		doh := dns.Handler(cfg.Resolver)
		mux.Handle(cfg.DNSPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// DNS — только для своих: иначе узел станет открытым DoH-резолвером.
			if !sessionAllowed(r.Context(), cfg) {
				decoy.Handler().ServeHTTP(w, r)
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
				decoy.Handler().ServeHTTP(w, r)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}

	mux.HandleFunc(cfg.ConnectIPPath, func(w http.ResponseWriter, r *http.Request) {
		if !sessionAllowed(r.Context(), cfg) {
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		assign, err := assignFor(r.Context(), cfg)
		if err != nil {
			// пул исчерпан или БД сбоит — не выдаём себя, роняем как decoy
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		req, err := connectip.ParseRequest(r, tmpl)
		if err != nil {
			// не валидный connect-ip запрос → decoy, не выдавать себя
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		conn, err := proxy.Proxy(w, req)
		if err != nil {
			return
		}
		go serveTunnel(ctx, conn, cfg, assign, router)
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
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	return srv.Serve(udp)
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
	if len(cfg.Outbounds) == 0 {
		return []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}, nil
	}
	host := hostFromAddr(cfg.Outbounds[0].Subnet, addr)
	return addrsForHost(cfg.Outbounds, host), nil
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
	dialer := cfg.outboundDialer(r.Header.Get(RouteHeader))
	ctx, cancel := context.WithTimeout(chain.WithHops(r.Context(), hops-1), 15*time.Second)
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
func serveTunnel(ctx context.Context, conn *connectip.Conn, cfg Config, assign []netip.Prefix, router netstack.Router) {
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
	_ = ns.Run(ctx, conn) // до закрытия туннеля
}
