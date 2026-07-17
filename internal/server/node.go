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
	// Assign — адреса, назначаемые клиенту (пока статический /32; пул — TODO).
	Assign []netip.Prefix
	// Routes — рекламируемые клиенту маршруты (обычно весь IPv4/IPv6).
	Routes []connectip.IPRoute
	// Dialer — выход наружу: direct (netstack.NetDialer) или chain.
	Dialer netstack.Dialer
	// Resolver — DNS узла (кеш + upstream). nil → эндпоинт /dns-query не поднимается.
	// Резолв обязан идти здесь: у клиента провайдер подменяет ответы на заглушку.
	Resolver *dns.Resolver
	// DNSPath — путь DoH-эндпоинта (RFC 8484), обычно "/dns-query".
	DNSPath string
	// DNSGCEvery — период мягкой очистки кеша (протухшее). 0 → минута.
	DNSGCEvery time.Duration
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

	mux := http.NewServeMux()
	mux.Handle("/", decoy.Handler()) // всё прочее — decoy

	// DoH (RFC 8484) в том же HTTP/3-соединении, что и туннель: DNS клиента едет
	// внутри QUIC, провайдеру его не видно и подменить нечего.
	if cfg.Resolver != nil && cfg.DNSPath != "" {
		mux.Handle(cfg.DNSPath, dns.Handler(cfg.Resolver))
		go cfg.Resolver.RunGC(ctx, cfg.DNSGCEvery)
		log.Printf("DoH на %s", cfg.DNSPath)
	}
	mux.HandleFunc(cfg.ConnectIPPath, func(w http.ResponseWriter, r *http.Request) {
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
		go serveTunnel(ctx, conn, cfg)
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
			serveConnect(w, r, cfg)
			return
		}
		mux.ServeHTTP(w, r)
	})

	srv := &http3.Server{
		Handler:         handler,
		EnableDatagrams: true,
		TLSConfig:       cfg.TLS,
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
	n := liveConnects.Add(1)
	defer liveConnects.Add(-1)
	if n%256 == 0 {
		log.Printf("CONNECT-стримов живо: %d", n)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	out, err := cfg.Dialer.DialTCP(ctx, dst)
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

// serveTunnel назначает клиенту адрес/маршруты и запускает forwarder.
func serveTunnel(ctx context.Context, conn *connectip.Conn, cfg Config) {
	if err := conn.AssignAddresses(ctx, cfg.Assign); err != nil {
		conn.Close()
		return
	}
	if err := conn.AdvertiseRoute(ctx, cfg.Routes); err != nil {
		conn.Close()
		return
	}
	ns, err := netstack.New(cfg.Dialer)
	if err != nil {
		conn.Close()
		return
	}
	_ = ns.Run(ctx, conn) // до закрытия туннеля
}
