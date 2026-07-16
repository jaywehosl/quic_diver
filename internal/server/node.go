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
	"net"
	"net/http"
	"net/netip"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"quicdiver/internal/server/decoy"
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

	tmpl := Template(cfg.Authority, cfg.ConnectIPPath)
	proxy := &connectip.Proxy{}

	mux := http.NewServeMux()
	mux.Handle("/", decoy.Handler()) // всё прочее — decoy
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

	srv := &http3.Server{
		Handler:         mux,
		EnableDatagrams: true,
		TLSConfig:       cfg.TLS,
	}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	return srv.Serve(udp)
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
