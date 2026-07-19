package server

import (
	"context"

	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"quicdiver/internal/server/chain"
	"quicdiver/internal/server/decoy"
	"quicdiver/internal/transport/connectudp"
)

// ConnectUDPPrefix — путь CONNECT-UDP (RFC 9298). Регистрируется префиксом:
// целевой адрес лежит в самом пути, поэтому точное совпадение не годится.
const ConnectUDPPrefix = "/.well-known/masque/udp/"

// liveUDPFlows — сколько UDP-флоу обслуживается сейчас (для диагностики).
var liveUDPFlows atomic.Int64

// serveConnectUDP обслуживает UDP-флоу клиента (RFC 9298).
//
// Симметрично TCP-шному serveConnect: метка маршрута едет тем же заголовком, а
// не в src-адресе. Это и есть смысл перехода на CONNECT-UDP — одна модель
// маршрутизации на оба протокола, поэтому транзит и правила пишутся один раз.
func serveConnectUDP(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Чужим этот путь знать незачем: неавторизованному отвечаем как обычной
		// страницей, не обнаруживая эндпоинт.
		if !sessionAllowed(r.Context(), cfg) {
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		if !connectudp.IsRequest(r) {
			// Путь наш, но это не расширенный CONNECT — снаружи выглядит как
			// обращение к несуществующей странице.
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		dst, err := connectudp.Target(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// hop-limit общий с TCP: транзитный запрос несёт остаток, клиентский —
		// нет. Ноль у транзита — петля между узлами.
		hops, fromClient := chain.HopsFromRequest(r)
		if !fromClient && hops <= 0 {
			decoy.Handler().ServeHTTP(w, r)
			return
		}

		// Выход для флоу: та же метка, что у TCP. Пусто/неизвестно → выход по
		// умолчанию.
		dialer := cfg.Dialer
		if cfg.Outbounds != nil {
			dialer = cfg.Outbounds.DialerForLabel(r.Header.Get(RouteHeader))
		}
		dctx, cancel := context.WithTimeout(chain.WithHops(r.Context(), hops-1), 15*time.Second)
		out, err := dialer.DialUDP(dctx, dst)
		cancel()
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer out.Close()

		// Согласие и перехват стрима. После Accept писать в ResponseWriter уже
		// нельзя — дальше только датаграммы.
		flow, err := connectudp.Accept(w, r)
		if err != nil {
			return
		}
		defer flow.Close()

		n := liveUDPFlows.Add(1)
		defer liveUDPFlows.Add(-1)
		if n%256 == 0 {
			log.Printf("UDP-флоу живо: %d", n)
		}
		pipeDatagrams(flow, out)
	})
}

// udpFlowTimeout — сколько держать флоу без трафика.
//
// UDP не сообщает о закрытии, поэтому висящие флоу подрезаем сами: иначе каждый
// DNS-запрос браузера оставлял бы стрим навсегда, и лимит стримов на соединение
// выело бы за день работы.
const udpFlowTimeout = 2 * time.Minute

// pipeDatagrams качает датаграммы в обе стороны, сохраняя границы пакетов, и
// гасит флоу, если по нему давно тихо.
//
// io.Copy здесь не годится: он режет и склеивает по буферу, а для UDP это
// означало бы слипшиеся или разорванные пакеты. Читаем и пишем поштучно.
func pipeDatagrams(flow, out net.Conn) {
	var lastSeen atomic.Int64
	lastSeen.Store(time.Now().UnixNano())

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		// 64 КБ — предельный размер UDP-датаграммы; меньший буфер молча резал бы
		// крупные пакеты.
		buf := make([]byte, 65535)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				lastSeen.Store(time.Now().UnixNano())
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go cp(out, flow) // от клиента наружу
	go cp(flow, out) // снаружи клиенту

	// Сторож простоя: будит закрытием, что вернёт обе горутины из Read.
	idle := make(chan struct{})
	go func() {
		t := time.NewTicker(udpFlowTimeout / 4)
		defer t.Stop()
		for {
			select {
			case <-idle:
				return
			case now := <-t.C:
				if now.UnixNano()-lastSeen.Load() > int64(udpFlowTimeout) {
					_ = flow.Close()
					_ = out.Close()
					return
				}
			}
		}
	}()

	<-done
	// Первая же оборвавшаяся сторона гасит флоу: держать половину открытой для
	// UDP смысла нет, а закрытие разбудит вторую горутину.
	close(idle)
	_ = flow.Close()
	_ = out.Close()
	<-done
}
