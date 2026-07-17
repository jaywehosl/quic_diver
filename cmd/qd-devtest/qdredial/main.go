// Command qdredial — проверка живучести туннеля при мёртвом пути (arch4 №2).
//
// Сценарий: клиент ходит к узлу через локальный UDP-релей. Убиваем релей —
// пакеты уходят в никуда, ответы не приходят, локальный адрес клиента при этом
// не меняется. Это и есть случай, который смена адреса не ловит: роутер пересобрал
// PPPoE, публичный IP сменился, NAT-маппинг слетел.
//
// Проверяем, что supervisor замечает смерть сессии и говорит об этом наверх
// (ErrSessionDead), а не оставляет клиента висеть с мёртвым туннелем.
//
// Прав администратора не требует: WinDivert и системный DNS не трогаем.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"sync/atomic"
	"time"

	"quicdiver/internal/client/netwatch"
	"quicdiver/internal/client/supervisor"
	"quicdiver/internal/server"
	"quicdiver/internal/transport/cip"
)

func main() {
	srv := flag.String("server", "localhost:8443", "endpoint узла")
	authority := flag.String("authority", "localhost:8443", "authority")
	wait := flag.Duration("wait", 75*time.Second, "сколько ждать смерти сессии (idle-таймаут 30с + запас)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *wait+60*time.Second)
	defer cancel()

	upstream, err := net.ResolveUDPAddr("udp", *srv)
	if err != nil {
		log.Fatalf("резолв узла: %v", err)
	}
	r, err := startRelay(ctx, upstream)
	if err != nil {
		log.Fatalf("релей: %v", err)
	}
	log.Printf("релей на %s → %s", r.addr, upstream)

	client, _, err := cip.Dial(ctx, r.addr.String(), server.Template(*authority, "/connect-ip"),
		&tls.Config{InsecureSkipVerify: true, ServerName: *authority})
	if err != nil {
		log.Fatalf("туннель через релей: %v", err)
	}
	defer client.Close()
	log.Print("туннель поднят через релей, сессия жива")

	sup := supervisor.New(supervisor.Config{
		Client: client,
		Watch:  netwatch.Watcher{Interval: time.Hour}, // адрес не трогаем — проверяем мёртвый путь
	})
	errc := make(chan error, 1)
	go func() { errc <- sup.Run(ctx) }()

	// даём трафику пойти, чтобы путь был обжитым
	if prefs, err := client.LocalPrefixes(ctx); err == nil {
		log.Printf("узел назначил: %v", prefs)
	}

	log.Print("РВУ ПУТЬ: глушу релей (пакеты уходят в никуда, адрес клиента прежний)")
	r.kill()
	start := time.Now()

	select {
	case err := <-errc:
		took := time.Since(start).Round(time.Second)
		if errors.Is(err, supervisor.ErrSessionDead) {
			log.Printf("УСПЕХ: supervisor заметил смерть пути за %v — клиент поднимет стек заново", took)
			log.Printf("(пакетов прошло через релей до обрыва: %d)", r.forwarded.Load())
			return
		}
		log.Fatalf("supervisor вернул %v, ожидался ErrSessionDead", err)
	case <-time.After(*wait):
		log.Fatalf("ПРОВАЛ: за %v смерть пути не замечена — клиент завис бы с мёртвым туннелем", *wait)
	case <-ctx.Done():
		log.Fatal("время вышло")
	}
}

// relay — UDP-форвардер клиент↔узел, который можно убить.
type relay struct {
	addr      *net.UDPAddr
	pc        *net.UDPConn
	dead      atomic.Bool
	forwarded atomic.Int64
}

// kill глушит релей: сокет остаётся открытым, но пакеты дальше не идут —
// именно так ведёт себя слетевший NAT-маппинг (тишина, а не отказ).
func (r *relay) kill() { r.dead.Store(true) }

func startRelay(ctx context.Context, upstream *net.UDPAddr) (*relay, error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	r := &relay{addr: pc.LocalAddr().(*net.UDPAddr), pc: pc}

	// сокет наружу — общий для всех ответов узла
	out, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		pc.Close()
		return nil, err
	}

	var client atomic.Pointer[net.UDPAddr]

	go func() { // клиент → узел
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if r.dead.Load() {
				continue // глухо: пакет проглочен
			}
			client.Store(from)
			if _, err := out.WriteToUDP(buf[:n], upstream); err == nil {
				r.forwarded.Add(1)
			}
		}
	}()

	go func() { // узел → клиент
		buf := make([]byte, 2048)
		for {
			n, _, err := out.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if r.dead.Load() {
				continue
			}
			if c := client.Load(); c != nil {
				_, _ = pc.WriteToUDP(buf[:n], c)
			}
		}
	}()

	go func() {
		<-ctx.Done()
		pc.Close()
		out.Close()
	}()
	return r, nil
}
