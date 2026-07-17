// Command qdredial — проверка живучести туннеля при мёртвом пути (arch4 №2).
//
// Сценарий: клиент ходит к узлу через локальный UDP-релей. Убиваем релей —
// пакеты уходят в никуда, ответы не приходят, локальный адрес клиента при этом
// не меняется. Это и есть случай, который смена адреса не ловит: роутер пересобрал
// PPPoE, публичный IP сменился, NAT-маппинг слетел.
//
// Проверяем главное: как только связь возвращается, туннель оживает сразу —
// supervisor чинит путь переездом на новый порт, не дожидаясь idle-таймаута.
//
// Прав администратора не требует: WinDivert и системный DNS не трогаем.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/netip"
	"sync"
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
	outage := flag.Duration("outage", 30*time.Second, "на сколько рвать связь (как пересборка PPPoE на роутере)")
	wait := flag.Duration("wait", 40*time.Second, "сколько ждать восстановления после возврата сети")
	rebind := flag.Bool("rebind", true, "оживить связь с НОВЫМ NAT-маппингом (как роутер после пересборки PPPoE)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *outage+*wait+60*time.Second)
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
		// Узел на стенде за релеем на loopback, поэтому переезжать надо туда же:
		// по умолчанию взялся бы реальный адрес машины, и новый путь до релея
		// физически не подтвердился бы.
		LocalAddr: func() (netip.Addr, error) { return netip.MustParseAddr("127.0.0.1"), nil },
	})
	errc := make(chan error, 1)
	go func() { errc <- sup.Run(ctx) }()

	// даём трафику пойти, чтобы путь был обжитым
	if prefs, err := client.LocalPrefixes(ctx); err == nil {
		log.Printf("узел назначил: %v", prefs)
	}

	log.Printf("РВУ ПУТЬ: глушу релей на %v (пакеты в никуда, адрес клиента прежний)", *outage)
	r.kill()

	select {
	case err := <-errc:
		log.Fatalf("сессия умерла прямо во время обрыва: %v", err)
	case <-time.After(*outage):
	}

	// Снимаем счётчик ИМЕННО ЗДЕСЬ, а не сразу после kill: в момент обрыва в
	// полёте ещё оставались ответы, они досчитывались уже после — и проверка
	// «recv вырос» срабатывала бы вникуда, показывая мгновенное восстановление.
	sent, before := client.Traffic()
	log.Printf("за обрыв: отправлено %d пакетов, принято %d (ответов нет — путь мёртв)", sent, before)

	log.Printf("СЕТЬ ВЕРНУЛАСЬ (новый NAT-маппинг: %v) — засекаю, когда пойдут ответы", *rebind)
	if err := r.revive(*rebind); err != nil {
		log.Fatalf("оживить релей: %v", err)
	}
	back := time.Now()

	// Ждём, когда счётчик принятых пакетов сдвинется: это и есть «связь есть».
	deadline := time.Now().Add(*wait)
	for time.Now().Before(deadline) {
		if _, recv := client.Traffic(); recv > before {
			repairs, failed := sup.RepairStats()
			log.Printf("УСПЕХ: связь восстановилась за %v после возврата сети",
				time.Since(back).Round(100*time.Millisecond))
			log.Printf("(починок пути: %d, из них неудачных пока сеть лежала: %d)", repairs, failed)
			return
		}
		select {
		case err := <-errc:
			log.Fatalf("сессия умерла вместо восстановления: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err := ctx.Err(); err != nil {
		log.Fatal("время вышло")
	}
	log.Fatalf("ПРОВАЛ: сеть вернулась, а связь не восстановилась за %v", *wait)
}

// relay — UDP-форвардер клиент↔узел, который можно убить и оживить.
//
// Наружу ходит через сменный сокет: это и есть NAT роутера. Оживить его можно с
// тем же портом (маппинг уцелел) или с новым — как роутер, пересобравший PPPoE:
// таблица NAT у него новая, и узел про новый адрес ещё не знает.
type relay struct {
	addr      *net.UDPAddr
	pc        *net.UDPConn
	upstream  *net.UDPAddr
	dead      atomic.Bool
	forwarded atomic.Int64

	mu     sync.Mutex
	out    *net.UDPConn
	client atomic.Pointer[net.UDPAddr]
}

// kill глушит релей: сокет остаётся открытым, но пакеты дальше не идут —
// именно так ведёт себя оборванный аплинк (тишина, а не отказ).
func (r *relay) kill() { r.dead.Store(true) }

// revive возвращает связь. rebind — завести новый исходящий порт, то есть новый
// NAT-маппинг: узел продолжит слать на старый, и ответы до нас не дойдут, пока
// клиент не переедет сам.
func (r *relay) revive(rebind bool) error {
	if rebind {
		out, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			return err
		}
		r.mu.Lock()
		old := r.out
		r.out = out
		r.mu.Unlock()
		old.Close()
		go r.pumpInbound(out)
	}
	r.dead.Store(false)
	return nil
}

// pumpInbound гонит ответы узла обратно клиенту.
func (r *relay) pumpInbound(out *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, _, err := out.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if r.dead.Load() {
			continue
		}
		if c := r.client.Load(); c != nil {
			_, _ = r.pc.WriteToUDP(buf[:n], c)
		}
	}
}

func startRelay(ctx context.Context, upstream *net.UDPAddr) (*relay, error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	// сокет наружу — это и есть NAT роутера; при rebind он меняется
	out, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		pc.Close()
		return nil, err
	}
	r := &relay{addr: pc.LocalAddr().(*net.UDPAddr), pc: pc, upstream: upstream, out: out}

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
			r.client.Store(from)
			r.mu.Lock()
			cur := r.out
			r.mu.Unlock()
			if _, err := cur.WriteToUDP(buf[:n], upstream); err == nil {
				r.forwarded.Add(1)
			}
		}
	}()
	go r.pumpInbound(out)

	go func() {
		<-ctx.Done()
		pc.Close()
		r.mu.Lock()
		cur := r.out
		r.mu.Unlock()
		cur.Close()
	}()
	return r, nil
}
