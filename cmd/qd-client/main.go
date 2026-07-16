// Command qd-client — клиентский сервис QUIC Diver (без GUI).
//
// Боевой поток (Windows): sysproxy off → WinDivert capture → connect-ip туннель к
// узлу → NAT (assigned src) → engine перегоняет трафик; при выходе sysproxy
// restore. Требует прав администратора (WinDivert грузит драйвер).
//
// GUI — отдельная веб-страница (переиспользует HTTP-слой decoy) — следующий кирпич.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
)

type options struct {
	server      string // UDP endpoint узла, host:port
	authority   string // :authority в connect-ip URI (по умолчанию = server)
	dll         string // путь к WinDivert.dll
	noProxy     bool   // не трогать системный прокси
	noDNS       bool   // не поднимать локальный резолвер и не трогать системный DNS
	nat46       string // синтез A для v6-only хостов: auto|on|off
	hybrid      bool   // TCP через CONNECT-стрим, UDP датаграммами
	recvWorkers int    // потоков захвата (1 — сохраняет порядок пакетов)
	mtu         int    // MTU локального стека (≤ MTU интерфейса; PPPoE обычно 1480)
	brutalMbps  int    // congestion: слать с этой полосой, игнорируя потери (0 — Cubic)
}

func main() {
	var o options
	flag.StringVar(&o.server, "server", "localhost:8443", "endpoint узла (host:port)")
	flag.StringVar(&o.authority, "authority", "", "authority в connect-ip URI (по умолчанию = server)")
	flag.StringVar(&o.dll, "dll", "", "путь к WinDivert.dll (пусто → вшитый распакуется в %APPDATA%\\QUICDiver)")
	flag.BoolVar(&o.noProxy, "no-proxy", false, "не отключать системный прокси")
	flag.BoolVar(&o.noDNS, "no-dns", false, "не поднимать локальный резолвер (резолв пойдёт мимо туннеля — провайдер подменит ответы)")
	flag.StringVar(&o.nat46, "nat46", "auto", "давать IPv6-only хостам фиктивный IPv4: auto (только если своего IPv6 нет), on, off")
	flag.BoolVar(&o.hybrid, "hybrid", true, "TCP через надёжный CONNECT-стрим, UDP датаграммами (false → всё датаграммами, модель B)")
	flag.IntVar(&o.recvWorkers, "recv-workers", 1, "потоков захвата: 1 сохраняет порядок пакетов; >1 ускоряет скачивание ценой reordering")
	flag.IntVar(&o.mtu, "mtu", 1500, "MTU локального стека; инжект идёт в интерфейс (у него обычно 1500), а не в PPPoE-путь")
	flag.IntVar(&o.brutalMbps, "brutal", 0, "слать с полосой N Мбит/с, игнорируя потери (0 — обычный Cubic); ставить НИЖЕ реальной полосы отдачи")
	pprofAddr := flag.String("pprof", "", "адрес pprof (напр. localhost:6061); пусто → выкл")
	flag.Parse()
	if o.authority == "" {
		o.authority = o.server
	}

	log.SetPrefix("qd-client: ")

	// congestion выбирается внутри quic-go (наш патч читает переменную) — флаг
	// удобнее для релиза, чем требовать env от пользователя.
	if o.brutalMbps > 0 {
		os.Setenv("QD_BRUTAL_MBPS", strconv.Itoa(o.brutalMbps))
		log.Printf("congestion: brutal %d Мбит/с (потери игнорируются)", o.brutalMbps)
	}

	if *pprofAddr != "" {
		go func() { log.Printf("pprof: %v", http.ListenAndServe(*pprofAddr, nil)) }()
		log.Printf("pprof включён на %s", *pprofAddr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := run(ctx, o); err != nil && ctx.Err() == nil {
		log.Fatalf("run: %v", err)
	}
	log.Print("остановлен")
}
