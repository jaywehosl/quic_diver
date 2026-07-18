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
	"time"
)

type options struct {
	server      string // UDP endpoint узла, host:port
	authority   string // :authority в connect-ip URI (по умолчанию = server)
	dll         string // путь к WinDivert.dll
	noProxy     bool   // не трогать системный прокси
	noDNS       bool   // не поднимать локальный резолвер и не трогать системный DNS
	nat46       string // синтез A для v6-only хостов: auto|on|off
	token       string // токен доступа к узлу (пусто → dev-узел без БД)
	hybrid      bool   // TCP через CONNECT-стрим, UDP датаграммами
	recvWorkers int    // потоков захвата (1 — сохраняет порядок пакетов)
	mtu         int    // MTU локального стека (≤ MTU интерфейса; PPPoE обычно 1480)
	brutalMbps  int    // congestion: слать с этой полосой, игнорируя потери (0 — Cubic)
	bypass      string // доп-префиксы в обход перехвата (через запятую) — для отладки
}

// Встроенные параметры для «боевой» сборки: задаются линковщиком
//
//	-ldflags "-X main.builtinServer=host:port -X main.builtinToken=qd_..."
//
// Тогда .exe запускается двойным кликом без флагов и сам идёт на нужный узел.
// Пустые (обычная dev-сборка) — работают штатные флаги и дефолты.
var (
	builtinServer    string
	builtinAuthority string
	builtinToken     string
	builtinBrutal    string // congestion Мбит/с для боевой сборки (upload)
)

func main() {
	// Боевая сборка сама поднимается с правами администратора (WinDivert грузит
	// драйвер): при двойном клике без elevation перезапускаемся через UAC.
	if builtinServer != "" {
		ensureElevated()
	}

	defServer := firstNonEmpty(builtinServer, "localhost:8443")

	var o options
	flag.StringVar(&o.server, "server", defServer, "endpoint узла (host:port)")
	flag.StringVar(&o.authority, "authority", builtinAuthority, "authority в connect-ip URI (по умолчанию = server)")
	flag.StringVar(&o.dll, "dll", "", "путь к WinDivert.dll (пусто → вшитый распакуется в %APPDATA%\\QUICDiver)")
	flag.BoolVar(&o.noProxy, "no-proxy", false, "не отключать системный прокси")
	flag.BoolVar(&o.noDNS, "no-dns", false, "не поднимать локальный резолвер (резолв пойдёт мимо туннеля — провайдер подменит ответы)")
	flag.StringVar(&o.nat46, "nat46", "auto", "давать IPv6-only хостам фиктивный IPv4: auto (только если своего IPv6 нет), on, off")
	flag.StringVar(&o.token, "token", builtinToken, "токен доступа к узлу (пусто → узел без БД, dev)")
	flag.BoolVar(&o.hybrid, "hybrid", true, "TCP через надёжный CONNECT-стрим, UDP датаграммами (false → всё датаграммами, модель B)")
	flag.IntVar(&o.recvWorkers, "recv-workers", 1, "потоков захвата: 1 сохраняет порядок пакетов; >1 ускоряет скачивание ценой reordering")
	flag.IntVar(&o.mtu, "mtu", 1500, "MTU локального стека; инжект идёт в интерфейс (у него обычно 1500), а не в PPPoE-путь")
	flag.IntVar(&o.brutalMbps, "brutal", 0, "слать с полосой N Мбит/с, игнорируя потери (0 — обычный Cubic); ставить НИЖЕ реальной полосы отдачи")
	flag.StringVar(&o.bypass, "bypass", "", "доп-префиксы в обход перехвата через запятую (напр. 1.2.3.4/32) — для отладки, чтобы не рвать свои соединения")
	pprofAddr := flag.String("pprof", "", "адрес pprof (напр. localhost:6061); пусто → выкл")
	flag.Parse()
	if o.authority == "" {
		o.authority = o.server
	}
	// Боевая сборка: brutal вшит (upload), если флагом не переопределён.
	if o.brutalMbps == 0 && builtinBrutal != "" {
		if v, err := strconv.Atoi(builtinBrutal); err == nil {
			o.brutalMbps = v
		}
	}

	if o.server != "" && o.token != "" {
		log.Printf("боевой режим: узел %s (токен вшит)", o.server)
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

	// Боевая сборка без консоли (двойной клик) — задержать окно на выходе, иначе
	// пользователь не увидит причину, если узел недоступен.
	if builtinServer != "" {
		defer holdOnExit()
	}

	serve(ctx, o)
	log.Print("остановлен")
}

// firstNonEmpty возвращает первый непустой аргумент.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Границы паузы между попытками переподключения.
//
// Потолок низкий намеренно: сюда попадаем, только когда путь не удалось починить
// переездом и сессия всё-таки умерла. Связь к этому моменту может вернуться в
// любую секунду, и ждать полминуты, когда интернет уже есть, — ровно то, что
// пользователь замечает как «висит».
const (
	minBackoff = time.Second
	maxBackoff = 5 * time.Second
	// stableRun — сколько сессия должна прожить, чтобы счесть её удавшейся и
	// сбросить паузу. Иначе после долгой работы первый же обрыв ждал бы полминуты.
	stableRun = time.Minute
)

// serve держит клиента поднятым: сессия умерла — поднимаем заново (arch4).
//
// Миграция спасает от смены адреса, но не от всего: если роутер пересобрал PPPoE,
// локальный адрес не менялся, а публичный сменился — NAT-маппинг слетел, ответы
// узла не доходят, и сессия умирает по idle-таймауту. Раньше на этом клиент просто
// падал (log.Fatal) и пользователь оставался без сети до ручного перезапуска.
//
// Пересоздаём весь стек, а не только сессию: со смертью QUIC умерли и все
// CONNECT-стримы, то есть соединения приложений оборваны в любом случае. Выход из
// run вернёт системе прокси и DNS, поэтому следующий резолв домена узла пойдёт
// через настоящий DNS провайдера, а не через наш уже неживой listener.
func serve(ctx context.Context, o options) { serveWith(ctx, o, run) }

// serveWith — та же петля с подставным запуском (для тестов).
func serveWith(ctx context.Context, o options, runFn func(context.Context, options) error) {
	backoff := minBackoff
	for attempt := 1; ctx.Err() == nil; attempt++ {
		start := time.Now()
		err := runFn(ctx, o)
		lived := time.Since(start)

		if ctx.Err() != nil {
			return // штатная остановка по Ctrl+C
		}
		if err == nil {
			return
		}
		if lived >= stableRun {
			backoff = minBackoff // сессия работала долго — обрыв разовый
		}
		log.Printf("сессия оборвалась после %v: %v", lived.Round(time.Second), err)
		log.Printf("переподключение через %v (попытка %d)", backoff, attempt)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
