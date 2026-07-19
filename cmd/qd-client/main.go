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
	"strings"
	"time"

	"quicdiver/internal/client/config"
)

type options struct {
	// verbose — подробный журнал: счётчики транспорта. Для отладки.
	verbose     bool
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
	rules       string // правила роутинга: "dom:youtube.com=chain;port:443=eu" (до веб-юи)
	routeDef    string // выход по умолчанию (нет совпадений правил)
}

// Встроенные параметры сборки: задаются линковщиком
//
//	-ldflags "-X main.builtinServer=host:port -X main.builtinBrutal=700"
//
// ТОКЕН СЮДА НЕ ВШИВАЕТСЯ. Раньше вшивался, и это было неверно: один и тот же
// файл получали все, а значит все ходили под одним доступом — отозвать его у
// одного человека было нельзя, не сломав остальным. Доступ выдаётся ссылкой
// подписки, которую человек вставляет в панель; сборка остаётся общей.
//
// Пустые (обычная dev-сборка) — работают штатные флаги и дефолты.
var (
	builtinServer    string
	builtinAuthority string
	builtinBrutal    string // congestion Мбит/с для боевой сборки (upload)
)

func main() {
	// Боевая сборка сама поднимается с правами администратора (WinDivert грузит
	// драйвер): при двойном клике без elevation перезапускаемся через UAC.
	if builtinServer != "" {
		ensureElevated()
	}

	// Файл настроек — основной источник: в релизе клиент запускается без
	// аргументов, а правит настройки веб-панель. Флаги остаются инструментом
	// разработки и перекрывают файл (см. applyFlagOverrides).
	cfg, cfgErr := config.Load()
	if cfgErr != nil {
		// Битый файл не должен молча стать «настройками по умолчанию»: клиент
		// ушёл бы не на тот узел. Говорим вслух и работаем на дефолтах.
		log.Printf("настройки не прочитаны (%v) — работаю на значениях по умолчанию", cfgErr)
	}

	defServer := firstNonEmpty(builtinServer, entryAddr(cfg))
	if defServer == "" {
		defServer = "localhost:8443"
	}

	var o options
	flag.StringVar(&o.server, "server", defServer, "endpoint узла (host:port)")
	flag.StringVar(&o.authority, "authority", firstNonEmpty(builtinAuthority, entrySNI(cfg)), "authority в connect-ip URI (по умолчанию = server)")
	flag.StringVar(&o.dll, "dll", "", "путь к WinDivert.dll (пусто → вшитый распакуется в %APPDATA%\\QUICDiver)")
	flag.BoolVar(&o.noProxy, "no-proxy", !cfg.Capture.ManageProxy, "не отключать системный прокси")
	flag.BoolVar(&o.noDNS, "no-dns", !cfg.Capture.ManageDNS, "не поднимать локальный резолвер (резолв пойдёт мимо туннеля — провайдер подменит ответы)")
	flag.StringVar(&o.nat46, "nat46", cfg.Capture.NAT46, "давать IPv6-only хостам фиктивный IPv4: auto (только если своего IPv6 нет), on, off")
	flag.StringVar(&o.token, "token", cfg.Node.Token, "токен доступа (обычно приезжает ссылкой подписки; флаг — для отладки)")
	flag.BoolVar(&o.hybrid, "hybrid", cfg.Transport.Hybrid, "TCP через надёжный CONNECT-стрим, UDP датаграммами (false → всё датаграммами, модель B)")
	flag.IntVar(&o.recvWorkers, "recv-workers", cfg.Transport.RecvWorkers, "потоков захвата: 1 сохраняет порядок пакетов; >1 ускоряет скачивание ценой reordering")
	flag.IntVar(&o.mtu, "mtu", cfg.Transport.MTU, "MTU локального стека; инжект идёт в интерфейс (у него обычно 1500), а не в PPPoE-путь")
	flag.IntVar(&o.brutalMbps, "brutal", cfg.Transport.BrutalMbps, "слать с полосой N Мбит/с, игнорируя потери (0 — обычный Cubic); ставить НИЖЕ реальной полосы отдачи")
	flag.StringVar(&o.bypass, "bypass", strings.Join(cfg.Capture.Bypass, ","), "доп-префиксы в обход перехвата через запятую (напр. 1.2.3.4/32) — для отладки, чтобы не рвать свои соединения")
	flag.StringVar(&o.rules, "rules", strings.Join(cfg.Routing.Rules, ";"), "правила роутинга через ; (напр. \"dom:youtube.com=chain;port:443=eu\"); пусто → весь трафик через выход по умолчанию")
	flag.StringVar(&o.routeDef, "route-default", cfg.Routing.Default, "метка выхода по умолчанию (нет совпадений правил)")
	flag.BoolVar(&o.verbose, "v", false,
		"печатать счётчики транспорта каждые несколько секунд (для отладки)")
	noAuto := flag.Bool("no-autoconnect", false,
		"поднять только сервис: панель и значок работают, трафик не заворачивается")
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

	log.SetPrefix("qd-client: ")
	// Журнал в файл: релизная сборка идёт без консоли, и без файла причина
	// поломки просто исчезала бы.
	defer setupLog(!hasConsole())()

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

	// Вшитая боевая сборка запускается двойным кликом и обязана подключаться
	// сама: у пользователя нет ни консоли, ни (пока) панели.
	serveService(ctx, o, cfg, !*noAuto && cfg.Autoconnect)
	log.Print("остановлен")
}

// firstNonEmpty возвращает первый непустой аргумент.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// entryAddr/entrySNI берут первую точку входа из настроек. Список приезжает
// подпиской (резервные адреса на случай блокировки), перебор по нему появится
// вместе с ней — пока используем первую.
func entryAddr(cfg config.Config) string {
	if len(cfg.Node.Entries) == 0 {
		return ""
	}
	return cfg.Node.Entries[0].Addr
}

func entrySNI(cfg config.Config) string {
	if len(cfg.Node.Entries) == 0 {
		return ""
	}
	return cfg.Node.Entries[0].SNI
}

// serveService держит процесс живым: панель, значок в лотке и сессия.
//
// Сервис и сессия разделены по ТЗ. Процесс работает всегда — отдаёт панель и
// держит управляющую связь с узлом; перехват трафика включается отдельно,
// кнопкой. Поэтому «отключено, узел на связи» — штатное состояние.
func serveService(ctx context.Context, o options, cfg config.Config, autoconnect bool) {
	ctx, quit := context.WithCancel(ctx)
	defer quit()

	rt, err := startRuntime(ctx, o, cfg, quit)
	if err != nil {
		log.Fatalf("панель не поднялась: %v", err)
	}

	if autoconnect {
		if err := rt.svc.Connect(ctx); err != nil {
			log.Printf("подключение: %v", err)
		}
	} else {
		log.Print("сервис поднят, трафик не заворачивается (автоподключение выключено)")
	}
	if cfg.Panel.Open {
		// Ждём, пока сессия встанет: браузер, открытый раньше снятия системного
		// прокси, запоминает его и продолжает ходить через него, пока его не
		// перезапустят. Со стороны это выглядит как «клиент подключён, а адрес
		// прежний». Наступали на это вживую.
		go func() {
			if autoconnect {
				rt.waitConnected(ctx, 15*time.Second)
			}
			rt.openPanel()
		}()
	}

	// Значок держит цикл сообщений и возвращается только при выходе.
	rt.runTray(ctx)
	<-ctx.Done()

	// Гасим сессию явно и ждём уборку: она возвращает системный DNS и прокси.
	// Уйти раньше — оставить машину с нашими настройками и без сети.
	stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := rt.svc.Disconnect(stopCtx); err != nil {
		log.Printf("остановка: %v", err)
	}
}
