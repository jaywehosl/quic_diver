//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"

	"github.com/quic-go/quic-go/http3"

	"quicdiver/internal/client/connectdial"
	"quicdiver/internal/client/dnsforward"
	"quicdiver/internal/client/dnsproxy"
	"quicdiver/internal/client/fakeip"
	"quicdiver/internal/client/nat"
	"quicdiver/internal/client/nat46"
	"quicdiver/internal/client/netwatch"
	"quicdiver/internal/client/routeclient"
	"quicdiver/internal/client/routing"
	"quicdiver/internal/client/supervisor"
	"quicdiver/internal/client/sysdns"
	"quicdiver/internal/client/sysproxy"
	"quicdiver/internal/engine"
	"quicdiver/internal/engine/connectip"
	"quicdiver/internal/engine/hybrid"
	"quicdiver/internal/guard"
	"quicdiver/internal/packet"
	"quicdiver/internal/packet/windivert"
	"quicdiver/internal/server"
	"quicdiver/internal/server/netstack"
	"quicdiver/internal/transport/cip"
)

func run(ctx context.Context, o options) error {
	// 0. Подобрать DNS, если прошлый запуск умер аварийно. Строго ДО резолва
	//    домена узла: в реестре сейчас может стоять наш 127.0.0.1, а listener'а за
	//    ним нет — резолв не отработает и клиент не поднимется вовсе.
	if !o.noDNS {
		recoverDNS()
	}

	// 1. Определить реальный исходящий адрес и IP узла (до перехвата).
	realIP, err := primaryIP()
	if err != nil {
		return fmt.Errorf("primary ip: %w", err)
	}
	serverIPs, err := resolveServerIPs(o.server)
	if err != nil {
		return fmt.Errorf("resolve server: %w", err)
	}
	log.Printf("realIP=%s, узел %v", realIP, serverIPs)

	// 2. Отключить системный прокси (приложения пойдут напрямую → под перехват).
	if !o.noProxy {
		saved, err := sysproxy.Disable()
		if err != nil {
			return fmt.Errorf("sysproxy off: %w", err)
		}
		defer func() {
			if err := saved.Restore(); err != nil {
				log.Printf("sysproxy restore: %v", err)
			} else {
				log.Print("системный прокси восстановлен")
			}
		}()
		log.Print("системный прокси отключён")
	}

	// 3. guard: локалка + IP узлов (анти-петля).
	g := guard.New(serverIPs)

	// 4. WinDivert: перехват TCP+UDP исходящих, кроме локалки и IP узлов
	//    (последнее критично — иначе перехватим собственный QUIC к узлу → петля).
	bypass := append([]netip.Prefix(nil), g.Bypasses()...)
	for _, ip := range serverIPs {
		bypass = append(bypass, netip.PrefixFrom(ip, ip.BitLen()))
	}
	// Доп-исключения из -bypass (отладка: не заворачивать свои соединения к другим
	// узлам/сервисам, иначе теряется доступ к ним на время работы клиента).
	for _, s := range strings.Split(o.bypass, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			bypass = append(bypass, p)
		} else if a, err := netip.ParseAddr(s); err == nil {
			bypass = append(bypass, netip.PrefixFrom(a, a.BitLen()))
		} else {
			log.Printf("bypass: пропускаю %q: %v", s, err)
		}
	}
	filter := windivert.BuildFilter(windivert.CaptureConfig{TCP: true, UDP: true, Bypass: bypass})
	log.Printf("filter: %s", filter)

	// WinDivert вшит в .exe: распаковываем в рабочую папку и грузим оттуда.
	// -dll переопределяет (для отладки со своей сборкой драйвера).
	dll := o.dll
	if dll == "" {
		dir, err := windivert.DefaultDir()
		if err != nil {
			return fmt.Errorf("рабочая папка: %w", err)
		}
		if dll, err = windivert.Extract(dir); err != nil {
			return fmt.Errorf("распаковать WinDivert: %w", err)
		}
		log.Printf("WinDivert распакован в %s", dir)
	}

	src, err := windivert.Open(dll, filter, 0) // боевой отвод
	if err != nil {
		return fmt.Errorf("windivert open: %w (нужны права администратора)", err)
	}
	defer src.Close()

	// 5. connect-ip туннель к узлу.
	host, _, _ := net.SplitHostPort(o.authority)
	tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: host} // dev self-signed
	tmpl := server.Template(o.authority, "/connect-ip")

	authURL := "https://" + o.authority + "/qd-auth"
	client, rsp, err := cip.DialAuth(ctx, o.server, tmpl, tlsConf, o.token, authURL)
	if err != nil {
		return fmt.Errorf("connect-ip dial: %w", err)
	}
	defer client.Close()
	log.Printf("туннель установлен (status %d)", rsp.StatusCode)

	// 6. Назначенный узлом адрес → NAT (src real→assigned).
	prefs, err := client.LocalPrefixes(ctx)
	if err != nil {
		return fmt.Errorf("local prefixes: %w", err)
	}
	assigned := make([]netip.Addr, 0, len(prefs))
	for _, p := range prefs {
		assigned = append(assigned, p.Addr())
	}
	log.Printf("узел назначил адреса: %v", assigned)
	rewriter := nat.New([]netip.Addr{realIP}, assigned)

	// 6.5. fake-IP / NAT46 — как резолвер подменяет ответы.
	//      С -rules: fake для ВСЕХ доменов (доменный роутинг — клиент точно знает
	//      имя по dst; fakeip поглощает и v6-only случай). Без правил: nat46 только
	//      для v6-only хостов (ntc.party и подобные, «несуществующие» на v4-клиенте).
	var fakePool *fakeip.Pool
	var nat46Table *nat46.Table
	var dnsDecorate func(dnsproxy.Exchanger) dnsproxy.Exchanger
	var router *routing.Router
	if o.rules != "" {
		parsed, err := routing.ParseRules(o.rules)
		if err != nil {
			return fmt.Errorf("правила: %w", err)
		}
		router = routing.NewRouter(routing.Compile(parsed, o.routeDef))
		fakePool = fakeip.New(fakeip.DefaultPool, fakeip.DefaultTTL)
		dnsDecorate = func(ex dnsproxy.Exchanger) dnsproxy.Exchanger { return fakeip.NewResolver(ex, fakePool) }
		log.Printf("роутинг: %d правил (по умолчанию %q), fake-IP из %s", len(parsed), o.routeDef, fakePool.Prefix())
	} else {
		nat46Table, err = setupNAT46(o.nat46)
		if err != nil {
			return err
		}
		if nat46Table != nil {
			dnsDecorate = func(ex dnsproxy.Exchanger) dnsproxy.Exchanger { return nat46.NewResolver(ex, nat46Table) }
		}
	}

	// 6.6. DNS: локальный listener + подмена системного резолвера. Без этого
	//      приложения спрашивают роутер (он в bypass как локальный), запрос уходит
	//      мимо туннеля и провайдер отдаёт свою заглушку вместо реального адреса.
	if !o.noDNS {
		stopDNS, err := startDNS(ctx, client.H3Conn(), o.authority, dnsDecorate)
		if err != nil {
			return fmt.Errorf("dns: %w", err)
		}
		defer stopDNS()
	}

	// 6.7. Supervisor (arch4): переезд Wi-Fi↔LTE или пересборка PPPoE меняет
	//      локальный адрес — переносим сессию на новый сокет, чтобы соединения
	//      приложений не рвались, и пересматриваем зависящее от сети.
	sup := supervisor.New(supervisor.Config{
		Client:  client,
		Watch:   netwatch.Watcher{HasIPv6: nat46.HostHasIPv6},
		Initial: netwatch.State{Primary: realIP, HasIPv6: nat46.HostHasIPv6()},
		OnNetworkChange: func(st netwatch.State) error {
			// У нового адаптера свой DHCP-DNS — снова уводим его на наш listener.
			// Apply идемпотентен: уже наши значения он не перезапишет.
			if o.noDNS {
				return nil
			}
			if _, err := sysdns.Apply(); err != nil {
				return fmt.Errorf("вернуть системный DNS на loopback: %w", err)
			}
			return nil
		},
	})
	supErr := make(chan error, 1)
	go func() { supErr <- sup.Run(ctx) }()
	defer func() {
		if m, f := sup.Stats(); m > 0 || f > 0 {
			log.Printf("supervisor: переездов пережито %d, неудачных миграций %d", m, f)
		}
	}()

	// 7. Гибрид: TCP-флоу терминирует локальный gVisor и уводит в надёжный
	//    CONNECT-стрим (потери туннеля закрывает ретрансмит QUIC); UDP остаётся на
	//    датаграммах connect-ip. Замерено: TCP-стрим 494 Мбит/stddev 9% против
	//    115 Мбит/пила на датаграммах.
	if o.hybrid {
		// MTU локального стека. Инжектим пакеты в ОС как «пришедшие из сети»,
		// поэтому они не должны превышать MTU интерфейса: при PPPoE это обычно
		// 1480 и меньше, а пакет крупнее ОС просто отбросит. Дефолт 1400 — с
		// запасом под PPPoE/VPN; -mtu задаёт явно.
		// Выход TCP-флоу: с правилами — routeclient метит по домену (fake-IP) и
		// подменяет fake→real; с nat46 — подмена v4→v6; иначе прямой CONNECT.
		var dialer netstack.Dialer = connectdial.Dialer{CC: client.H3Conn()}
		switch {
		case router != nil:
			dialer = routeclient.Dialer{CC: client.H3Conn(), Router: router, Fake: fakePool, Default: o.routeDef}
		case nat46Table != nil:
			dialer = nat46.Dialer{Inner: connectdial.Dialer{CC: client.H3Conn()}, Table: nat46Table}
		}
		ns, err := netstack.NewWithMTU(dialer, o.mtu)
		if err != nil {
			return fmt.Errorf("netstack: %w", err)
		}
		eng := hybrid.New(g, rewriter, ns, o.recvWorkers)
		log.Print("проксирование запущено (ГИБРИД: TCP→стрим, UDP→датаграмма)")
		return firstErr(runEngine(ctx, eng, src, client), supErr)
	}

	eng := connectip.New(g, rewriter)
	log.Print("проксирование запущено (модель B: всё датаграммами)")
	return firstErr(runEngine(ctx, eng, src, client), supErr)
}

// engineRunner — общее у гибрида и модели B.
type engineRunner interface {
	Run(ctx context.Context, src packet.Source, tun engine.PacketTunnel) error
}

func runEngine(ctx context.Context, e engineRunner, src packet.Source, tun engine.PacketTunnel) <-chan error {
	c := make(chan error, 1)
	go func() { c <- e.Run(ctx, src, tun) }()
	return c
}

// firstErr отдаёт то, что случилось раньше: обрыв движка или приговор supervisor'а.
//
// Сессию может убить и то, и другое: движок увидит ошибку чтения из мёртвого
// туннеля, supervisor — закрытый контекст сессии. Кто первый, тот и причина;
// возвращаем её наверх, где serve поднимет стек заново.
func firstErr(engErr <-chan error, supErr <-chan error) error {
	select {
	case err := <-engErr:
		return err
	case err := <-supErr:
		if err != nil {
			return err
		}
		return <-engErr // supervisor завершился штатно — ждём движок
	}
}

// recoverDNS возвращает системный резолвер, если прошлый запуск умер аварийно
// (паника, kill, BSOD — defer не отработал) и оставил в реестре наш loopback.
//
// Подбираем, только если 127.0.0.1:53 свободен: занятый порт означает, что рядом
// работает другой экземпляр, и откат сорвал бы ему резолв.
func recoverDNS() {
	probe, err := net.ListenPacket("udp", net.JoinHostPort(sysdns.Loopback4, "53"))
	if err != nil {
		return // порт занят — другой экземпляр уже держит DNS на себе
	}
	probe.Close()

	found, err := sysdns.RestoreStale()
	if err != nil {
		log.Printf("dns: не подобрать состояние прошлого запуска: %v", err)
		return
	}
	if found {
		log.Print("DNS: прошлый запуск завершился аварийно — прежний резолвер возвращён")
	}
}

// setupNAT46 решает, включать ли синтез A для v6-only хостов.
//
// auto — по факту наличия своего глобального IPv6. Это состояние сети, а она
// меняется на ходу (Wi-Fi с v6 ↔ LTE без него), поэтому решение переоценивает
// supervisor при смене параметров сети, а не только старт.
func setupNAT46(mode string) (*nat46.Table, error) {
	switch mode {
	case "off":
		return nil, nil
	case "on", "auto":
	default:
		return nil, fmt.Errorf("-nat46: нужно auto, on или off (получено %q)", mode)
	}
	if mode == "auto" && nat46.HostHasIPv6() {
		log.Print("NAT46: выключен — у машины есть свой IPv6, приложения пойдут по AAAA сами")
		return nil, nil
	}
	t := nat46.NewTable(nat46.DefaultPool, nat46.DefaultTTL)
	log.Printf("NAT46: включён (своего IPv6 нет) — v6-only хосты получат адрес из %s", t.Pool())
	return t, nil
}

// startDNS поднимает локальный резолвер на обоих loopback'ах и переводит на него
// систему. Возвращает функцию остановки (она же возвращает прежний DNS).
//
// Порядок важен: сначала listener, потом подмена — иначе между подменой и
// готовностью listener'а система осталась бы вообще без резолвера.
func startDNS(ctx context.Context, cc *http3.ClientConn, authority string, decorate func(dnsproxy.Exchanger) dnsproxy.Exchanger) (func(), error) {
	var ex dnsproxy.Exchanger = dnsforward.New(cc, "https://"+authority+"/dns-query")
	if decorate != nil {
		ex = decorate(ex)
	}
	p, err := dnsproxy.New(dnsproxy.Config{
		Addrs:    []string{net.JoinHostPort(sysdns.Loopback4, "53"), net.JoinHostPort(sysdns.Loopback6, "53")},
		Exchange: ex,
	})
	if err != nil {
		return nil, err
	}
	dnsCtx, cancel := context.WithCancel(ctx)
	go func() {
		if err := p.Run(dnsCtx); err != nil {
			log.Printf("dns listener: %v", err)
		}
	}()

	saved, err := sysdns.Apply()
	if err != nil {
		cancel()
		return nil, err
	}
	log.Printf("DNS: слушаю %v, системный резолвер переведён на loopback", p.Addrs())

	return func() {
		cancel()
		if err := saved.Restore(); err != nil {
			log.Printf("dns restore: %v", err)
		} else {
			log.Print("системный DNS восстановлен")
		}
		if q, f := p.Stats(); q > 0 {
			log.Printf("DNS: запросов %d, неудач %d", q, f)
		}
	}, nil
}

// primaryIP выбирает исходящий LAN-адрес по маршруту по умолчанию (сокет не шлёт
// данных). Берём маршрут наружу, а не к узлу: узел может быть на localhost, тогда
// loopback-адрес не совпал бы с реальным src приложений.
func primaryIP() (netip.Addr, error) {
	c, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, fmt.Errorf("unexpected local addr")
	}
	a, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.Addr{}, fmt.Errorf("bad local ip")
	}
	return a.Unmap(), nil
}

// resolveServerIPs резолвит host узла в список IP (для анти-петли и bypass).
func resolveServerIPs(server string) ([]netip.Addr, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return out, nil
}
