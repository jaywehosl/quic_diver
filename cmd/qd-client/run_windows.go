//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/netip"

	"quicdiver/internal/client/nat"
	"quicdiver/internal/client/sysproxy"
	"quicdiver/internal/engine/connectip"
	"quicdiver/internal/guard"
	"quicdiver/internal/packet/windivert"
	"quicdiver/internal/server"
	"quicdiver/internal/transport/cip"
)

func run(ctx context.Context, o options) error {
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
	filter := windivert.BuildFilter(windivert.CaptureConfig{TCP: true, UDP: true, Bypass: bypass})
	log.Printf("filter: %s", filter)

	src, err := windivert.Open(o.dll, filter, 0) // боевой отвод
	if err != nil {
		return fmt.Errorf("windivert open: %w", err)
	}
	defer src.Close()

	// 5. connect-ip туннель к узлу.
	host, _, _ := net.SplitHostPort(o.authority)
	tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: host} // dev self-signed
	tmpl := server.Template(o.authority, "/connect-ip")

	client, rsp, err := cip.Dial(ctx, o.server, tmpl, tlsConf)
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

	// 7. Гонять трафик.
	eng := connectip.New(g, rewriter)
	log.Print("проксирование запущено")
	return eng.Run(ctx, src, client)
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
