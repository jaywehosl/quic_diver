package windivert

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// CaptureConfig — гибкое управление перехватом (arch: по семействам, протоколам и
// портам — глобально или выборочно). Строит WinDivert filter для NETWORK-слоя,
// только исходящий трафик.
//
// Per-process перехват сюда не входит: на NETWORK-слое нет PID. Он делается
// отдельным механизмом (наблюдение SOCKET-слоя: PID→5-tuple, затем сужение
// фильтра/пост-фильтрация) — следующий под-шаг B.
type CaptureConfig struct {
	// IPv4/IPv6 — какие семейства перехватывать. Оба false → оба (по умолчанию).
	IPv4, IPv6 bool
	// TCP/UDP — какие протоколы. Оба false → все протоколы.
	TCP, UDP bool
	// Ports — конкретные dst-порты; пусто → все порты.
	Ports []uint16
	// Bypass — префиксы, которые НЕ перехватывать (локалка + IP узлов). Первый
	// рубеж arch5 + анти-петля: драйвер даже не отдаёт их в userspace.
	Bypass []netip.Prefix
}

// BuildFilter собирает WinDivert filter-выражение из конфигурации.
func BuildFilter(cfg CaptureConfig) string {
	v4, v6 := cfg.IPv4, cfg.IPv6
	if !v4 && !v6 {
		v4, v6 = true, true
	}

	parts := []string{"outbound"}

	switch {
	case v4 && v6:
		// без ограничения по семейству
	case v4:
		parts = append(parts, "ip")
	case v6:
		parts = append(parts, "ipv6")
	}

	switch {
	case cfg.TCP && cfg.UDP:
		parts = append(parts, "(tcp or udp)")
	case cfg.TCP:
		parts = append(parts, "tcp")
	case cfg.UDP:
		parts = append(parts, "udp")
	}

	if len(cfg.Ports) > 0 {
		parts = append(parts, portClause(cfg))
	}

	for _, p := range bypassClauses(cfg.Bypass) {
		parts = append(parts, p)
	}

	return strings.Join(parts, " and ")
}

// portClause — "(tcp.DstPort == a or udp.DstPort == a or ...)".
func portClause(cfg CaptureConfig) string {
	// какие протоколы учитывать для портов
	tcp := cfg.TCP || (!cfg.TCP && !cfg.UDP)
	udp := cfg.UDP || (!cfg.TCP && !cfg.UDP)

	var cl []string
	for _, p := range cfg.Ports {
		if tcp {
			cl = append(cl, fmt.Sprintf("tcp.DstPort == %d", p))
		}
		if udp {
			cl = append(cl, fmt.Sprintf("udp.DstPort == %d", p))
		}
	}
	return "(" + strings.Join(cl, " or ") + ")"
}

// bypassClauses — по одному "not <field> == <cidr>" на префикс, детерминированно
// отсортированы (стабильный фильтр для тестов и логов).
func bypassClauses(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, pfx := range prefixes {
		field := "ip.DstAddr"
		if pfx.Addr().Is6() {
			field = "ipv6.DstAddr"
		}
		out = append(out, fmt.Sprintf("not %s == %s", field, pfx.String()))
	}
	sort.Strings(out)
	return out
}
