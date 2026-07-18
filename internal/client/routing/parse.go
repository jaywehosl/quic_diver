package routing

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ParseRules разбирает правила из компактной записи (флаг/конфиг, до веб-юи).
// Формат: правила через ';', каждое — "матчер=выход". Матчеры:
//
//	dom:youtube.com=chain     — доменный суффикс
//	proc:telegram.exe=chain   — процесс
//	cidr:1.2.3.0/24=chain      — подсеть назначения
//	port:443=chain            — порт назначения
//
// Порядок сохраняется (= приоритет). Пустая строка → пустой набор.
func ParseRules(s string) ([]Rule, error) {
	var rules []Rule
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		cond, out, ok := strings.Cut(part, "=")
		if !ok || out == "" {
			return nil, fmt.Errorf("правило %q: нужно матчер=выход", part)
		}
		kind, val, ok := strings.Cut(cond, ":")
		if !ok {
			return nil, fmt.Errorf("правило %q: нужен префикс матчера (dom/proc/cidr/port)", part)
		}
		r := Rule{Out: strings.TrimSpace(out)}
		switch kind {
		case "dom":
			r.Match.Domain = val
		case "proc":
			r.Match.Process = val
		case "cidr":
			p, err := netip.ParsePrefix(val)
			if err != nil {
				return nil, fmt.Errorf("правило %q: %w", part, err)
			}
			r.Match.CIDR = p
		case "port":
			n, err := strconv.ParseUint(val, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("правило %q: порт: %w", part, err)
			}
			r.Match.Port = uint16(n)
		default:
			return nil, fmt.Errorf("правило %q: неизвестный матчер %q", part, kind)
		}
		rules = append(rules, r)
	}
	return rules, nil
}
