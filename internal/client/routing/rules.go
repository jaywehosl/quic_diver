// Package routing — клиентская классификация трафика: какой флоу через какой
// выход (метку) пустить. Клиент решает, узел следует метке.
//
// Правила задаются в веб-юи разово, компилируются в неизменяемый набор и
// применяются атомарной заменой указателя (atomic swap) — без окна, когда
// роутинг не работает. Классификация идёт раз на ФЛОУ (5-tuple), решение
// кешируется (conntrack): горячий путь пакета берёт готовую метку, не гоняя
// правила заново.
//
// Матчеры (проверяются в порядке правил, первое совпадение выигрывает — так
// решается конфликт «весь Chrome через ноду 2, но .cn-домены через ноду 1»:
// правило для .cn стоит выше):
//   - Process — имя процесса (per-app; PID→имя даёт перехват);
//   - Domain  — доменный суффикс (fake-IP даёт точное имя без CDN-коллизий);
//   - CIDR    — подсеть назначения;
//   - Port    — порт назначения.
package routing

import (
	"net/netip"
	"strings"
	"sync/atomic"
)

// RouteHeaderName — заголовок метки выхода в CONNECT (должен совпадать с
// server.RouteHeader). Держим свой, чтобы клиент не тянул серверный пакет.
const RouteHeaderName = "Qd-Route"

// Match — условие правила. Задано ровно одно поле (пустые игнорируются). Так
// правило остаётся простым «одно условие → выход», а сложные политики
// набираются порядком правил.
type Match struct {
	Process string       // имя процесса, напр. "telegram.exe" (регистронезависимо)
	Domain  string       // доменный суффикс, напр. "youtube.com" (матчит и *.youtube.com)
	CIDR    netip.Prefix // подсеть назначения
	Port    uint16       // порт назначения
}

// Rule — правило: условие → метка выхода (Qd-Route/подсеть на узле).
type Rule struct {
	Match Match
	Out   string // метка выхода, напр. "chain" или "direct"
}

// Flow — то, что известно о флоу на момент классификации.
type Flow struct {
	Dst     netip.AddrPort
	Domain  string // из fake-IP/DNS, если известен (иначе пусто)
	Process string // из PID, если известен (иначе пусто)
}

// Ruleset — скомпилированный неизменяемый набор. Создаётся Compile, читается
// Classify. Заменяется целиком (atomic swap в Router).
type Ruleset struct {
	rules []Rule
	def   string // выход по умолчанию (нет совпадений)
}

// Compile строит набор из правил. def — выход по умолчанию (обычно "direct").
//
// Матч линейный (порядок правил = приоритет). Доменные наборы на тысячи записей
// поедут через суффиксное дерево, когда до них дойдёт (сейчас правил единицы —
// линейного хватает, и он сохраняет порядок без ухищрений).
func Compile(rules []Rule, def string) *Ruleset {
	return &Ruleset{rules: append([]Rule(nil), rules...), def: def}
}

// Classify возвращает метку выхода для флоу. Первое совпавшее правило выигрывает;
// нет совпадений → выход по умолчанию.
func (rs *Ruleset) Classify(f Flow) string {
	for i := range rs.rules {
		if out, ok := matchRule(&rs.rules[i], f); ok {
			return out
		}
	}
	return rs.def
}

func matchRule(r *Rule, f Flow) (string, bool) {
	m := &r.Match
	switch {
	case m.Process != "":
		if f.Process != "" && strings.EqualFold(m.Process, f.Process) {
			return r.Out, true
		}
	case m.Domain != "":
		if f.Domain != "" && domainMatches(m.Domain, f.Domain) {
			return r.Out, true
		}
	case m.CIDR.IsValid():
		if m.CIDR.Contains(f.Dst.Addr()) {
			return r.Out, true
		}
	case m.Port != 0:
		if m.Port == f.Dst.Port() {
			return r.Out, true
		}
	}
	return "", false
}

// domainMatches — суффиксное совпадение: правило "youtube.com" матчит
// "youtube.com" и "rr1.youtube.com", но не "notyoutube.com".
func domainMatches(suffix, name string) bool {
	suffix = strings.ToLower(strings.TrimSuffix(suffix, "."))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == suffix {
		return true
	}
	return strings.HasSuffix(name, "."+suffix)
}

// Router держит текущий набор и меняет его атомарно (обновление правил из
// веб-юи без окна простоя).
type Router struct {
	rs atomic.Pointer[Ruleset]
}

// NewRouter создаёт роутер с начальным набором (nil → всё в def "direct").
func NewRouter(rs *Ruleset) *Router {
	r := &Router{}
	if rs == nil {
		rs = Compile(nil, "direct")
	}
	r.rs.Store(rs)
	return r
}

// Swap атомарно заменяет набор. Старый жив до замены, новый — сразу после;
// окна без роутинга нет.
func (r *Router) Swap(rs *Ruleset) { r.rs.Store(rs) }

// Classify классифицирует флоу текущим набором.
func (r *Router) Classify(f Flow) string { return r.rs.Load().Classify(f) }
