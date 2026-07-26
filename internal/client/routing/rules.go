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
	GeoSite string       // категория geosite, напр. "google", "youtube", "ru", "category-ads-all"
	GeoIP   string       // код geoip, напр. "ru", "private"
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

// SortRulesByPriority сортирует правила по строгому иерархическому приоритету:
// 1. Доменные правила, GeoSite, GeoIP, CIDR и Порты (самый высокий приоритет — точечные переопределения).
// 2. Правила по процессам (proc:) (средний приоритет — приложение целиком).
// Порядок внутри каждой категории сохраняется.
func SortRulesByPriority(rules []Rule) []Rule {
	var specific []Rule
	var proc []Rule

	for _, r := range rules {
		if r.Match.Process != "" && r.Match.Domain == "" && r.Match.GeoSite == "" && r.Match.GeoIP == "" && !r.Match.CIDR.IsValid() && r.Match.Port == 0 {
			proc = append(proc, r)
		} else {
			specific = append(specific, r)
		}
	}

	return append(specific, proc...)
}

// Compile строит набор из правил с авто-сортировкой по приоритету (Домены/Geo -> Процессы -> Default).
func Compile(rules []Rule, def string) *Ruleset {
	sorted := SortRulesByPriority(rules)
	return &Ruleset{rules: sorted, def: def}
}

// Classify возвращает метку выхода для флоу. Первое совпавшее правило выигрывает;
// нет совпадений → выход по умолчанию.
func (rs *Ruleset) Classify(f Flow) string {
	out, _ := rs.Explain(f)
	return out
}

// Explain — то же, но с указанием, КАКОЕ правило сработало (-1 — ни одно, ушло
// в выход по умолчанию).
//
// Нужен панели: правила матчатся по порядку, и «почему трафик пошёл не туда»
// иначе выясняется экспериментом на живом трафике. Показать сработавшее правило
// дешевле, чем заставлять человека угадывать.
func (rs *Ruleset) Explain(f Flow) (out string, rule int) {
	for i := range rs.rules {
		if out, ok := matchRule(&rs.rules[i], f); ok {
			return out, i
		}
	}
	return rs.def, -1
}

// Rules — копия правил набора (панели нужно показать их с номерами).
func (rs *Ruleset) Rules() []Rule { return append([]Rule(nil), rs.rules...) }

// Default — выход по умолчанию.
func (rs *Ruleset) Default() string { return rs.def }

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
	case m.GeoSite != "":
		if f.Domain != "" && geoSiteMatches(m.GeoSite, f.Domain) {
			return r.Out, true
		}
	case m.GeoIP != "":
		if f.Dst.Addr().IsValid() && geoIPMatches(m.GeoIP, f.Dst.Addr()) {
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

// CurrentRuleset возвращает текущий скомпилированный набор правил.
func (r *Router) CurrentRuleset() *Ruleset { return r.rs.Load() }

// AddRule добавляет новое правило в конец набора и атомарно обновляет роутер.
func (r *Router) AddRule(rule Rule) {
	cur := r.rs.Load()
	rules := cur.Rules()
	rules = append(rules, rule)
	r.Swap(Compile(rules, cur.Default()))
}

// UpdateRule обновляет правило по индексу.
func (r *Router) UpdateRule(index int, rule Rule) bool {
	cur := r.rs.Load()
	rules := cur.Rules()
	if index < 0 || index >= len(rules) {
		return false
	}
	rules[index] = rule
	r.Swap(Compile(rules, cur.Default()))
	return true
}

// DeleteRule удаляет правило по индексу.
func (r *Router) DeleteRule(index int) bool {
	cur := r.rs.Load()
	rules := cur.Rules()
	if index < 0 || index >= len(rules) {
		return false
	}
	rules = append(rules[:index], rules[index+1:]...)
	r.Swap(Compile(rules, cur.Default()))
	return true
}

// MoveRule меняет порядок правил (переставляет правило с from на to).
func (r *Router) MoveRule(from, to int) bool {
	cur := r.rs.Load()
	rules := cur.Rules()
	if from < 0 || from >= len(rules) || to < 0 || to >= len(rules) || from == to {
		return false
	}
	item := rules[from]
	rules = append(rules[:from], rules[from+1:]...)
	rules = append(rules[:to], append([]Rule{item}, rules[to:]...)...)
	r.Swap(Compile(rules, cur.Default()))
	return true
}
