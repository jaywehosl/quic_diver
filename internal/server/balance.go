package server

import (
	"sort"
	"sync"
	"time"
)

// PathStats — качество пути до соседа: сглаженный RTT, его разброс и потери.
//
// Дублирует cip.PathStats намеренно: server не должен зависеть от клиентского
// транспорта (тот сам импортирует server ради Template — вышел бы цикл).
type PathStats struct {
	SRTT   time.Duration
	RTTVar time.Duration
	Loss   float64
}

// Score — во что обходится путь.
//
// Не голый RTT: узел со стабильными 30 мс лучше узла с 20±40 мс, а по среднему
// они неразличимы. Разброс входит с весом 2 (как в RFC 6298 при расчёте RTO) —
// так «быстрый, но рваный» узел честно проигрывает ровному.
//
// Потери штрафуются отдельно и жёстко: для TCP поверх туннеля процент потерь
// бьёт по скорости сильнее лишних миллисекунд задержки — окно схлопывается, и
// пользователь видит не «чуть медленнее», а «встало».
func (p PathStats) Score() time.Duration {
	return p.SRTT + 2*p.RTTVar + time.Duration(p.Loss*float64(lossPenalty))
}

// Пороги балансировки. Стартовые значения — калибровать на живом стенде;
// переезжают в БД и admin-API вместе с остальными настройками сети.
const (
	// lossPenalty — штраф за 100% потерь. 1% потерь ≈ 20 мс.
	lossPenalty = 2 * time.Second
	// betterBy — во сколько кандидат должен быть дешевле текущего.
	//
	// Порог относительный, а не абсолютный: 10 мс при 15↔25 мс — выигрыш 40%, а
	// при 150↔160 мс — шум 6%.
	betterBy = 0.8
	// minGain — но и абсолютная разница обязана быть заметной, иначе на очень
	// низких RTT балансировщик дёргался бы на шуме измерений.
	minGain = 5 * time.Millisecond
	// holdWindows — сколько замеров подряд кандидат должен выигрывать. Это и
	// есть «устойчивое преимущество», а не разовая удача.
	holdWindows = 3
	// switchCooldown — пауза после переключения. Без неё два близких узла
	// устроили бы пинг-понг.
	switchCooldown = 5 * time.Minute
	// statsStale — после какого молчания метрика перестаёт считаться свежей.
	statsStale = 2 * time.Minute
)

// balancer выбирает узел под метку auto:<тег> по живым метрикам.
//
// Держит выбор, а не пересчитывает его на каждый флоу: переключение стоит
// дорого — существующие флоу привязаны к выходу и на новый узел не переезжают
// (TCP-соединение нельзя перенести). Поэтому меняем выход только при устойчивом
// преимуществе и не чаще раза в cooldown.
type balancer struct {
	mu      sync.Mutex
	stats   map[string]sample    // узел → последняя метрика
	choice  map[string]*decision // тег → выбор
	nowFunc func() time.Time     // подменяется в тестах
}

type sample struct {
	stats PathStats
	at    time.Time
}

type decision struct {
	// node — кого выбрали и с какого момента.
	node  string
	since time.Time
	// challenger — кандидат, который выигрывает, и сколько окон подряд.
	challenger string
	wins       int
}

func newBalancer() *balancer {
	return &balancer{
		stats:   map[string]sample{},
		choice:  map[string]*decision{},
		nowFunc: time.Now,
	}
}

func (b *balancer) now() time.Time { return b.nowFunc() }

// Observe запоминает метрику узла.
func (b *balancer) Observe(node string, st PathStats) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stats[node] = sample{stats: st, at: b.now()}
}

// Forget убирает узел из метрик (вышел из сети, связь закрыта).
func (b *balancer) Forget(node string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.stats, node)
}

// Pick выбирает узел под тег из кандидатов.
//
// candidates — уже отфильтрованные по тегу и живости. Пустой ответ означает
// «подходящих нет»: флоу выйдет на текущем узле, а не умрёт.
func (b *balancer) Pick(tag string, candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()

	// Порядок кандидатов не должен влиять на выбор: без сортировки узлы с
	// одинаковым (или отсутствующим) счётом менялись бы местами от вызова к
	// вызову — это тот самый флаппинг, только незаметный.
	sorted := append([]string(nil), candidates...)
	sort.Strings(sorted)

	cur := b.choice[tag]
	if cur == nil || !contains(sorted, cur.node) {
		// Выбора ещё нет или прежний узел выбыл — берём лучший немедленно.
		// Ждать «устойчивости» тут нечего: альтернативы всё равно нет.
		best := b.bestLocked(sorted, now)
		b.choice[tag] = &decision{node: best, since: now}
		return best
	}

	best := b.bestLocked(sorted, now)
	if best == "" || best == cur.node {
		cur.challenger, cur.wins = "", 0
		return cur.node
	}
	// Свежая пауза после прошлого переключения — не дёргаемся.
	if now.Sub(cur.since) < switchCooldown {
		return cur.node
	}
	if !b.worthSwitchLocked(cur.node, best, now) {
		cur.challenger, cur.wins = "", 0
		return cur.node
	}

	// Кандидат выигрывает — но должен выиграть несколько окон подряд.
	if cur.challenger != best {
		cur.challenger, cur.wins = best, 1
		return cur.node
	}
	cur.wins++
	if cur.wins < holdWindows {
		return cur.node
	}
	b.choice[tag] = &decision{node: best, since: now}
	return best
}

// bestLocked — кандидат с наименьшим счётом. Узлы без свежих метрик идут
// последними: о них ничего не известно, и предпочитать их измеренным нельзя.
func (b *balancer) bestLocked(candidates []string, now time.Time) string {
	best, bestScore := "", time.Duration(0)
	var fallback string
	for _, node := range candidates {
		s, ok := b.stats[node]
		if !ok || now.Sub(s.at) > statsStale {
			if fallback == "" {
				fallback = node
			}
			continue
		}
		score := s.stats.Score()
		if best == "" || score < bestScore {
			best, bestScore = node, score
		}
	}
	if best == "" {
		return fallback
	}
	return best
}

// worthSwitchLocked — стоит ли кандидат переключения.
//
// О кандидате нужны свежие данные: менять известное на неизвестное — не выбор, а
// лотерея.
//
// А вот о ТЕКУЩЕМ узле их может не быть, и это сам по себе довод уйти: метрика
// снимается с живого соединения, поэтому её отсутствие означает, что связь с ним
// оборвалась или замерла. Требовать здесь свежий замер значило бы намертво
// прилипнуть к замолчавшему узлу — сравнивать было бы не с чем, и переключение
// не случилось бы никогда.
func (b *balancer) worthSwitchLocked(cur, candidate string, now time.Time) bool {
	candSample, ok := b.stats[candidate]
	if !ok || now.Sub(candSample.at) > statsStale {
		return false
	}
	curSample, ok := b.stats[cur]
	if !ok || now.Sub(curSample.at) > statsStale {
		return true // о текущем ничего не знаем, о кандидате знаем
	}
	curScore, candScore := curSample.stats.Score(), candSample.stats.Score()
	return float64(candScore) < float64(curScore)*betterBy && curScore-candScore >= minGain
}

// Snapshot — текущие метрики и выборы (для admin-API и диагностики).
func (b *balancer) Snapshot() ([]NodeMetric, map[string]string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()

	out := make([]NodeMetric, 0, len(b.stats))
	for node, s := range b.stats {
		out = append(out, NodeMetric{
			Node:   node,
			SRTT:   s.stats.SRTT.Round(time.Millisecond).String(),
			RTTVar: s.stats.RTTVar.Round(time.Millisecond).String(),
			Loss:   s.stats.Loss,
			Score:  s.stats.Score().Round(time.Millisecond).String(),
			Fresh:  now.Sub(s.at) <= statsStale,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })

	chosen := map[string]string{}
	for tag, d := range b.choice {
		chosen[tag] = d.node
	}
	return out, chosen
}

// NodeMetric — метрика соседа для панели.
type NodeMetric struct {
	Node   string  `json:"node"`
	SRTT   string  `json:"srtt"`
	RTTVar string  `json:"rtt_var"`
	Loss   float64 `json:"loss"`
	Score  string  `json:"score"`
	Fresh  bool    `json:"fresh"`
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
