package routing

import (
	"net/netip"
	"sync"
	"time"
)

// Conntrack кеширует решение классификатора по флоу (5-tuple), чтобы горячий путь
// пакета не гонял правила заново на каждый пакет — только на первый пакет флоу.
//
// Ключ — src-порт + dst-адрес+порт (proto опускаем: клиент и так знает транспорт
// из пути). Запись живёт TTL после последнего касания; протухшие вычищаются
// лениво при обращении и периодически (Sweep).
type Conntrack struct {
	ttl time.Duration
	mu  sync.Mutex
	m   map[flowKey]ctEntry
}

type flowKey struct {
	srcPort uint16
	dst     netip.AddrPort
}

type ctEntry struct {
	out  string
	seen time.Time
}

// NewConntrack создаёт кеш с временем жизни записи ttl.
func NewConntrack(ttl time.Duration) *Conntrack {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Conntrack{ttl: ttl, m: map[flowKey]ctEntry{}}
}

// Decide возвращает метку выхода для флоу: из кеша, иначе классифицирует и
// запоминает. classify вызывается лишь на первый пакет флоу.
func (c *Conntrack) Decide(srcPort uint16, f Flow, classify func(Flow) string) string {
	k := flowKey{srcPort: srcPort, dst: f.Dst}
	now := time.Now()

	c.mu.Lock()
	if e, ok := c.m[k]; ok && now.Sub(e.seen) < c.ttl {
		e.seen = now
		c.m[k] = e
		c.mu.Unlock()
		return e.out
	}
	c.mu.Unlock()

	out := classify(f)

	c.mu.Lock()
	c.m[k] = ctEntry{out: out, seen: now}
	c.mu.Unlock()
	return out
}

// Sweep вычищает протухшие записи. Возвращает число удалённых.
func (c *Conntrack) Sweep() int {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	var n int
	for k, e := range c.m {
		if now.Sub(e.seen) >= c.ttl {
			delete(c.m, k)
			n++
		}
	}
	return n
}

// Len — сколько флоу в кеше (для диагностики/утечек).
func (c *Conntrack) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
