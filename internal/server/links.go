package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"quicdiver/internal/server/db"
	"quicdiver/internal/server/netstack"
)

// NodeDialer поднимает соединение к соседнему узлу.
//
// Живёт в main (там доступен транспорт cip), сюда приходит функцией, чтобы
// server не тянул за собой клиентский стек.
type NodeDialer func(ctx context.Context, node db.Node, selfToken string) (netstack.Dialer, io.Closer, error)

// NodeLinks — соединения к соседним узлам, поднимаемые по мере надобности.
//
// Заменяет прежние аутбаунды. Разница принципиальная: аутбаунд был ручной
// связью с чужим секретом в конфиге, а здесь узел берёт соседа из общей реплики
// и представляется СВОИМ токеном. Значит добавление узла в сеть сразу делает его
// доступным всем — копировать секреты между машинами не нужно.
type NodeLinks struct {
	selfID    string
	selfToken string
	dial      NodeDialer

	mu     sync.Mutex
	nodes  map[string]db.Node   // реестр, обновляется Reload
	links  map[string]*link     // поднятые соединения
	failed map[string]time.Time // когда последний раз не вышло подняться

	// balance — выбор узла под auto:<тег> по живым метрикам.
	balance *balancer
}

type link struct {
	dialer netstack.Dialer
	closer io.Closer
	// born — когда соединение поднято: по нему решаем, стоит ли пробовать заново
	// после отказа, или узел лежит и не надо долбить его на каждый флоу.
	born time.Time
}

// linkRetryAfter — как скоро пробовать соседа снова после неудачи.
//
// Без паузы каждый флоу на упавший узел стучался бы заново, и потолок стримов
// выело бы за секунды. С паузой неудача стоит одну попытку на интервал.
const linkRetryAfter = 15 * time.Second

// NewNodeLinks создаёт менеджер связей.
func NewNodeLinks(selfID, selfToken string, dial NodeDialer) *NodeLinks {
	return &NodeLinks{
		selfID: selfID, selfToken: selfToken, dial: dial,
		nodes:   map[string]db.Node{},
		links:   map[string]*link{},
		failed:  map[string]time.Time{},
		balance: newBalancer(),
	}
}

// Reload перечитывает реестр узлов.
//
// Соединения не рвём: узел мог просто сменить метку. Рвём только те, чей адрес
// изменился или кого выключили — иначе трафик продолжил бы идти по старому пути.
func (l *NodeLinks) Reload(ctx context.Context, store *db.SQLite) error {
	nodes, err := store.ListNodes(ctx)
	if err != nil {
		return err
	}
	fresh := make(map[string]db.Node, len(nodes))
	for _, n := range nodes {
		if n.ID == l.selfID {
			continue // сам себе сосед не нужен
		}
		fresh[n.ID] = n
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	for id, ln := range l.links {
		n, ok := fresh[id]
		old := l.nodes[id]
		if !ok || !n.Enabled || n.Addr != old.Addr || n.SNI != old.SNI {
			ln.close()
			delete(l.links, id)
		}
		if _, ok := fresh[id]; !ok {
			// Узел вышел из сети — метрика по нему устарела навсегда.
			l.balance.Forget(id)
		}
	}
	l.nodes = fresh
	return nil
}

// Dialer отдаёт соединение к узлу, поднимая его при первом обращении.
//
// nil означает «вести туда нечем» — вызывающий выпустит флоу наружу у себя, а не
// уронит его (см. routeFlow).
func (l *NodeLinks) Dialer(ctx context.Context, id string) netstack.Dialer {
	if id == "" || id == l.selfID {
		return nil
	}
	l.mu.Lock()
	node, known := l.nodes[id]
	ln := l.links[id]
	l.mu.Unlock()

	if !known || !node.Enabled {
		return nil
	}
	if ln != nil {
		return ln.dialer
	}
	// Недавно не вышло — не долбим упавший узел на каждом флоу: потолок стримов
	// выело бы за секунды, а толку ноль.
	l.mu.Lock()
	if last, ok := l.failed[id]; ok && time.Since(last) < linkRetryAfter {
		l.mu.Unlock()
		return nil
	}
	l.mu.Unlock()

	dialer, closer, err := l.dial(ctx, node, l.selfToken)
	if err != nil {
		// СОБЫТИЕ ДЛЯ АЛЕРТА: сосед недоступен, флоу уйдёт наружу здесь.
		log.Printf("узел %s недоступен: %v", id, linkError(node, err))
		l.mu.Lock()
		l.failed[id] = time.Now()
		l.mu.Unlock()
		return nil
	}

	l.mu.Lock()
	// Пока поднимали, связь мог открыть и кто-то ещё — лишнюю гасим.
	if cur, ok := l.links[id]; ok {
		l.mu.Unlock()
		_ = closer.Close()
		return cur.dialer
	}
	l.links[id] = &link{dialer: dialer, closer: closer, born: time.Now()}
	delete(l.failed, id)
	l.mu.Unlock()

	log.Printf("связь с узлом %s поднята", id)
	return dialer
}

// Nodes — снимок реестра (для выбора по категории).
func (l *NodeLinks) Nodes() []db.Node {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]db.Node, 0, len(l.nodes))
	for _, n := range l.nodes {
		out = append(out, n)
	}
	return out
}

// Close гасит все связи.
func (l *NodeLinks) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, ln := range l.links {
		ln.close()
		delete(l.links, id)
	}
}

func (ln *link) close() {
	if ln.closer != nil {
		_ = ln.closer.Close()
	}
}

// pickByCategory выбирает узел категории для метки auto:<тег>.
//
// Кандидатов отбирает реестр, лучшего из них — балансировщик по живым метрикам
// (RTT, разброс, потери) с гистерезисом. Пусто означает «подходящих нет»: флоу
// выйдет на текущем узле, а не умрёт.
func (l *NodeLinks) pickByCategory(tag string) string {
	l.mu.Lock()
	candidates := make([]string, 0, len(l.nodes))
	for _, n := range l.nodes {
		if !n.Enabled {
			continue
		}
		// Тег совпал или это прямо категория (entry/exit).
		if n.HasTag(tag) || n.Category == tag {
			candidates = append(candidates, n.ID)
		}
	}
	l.mu.Unlock()

	return l.balance.Pick(tag, candidates)
}

// PathStatsSource — соединение, которое может рассказать о качестве пути.
//
// QUIC меряет RTT сам, поэтому связь с соседом — уже готовый измеритель: метрика
// снимается с ТОГО ЖЕ пути, по которому пойдёт трафик. Синтетический пинг такого
// не даёт, да и лишний механизм заводить незачем.
type PathStatsSource interface {
	Stats() (srtt, rttVar time.Duration, loss float64, ok bool)
}

// pollStats — как часто опрашивать связи.
//
// Совпадает с окном удержания в балансировщике: holdWindows замеров подряд и
// составляют «устойчивое преимущество».
const pollStats = 10 * time.Second

// PollStats снимает метрики с поднятых связей до отмены ctx.
//
// Только с поднятых: соединение к узлу, которым никто не пользуется, держать
// ради замеров незачем — а когда им воспользуются, метрика появится сама.
func (l *NodeLinks) PollStats(ctx context.Context) {
	t := time.NewTicker(pollStats)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.sampleOnce()
		}
	}
}

func (l *NodeLinks) sampleOnce() {
	l.mu.Lock()
	links := make(map[string]*link, len(l.links))
	for id, ln := range l.links {
		links[id] = ln
	}
	l.mu.Unlock()

	for id, ln := range links {
		src, ok := ln.closer.(PathStatsSource)
		if !ok {
			continue
		}
		srtt, rttVar, loss, ok := src.Stats()
		if !ok {
			continue // соединение только поднялось, образцов RTT ещё нет
		}
		l.balance.Observe(id, PathStats{SRTT: srtt, RTTVar: rttVar, Loss: loss})
	}
}

// Metrics — метрики соседей и текущие выборы (для admin-API).
func (l *NodeLinks) Metrics() ([]NodeMetric, map[string]string) {
	return l.balance.Snapshot()
}

// linkError — понятная ошибка подъёма связи.
func linkError(node db.Node, err error) error {
	return fmt.Errorf("узел %s (%s): %w", node.ID, node.Addr, err)
}
