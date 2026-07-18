package server

import (
	"context"
	"io"
	"log"
	"net/netip"
	"sync"

	"quicdiver/internal/server/db"
	"quicdiver/internal/server/netstack"
)

// ChainDialer поднимает выход-цепочку к upstream-узлу. Возвращает Dialer и
// Closer (закрыть при удалении выхода). Приходит извне (main), потому что cip
// импортирует server — прямой импорт дал бы цикл.
type ChainDialer func(ctx context.Context, addr, authority, token string) (netstack.Dialer, io.Closer, error)

// Outbounds — живой набор выходов узла: строится из БД, пересобирается по команде
// admin. Реализует netstack.Router (выбор по src) и отдаёт выбор по метке (для
// CONNECT). Первый выход всегда встроенный direct.
type Outbounds struct {
	pool      netip.Prefix
	direct    netstack.Dialer
	chainDial ChainDialer

	mu     sync.RWMutex
	list   []Outbound              // direct + chains, с подсетями
	closes map[string]io.Closer    // label → закрытие chain-клиента
	byAddr map[string]cachedClient // addr|auth|token → переиспользуемый клиент
}

type cachedClient struct {
	dialer netstack.Dialer
	closer io.Closer
}

// NewOutbounds создаёт набор с одним выходом direct (chains добавит Reload).
func NewOutbounds(pool netip.Prefix, direct netstack.Dialer, chainDial ChainDialer) *Outbounds {
	o := &Outbounds{
		pool: pool, direct: direct, chainDial: chainDial,
		closes: map[string]io.Closer{},
		byAddr: map[string]cachedClient{},
	}
	o.rebuild(nil) // только direct
	return o
}

// Reload перечитывает выходы из БД: поднимает новые chain-клиенты, закрывает
// исчезнувшие, пересобирает подсети и роутер. Атомарно под mu.
func (o *Outbounds) Reload(ctx context.Context, store db.Store) error {
	rows, err := store.ListOutbounds(ctx)
	if err != nil {
		return err
	}
	// chains из БД (direct добавим в rebuild как первый выход)
	var chains []db.OutboundRow
	for _, r := range rows {
		if r.Type == db.OutChain {
			chains = append(chains, r)
		}
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	live := map[string]cachedClient{} // ключи, которые остаются
	built := make([]resolvedChain, 0, len(chains))
	for _, c := range chains {
		key := c.Addr + "|" + c.Authority + "|" + c.Token
		cc, ok := o.byAddr[key]
		if !ok {
			d, closer, err := o.chainDial(ctx, c.Addr, c.Authority, c.Token)
			if err != nil {
				log.Printf("outbound %q: не поднять цепочку до %s: %v", c.Label, c.Addr, err)
				continue // пропустить сломанный выход, не валить остальные
			}
			cc = cachedClient{dialer: d, closer: closer}
			log.Printf("outbound %q: цепочка до %s поднята", c.Label, c.Addr)
		}
		live[key] = cc
		built = append(built, resolvedChain{label: c.Label, dialer: cc.dialer})
	}

	// закрыть клиентов, которых больше нет
	for key, cc := range o.byAddr {
		if _, keep := live[key]; !keep && cc.closer != nil {
			_ = cc.closer.Close()
		}
	}
	o.byAddr = live
	o.rebuild(built)
	return nil
}

type resolvedChain struct {
	label  string
	dialer netstack.Dialer
}

// rebuild пересобирает list с подсетями. Вызывать под mu (кроме конструктора).
// Первый выход — direct, дальше chains. Пул делится на степень двойки ≥ N.
func (o *Outbounds) rebuild(chains []resolvedChain) {
	n := 1 + len(chains)
	subs := SplitPool(o.pool, n)
	if subs == nil {
		log.Printf("outbounds: пул %s мал для %d выходов — оставляю только direct", o.pool, n)
		subs = []netip.Prefix{o.pool}
		chains = nil
	}
	list := make([]Outbound, 0, n)
	list = append(list, Outbound{Label: "direct", Subnet: subs[0], Dialer: o.direct})
	for i, c := range chains {
		list = append(list, Outbound{Label: c.label, Subnet: subs[i+1], Dialer: c.dialer})
	}
	o.list = list
}

// For выбирает выход по src-адресу (netstack.Router).
func (o *Outbounds) For(src netip.Addr) netstack.Dialer {
	o.mu.RLock()
	defer o.mu.RUnlock()
	for i := range o.list {
		if o.list[i].Subnet.Contains(src) {
			return o.list[i].Dialer
		}
	}
	return o.direct
}

// DialerForLabel выбирает выход по метке Qd-Route (для CONNECT). Пусто/неизвестно
// → direct.
func (o *Outbounds) DialerForLabel(label string) netstack.Dialer {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if label != "" {
		for i := range o.list {
			if o.list[i].Label == label {
				return o.list[i].Dialer
			}
		}
	}
	return o.direct
}

// BaseSubnet — подсеть выхода direct: в ней аллокатор выдаёт хост-номера.
func (o *Outbounds) BaseSubnet() netip.Prefix {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.list[0].Subnet
}

// AddrsForHost — адреса клиента по одному в каждой подсети выхода (общий
// хост-номер).
func (o *Outbounds) AddrsForHost(host uint32) []netip.Prefix {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return addrsForHost(o.list, host)
}

// Labels — метки выходов (для admin-GET).
func (o *Outbounds) Labels() []string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]string, 0, len(o.list))
	for i := range o.list {
		out = append(out, o.list[i].Label)
	}
	return out
}

// Close закрывает все chain-клиенты.
func (o *Outbounds) Close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, cc := range o.byAddr {
		if cc.closer != nil {
			_ = cc.closer.Close()
		}
	}
	o.byAddr = map[string]cachedClient{}
}

var _ netstack.Router = (*Outbounds)(nil)
