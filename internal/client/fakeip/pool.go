// Package fakeip даёт клиенту точное имя домена по адресу назначения — основа
// доменного роутинга.
//
// Проблема: узел и приложения видят IP, а правила заданы по доменам. Обратный
// map «IP→домен» ненадёжен: за одним CDN-адресом сотни доменов. Решение (как в
// sing-box/Clash): резолвер отдаёт приложению уникальный фиктивный адрес на
// каждый домен и помнит fake→(домен, реальные адреса). Флоу приходит на fake —
// домен известен ТОЧНО, классификатор метит выход, а перед дозвоном fake
// подменяется реальным адресом.
//
// Это обобщение nat46: тот выдавал fake только v6-only хостам (нет A). Здесь fake
// для ЛЮБОГО домена, ради знания имени. Пул тот же — 198.18.0.0/15 (RFC 2544, не
// маршрутизируется), перехват этого диапазона ничего живого не ломает.
package fakeip

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// DefaultPool — фиктивные адреса (RFC 2544, стендовый диапазон, в интернете не
// маршрутизируется).
var DefaultPool = netip.MustParsePrefix("198.18.0.0/15")

// DefaultTTL — сколько держать маппинг домена. Меньше — быстрее переиспользуем
// адреса, но рискуем оборвать соединение, открытое по старому fake.
const DefaultTTL = time.Hour

type entry struct {
	domain  string
	real    []netip.Addr
	expires time.Time
}

// Pool раздаёт фиктивные v4 по доменам и помнит соответствие в обе стороны.
type Pool struct {
	mu       sync.RWMutex
	pool     netip.Prefix
	ttl      time.Duration
	lo, hi   uint32
	next     uint32
	byFake   map[netip.Addr]entry
	byDomain map[string]netip.Addr
}

// New создаёт пул. prefix обязан быть IPv4.
func New(prefix netip.Prefix, ttl time.Duration) *Pool {
	if !prefix.Addr().Is4() {
		panic("fakeip: пул должен быть IPv4")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	lo := u32(prefix.Masked().Addr())
	hi := lo | (^uint32(0) >> uint(prefix.Bits()))
	return &Pool{
		pool: prefix, ttl: ttl,
		lo: lo, hi: hi, next: lo,
		byFake:   make(map[netip.Addr]entry),
		byDomain: make(map[string]netip.Addr),
	}
}

// Prefix — обслуживаемый диапазон (перехват не должен пускать его в bypass).
func (p *Pool) Prefix() netip.Prefix { return p.pool }

// Assign выдаёт фиктивный v4 для домена, запоминая реальные адреса. Тот же домен
// получает тот же fake, пока не протухнет; real обновляются (DNS мог смениться).
func (p *Pool) Assign(domain string, real []netip.Addr) (netip.Addr, bool) {
	domain = normDomain(domain)
	if domain == "" {
		return netip.Addr{}, false
	}
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	if fake, ok := p.byDomain[domain]; ok {
		if e, ok := p.byFake[fake]; ok {
			e.real, e.expires = real, now.Add(p.ttl)
			p.byFake[fake] = e
			return fake, true
		}
	}
	fake, ok := p.alloc(now)
	if !ok {
		return netip.Addr{}, false
	}
	p.byFake[fake] = entry{domain: domain, real: real, expires: now.Add(p.ttl)}
	p.byDomain[domain] = fake
	return fake, true
}

// Domain возвращает домен по фиктивному адресу (для классификации).
func (p *Pool) Domain(fake netip.Addr) (string, bool) {
	p.mu.RLock()
	e, ok := p.byFake[fake]
	p.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return "", false
	}
	return e.domain, true
}

// Real возвращает реальные адреса по фиктивному (для подмены перед дозвоном).
func (p *Pool) Real(fake netip.Addr) ([]netip.Addr, bool) {
	p.mu.RLock()
	e, ok := p.byFake[fake]
	p.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.real, true
}

// Contains — принадлежит ли адрес пулу fake.
func (p *Pool) Contains(a netip.Addr) bool { return p.pool.Contains(a) }

// DomainOf — домен по адресу (пусто, если не fake или протух). Для классификатора.
func (p *Pool) DomainOf(a netip.Addr) string {
	d, _ := p.Domain(a)
	return d
}

// RealAddr — первый реальный адрес по fake (для подмены перед дозвоном). !ok,
// если адрес не из пула или маппинг протух.
func (p *Pool) RealAddr(fake netip.Addr) (netip.Addr, bool) {
	real, ok := p.Real(fake)
	if !ok || len(real) == 0 {
		return netip.Addr{}, false
	}
	return real[0], true
}

// Len — сколько доменов в пуле (диагностика).
func (p *Pool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.byFake)
}

// alloc выдаёт следующий свободный адрес по кругу; протухший переиспользуется.
// Вызывать под mu.
func (p *Pool) alloc(now time.Time) (netip.Addr, bool) {
	size := uint64(p.hi) - uint64(p.lo) + 1
	for i := uint64(0); i < size; i++ {
		cand := addr4(p.next)
		p.next++
		if p.next > p.hi {
			p.next = p.lo
		}
		e, taken := p.byFake[cand]
		if !taken {
			return cand, true
		}
		if now.After(e.expires) {
			delete(p.byFake, cand)
			delete(p.byDomain, e.domain)
			return cand, true
		}
	}
	return netip.Addr{}, false
}

func normDomain(d string) string {
	if len(d) > 0 && d[len(d)-1] == '.' {
		d = d[:len(d)-1]
	}
	return d
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func addr4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
