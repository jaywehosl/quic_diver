// Package nat46 даёт клиенту без IPv6 доступ к IPv6-only ресурсам.
//
// Задача: у клиента нет ни v6-адреса, ни маршрута (типичный случай: провайдер
// раздаёт только v4). ОС не сгенерирует пакет к адресу, который ей нечем
// адресовать, поэтому браузер AAAA-запись просто игнорирует и хост выглядит
// «несуществующим» — так, например, недоступен ntc.party (только AAAA).
//
// Решение: резолвер, увидев «A → пусто, AAAA → есть», отдаёт приложению
// фиктивный IPv4 из непубличного пула и запоминает fake→real. Приложение идёт по
// IPv4 (он у него есть), клиент перехватывает пакет, а перед дозвоном подменяет
// адрес обратно на настоящий IPv6 — узел выходит наружу по v6 сам.
//
// Почему не «выдать клиенту v6-адрес и маршрут»: пришлось бы править сетевой стек
// ОС и полагаться на политики выбора адреса (RFC 6724), а наружу узел всё равно
// выходит своим адресом — клиентский v6 в любом случае остаётся фикцией. Здесь же
// ОС не трогаем вовсе, и работает одинаково на всех платформах.
//
// Ограничение: спасает только резолв по имени. Набранный руками v6-литерал не
// поедет — но с ним и так некуда, v6-связности у клиента нет.
package nat46

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// DefaultPool — фиктивные адреса. 198.18.0.0/15 (RFC 2544) отведён под
// стендовые измерения и в интернете не маршрутизируется, поэтому перехват этого
// диапазона ничего живого не ломает. 131072 адреса — с запасом.
var DefaultPool = netip.MustParsePrefix("198.18.0.0/15")

// DefaultTTL — сколько держать выданный маппинг. Меньше — быстрее переиспользуем
// адреса, но рискуем оборвать соединение, открытое по старому fake.
const DefaultTTL = time.Hour

type entry struct {
	real    netip.Addr
	expires time.Time
}

// Table раздаёт фиктивные v4 и помнит, какому v6 каждый соответствует.
type Table struct {
	mu     sync.RWMutex
	pool   netip.Prefix
	ttl    time.Duration
	lo, hi uint32 // границы пула включительно
	next   uint32
	byFake map[netip.Addr]entry
	byReal map[netip.Addr]netip.Addr
}

// NewTable создаёт таблицу. pool должен быть IPv4-префиксом.
func NewTable(pool netip.Prefix, ttl time.Duration) *Table {
	if !pool.Addr().Is4() {
		panic("nat46: пул должен быть IPv4")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	lo := u32(pool.Masked().Addr())
	hi := lo | (^uint32(0) >> uint(pool.Bits()))
	return &Table{
		pool: pool, ttl: ttl,
		lo: lo, hi: hi, next: lo,
		byFake: make(map[netip.Addr]entry),
		byReal: make(map[netip.Addr]netip.Addr),
	}
}

// Pool — обслуживаемый диапазон (нужен для правил перехвата: пул не должен
// попасть в bypass, иначе пакеты уйдут в реальную сеть).
func (t *Table) Pool() netip.Prefix { return t.pool }

// Map возвращает фиктивный v4 для v6-адреса, выдавая новый при необходимости.
// Для одного и того же v6 отдаёт тот же fake, пока тот не протух.
func (t *Table) Map(v6 netip.Addr) (netip.Addr, bool) {
	if !v6.Is6() || v6.Is4In6() {
		return netip.Addr{}, false
	}
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	if fake, ok := t.byReal[v6]; ok {
		if e, ok := t.byFake[fake]; ok && now.Before(e.expires) {
			e.expires = now.Add(t.ttl) // продлить: адрес всё ещё в ходу
			t.byFake[fake] = e
			return fake, true
		}
	}
	fake, ok := t.alloc(now)
	if !ok {
		return netip.Addr{}, false
	}
	t.byFake[fake] = entry{real: v6, expires: now.Add(t.ttl)}
	t.byReal[v6] = fake
	return fake, true
}

// Lookup возвращает настоящий v6 по фиктивному v4.
func (t *Table) Lookup(fake netip.Addr) (netip.Addr, bool) {
	t.mu.RLock()
	e, ok := t.byFake[fake]
	t.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return netip.Addr{}, false
	}
	return e.real, true
}

// Len — сколько маппингов живо.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byFake)
}

// alloc выдаёт следующий свободный адрес, по кругу. Занятый, но протухший
// переиспользуется — иначе пул бы кончился на долгой сессии.
// Вызывать под t.mu.
func (t *Table) alloc(now time.Time) (netip.Addr, bool) {
	size := uint64(t.hi) - uint64(t.lo) + 1
	for i := uint64(0); i < size; i++ {
		cand := addr4(t.next)
		t.next++
		if t.next > t.hi {
			t.next = t.lo
		}
		e, taken := t.byFake[cand]
		if !taken {
			return cand, true
		}
		if now.After(e.expires) {
			delete(t.byFake, cand)
			delete(t.byReal, e.real)
			return cand, true
		}
	}
	return netip.Addr{}, false // пул исчерпан живыми маппингами
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
