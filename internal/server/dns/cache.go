// Package dns — резолвер узла: кеш + upstream (plain/DoT/DoH).
//
// Резолв обязан происходить ЗДЕСЬ, а не у провайдера клиента: иначе провайдер
// отдаёт адрес своей заглушки, и туннель добросовестно везёт клиента на подставной
// хост (проверено: instagram.com → 188.186.154.88 = *.ertelecom.ru, при том что
// настоящий адрес 31.13.72.174).
//
// Кеш живёт на узле, а не на клиенте: так он переживает смену сети у клиента
// (Wi-Fi↔LTE, пересборка PPPoE) и настраивается централизованно из админки.
package dns

import (
	"container/list"
	"sync"
	"time"
)

// Cache — LRU-кеш DNS-ответов с ограничением по числу записей.
type Cache struct {
	mu           sync.Mutex
	max          int
	ll           *list.List               // порядок использования: front — свежие
	m            map[string]*list.Element // ключ → элемент списка
	hits, misses uint64
}

type entry struct {
	key     string
	resp    []byte
	expires time.Time
}

// NewCache создаёт кеш на max записей (0 → без кеша).
func NewCache(max int) *Cache {
	return &Cache{max: max, ll: list.New(), m: make(map[string]*list.Element)}
}

// Get возвращает ответ, если он есть и не протух.
func (c *Cache) Get(key string) ([]byte, bool) {
	if c == nil || c.max == 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.m[key]
	if !ok {
		c.misses++
		return nil, false
	}
	e := el.Value.(*entry)
	if time.Now().After(e.expires) {
		c.removeLocked(el)
		c.misses++
		return nil, false
	}
	c.ll.MoveToFront(el)
	c.hits++
	resp := make([]byte, len(e.resp))
	copy(resp, e.resp)
	return resp, true
}

// Put кладёт ответ с временем жизни ttl, вытесняя самый давний при переполнении.
func (c *Cache) Put(key string, resp []byte, ttl time.Duration) {
	if c == nil || c.max == 0 || ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	stored := make([]byte, len(resp))
	copy(stored, resp)
	if el, ok := c.m[key]; ok {
		e := el.Value.(*entry)
		e.resp, e.expires = stored, time.Now().Add(ttl)
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&entry{key: key, resp: stored, expires: time.Now().Add(ttl)})
	c.m[key] = el
	for c.ll.Len() > c.max {
		c.removeLocked(c.ll.Back())
	}
}

// FlushExpired — мягкая очистка: выбрасывает только протухшее.
func (c *Cache) FlushExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	var n int
	for el := c.ll.Back(); el != nil; {
		prev := el.Prev()
		if now.After(el.Value.(*entry).expires) {
			c.removeLocked(el)
			n++
		}
		el = prev
	}
	return n
}

// FlushAll — грубая очистка: выбрасывает всё.
func (c *Cache) FlushAll() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.ll.Len()
	c.ll.Init()
	c.m = make(map[string]*list.Element)
	return n
}

// Stats — размер и попадания (для статистики узла в админке).
func (c *Cache) Stats() (size int, hits, misses uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len(), c.hits, c.misses
}

func (c *Cache) removeLocked(el *list.Element) {
	c.ll.Remove(el)
	delete(c.m, el.Value.(*entry).key)
}
