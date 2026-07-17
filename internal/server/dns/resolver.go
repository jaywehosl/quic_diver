package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// canaryDomain — по нему браузеры проверяют, можно ли включать свой DoH.
// Отвечаем NXDOMAIN: иначе Firefox уведёт резолв в собственный DoH мимо узла —
// провайдер его не увидит, но и наш кеш с политиками работать перестанут.
// (Chrome в режиме automatic отпадает сам: системный DNS клиента указывает на
// нас, а нас нет в списке известных DoH-провайдеров.)
const canaryDomain = "use-application-dns.net."

// Config — настройки резолвера узла.
type Config struct {
	Upstream    Upstream
	CacheSize   int           // записей; 0 — без кеша
	TTLOverride time.Duration // >0 — игнорировать TTL ответа
	MinTTL      time.Duration // не кешировать короче
	MaxTTL      time.Duration // не кешировать дольше
	Timeout     time.Duration // на один запрос к upstream
}

// Resolver — DNS-резолвер узла с кешем.
type Resolver struct {
	cfg   Config
	cache *Cache
}

// New создаёт резолвер.
func New(cfg Config) *Resolver {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = time.Hour
	}
	return &Resolver{cfg: cfg, cache: NewCache(cfg.CacheSize)}
}

// Cache — доступ к кешу (статистика и очистка из админки).
func (r *Resolver) Cache() *Cache { return r.cache }

// RunGC периодически делает мягкую очистку и блокируется до отмены ctx.
//
// Без неё протухшие записи занимают место до вытеснения по LRU: на редко
// спрашиваемых именах кеш держится полным из мусора, а живые записи вылетают
// раньше времени. Грубая очистка (FlushAll) остаётся ручной — она для админки.
func (r *Resolver) RunGC(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.cache.FlushExpired()
		}
	}
}

// Query резолвит DNS-сообщение в проводном формате.
func (r *Resolver) Query(ctx context.Context, query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, fmt.Errorf("разбор запроса: %w", err)
	}
	q, err := p.Question()
	if err != nil {
		return nil, fmt.Errorf("вопрос запроса: %w", err)
	}

	if strings.EqualFold(q.Name.String(), canaryDomain) {
		return nxdomain(hdr.ID, q)
	}

	key := cacheKey(q)
	if resp, ok := r.cache.Get(key); ok {
		return withID(resp, hdr.ID)
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()
	resp, err := r.cfg.Upstream.Exchange(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %w", r.cfg.Upstream, err)
	}
	if ttl := r.ttlOf(resp); ttl > 0 {
		r.cache.Put(key, resp, ttl)
	}
	return resp, nil
}

func cacheKey(q dnsmessage.Question) string {
	return strings.ToLower(q.Name.String()) + "|" + q.Type.String() + "|" + q.Class.String()
}

// ttlOf берёт минимальный TTL из ответа и приводит к настройкам узла.
func (r *Resolver) ttlOf(resp []byte) time.Duration {
	if r.cfg.TTLOverride > 0 {
		return r.cfg.TTLOverride
	}
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return 0
	}
	if err := p.SkipAllQuestions(); err != nil {
		return 0
	}
	min := ^uint32(0)
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if h.TTL < min {
			min = h.TTL
		}
		if err := p.SkipAnswer(); err != nil {
			break
		}
	}
	if min == ^uint32(0) {
		return 0 // ответов нет — не кешируем
	}
	ttl := time.Duration(min) * time.Second
	if ttl < r.cfg.MinTTL {
		ttl = r.cfg.MinTTL
	}
	if ttl > r.cfg.MaxTTL {
		ttl = r.cfg.MaxTTL
	}
	return ttl
}

// withID подставляет идентификатор запроса в кешированный ответ: у каждого
// запроса он свой, а тело ответа общее.
func withID(resp []byte, id uint16) ([]byte, error) {
	if len(resp) < 2 {
		return nil, fmt.Errorf("короткий ответ")
	}
	out := make([]byte, len(resp))
	copy(out, resp)
	out[0], out[1] = byte(id>>8), byte(id)
	return out, nil
}

func nxdomain(id uint16, q dnsmessage.Question) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: id, Response: true, RCode: dnsmessage.RCodeNameError,
		RecursionDesired: true, RecursionAvailable: true,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	return b.Finish()
}
