package decoy

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Site — публичная витрина узла на TCP:443.
//
// Зачем она нужна помимо decoy на H3. Узел, слушающий только UDP:443, — маркер:
// домен резолвится, HTTPS по TCP не отвечает, а QUIC на том же порту работает.
// Настоящие сайты так себя не ведут: HTTP/3 всегда идёт В ДОПОЛНЕНИЕ к TCP и
// анонсируется заголовком Alt-Svc. Без TCP-витрины «сайт под конструкцией»
// нельзя открыть браузером — при активном пробинге это выглядит абсурдно и
// обесценивает всю невидимость авторизации.
//
// Здесь же — защита витрины: лимит запросов с адреса (флуд не должен занимать
// ресурсы узла) и запрет индексации (домен, который раздаётся клиентам, не
// должен всплыть в поисковой выдаче — это палево само по себе).
type Site struct {
	altSvc string
	lim    *limiter
	page   http.Handler
}

// Значения по умолчанию: пара обновлений страницы живому человеку не мешает,
// а перебор быстро упирается в лимит.
const (
	defaultBurst  = 20               // запросов с адреса за окно
	defaultWindow = time.Minute      // окно учёта
	defaultBan    = 60 * time.Second // сколько «курить» после перебора
)

// NewSite строит витрину. altSvcPort — порт, на котором узел слушает QUIC:
// он уходит в Alt-Svc, делая HTTP/3 на этом порту естественным продолжением
// обычного сайта.
func NewSite(altSvcPort int) *Site {
	return &Site{
		altSvc: `h3=":` + strconv.Itoa(altSvcPort) + `"; ma=86400`,
		lim:    newLimiter(defaultBurst, defaultWindow, defaultBan),
		page:   Handler(),
	}
}

func (s *Site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	// Alt-Svc — легитимный способ сказать «у меня есть HTTP/3 на этом порту».
	h.Set("Alt-Svc", s.altSvc)
	// Ни поисковикам, ни архиваторам здесь делать нечего.
	h.Set("X-Robots-Tag", "noindex, nofollow, noarchive")

	if r.URL.Path == "/robots.txt" {
		h.Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
		return
	}

	if retry, ok := s.lim.allow(clientIP(r), time.Now()); !ok {
		h.Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}
	s.page.ServeHTTP(w, r)
}

// clientIP берёт адрес соединения. Заголовкам X-Forwarded-For здесь верить
// нельзя: узел стоит без обратного прокси, значит такой заголовок — подделка
// клиента, которой легко обойти лимит.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limiter — счётчик запросов с адреса в скользящем окне.
type limiter struct {
	burst  int
	window time.Duration
	ban    time.Duration

	mu      sync.Mutex
	seen    map[string]*counter
	lastGC  time.Time
	maxKeys int
}

type counter struct {
	n       int
	resetAt time.Time
	banTill time.Time
}

func newLimiter(burst int, window, ban time.Duration) *limiter {
	return &limiter{
		burst: burst, window: window, ban: ban,
		seen: make(map[string]*counter),
		// Потолок на размер таблицы: флуд с миллиона адресов не должен
		// съесть память узла — при переполнении таблица сбрасывается.
		maxKeys: 100_000,
	}
}

// allow говорит, пускать ли запрос; при отказе возвращает, через сколько можно.
func (l *limiter) allow(ip string, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.gcLocked(now)

	c := l.seen[ip]
	if c == nil {
		c = &counter{resetAt: now.Add(l.window)}
		l.seen[ip] = c
	}
	if now.Before(c.banTill) {
		return c.banTill.Sub(now), false
	}
	// Бан отсижен — учёт начинаем заново. Без сброса счётчик остался бы выше
	// лимита, и первый же следующий запрос загонял бы адрес в бан снова: клиент,
	// который продолжает стучаться, не разблокировался бы никогда.
	if !c.banTill.IsZero() {
		c.banTill = time.Time{}
		c.n, c.resetAt = 0, now.Add(l.window)
	}
	if now.After(c.resetAt) {
		c.n, c.resetAt = 0, now.Add(l.window)
	}
	c.n++
	if c.n > l.burst {
		c.banTill = now.Add(l.ban)
		return l.ban, false
	}
	return 0, true
}

// gcLocked изредка выметает протухшие записи. Вызывать под mu.
func (l *limiter) gcLocked(now time.Time) {
	if len(l.seen) >= l.maxKeys {
		l.seen = make(map[string]*counter)
		l.lastGC = now
		return
	}
	if now.Sub(l.lastGC) < l.window {
		return
	}
	for ip, c := range l.seen {
		if now.After(c.resetAt) && now.After(c.banTill) {
			delete(l.seen, ip)
		}
	}
	l.lastGC = now
}
