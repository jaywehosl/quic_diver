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

// Значения по умолчанию. Считать надо в ЗАПРОСАХ, а не в «обновлениях
// страницы»: браузер на одно F5 тянет ещё favicon, а после Alt-Svc держит
// параллельно TCP и HTTP/3 — при лимите 20 живой человек упирался в него
// с пятого обновления. 60/мин даёт запас обычному посетителю и всё равно
// быстро осаживает перебор.
const (
	defaultBurst  = 60               // запросов с адреса за окно
	defaultWindow = time.Minute      // окно учёта
	defaultBan    = 60 * time.Second // сколько «курить» после перебора
)

// favicon — прозрачный PNG 1×1. Браузер просит /favicon.ico на каждой странице;
// без ответа он долбит его снова и снова, съедая лимит живому посетителю.
// Отдаём с длинным кэшем, чтобы спросил один раз.
var favicon = []byte{
	0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R',
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
	0x89, 0x00, 0x00, 0x00, 0x0a, 'I', 'D', 'A', 'T', 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 'I', 'E', 'N', 'D',
	0xae, 0x42, 0x60, 0x82,
}

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

	// Фавикон и robots — до лимита: это служебные запросы браузера и краулеров,
	// они не должны съедать квоту живого посетителя.
	switch r.URL.Path {
	case "/robots.txt":
		h.Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
		return
	case "/favicon.ico":
		h.Set("Content-Type", "image/png")
		h.Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(favicon)
		return
	}

	if retry, ok := s.lim.allow(clientIP(r), time.Now()); !ok {
		h.Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
		writePage(w, http.StatusTooManyRequests, "Too many requests",
			"You are sending requests too quickly. Please wait a moment and try again.")
		return
	}

	// Настоящий сайт не отдаёт главную на произвольный URL — он отвечает 404.
	// Отдавая одну и ту же страницу на любой путь, узел выдавал бы заглушку.
	if r.URL.Path != "/" {
		writePage(w, http.StatusNotFound, "Not found",
			"The page you requested does not exist.")
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
