package decoy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func req(path, ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = ip + ":54321"
	return r
}

// Alt-Svc обязателен: без него QUIC на том же порту не выглядит продолжением
// обычного сайта — а это и есть маркер, ради которого витрина поднималась.
func TestAltSvcAnnouncesH3(t *testing.T) {
	w := httptest.NewRecorder()
	NewSite(443).ServeHTTP(w, req("/", "1.2.3.4"))

	got := w.Header().Get("Alt-Svc")
	if !strings.Contains(got, `h3=":443"`) {
		t.Fatalf("Alt-Svc = %q, ожидался анонс h3 на :443", got)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d, ожидался 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Under construction") {
		t.Fatal("витрина не отдала decoy-страницу")
	}
}

// Индексация запрещена: домен раздаётся клиентам и не должен всплыть в выдаче.
func TestNoIndexHeaderAndRobots(t *testing.T) {
	w := httptest.NewRecorder()
	NewSite(443).ServeHTTP(w, req("/", "1.2.3.4"))
	if tag := w.Header().Get("X-Robots-Tag"); !strings.Contains(tag, "noindex") {
		t.Fatalf("X-Robots-Tag = %q, ожидался noindex", tag)
	}

	w = httptest.NewRecorder()
	NewSite(443).ServeHTTP(w, req("/robots.txt", "1.2.3.4"))
	body := w.Body.String()
	if !strings.Contains(body, "User-agent: *") || !strings.Contains(body, "Disallow: /") {
		t.Fatalf("robots.txt = %q, ожидался полный запрет", body)
	}
}

// Перебор упирается в лимит и получает 429 с Retry-After.
func TestRateLimitBansFlood(t *testing.T) {
	s := NewSite(443)
	const ip = "9.9.9.9"
	for i := 0; i < defaultBurst; i++ {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req("/", ip))
		if w.Code != http.StatusOK {
			t.Fatalf("запрос %d получил %d, лимит сработал раньше времени", i+1, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req("/", ip))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("после перебора статус %d, ожидался 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 без Retry-After — клиент не знает, когда возвращаться")
	}
}

// Лимит персональный: сосед по адресу не должен страдать от чужого флуда.
func TestRateLimitIsPerAddress(t *testing.T) {
	s := NewSite(443)
	for i := 0; i < defaultBurst+5; i++ {
		s.ServeHTTP(httptest.NewRecorder(), req("/", "9.9.9.9"))
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req("/", "8.8.8.8"))
	if w.Code != http.StatusOK {
		t.Fatalf("чистый адрес получил %d — лимит не персональный", w.Code)
	}
}

// Подделанный X-Forwarded-For не должен обходить лимит: узел стоит без
// обратного прокси, значит такой заголовок прислал сам клиент.
func TestForwardedHeaderDoesNotBypassLimit(t *testing.T) {
	s := NewSite(443)
	for i := 0; i < defaultBurst; i++ {
		s.ServeHTTP(httptest.NewRecorder(), req("/", "9.9.9.9"))
	}
	r := req("/", "9.9.9.9")
	r.Header.Set("X-Forwarded-For", "5.5.5.5")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("статус %d — лимит обошли подделкой X-Forwarded-For", w.Code)
	}
}

// Бан не вечен: отсидев положенное, адрес снова обслуживается.
func TestBanExpires(t *testing.T) {
	l := newLimiter(2, time.Minute, 50*time.Millisecond)
	now := time.Now()
	l.allow("1.1.1.1", now)
	l.allow("1.1.1.1", now)
	if _, ok := l.allow("1.1.1.1", now); ok {
		t.Fatal("третий запрос прошёл, лимит не сработал")
	}
	if _, ok := l.allow("1.1.1.1", now.Add(60*time.Millisecond)); !ok {
		t.Fatal("после истечения бана адрес всё ещё заблокирован")
	}
}

// Таблица не растёт бесконечно: флуд с миллиона адресов не должен съесть память.
func TestLimiterCapsTableSize(t *testing.T) {
	l := newLimiter(1, time.Minute, time.Minute)
	l.maxKeys = 10
	now := time.Now()
	for i := 0; i < 50; i++ {
		l.allow(string(rune('a'+i%26))+string(rune('0'+i/26)), now)
	}
	l.mu.Lock()
	n := len(l.seen)
	l.mu.Unlock()
	if n > l.maxKeys {
		t.Fatalf("в таблице %d записей при потолке %d", n, l.maxKeys)
	}
}
