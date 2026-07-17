package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionAuthorizeFlow(t *testing.T) {
	s := &Session{}
	if s.Authorized() {
		t.Fatal("свежая сессия не должна быть авторизована")
	}
	s.Authorize(RoleUser, "hash123")
	role, hash, ok := s.Status()
	if !ok || role != RoleUser || hash != "hash123" {
		t.Fatalf("после Authorize: role=%q hash=%q ok=%v", role, hash, ok)
	}
}

// Сессия кладётся через ConnContext и обязана доезжать до запроса тем же
// значением (не копией): авторизация одного стрима видна остальным стримам той
// же QUIC-сессии.
func TestSessionSharedThroughContext(t *testing.T) {
	connCtx := NewSessionContext(context.Background())

	// первый «стрим» авторизует
	if s := SessionFrom(connCtx); s != nil {
		s.Authorize(RoleUser, "h")
	} else {
		t.Fatal("сессия не положена в контекст")
	}
	// второй «стрим» (наследует connCtx) видит ту же авторизацию
	reqCtx := context.WithValue(connCtx, struct{ x int }{}, 1) // имитируем производный ctx запроса
	s := SessionFrom(reqCtx)
	if s == nil || !s.Authorized() {
		t.Fatal("производный контекст не видит авторизацию сессии")
	}
}

func TestTokenFromRequest(t *testing.T) {
	tok, _ := Generate()
	r := httptest.NewRequest(http.MethodGet, "/qd-auth", nil)
	r.Header.Set(HeaderToken, tok)
	if got := TokenFromRequest(r); got != tok {
		t.Fatalf("токен не извлечён: %q", got)
	}

	// мусорный заголовок не должен доходить до БД
	r2 := httptest.NewRequest(http.MethodGet, "/qd-auth", nil)
	r2.Header.Set(HeaderToken, "Bearer nonsense")
	if got := TokenFromRequest(r2); got != "" {
		t.Fatalf("мусор принят за токен: %q", got)
	}

	// без заголовка — пусто
	r3 := httptest.NewRequest(http.MethodGet, "/qd-auth", nil)
	if got := TokenFromRequest(r3); got != "" {
		t.Fatalf("пустой заголовок дал токен: %q", got)
	}
}
