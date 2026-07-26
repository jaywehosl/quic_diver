package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
	"quicdiver/internal/server/dns"
)

// fakeUp — минимальный upstream для резолвера в тесте.
type fakeUp struct{ name string }

func (f fakeUp) Exchange(context.Context, []byte) ([]byte, error) { return nil, nil }
func (f fakeUp) String() string                                   { return f.name }

// fakeStore — Store, отличающий «БД есть» от «узел открыт».
type fakeStore struct{ db.Store }

func adminCfg() Config {
	return Config{
		Store:    fakeStore{},
		Resolver: dns.New(dns.Config{Upstream: fakeUp{"udp://1.1.1.1:53"}, CacheSize: 100}),
	}
}

// reqWithRole вешает на запрос авторизованную сессию заданной роли.
func reqWithRole(method, body string, role auth.Role) *http.Request {
	r := httptest.NewRequest(method, "/qd-admin/dns", strings.NewReader(body))
	ctx := auth.NewSessionContext(r.Context())
	if role != "" {
		auth.SessionFrom(ctx).Authorize(role, "hash")
	}
	return r.WithContext(ctx)
}

// Только admin проходит; user/node/аноним → decoy (не эндпоинт).
func TestAdminDNSRequiresAdmin(t *testing.T) {
	h := adminDNS(adminCfg())

	for _, role := range []auth.Role{"", auth.RoleUser, auth.RoleNode} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, reqWithRole(http.MethodGet, "", role))
		// decoy отдаёт HTML-страницу, не JSON
		if ct := w.Header().Get("Content-Type"); strings.Contains(ct, "application/json") {
			t.Fatalf("роль %q получила admin-JSON вместо decoy", role)
		}
	}
	// admin — видит настройки
	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithRole(http.MethodGet, "", auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("admin GET статус %d", w.Code)
	}
	var st dnsStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("не JSON: %v", err)
	}
	if st.Upstream != "udp://1.1.1.1:53" {
		t.Fatalf("upstream в статусе: %q", st.Upstream)
	}
}

// POST со сменой upstream применяется на лету и виден в ответе.
func TestAdminDNSSetUpstream(t *testing.T) {
	cfg := adminCfg()
	h := adminDNS(cfg)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithRole(http.MethodPost, `{"upstream":"udp://8.8.8.8:53"}`, auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	if got := cfg.Resolver.Settings().Upstream; got != "plain://8.8.8.8:53" {
		t.Fatalf("upstream не сменился: %q", got)
	}
}

// Битый upstream — 400, старый не тронут.
func TestAdminDNSBadUpstream(t *testing.T) {
	cfg := adminCfg()
	h := adminDNS(cfg)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithRole(http.MethodPost, `{"upstream":"ftp://nope"}`, auth.RoleAdmin))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("битая схема принята, статус %d", w.Code)
	}
	if got := cfg.Resolver.Settings().Upstream; got != "udp://1.1.1.1:53" {
		t.Fatalf("старый upstream затёрт при ошибке: %q", got)
	}
}

func bytesContains(b []byte, s string) bool {
	return strings.Contains(string(b), s)
}

// Панель живёт на клиенте и проксирует админ-запросы через УЖЕ поднятую
// клиентскую связь: роль сессии там навсегда «user». Без проверки заголовка
// админ-API из панели был бы недоступен вовсе — на это и наткнулись вживую.
func TestAdminTokenFromHeaderAllowed(t *testing.T) {
	cfg, store := usersCfg(t)
	adminToken, _ := auth.Generate()
	store.PutToken(context.Background(), auth.Hash(adminToken), auth.RoleAdmin, "админ")

	// Сессия — клиентская, как при проксировании через панель.
	r := req(http.MethodGet, "/qd-admin/users", "", auth.RoleUser)
	r.Header.Set(auth.HeaderToken, adminToken)

	if !adminAllowed(r, cfg) {
		t.Fatal("админ-токен в заголовке не признан — панель не сможет управлять сетью")
	}
}

// Клиентский токен в заголовке админом не делает.
func TestUserTokenInHeaderRejected(t *testing.T) {
	cfg, store := usersCfg(t)
	userToken, _ := auth.Generate()
	store.PutToken(context.Background(), auth.Hash(userToken), auth.RoleUser, "клиент")

	r := req(http.MethodGet, "/qd-admin/users", "", auth.RoleUser)
	r.Header.Set(auth.HeaderToken, userToken)

	if adminAllowed(r, cfg) {
		t.Fatal("клиентский токен дал админский доступ")
	}
}

// Отозванный админ доступа не имеет: Lookup отдаёт только живые токены.
func TestRevokedAdminTokenRejected(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	adminToken, _ := auth.Generate()
	store.PutToken(ctx, auth.Hash(adminToken), auth.RoleAdmin, "бывший админ")
	store.Revoke(ctx, auth.Hash(adminToken))

	r := req(http.MethodGet, "/qd-admin/users", "", auth.RoleUser)
	r.Header.Set(auth.HeaderToken, adminToken)

	if adminAllowed(r, cfg) {
		t.Fatal("отозванный админ-токен принят")
	}
}

func TestClusterBroadcast(t *testing.T) {
	cfg, _ := usersCfg(t)
	cfg.NodeID = "master.node"

	h := adminCluster(cfg)
	r := req(http.MethodPut, "/qd-admin/cluster", "", auth.RoleAdmin)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("PUT status %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Свежая база данных") {
		t.Fatalf("ожидалось сообщение о рассылке, получено %s", w.Body.String())
	}
}
