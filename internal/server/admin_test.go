package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

// API выходов: admin добавляет chain, он появляется активным; удаление убирает.
func TestAdminOutboundsCRUD(t *testing.T) {
	store := newMemStore()
	dials, closes := 0, 0
	obs := NewOutbounds(netip.MustParsePrefix("10.9.0.0/16"), markDialer{"direct"}, fakeChain(&dials, &closes))
	_ = obs.Reload(context.Background(), store)

	cfg := Config{Store: fakeStore{}, OutboundStore: store, Outbounds: obs}
	h := adminOutbounds(cfg)

	// GET: только direct
	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithRole(http.MethodGet, "", auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("GET статус %d", w.Code)
	}
	var got []outboundView
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if len(got) != 1 || got[0].Label != "direct" {
		t.Fatalf("исходно не только direct: %+v", got)
	}

	// POST: добавить chain "eu"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, reqWithRole(http.MethodPost,
		`{"label":"eu","type":"chain","addr":"1.2.3.4:443","token":"qd_node"}`, auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("POST статус %d: %s", w.Code, w.Body)
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	var eu *outboundView
	for i := range got {
		if got[i].Label == "eu" {
			eu = &got[i]
		}
	}
	if eu == nil || !eu.Active {
		t.Fatalf("chain eu не активен: %+v", got)
	}
	if eu.HasToken != true {
		t.Fatal("has_token=false, ожидался true")
	}
	// токен НЕ отдаётся в открытую
	if bytesContains(w.Body.Bytes(), "qd_node") {
		t.Fatal("токен выхода утёк в ответ API")
	}

	// роутер знает eu
	if obs.DialerForLabel("eu").(markDialer).mark != "1.2.3.4:443" {
		t.Fatal("после POST роутер не знает eu")
	}

	// DELETE
	w = httptest.NewRecorder()
	req := reqWithRole(http.MethodDelete, "", auth.RoleAdmin)
	req.URL.RawQuery = "label=eu"
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE статус %d", w.Code)
	}
	if obs.DialerForLabel("eu").(markDialer).mark != "direct" {
		t.Fatal("после DELETE eu ещё в роутере")
	}
}

// user-токен в API выходов не пускает.
func TestAdminOutboundsRequiresAdmin(t *testing.T) {
	d, c := 0, 0
	obs := NewOutbounds(netip.MustParsePrefix("10.9.0.0/16"), markDialer{"direct"}, fakeChain(&d, &c))
	cfg := Config{Store: fakeStore{}, OutboundStore: newMemStore(), Outbounds: obs}
	h := adminOutbounds(cfg)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithRole(http.MethodGet, "", auth.RoleUser))
	if ct := w.Header().Get("Content-Type"); ct == "application/json" {
		t.Fatal("user получил JSON вместо decoy")
	}
}

func bytesContains(b []byte, s string) bool {
	return strings.Contains(string(b), s)
}
