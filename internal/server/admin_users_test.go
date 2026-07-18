package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
)

func usersCfg(t *testing.T) (Config, *db.SQLite) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return Config{Store: store, Authority: "тест"}, store
}

// req собирает запрос с сессией нужной роли.
func req(method, path, body string, role auth.Role) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	ctx := auth.NewSessionContext(r.Context())
	if role != "" {
		auth.SessionFrom(ctx).Authorize(role, "hash")
	}
	return r.WithContext(ctx)
}

// Учёт клиентов — только для admin. Всем прочим отдаётся decoy, а не 403:
// эндпоинт не должен обнаруживать себя тому, кто до него не дорос.
func TestUsersRequireAdmin(t *testing.T) {
	cfg, _ := usersCfg(t)
	h := adminUsers(cfg)
	for _, role := range []auth.Role{"", auth.RoleUser, auth.RoleNode} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req(http.MethodGet, "/qd-admin/users", "", role))
		if ct := w.Header().Get("Content-Type"); strings.Contains(ct, "application/json") {
			t.Fatalf("роль %q получила admin-JSON вместо decoy", role)
		}
	}
}

// Создание клиента отдаёт открытый токен ровно один раз; дальше в базе только
// хеш, и повторно показать доступ нельзя.
func TestCreateUserReturnsTokenOnce(t *testing.T) {
	cfg, store := usersCfg(t)
	h := adminUsers(cfg)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(http.MethodPost, "/qd-admin/users",
		`{"label":"Вася","limit_devices":2,"limit_sessions":3}`, auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("создание: статус %d, тело %s", w.Code, w.Body)
	}
	var created struct{ Token, Hash string }
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Token == "" || created.Hash == "" {
		t.Fatalf("пустой токен/хеш: %s", w.Body)
	}
	if auth.Hash(created.Token) != created.Hash {
		t.Fatal("хеш не соответствует выданному токену")
	}

	// Токен работает, лимиты записаны.
	if _, err := store.Lookup(context.Background(), created.Hash); err != nil {
		t.Fatalf("выданный токен не проходит авторизацию: %v", err)
	}
	row, err := store.TokenRowByHash(context.Background(), created.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if row.LimitDevices != 2 || row.LimitSessions != 3 || row.Label != "Вася" {
		t.Fatalf("лимиты/метка не сохранились: %+v", row)
	}

	// В списке открытого токена уже нет — только хеш.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req(http.MethodGet, "/qd-admin/users", "", auth.RoleAdmin))
	if strings.Contains(w.Body.String(), created.Token) {
		t.Fatal("список отдал открытый токен — он должен показываться один раз")
	}
}

// Подробности клиента приезжают с устройствами, сессиями и трафиком: панели
// нужно показать, откуда он ходит и сколько прокачал.
func TestUserDetailCarriesDevicesAndSessions(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	hash := auth.Hash("клиент")
	store.PutToken(ctx, hash, auth.RoleUser, "Петя")
	store.TouchDevice(ctx, hash, "hw-1", "1.2.3.4")
	store.OpenSession(ctx, db.Session{ID: "s1", TokenHash: hash, RemoteIP: "1.2.3.4"}, 0)
	store.TouchSession(ctx, "s1", hash, 111, 222)

	w := httptest.NewRecorder()
	adminUsers(cfg).ServeHTTP(w, req(http.MethodGet, "/qd-admin/users?hash="+hash, "", auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	var u userView
	if err := json.Unmarshal(w.Body.Bytes(), &u); err != nil {
		t.Fatal(err)
	}
	if len(u.Devices) != 1 || u.Devices[0].HWID != "hw-1" || u.Devices[0].LastIP != "1.2.3.4" {
		t.Fatalf("устройства: %+v", u.Devices)
	}
	if len(u.Sessions) != 1 || u.Sessions[0].ID != "s1" {
		t.Fatalf("сессии: %+v", u.Sessions)
	}
	if u.Traffic.BytesIn != 111 || u.Traffic.BytesOut != 222 {
		t.Fatalf("трафик: %+v", u.Traffic)
	}
}

// Отзыв токена обязан СРАЗУ снять живые сессии: иначе клиент доработает до
// собственного обрыва, хотя доступ уже закрыт.
func TestRevokeUserClosesLiveSessions(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	hash := auth.Hash("клиент")
	store.PutToken(ctx, hash, auth.RoleUser, "Петя")
	store.OpenSession(ctx, db.Session{ID: "s1", TokenHash: hash}, 0)
	store.OpenSession(ctx, db.Session{ID: "s2", TokenHash: hash}, 0)

	w := httptest.NewRecorder()
	adminUsers(cfg).ServeHTTP(w, req(http.MethodDelete, "/qd-admin/users?hash="+hash, "", auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("отзыв: статус %d, тело %s", w.Code, w.Body)
	}
	if sessions, _ := store.ListSessions(ctx, hash); len(sessions) != 0 {
		t.Fatalf("после отзыва остались сессии: %+v", sessions)
	}
	if _, err := store.Lookup(ctx, hash); err == nil {
		t.Fatal("отозванный токен всё ещё проходит авторизацию")
	}
}

// Отзыв устройства точечный: токен и остальные машины не страдают.
func TestPatchRevokesSingleDevice(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	hash := auth.Hash("клиент")
	store.PutToken(ctx, hash, auth.RoleUser, "Петя")
	store.TouchDevice(ctx, hash, "hw-1", "1.1.1.1")
	store.TouchDevice(ctx, hash, "hw-2", "2.2.2.2")

	body := `{"hash":"` + hash + `","device":"hw-1","device_revoked":true}`
	w := httptest.NewRecorder()
	adminUsers(cfg).ServeHTTP(w, req(http.MethodPatch, "/qd-admin/users", body, auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("patch: статус %d, тело %s", w.Code, w.Body)
	}
	if err := store.TouchDevice(ctx, hash, "hw-1", "1.1.1.1"); err == nil {
		t.Fatal("отозванное устройство всё ещё пускают")
	}
	if err := store.TouchDevice(ctx, hash, "hw-2", "2.2.2.2"); err != nil {
		t.Fatalf("соседнее устройство пострадало: %v", err)
	}
	if _, err := store.Lookup(ctx, hash); err != nil {
		t.Fatalf("токен пострадал от отзыва устройства: %v", err)
	}
}

// Правка лимитов не требует пересоздавать клиента.
func TestPatchUpdatesLimits(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	hash := auth.Hash("клиент")
	store.PutToken(ctx, hash, auth.RoleUser, "Петя")

	body := `{"hash":"` + hash + `","limit_devices":5}`
	w := httptest.NewRecorder()
	adminUsers(cfg).ServeHTTP(w, req(http.MethodPatch, "/qd-admin/users", body, auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	row, _ := store.TokenRowByHash(ctx, hash)
	if row.LimitDevices != 5 {
		t.Fatalf("лимит устройств %d, ожидалось 5", row.LimitDevices)
	}
}

// Состояние узла отдаётся только админу и несёт то, ради чего иначе лезли бы
// по ssh: аптайм, память, число клиентов.
func TestStatsForAdminOnly(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	store.PutToken(ctx, auth.Hash("к1"), auth.RoleUser, "к1")

	w := httptest.NewRecorder()
	adminStats(cfg).ServeHTTP(w, req(http.MethodGet, "/qd-admin/stats", "", auth.RoleUser))
	if strings.Contains(w.Header().Get("Content-Type"), "application/json") {
		t.Fatal("не-admin получил статистику")
	}

	w = httptest.NewRecorder()
	adminStats(cfg).ServeHTTP(w, req(http.MethodGet, "/qd-admin/stats", "", auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d", w.Code)
	}
	var st nodeStats
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Uptime == "" || st.Go.Goroutines == 0 || st.Clients.Tokens != 1 {
		t.Fatalf("статистика пустовата: %+v", st)
	}
}

// Живые сессии видны админу списком и закрываются поимённо.
func TestSessionsListAndClose(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	hash := auth.Hash("клиент")
	store.PutToken(ctx, hash, auth.RoleUser, "Петя")
	store.OpenSession(ctx, db.Session{ID: "s1", TokenHash: hash, RemoteIP: "9.9.9.9"}, 0)

	h := adminSessions(cfg)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(http.MethodGet, "/qd-admin/sessions", "", auth.RoleAdmin))
	if !strings.Contains(w.Body.String(), "9.9.9.9") {
		t.Fatalf("сессия не видна: %s", w.Body)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, req(http.MethodDelete, "/qd-admin/sessions?id=s1", "", auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("закрытие: статус %d", w.Code)
	}
	if s, _ := store.ListSessions(ctx, hash); len(s) != 0 {
		t.Fatalf("сессия не закрылась: %+v", s)
	}
}
