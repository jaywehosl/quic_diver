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
)

func subCfg(t *testing.T) (Config, *db.SQLite) {
	t.Helper()
	cfg, store := usersCfg(t)
	cfg.NodeID, cfg.Authority, cfg.Listen = "node.example", "node.example", ":27015"
	return cfg, store
}

func fetchSub(t *testing.T, cfg Config, hash string) subscription {
	t.Helper()
	r := req(http.MethodGet, SubscriptionPath, "", auth.RoleUser)
	if hash != "" {
		auth.SessionFrom(r.Context()).Authorize(auth.RoleUser, hash)
	}
	w := httptest.NewRecorder()
	serveSubscription(cfg, http.NotFoundHandler()).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	var sub subscription
	if err := json.Unmarshal(w.Body.Bytes(), &sub); err != nil {
		t.Fatal(err)
	}
	return sub
}

// Одиночный узел себя не регистрирует — не с кем было объединяться. Отдать
// пустой список точек входа значило бы лишить клиента даже той, через которую
// он сейчас и спрашивает.
func TestSubscriptionFallsBackToSelf(t *testing.T) {
	cfg, _ := subCfg(t)

	sub := fetchSub(t, cfg, "")
	if len(sub.Entries) != 1 {
		t.Fatalf("точки входа: %+v", sub.Entries)
	}
	// Порт обязан быть: authority у узла обычно голый домен, а клиенту нужен
	// адрес подключения целиком.
	if !strings.Contains(sub.Entries[0].Addr, ":27015") {
		t.Fatalf("адрес без порта: %q", sub.Entries[0].Addr)
	}
}

// Выходной узел точкой входа не служит: клиент к нему не подключается.
func TestSubscriptionSkipsExitNodes(t *testing.T) {
	cfg, store := subCfg(t)
	ctx := context.Background()
	store.PutNode(ctx, db.Node{ID: "in.example", Addr: "in.example:443", Enabled: true})
	store.PutNode(ctx, db.Node{
		ID: "out.example", Addr: "out.example:443", Category: db.CategoryExit, Enabled: true,
	})

	sub := fetchSub(t, cfg, "")
	for _, e := range sub.Entries {
		if strings.HasPrefix(e.Addr, "out.example") {
			t.Fatalf("выходной узел предложен точкой входа: %+v", sub.Entries)
		}
	}
	if len(sub.Entries) != 1 {
		t.Fatalf("точки входа: %+v", sub.Entries)
	}
}

// О себе клиент узнаёт из подписки: сколько осталось и сколько устройств —
// чтобы не спрашивать администратора.
func TestSubscriptionCarriesClientInfo(t *testing.T) {
	cfg, store := subCfg(t)
	ctx := context.Background()
	hash := auth.Hash("клиент")
	store.PutToken(ctx, hash, auth.RoleUser, "ноутбук")
	store.SetTrafficLimit(ctx, hash, 1<<30, 30)
	store.TouchDevice(ctx, hash, "hwid-1", "203.0.113.10")

	sub := fetchSub(t, cfg, hash)
	if sub.Client.Label != "ноутбук" {
		t.Fatalf("имя клиента: %q", sub.Client.Label)
	}
	if sub.Client.Quota.Limit != 1<<30 || sub.Client.Devices != 1 {
		t.Fatalf("лимиты и устройства: %+v", sub.Client)
	}
}

// Посторонний видит витрину: публичной страницы подписки у нас нет намеренно —
// доступная всем ссылка парсится и выдаёт состав сети перебором.
func TestSubscriptionHiddenFromStrangers(t *testing.T) {
	cfg, _ := subCfg(t)
	site := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("витрина"))
	})

	w := httptest.NewRecorder()
	serveSubscription(cfg, site).ServeHTTP(w, req(http.MethodGet, SubscriptionPath, "", ""))
	if !strings.Contains(w.Body.String(), "витрина") {
		t.Fatalf("подписка отдана постороннему: %s", w.Body)
	}
}

// Ссылка при создании клиента содержит и токен, и точку входа: иначе её
// пришлось бы собирать руками, а токен показывается один раз.
func TestBundleLinkIsUsable(t *testing.T) {
	cfg, store := subCfg(t)
	link := bundleFor(context.Background(), store, cfg, "qd_секрет")

	if !strings.HasPrefix(link, "qd://") {
		t.Fatalf("ссылка: %q", link)
	}
	// Разбираем тем же кодом, что и клиент.
	if !strings.Contains(link, "qd://") || len(link) < 30 {
		t.Fatalf("ссылка подозрительно коротка: %q", link)
	}
}
