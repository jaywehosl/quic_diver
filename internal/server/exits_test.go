package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
)

// exitsOf — список выходов, как его увидит клиент.
func exitsOf(t *testing.T, cfg Config) map[string]exitView {
	t.Helper()
	w := httptest.NewRecorder()
	serveExits(cfg, http.NotFoundHandler()).ServeHTTP(w, req(http.MethodGet, "/qd-exits", "", auth.RoleUser))
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	var list []exitView
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	out := map[string]exitView{}
	for _, e := range list {
		out[e.Route] = e
	}
	return out
}

// Клиент получает метки для правил: direct, каждый узел и auto:<тег>. Адресов
// подключения и хешей здесь нет — секретов в этом списке быть не должно.
func TestExitsListsNodesAndAuto(t *testing.T) {
	cfg, store := usersCfg(t)
	cfg.NodeID = "here.example"
	ctx := context.Background()
	store.PutNode(ctx, db.Node{
		ID: "here.example", Addr: "here.example:443", Category: db.CategoryEntry, Enabled: true,
	})
	store.PutNode(ctx, db.Node{
		ID: "de.example", Addr: "de.example:443", Category: db.CategoryExit,
		Tags: []string{"de"}, Enabled: true,
	})
	store.TouchNode(ctx, "de.example")

	exits := exitsOf(t, cfg)
	if _, ok := exits["direct"]; !ok {
		t.Fatal("нет выхода direct")
	}
	if e, ok := exits["de.example"]; !ok || !e.Alive {
		t.Fatalf("узел de: %+v", e)
	}
	// Правило «в Германию» не должно ломаться при замене конкретного узла.
	if e, ok := exits["auto:de"]; !ok || !e.Auto || !e.Alive {
		t.Fatalf("auto-метка по тегу: %+v", e)
	}
	if e, ok := exits["auto:exit"]; !ok || !e.Auto {
		t.Fatalf("auto-метка по категории: %+v", e)
	}
	if e := exits["here.example"]; !e.Self {
		t.Fatal("свой узел не помечен")
	}

	// Ни адресов подключения, ни хешей — иначе список стал бы картой сети.
	w := httptest.NewRecorder()
	serveExits(cfg, http.NotFoundHandler()).ServeHTTP(w, req(http.MethodGet, "/qd-exits", "", auth.RoleUser))
	for _, leak := range []string{"de.example:443", "token", "addr"} {
		if bytesContains(w.Body.Bytes(), leak) {
			t.Fatalf("список выходов отдал %q: %s", leak, w.Body)
		}
	}
}

// Мёртвый узел из списка не пропадает: правило на него остаётся рабочим (трафик
// выйдет на текущем узле), а видеть, что выход лёг, полезнее, чем недоумевать,
// куда делось правило.
func TestExitsKeepsDeadNodes(t *testing.T) {
	cfg, store := usersCfg(t)
	store.PutNode(context.Background(), db.Node{ID: "dead.example", Enabled: true})

	e, ok := exitsOf(t, cfg)["dead.example"]
	if !ok {
		t.Fatal("мёртвый узел исчез из списка")
	}
	if e.Alive {
		t.Fatal("узел без heartbeat помечен живым")
	}
}

// Выведенный из сети узел клиенту не предлагаем.
func TestExitsHidesDisabled(t *testing.T) {
	cfg, store := usersCfg(t)
	store.PutNode(context.Background(), db.Node{ID: "off.example", Enabled: false})

	if _, ok := exitsOf(t, cfg)["off.example"]; ok {
		t.Fatal("выключенный узел предложен клиенту")
	}
}

// Посторонний видит витрину, а не карту сети.
func TestExitsRequireSession(t *testing.T) {
	cfg, _ := usersCfg(t)
	w := httptest.NewRecorder()
	serveExits(cfg, http.NotFoundHandler()).ServeHTTP(w, req(http.MethodGet, "/qd-exits", "", ""))
	if w.Code == http.StatusOK {
		t.Fatal("неавторизованный получил список выходов")
	}
}
