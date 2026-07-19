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

// Реестр узлов — только админу; прочим не видно, что эндпоинт есть.
func TestNodesRequireAdmin(t *testing.T) {
	cfg, _ := usersCfg(t)
	for _, role := range []auth.Role{"", auth.RoleUser, auth.RoleNode} {
		w := httptest.NewRecorder()
		adminNodes(cfg).ServeHTTP(w, req(http.MethodGet, "/qd-admin/nodes", "", role))
		if ct := w.Header().Get("Content-Type"); strings.Contains(ct, "application/json") {
			t.Fatalf("роль %q увидела реестр узлов", role)
		}
	}
}

// Добавление узла отдаёт токен ровно один раз; в базе только хеш, поэтому секрет
// остаётся у самого узла, а по сети расходятся хеши.
func TestAddNodeReturnsTokenOnce(t *testing.T) {
	cfg, store := usersCfg(t)
	h := adminNodes(cfg)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(http.MethodPost, "/qd-admin/nodes",
		`{"id":"glitter.example","category":"exit","label":"Германия","tags":["de"]}`, auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	var created struct {
		Token string  `json:"token"`
		Node  db.Node `json:"node"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Token == "" {
		t.Fatal("токен узла не выдан")
	}
	// Адрес выведен из домена — пользователь вводит только его.
	if created.Node.Addr != "glitter.example:443" {
		t.Fatalf("адрес %q", created.Node.Addr)
	}
	// Узел опознаётся по хешу выданного токена.
	got, err := store.NodeByTokenHash(context.Background(), auth.Hash(created.Token))
	if err != nil || got.ID != "glitter.example" {
		t.Fatalf("узел не опознаётся своим токеном: %+v, %v", got, err)
	}

	// В списке токена уже нет — он показывается один раз.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req(http.MethodGet, "/qd-admin/nodes", "", auth.RoleAdmin))
	if strings.Contains(w.Body.String(), created.Token) {
		t.Fatal("список отдал токен узла")
	}
	if strings.Contains(w.Body.String(), "token_hash") {
		t.Fatal("список отдал хеш токена — наружу его быть не должно")
	}
}

// У каждого узла свой токен: общий на всю сеть означал бы, что утечка одного
// открывает остальные.
func TestEachNodeGetsOwnToken(t *testing.T) {
	cfg, _ := usersCfg(t)
	h := adminNodes(cfg)
	seen := map[string]bool{}
	for _, id := range []string{"n1.example", "n2.example"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req(http.MethodPost, "/qd-admin/nodes", `{"id":"`+id+`"}`, auth.RoleAdmin))
		var resp struct {
			Token string `json:"token"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if seen[resp.Token] {
			t.Fatal("два узла получили один токен")
		}
		seen[resp.Token] = true
	}
}

// Категорию задаёт админ и может поменять позже — на ней строятся правила.
func TestPatchCategoryAndTags(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	store.PutNode(ctx, db.Node{ID: "n1", Enabled: true})

	w := httptest.NewRecorder()
	adminNodes(cfg).ServeHTTP(w, req(http.MethodPatch, "/qd-admin/nodes",
		`{"id":"n1","category":"entry","tags":["ru","msk"]}`, auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	got, _ := store.NodeByID(ctx, "n1")
	if got.Category != db.CategoryEntry || !got.HasTag("msk") {
		t.Fatalf("узел: %+v", got)
	}
}

// Неизвестная категория отвергается: опечатка не должна тихо выключить узел из
// правил.
func TestUnknownCategoryRejected(t *testing.T) {
	cfg, _ := usersCfg(t)
	w := httptest.NewRecorder()
	adminNodes(cfg).ServeHTTP(w, req(http.MethodPost, "/qd-admin/nodes",
		`{"id":"n1","category":"середина"}`, auth.RoleAdmin))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("статус %d, ожидался отказ", w.Code)
	}
}

// Правка метки не должна отзывать узлу доступ.
func TestPatchKeepsNodeToken(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	token := "qd_узел"
	store.PutNode(ctx, db.Node{ID: "n1", TokenHash: auth.Hash(token), Enabled: true})

	w := httptest.NewRecorder()
	adminNodes(cfg).ServeHTTP(w, req(http.MethodPatch, "/qd-admin/nodes",
		`{"id":"n1","label":"новое имя"}`, auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	if _, err := store.NodeByTokenHash(ctx, auth.Hash(token)); err != nil {
		t.Fatalf("узел потерял доступ после правки метки: %v", err)
	}
}

// Ротация токена выдаёт новый и обесценивает старый.
func TestRotateNodeToken(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	old := "qd_старый"
	store.PutNode(ctx, db.Node{ID: "n1", TokenHash: auth.Hash(old), Enabled: true})

	w := httptest.NewRecorder()
	adminNodes(cfg).ServeHTTP(w, req(http.MethodPatch, "/qd-admin/nodes",
		`{"id":"n1","rotate_token":true}`, auth.RoleAdmin))
	var resp struct {
		Token string `json:"token"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Token == "" {
		t.Fatalf("новый токен не выдан: %s", w.Body)
	}
	if _, err := store.NodeByTokenHash(ctx, auth.Hash(old)); err == nil {
		t.Fatal("старый токен всё ещё действует")
	}
	if _, err := store.NodeByTokenHash(ctx, auth.Hash(resp.Token)); err != nil {
		t.Fatalf("новый токен не работает: %v", err)
	}
}

// Узел помечается живым по heartbeat; молчащий давно — не живой.
func TestListMarksAliveAndSelf(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	cfg.NodeID = "self.example"
	store.PutNode(ctx, db.Node{ID: "self.example", Enabled: true})
	store.PutNode(ctx, db.Node{ID: "quiet.example", Enabled: true})
	store.TouchNode(ctx, "self.example")

	w := httptest.NewRecorder()
	adminNodes(cfg).ServeHTTP(w, req(http.MethodGet, "/qd-admin/nodes", "", auth.RoleAdmin))
	var list []nodeView
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	for _, n := range list {
		switch n.ID {
		case "self.example":
			if !n.Self || !n.Alive {
				t.Fatalf("свой узел: self=%v alive=%v", n.Self, n.Alive)
			}
		case "quiet.example":
			if n.Alive {
				t.Fatal("узел без heartbeat помечен живым")
			}
		}
	}
}

func TestDeleteNodeFromNetwork(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	store.PutNode(ctx, db.Node{ID: "n1", Enabled: true})

	w := httptest.NewRecorder()
	adminNodes(cfg).ServeHTTP(w, req(http.MethodDelete, "/qd-admin/nodes?id=n1", "", auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	if _, err := store.NodeByID(ctx, "n1"); err == nil {
		t.Fatal("узел остался в реестре")
	}
}
