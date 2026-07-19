package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
)

// Отметки живости — только своим. Клиенту и постороннему не должно быть даже
// видно, что эндпоинт существует: реестр узлов сети наружу не светим.
func TestHeartbeatRequiresNode(t *testing.T) {
	cfg, _ := usersCfg(t)
	for _, role := range []auth.Role{"", auth.RoleUser} {
		w := httptest.NewRecorder()
		serveHeartbeat(cfg).ServeHTTP(w, req(http.MethodPost, HeartbeatPath, "", role))
		if w.Code == http.StatusNoContent {
			t.Fatalf("роль %q отметилась живой", role)
		}
	}
}

// Стук узла обновляет его last_seen — иначе балансировщик считал бы живой узел
// мёртвым и уводил бы с него трафик.
func TestHeartbeatMarksNodeAlive(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()

	token, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	hash := auth.Hash(token)
	store.PutNode(ctx, db.Node{ID: "peer.example", TokenHash: hash, Enabled: true})

	before, _ := store.NodeByID(ctx, "peer.example")
	if !before.LastSeen.IsZero() {
		t.Fatal("узел уже отмечен живым до стука")
	}

	w := httptest.NewRecorder()
	r := req(http.MethodPost, HeartbeatPath, "", auth.RoleNode)
	// Сессия несёт хеш токена — по нему узел и опознаётся.
	auth.SessionFrom(r.Context()).Authorize(auth.RoleNode, hash)
	serveHeartbeat(cfg).ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	after, _ := store.NodeByID(ctx, "peer.example")
	if after.LastSeen.IsZero() || time.Since(after.LastSeen) > time.Minute {
		t.Fatalf("узел не отмечен живым: %v", after.LastSeen)
	}
}

// Стук несёт отчёт о расходе клиентов: без него мастер видел бы только свой
// трафик, и расход через реплики не попадал бы ни в панель, ни в лимиты.
func TestHeartbeatAcceptsTrafficReport(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	client := auth.Hash("клиент")
	store.PutToken(ctx, client, auth.RoleUser, "клиент")

	token, _ := auth.Generate()
	hash := auth.Hash(token)
	store.PutNode(ctx, db.Node{ID: "peer.example", TokenHash: hash, Enabled: true})

	body := `{"traffic":[{"token_hash":"` + client + `","bytes_in":700,"bytes_out":300}]}`
	w := httptest.NewRecorder()
	r := req(http.MethodPost, HeartbeatPath, body, auth.RoleNode)
	auth.SessionFrom(r.Context()).Authorize(auth.RoleNode, hash)
	serveHeartbeat(cfg).ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	total, err := store.NetworkTrafficOf(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if total.BytesIn != 700 || total.BytesOut != 300 {
		t.Fatalf("отчёт не учтён: %+v", total)
	}
}

// Битый отчёт не должен отменять отметку живости: узел жив, это главное.
func TestHeartbeatSurvivesBadBody(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	token, _ := auth.Generate()
	hash := auth.Hash(token)
	store.PutNode(ctx, db.Node{ID: "peer.example", TokenHash: hash, Enabled: true})

	w := httptest.NewRecorder()
	r := req(http.MethodPost, HeartbeatPath, "не json", auth.RoleNode)
	auth.SessionFrom(r.Context()).Authorize(auth.RoleNode, hash)
	serveHeartbeat(cfg).ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	if n, _ := store.NodeByID(ctx, "peer.example"); n.LastSeen.IsZero() {
		t.Fatal("битое тело отменило отметку живости")
	}
}

// Ответ несёт поколение мастера: так смена мастера доезжает за минуту, а не со
// следующим снимком — иначе узел четверть часа ходил бы за базой не туда.
func TestHeartbeatReportsMaster(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	store.Promote(ctx, "boss.example")

	token, _ := auth.Generate()
	hash := auth.Hash(token)
	store.PutNode(ctx, db.Node{ID: "peer.example", TokenHash: hash, Enabled: true})

	w := httptest.NewRecorder()
	r := req(http.MethodPost, HeartbeatPath, "", auth.RoleNode)
	auth.SessionFrom(r.Context()).Authorize(auth.RoleNode, hash)
	serveHeartbeat(cfg).ServeHTTP(w, r)

	if got := w.Header().Get(HeaderMaster); got != "boss.example" {
		t.Fatalf("мастер в ответе: %q", got)
	}
	if got := w.Header().Get(HeaderEpoch); got != "1" {
		t.Fatalf("поколение в ответе: %q", got)
	}
}

// Админский токен на этот эндпоинт проходит (диагностика), но узла за ним нет —
// отмечать нечего, и падать на этом нельзя.
func TestHeartbeatFromAdminIsHarmless(t *testing.T) {
	cfg, _ := usersCfg(t)
	w := httptest.NewRecorder()
	serveHeartbeat(cfg).ServeHTTP(w, req(http.MethodPost, HeartbeatPath, "", auth.RoleAdmin))
	if w.Code != http.StatusNoContent {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
}

// Узел, снятый с эксплуатации, живым не отмечается: NodeByTokenHash отдаёт
// только включённые, иначе выключенный узел выглядел бы живым в панели.
func TestHeartbeatIgnoresDisabledNode(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	token, _ := auth.Generate()
	hash := auth.Hash(token)
	store.PutNode(ctx, db.Node{ID: "off.example", TokenHash: hash, Enabled: false})

	w := httptest.NewRecorder()
	r := req(http.MethodPost, HeartbeatPath, "", auth.RoleNode)
	auth.SessionFrom(r.Context()).Authorize(auth.RoleNode, hash)
	serveHeartbeat(cfg).ServeHTTP(w, r)

	n, _ := store.NodeByID(ctx, "off.example")
	if !n.LastSeen.IsZero() {
		t.Fatal("выключенный узел отмечен живым")
	}
}

// Панель обслуживает сам узел — мёртвым он себя показывать не может, даже если
// собственного heartbeat ещё не было (одиночная установка, мастер).
func TestSelfAlwaysAlive(t *testing.T) {
	cfg, store := usersCfg(t)
	cfg.NodeID = "self.example"
	store.PutNode(context.Background(), db.Node{ID: "self.example", Enabled: true})

	w := httptest.NewRecorder()
	adminNodes(cfg).ServeHTTP(w, req(http.MethodGet, "/qd-admin/nodes", "", auth.RoleAdmin))
	if !strings.Contains(w.Body.String(), `"alive":true`) {
		t.Fatalf("узел показал себя мёртвым: %s", w.Body)
	}
}
