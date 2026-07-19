package db

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"quicdiver/internal/server/auth"
)

func nodeStore(t *testing.T) *SQLite {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "nodes.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestPutAndListNodes(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	want := Node{
		ID: "glitter.example", Label: "Германия", Category: CategoryExit,
		Tags: []string{"de", "eu"}, Addr: "203.0.113.10:443", SNI: "glitter.example",
		TokenHash: auth.Hash("секрет-узла"), Enabled: true,
	}
	if err := s.PutNode(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := s.NodeByID(ctx, want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Category != CategoryExit || got.Label != "Германия" || got.Addr != want.Addr {
		t.Fatalf("узел разошёлся: %+v", got)
	}
	if len(got.Tags) != 2 || !got.HasTag("DE") { // теги сравниваются без регистра
		t.Fatalf("теги: %v", got.Tags)
	}
	if list, _ := s.ListNodes(ctx); len(list) != 1 {
		t.Fatalf("в списке %d узлов", len(list))
	}
}

// Узел узнаётся по хешу предъявленного токена: секрета соседа у него нет, есть
// только хеши из реплики.
func TestNodeByTokenHash(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	token := "qd_секрет-соседа"
	s.PutNode(ctx, Node{ID: "n1", TokenHash: auth.Hash(token), Enabled: true})

	got, err := s.NodeByTokenHash(ctx, auth.Hash(token))
	if err != nil || got.ID != "n1" {
		t.Fatalf("узел не опознан по токену: %+v, %v", got, err)
	}
	if _, err := s.NodeByTokenHash(ctx, auth.Hash("чужое")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("чужой токен опознан: %v", err)
	}
}

// Выключенный узел не признаётся при подключении — иначе выключение в панели
// ничего бы не значило для транзита.
func TestDisabledNodeNotRecognised(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	token := "qd_токен"
	s.PutNode(ctx, Node{ID: "n1", TokenHash: auth.Hash(token), Enabled: true})
	s.PutNode(ctx, Node{ID: "n1", TokenHash: auth.Hash(token), Enabled: false})

	if _, err := s.NodeByTokenHash(ctx, auth.Hash(token)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("выключенный узел опознан: %v", err)
	}
	// Но в списке он остаётся: админ должен его видеть и уметь включить обратно.
	if list, _ := s.ListNodes(ctx); len(list) != 1 {
		t.Fatal("выключенный узел пропал из списка")
	}
}

// Правка метки или категории не должна отзывать узлу доступ: пустой хеш в
// запросе означает «не трогать», а не «стереть».
func TestEditKeepsToken(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	token := "qd_токен"
	s.PutNode(ctx, Node{ID: "n1", TokenHash: auth.Hash(token), Enabled: true})

	// Админ поменял категорию, токен не присылал.
	if err := s.PutNode(ctx, Node{ID: "n1", Category: CategoryExit, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	got, err := s.NodeByTokenHash(ctx, auth.Hash(token))
	if err != nil {
		t.Fatalf("после правки узел потерял доступ: %v", err)
	}
	if got.Category != CategoryExit {
		t.Fatalf("категория не применилась: %q", got.Category)
	}
}

// Наружу не отдаём даже хеш токена: в JSON панели его быть не должно.
func TestTokenHashNotSerialised(t *testing.T) {
	b, err := json.Marshal(Node{ID: "n1", TokenHash: "секретный-хеш", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "секретный-хеш") || strings.Contains(string(b), "token") {
		t.Fatalf("хеш токена утёк в JSON: %s", b)
	}
}

// Имя для TLS отделено от адреса: идём на голый IP, представляясь доменом.
func TestAuthorityPrefersSNI(t *testing.T) {
	if got := (Node{Addr: "203.0.113.10:443", SNI: "glitter.example"}).Authority(); got != "glitter.example" {
		t.Fatalf("authority = %q", got)
	}
	if got := (Node{Addr: "glitter.example:443"}).Authority(); got != "glitter.example" {
		t.Fatalf("authority = %q", got)
	}
}

func TestTouchAndDeleteNode(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	s.PutNode(ctx, Node{ID: "n1", Enabled: true})

	if err := s.TouchNode(ctx, "n1"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.NodeByID(ctx, "n1")
	if got.LastSeen.IsZero() {
		t.Fatal("heartbeat не отметился")
	}
	if err := s.DeleteNode(ctx, "n1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NodeByID(ctx, "n1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("узел не удалён: %v", err)
	}
	if err := s.DeleteNode(ctx, "нет-такого"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("удаление несуществующего: %v", err)
	}
}
