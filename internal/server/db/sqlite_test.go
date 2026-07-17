package db

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"quicdiver/internal/server/auth"
)

func openTemp(t *testing.T) *SQLite {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "qd.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestPutAndLookup(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	tok, _ := auth.Generate()
	h := auth.Hash(tok)

	if err := s.PutToken(ctx, h, auth.RoleUser, "вася"); err != nil {
		t.Fatal(err)
	}
	info, err := s.Lookup(ctx, h)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if info.Role != auth.RoleUser || info.Label != "вася" {
		t.Fatalf("got %+v", info)
	}
}

// В БД лежит только хеш: по открытому токену поиск не идёт, и сам токен нигде не
// хранится — утёкшая реплика бесполезна.
func TestOnlyHashStored(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	tok, _ := auth.Generate()

	if err := s.PutToken(ctx, auth.Hash(tok), auth.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	// поиск по самому токену (а не по его хешу) не должен находить
	if _, err := s.Lookup(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatal("токен нашёлся по открытому значению — значит он где-то хранится в открытом виде")
	}
}

// Отозванный токен обязан читаться как отсутствующий — иначе бан не действует.
func TestRevokeHidesToken(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	h := auth.Hash(mustToken(t))

	_ = s.PutToken(ctx, h, auth.RoleUser, "")
	if err := s.Revoke(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup(ctx, h); !errors.Is(err, ErrNotFound) {
		t.Fatal("отозванный токен всё ещё авторизует")
	}
	// строка остаётся (tombstone) — иначе отзыв не доехал бы до реплики
	var revoked int
	if err := s.db.QueryRow(`SELECT revoked FROM tokens WHERE hash=?`, h).Scan(&revoked); err != nil {
		t.Fatalf("строка отозванного токена исчезла: %v", err)
	}
	if revoked != 1 {
		t.Fatal("tombstone не выставлен")
	}
}

// Повторный Put того же токена (напр. смена роли) не плодит дублей и снимает
// отзыв — токен возвращают к жизни осознанно.
func TestPutIsUpsert(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	h := auth.Hash(mustToken(t))

	_ = s.PutToken(ctx, h, auth.RoleUser, "старое")
	_ = s.Revoke(ctx, h)
	if err := s.PutToken(ctx, h, auth.RoleAdmin, "новое"); err != nil {
		t.Fatal(err)
	}
	info, err := s.Lookup(ctx, h)
	if err != nil {
		t.Fatalf("после повторного Put токен не найден: %v", err)
	}
	if info.Role != auth.RoleAdmin || info.Label != "новое" {
		t.Fatalf("upsert не обновил: %+v", info)
	}
}

func TestAssignment(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	h := auth.Hash(mustToken(t))
	_ = s.PutToken(ctx, h, auth.RoleUser, "")

	if _, err := s.Assignment(ctx, h); !errors.Is(err, ErrNotFound) {
		t.Fatal("адрес нашёлся до назначения")
	}
	if err := s.SetAssignment(ctx, h, "10.7.0.5/32"); err != nil {
		t.Fatal(err)
	}
	addr, err := s.Assignment(ctx, h)
	if err != nil || addr != "10.7.0.5/32" {
		t.Fatalf("addr=%q err=%v", addr, err)
	}
}

func TestBadRoleRejected(t *testing.T) {
	s := openTemp(t)
	if err := s.PutToken(context.Background(), auth.Hash(mustToken(t)), auth.Role("root"), ""); err == nil {
		t.Fatal("неизвестная роль принята")
	}
}

func TestReopenPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "qd.db")
	h := auth.Hash(mustToken(t))

	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s1.PutToken(context.Background(), h, auth.RoleNode, "узел-2")
	s1.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	info, err := s2.Lookup(context.Background(), h)
	if err != nil {
		t.Fatalf("после переоткрытия токен пропал: %v", err)
	}
	if info.Role != auth.RoleNode {
		t.Fatalf("роль не сохранилась: %+v", info)
	}
}

func mustToken(t *testing.T) string {
	t.Helper()
	tok, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
