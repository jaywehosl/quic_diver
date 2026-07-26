package db

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
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

// Адрес стабилен по токену: повторный запрос отдаёт тот же — иначе роутинг по
// клиенту и логи ломаются на каждом переподключении.
func TestAllocateStable(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	pool := netip.MustParsePrefix("10.7.0.0/24")
	h := auth.Hash(mustToken(t))
	_ = s.PutToken(ctx, h, auth.RoleUser, "")

	a1, err := s.AllocateAddress(ctx, h, pool)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := s.AllocateAddress(ctx, h, pool)
	if err != nil {
		t.Fatal(err)
	}
	if a1 != a2 {
		t.Fatalf("адрес не стабилен: %v != %v", a1, a2)
	}
	// первый клиентский — .2 (.0 сеть, .1 узел)
	if a1 != netip.MustParseAddr("10.7.0.2") {
		t.Fatalf("первый адрес %v, ожидался 10.7.0.2", a1)
	}
}

// Разным токенам — разные адреса, без дублей.
func TestAllocateUnique(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	pool := netip.MustParsePrefix("10.7.0.0/24")

	seen := make(map[netip.Addr]bool)
	for i := 0; i < 10; i++ {
		h := auth.Hash(mustToken(t))
		_ = s.PutToken(ctx, h, auth.RoleUser, "")
		a, err := s.AllocateAddress(ctx, h, pool)
		if err != nil {
			t.Fatal(err)
		}
		if seen[a] {
			t.Fatalf("адрес %v выдан дважды", a)
		}
		seen[a] = true
	}
}

// Параллельное выделение не должно давать дублей: UNIQUE(addr) + транзакция.
func TestAllocateConcurrent(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	pool := netip.MustParsePrefix("10.7.0.0/24")

	const n = 20
	hashes := make([]string, n)
	for i := range hashes {
		hashes[i] = auth.Hash(mustToken(t))
		_ = s.PutToken(ctx, hashes[i], auth.RoleUser, "")
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[netip.Addr]bool)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			a, err := s.AllocateAddress(ctx, h, pool)
			if err != nil {
				errs <- err
				return
			}
			mu.Lock()
			if seen[a] {
				err = fmt.Errorf("дубль адреса %v", a)
			}
			seen[a] = true
			mu.Unlock()
			if err != nil {
				errs <- err
			}
		}(hashes[i])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if len(seen) != n {
		t.Fatalf("выдано %d уникальных адресов из %d", len(seen), n)
	}
}

// Исчерпание пула — понятная ошибка, а не паника или дубль.
func TestAllocateExhaustion(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	// /30 = 4 адреса, минус .0 (сеть) и .1 (узел) = 2 клиентских (.2, .3)
	pool := netip.MustParsePrefix("10.7.0.0/30")

	for i := 0; i < 2; i++ {
		h := auth.Hash(mustToken(t))
		_ = s.PutToken(ctx, h, auth.RoleUser, "")
		if _, err := s.AllocateAddress(ctx, h, pool); err != nil {
			t.Fatalf("клиент %d: %v", i, err)
		}
	}
	h := auth.Hash(mustToken(t))
	_ = s.PutToken(ctx, h, auth.RoleUser, "")
	if _, err := s.AllocateAddress(ctx, h, pool); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("ожидался ErrPoolExhausted, получено %v", err)
	}
}

// Освобождённый адрес (токен отозван → CASCADE удаляет assignment) должен
// переиспользоваться.
func TestAllocateReusesFreed(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	pool := netip.MustParsePrefix("10.7.0.0/30") // 2 клиентских

	h1 := auth.Hash(mustToken(t))
	_ = s.PutToken(ctx, h1, auth.RoleUser, "")
	a1, _ := s.AllocateAddress(ctx, h1, pool)

	// удалить assignment напрямую (как сделал бы CASCADE при физическом удалении)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM assignments WHERE token_hash=?`, h1); err != nil {
		t.Fatal(err)
	}

	h2 := auth.Hash(mustToken(t))
	_ = s.PutToken(ctx, h2, auth.RoleUser, "")
	a2, err := s.AllocateAddress(ctx, h2, pool)
	if err != nil {
		t.Fatalf("освобождённый адрес не переиспользован: %v", err)
	}
	if a2 != a1 {
		t.Fatalf("выдан %v, ожидался переиспользованный %v", a2, a1)
	}
}

func TestClientConfigBackup(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	hash := auth.Hash(mustToken(t))
	_ = s.PutToken(ctx, hash, auth.RoleUser, "test-user")

	// 1. Бэкап пока не существует
	if _, _, err := s.GetClientConfig(ctx, hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ожидался ErrNotFound, получено %v", err)
	}

	// 2. Добавляем бэкап
	cfgJSON := `{"routing":{"rules":["geosite:google=node1"]}}`
	if err := s.PutClientConfig(ctx, hash, cfgJSON); err != nil {
		t.Fatalf("PutClientConfig: %v", err)
	}

	// 3. Считываем бэкап
	gotJSON, updated, err := s.GetClientConfig(ctx, hash)
	if err != nil {
		t.Fatalf("GetClientConfig: %v", err)
	}
	if gotJSON != cfgJSON {
		t.Fatalf("получено %q, ожидалось %q", gotJSON, cfgJSON)
	}
	if updated.IsZero() {
		t.Fatal("updated_at не должен быть нулевым")
	}
}
