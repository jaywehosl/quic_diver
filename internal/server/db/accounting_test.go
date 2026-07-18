package db

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"quicdiver/internal/server/auth"
)

func acctStore(t *testing.T) (*SQLite, string) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "acct.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	hash := auth.Hash("клиентский-токен")
	if err := s.PutToken(context.Background(), hash, auth.RoleUser, "тест"); err != nil {
		t.Fatalf("токен: %v", err)
	}
	return s, hash
}

func setLimits(t *testing.T, s *SQLite, hash string, devices, sessions int) {
	t.Helper()
	if _, err := s.db.Exec(`UPDATE tokens SET limit_devices = ?, limit_sessions = ? WHERE hash = ?`,
		devices, sessions, hash); err != nil {
		t.Fatalf("лимиты: %v", err)
	}
}

// Известное устройство пускают всегда: смена адреса не должна выглядеть новой
// машиной и выедать квоту.
func TestKnownDeviceNotCountedTwice(t *testing.T) {
	s, hash := acctStore(t)
	ctx := context.Background()
	setLimits(t, s, hash, 1, 0)

	if err := s.TouchDevice(ctx, hash, "hw-1", "1.1.1.1"); err != nil {
		t.Fatalf("первое появление: %v", err)
	}
	if err := s.TouchDevice(ctx, hash, "hw-1", "2.2.2.2"); err != nil {
		t.Fatalf("та же машина с другого адреса отклонена: %v", err)
	}
	devs, err := s.ListDevices(ctx, hash)
	if err != nil || len(devs) != 1 {
		t.Fatalf("устройств %d (ошибка %v), ожидалось 1", len(devs), err)
	}
	if devs[0].LastIP != "2.2.2.2" {
		t.Fatalf("адрес не обновился: %q", devs[0].LastIP)
	}
}

// Лимит устройств — заслон от раздачи токена знакомым.
func TestDeviceLimitBlocksExtra(t *testing.T) {
	s, hash := acctStore(t)
	ctx := context.Background()
	setLimits(t, s, hash, 2, 0)

	if err := s.TouchDevice(ctx, hash, "hw-1", "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchDevice(ctx, hash, "hw-2", "1.1.1.2"); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchDevice(ctx, hash, "hw-3", "1.1.1.3"); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("третье устройство при лимите 2 дало %v", err)
	}
}

// Нулевой лимит — без ограничений (узел для своих).
func TestZeroLimitMeansUnlimited(t *testing.T) {
	s, hash := acctStore(t)
	ctx := context.Background()
	for i, hw := range []string{"a", "b", "c", "d"} {
		if err := s.TouchDevice(ctx, hash, hw, "1.1.1.1"); err != nil {
			t.Fatalf("устройство %d отклонено: %v", i, err)
		}
	}
}

// Отзыв бьёт по одной машине, не по токену: увели ноутбук — остальные работают.
func TestRevokedDeviceRejectedOthersLive(t *testing.T) {
	s, hash := acctStore(t)
	ctx := context.Background()
	s.TouchDevice(ctx, hash, "hw-1", "1.1.1.1")
	s.TouchDevice(ctx, hash, "hw-2", "1.1.1.2")

	if err := s.RevokeDevice(ctx, hash, "hw-1", true); err != nil {
		t.Fatalf("отзыв: %v", err)
	}
	if err := s.TouchDevice(ctx, hash, "hw-1", "1.1.1.1"); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("отозванное устройство пустили: %v", err)
	}
	if err := s.TouchDevice(ctx, hash, "hw-2", "1.1.1.2"); err != nil {
		t.Fatalf("соседнее устройство пострадало: %v", err)
	}
}

// Отозванное устройство не занимает квоту — иначе отзыв не освобождал бы место.
func TestRevokedDeviceFreesSlot(t *testing.T) {
	s, hash := acctStore(t)
	ctx := context.Background()
	setLimits(t, s, hash, 1, 0)

	s.TouchDevice(ctx, hash, "hw-1", "1.1.1.1")
	if err := s.TouchDevice(ctx, hash, "hw-2", "1.1.1.2"); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("ожидался лимит, получено %v", err)
	}
	if err := s.RevokeDevice(ctx, hash, "hw-1", true); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchDevice(ctx, hash, "hw-2", "1.1.1.2"); err != nil {
		t.Fatalf("после отзыва место не освободилось: %v", err)
	}
}

// Лимит сессий держит там, где hwid подделан: живое соединение не подделаешь.
func TestSessionLimit(t *testing.T) {
	s, hash := acctStore(t)
	ctx := context.Background()

	if err := s.OpenSession(ctx, Session{ID: "s1", TokenHash: hash, RemoteIP: "1.1.1.1"}, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.OpenSession(ctx, Session{ID: "s2", TokenHash: hash, RemoteIP: "2.2.2.2"}, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.OpenSession(ctx, Session{ID: "s3", TokenHash: hash}, 2); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("третья сессия при лимите 2 дала %v", err)
	}
	// Освободили место — снова пускают.
	if err := s.CloseSession(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if err := s.OpenSession(ctx, Session{ID: "s3", TokenHash: hash}, 2); err != nil {
		t.Fatalf("после закрытия сессии место не освободилось: %v", err)
	}
}

// Трафик копится сверх сессий и переживает их закрытие: счётчик клиента не
// должен обнуляться каждым обрывом.
func TestTrafficSurvivesSessionClose(t *testing.T) {
	s, hash := acctStore(t)
	ctx := context.Background()
	s.OpenSession(ctx, Session{ID: "s1", TokenHash: hash}, 0)
	s.TouchSession(ctx, "s1", hash, 1000, 2000)
	s.TouchSession(ctx, "s1", hash, 500, 100)
	s.CloseSession(ctx, "s1")

	tr, err := s.TrafficOf(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if tr.BytesIn != 1500 || tr.BytesOut != 2100 {
		t.Fatalf("трафик %d/%d, ожидалось 1500/2100", tr.BytesIn, tr.BytesOut)
	}
}

// Узел мог умереть, не закрыв сессии: без уборки список активных превратится в
// кладбище, а лимит одновременных подключений заклинит навсегда.
func TestSweepRemovesStaleSessions(t *testing.T) {
	s, hash := acctStore(t)
	ctx := context.Background()
	s.OpenSession(ctx, Session{ID: "живая", TokenHash: hash}, 0)
	s.OpenSession(ctx, Session{ID: "мёртвая", TokenHash: hash}, 0)
	// Состарим одну искусственно.
	old := time.Now().Add(-time.Hour).UnixNano()
	if _, err := s.db.Exec(`UPDATE sessions SET last_seen = ? WHERE id = 'мёртвая'`, old); err != nil {
		t.Fatal(err)
	}

	n, err := s.SweepSessions(ctx, 10*time.Minute)
	if err != nil || n != 1 {
		t.Fatalf("убрано %d (ошибка %v), ожидалась 1", n, err)
	}
	live, _ := s.ListSessions(ctx, hash)
	if len(live) != 1 || live[0].ID != "живая" {
		t.Fatalf("после уборки остались: %+v", live)
	}
}

// Клиент старой версии не шлёт hwid — учёт устройств просто не ведётся, но
// подключаться ему это не мешает.
func TestEmptyHWIDIsIgnored(t *testing.T) {
	s, hash := acctStore(t)
	ctx := context.Background()
	setLimits(t, s, hash, 1, 0)
	if err := s.TouchDevice(ctx, hash, "", "1.1.1.1"); err != nil {
		t.Fatalf("пустой hwid дал ошибку: %v", err)
	}
	if devs, _ := s.ListDevices(ctx, hash); len(devs) != 0 {
		t.Fatalf("пустой hwid попал в устройства: %+v", devs)
	}
}
