package db

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"quicdiver/internal/server/auth"
)

// Одиночный узел, которого никто не объявлял мастером, обязан считать мастером
// себя — иначе первая же установка получила бы базу, в которую нельзя писать.
func TestLoneNodeIsMaster(t *testing.T) {
	s := nodeStore(t)
	c, err := s.ClusterState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsMaster("любой-узел") {
		t.Fatalf("одиночный узел не мастер: %+v", c)
	}
}

// Промоушен повышает поколение: иначе вернувшийся старый мастер объявил бы себя
// заново тем же номером, и в сети стало бы двое пишущих.
func TestPromoteRaisesEpoch(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()

	first, err := s.Promote(ctx, "n1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Promote(ctx, "n2")
	if err != nil {
		t.Fatal(err)
	}
	if second.Epoch <= first.Epoch {
		t.Fatalf("поколение не выросло: %d → %d", first.Epoch, second.Epoch)
	}
	cur, _ := s.ClusterState(ctx)
	if !cur.IsMaster("n2") || cur.IsMaster("n1") {
		t.Fatalf("мастером остался не тот: %+v", cur)
	}
}

// Состояние из чужого снимка принимается только со СТРОГО большим поколением:
// отставшая реплика не должна откатить сеть к прежнему мастеру.
func TestAdoptRejectsStaleEpoch(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	s.Promote(ctx, "n1") // epoch 1
	s.Promote(ctx, "n2") // epoch 2

	// Пришёл снимок от узла, который отстал.
	err := s.AdoptCluster(ctx, Cluster{Epoch: 1, MasterID: "n1"})
	if !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("старое поколение принято: %v", err)
	}
	// То же поколение — тоже отказ: мастер уже выбран.
	if err := s.AdoptCluster(ctx, Cluster{Epoch: 2, MasterID: "n1"}); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("равное поколение принято: %v", err)
	}
	cur, _ := s.ClusterState(ctx)
	if !cur.IsMaster("n2") {
		t.Fatalf("мастер сменился: %+v", cur)
	}
}

// Новое поколение принимается — так узел узнаёт о смене мастера.
func TestAdoptAcceptsNewerEpoch(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	s.Promote(ctx, "n1")

	if err := s.AdoptCluster(ctx, Cluster{Epoch: 7, MasterID: "n9"}); err != nil {
		t.Fatal(err)
	}
	cur, _ := s.ClusterState(ctx)
	if cur.Epoch != 7 || !cur.IsMaster("n9") {
		t.Fatalf("состояние не принято: %+v", cur)
	}
}

// Горячая подмена: база меняется на свежий снимок без перезапуска узла.
func TestLiveSwapAppliesSnapshot(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	live, err := NewLive(filepath.Join(dir, "qd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	live.DB().PutToken(ctx, auth.Hash("старый"), auth.RoleUser, "старый")

	// Готовим «снимок мастера» с другим клиентом.
	master, _ := Open(filepath.Join(dir, "master.db"))
	master.PutToken(ctx, auth.Hash("новый"), auth.RoleUser, "новый")
	snap := filepath.Join(dir, "snap.db")
	if err := master.Backup(ctx, snap); err != nil {
		t.Fatal(err)
	}
	master.Close()

	if err := live.SwapFile(snap); err != nil {
		t.Fatalf("подмена: %v", err)
	}
	// Store-интерфейс сразу отвечает из свежей базы — без перезапуска.
	if _, err := live.Lookup(ctx, auth.Hash("новый")); err != nil {
		t.Fatalf("клиент из снимка не виден: %v", err)
	}
	if _, err := live.Lookup(ctx, auth.Hash("старый")); err == nil {
		t.Fatal("старая база всё ещё отвечает")
	}
}

// Мусор вместо снимка не должен подменять рабочую базу.
func TestLiveSwapRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	live, err := NewLive(filepath.Join(dir, "qd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	live.DB().PutToken(ctx, auth.Hash("живой"), auth.RoleUser, "живой")

	bad := filepath.Join(dir, "bad.db")
	os.WriteFile(bad, []byte("не база"), 0o600)

	if err := live.SwapFile(bad); err == nil {
		t.Fatal("мусор применён")
	}
	if _, err := live.Lookup(ctx, auth.Hash("живой")); err != nil {
		t.Fatalf("рабочая база пострадала: %v", err)
	}
}

// Снимок мастера не должен стирать то, что узел наблюдал сам: живые сессии,
// устройства и счётчики трафика. Иначе реплика теряла бы учёт каждые несколько
// минут — с частотой обновлений.
func TestLiveSwapKeepsLocalAccounting(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	hash := auth.Hash("клиент")

	live, err := NewLive(filepath.Join(dir, "qd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	live.DB().PutToken(ctx, hash, auth.RoleUser, "клиент")
	live.DB().TouchDevice(ctx, hash, "hwid-1", "10.0.0.9")
	live.DB().OpenSession(ctx, Session{ID: "s1", TokenHash: hash, HWID: "hwid-1", Node: "нода"}, 0)
	live.DB().TouchSession(ctx, "s1", hash, 5000, 7000)

	// Мастер знает клиента, но ни о сессии, ни о трафике не в курсе.
	master, _ := Open(filepath.Join(dir, "master.db"))
	master.PutToken(ctx, hash, auth.RoleUser, "клиент")
	snap := filepath.Join(dir, "snap.db")
	master.Backup(ctx, snap)
	master.Close()

	if err := live.SwapFile(snap); err != nil {
		t.Fatal(err)
	}

	sessions, err := live.DB().ListSessions(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].ID != "s1" {
		t.Fatalf("живая сессия потеряна при подмене: %+v", sessions)
	}
	devices, err := live.DB().ListDevices(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].HWID != "hwid-1" {
		t.Fatalf("устройство потеряно при подмене: %+v", devices)
	}
	tr, err := live.DB().TrafficOf(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if tr.BytesIn != 5000 || tr.BytesOut != 7000 {
		t.Fatalf("счётчик трафика сброшен подменой: %+v", tr)
	}
}

// Перезапуск после подмены обязан поднять узел на СВЕЖИХ данных: иначе реплика
// после рестарта раздавала бы устаревший реестр узлов.
func TestLiveSwapSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	path := filepath.Join(dir, "qd.db")

	live, err := NewLive(path)
	if err != nil {
		t.Fatal(err)
	}
	live.DB().PutToken(ctx, auth.Hash("старый"), auth.RoleUser, "старый")

	master, _ := Open(filepath.Join(dir, "master.db"))
	master.PutToken(ctx, auth.Hash("новый"), auth.RoleUser, "новый")
	snap := filepath.Join(dir, "snap.db")
	master.Backup(ctx, snap)
	master.Close()

	if err := live.SwapFile(snap); err != nil {
		t.Fatal(err)
	}
	live.Close() // узел погасили

	again, err := NewLive(path) // и подняли заново
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if _, err := again.Lookup(ctx, auth.Hash("новый")); err != nil {
		t.Fatalf("после перезапуска снимок потерян: %v", err)
	}
	if _, err := again.Lookup(ctx, auth.Hash("старый")); err == nil {
		t.Fatal("после перезапуска откатились к старой базе")
	}
}

// Запросы во время подмены не должны падать: старая база доживает, новая уже
// отвечает.
func TestLiveSwapUnderLoad(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	live, err := NewLive(filepath.Join(dir, "qd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	hash := auth.Hash("общий")
	live.DB().PutToken(ctx, hash, auth.RoleUser, "общий")

	master, _ := Open(filepath.Join(dir, "master.db"))
	master.PutToken(ctx, hash, auth.RoleUser, "он же из снимка")
	snap := filepath.Join(dir, "snap.db")
	master.Backup(ctx, snap)
	master.Close()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var failures int
	var mu sync.Mutex
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := live.Lookup(ctx, hash); err != nil {
					mu.Lock()
					failures++
					mu.Unlock()
				}
			}
		}()
	}
	if err := live.SwapFile(snap); err != nil {
		t.Fatalf("подмена: %v", err)
	}
	close(stop)
	wg.Wait()

	if failures > 0 {
		t.Fatalf("%d запросов упало во время подмены", failures)
	}
}
