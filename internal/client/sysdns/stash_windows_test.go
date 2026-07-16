//go:build windows

package sysdns

import (
	"encoding/json"
	"os"
	"testing"
)

// Аварийное завершение (паника, kill, BSOD) не даёт отработать defer, поэтому
// прежний DNS обязан лежать на диске: иначе машина навсегда остаётся с
// NameServer=127.0.0.1, listener'а нет и резолва нет вообще.
func TestStashSurvivesAndRestores(t *testing.T) {
	path, err := stashPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Skip("на машине лежит настоящий stash — не трогаем")
	}
	t.Cleanup(func() { os.Remove(path) })

	// состояние несуществующего интерфейса: restore его пропустит, но путь
	// «сохранили → нашли → подобрали → удалили» проверяется целиком
	s := &Saved{entries: []saved{{
		Key: v4Ifaces, GUID: "{00000000-0000-0000-0000-000000000000}",
		Value: "192.168.31.1", Had: true,
	}}}
	if err := s.stash(); err != nil {
		t.Fatalf("stash: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("файл не создан: %v", err)
	}
	var got []saved
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("не разобрать: %v", err)
	}
	if len(got) != 1 || got[0].Value != "192.168.31.1" || !got[0].Had {
		t.Fatalf("на диск легло не то: %+v", got)
	}

	found, err := RestoreStale()
	if err != nil {
		t.Fatalf("RestoreStale: %v", err)
	}
	if !found {
		t.Fatal("осиротевшее состояние не подобрано — машина осталась бы без DNS")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("файл не удалён после подбора — восстановили бы повторно поверх свежего DNS")
	}
}

// Штатный выход: файла остаться не должно, иначе следующий запуск затрёт
// настоящий DNS устаревшим значением.
func TestRestoreClearsStash(t *testing.T) {
	path, err := stashPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Skip("на машине лежит настоящий stash — не трогаем")
	}
	t.Cleanup(func() { os.Remove(path) })

	s := &Saved{entries: []saved{{
		Key: v4Ifaces, GUID: "{00000000-0000-0000-0000-000000000000}", Had: false,
	}}}
	if err := s.stash(); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("после штатного Restore файл остался")
	}
}

// Пустого файла быть не должно, но если он появился — не падать и не считать,
// что было что подбирать.
func TestRestoreStaleWithoutFile(t *testing.T) {
	path, err := stashPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Skip("на машине лежит настоящий stash — не трогаем")
	}
	found, err := RestoreStale()
	if err != nil {
		t.Fatalf("без файла должно быть тихо: %v", err)
	}
	if found {
		t.Fatal("подобрано несуществующее состояние")
	}
}
