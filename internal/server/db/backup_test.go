package db

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"quicdiver/internal/server/auth"
)

// Снимок обязан содержать данные, которые ещё лежат в WAL: в WAL-режиме сам файл
// базы может быть почти пустым, и простое копирование потеряло бы свежие записи.
func TestBackupIncludesRecentWrites(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	ctx := context.Background()
	hash := auth.Hash("свежий-клиент")
	if err := src.PutToken(ctx, hash, auth.RoleUser, "только что заведён"); err != nil {
		t.Fatal(err)
	}

	snap := filepath.Join(dir, "snap.db")
	if err := src.Backup(ctx, snap); err != nil {
		t.Fatalf("снимок: %v", err)
	}

	restored, err := Open(snap)
	if err != nil {
		t.Fatalf("открыть снимок: %v", err)
	}
	defer restored.Close()
	info, err := restored.Lookup(ctx, hash)
	if err != nil {
		t.Fatalf("свежая запись не попала в снимок: %v", err)
	}
	if info.Label != "только что заведён" {
		t.Fatalf("метка в снимке: %q", info.Label)
	}
}

// Снимок можно снимать повторно в тот же путь — иначе плановый бэкап падал бы
// со второго раза.
func TestBackupOverwrites(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(filepath.Join(dir, "src.db"))
	defer s.Close()
	snap := filepath.Join(dir, "snap.db")
	if err := s.Backup(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(context.Background(), snap); err != nil {
		t.Fatalf("повторный снимок: %v", err)
	}
}

// Подсунутый мусор не должен затереть рабочую базу.
func TestValidateRejectsGarbage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "мусор.db")
	if err := os.WriteFile(p, []byte("это точно не sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSnapshot(context.Background(), p); !errors.Is(err, ErrNotSnapshot) {
		t.Fatalf("мусор принят как база: %v", err)
	}
}

// Чужая (пусть и валидная) база тоже не годится: без наших таблиц узел остался
// бы без токенов, то есть без клиентов.
func TestValidateRejectsForeignDatabase(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "чужая.db")
	foreign, err := openRaw(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.Exec(`CREATE TABLE что_то_чужое (id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	foreign.Close()

	if err := ValidateSnapshot(context.Background(), p); !errors.Is(err, ErrNotSnapshot) {
		t.Fatalf("чужая база принята: %v", err)
	}
}

// Полный круг: сняли снимок, отложили восстановление, применили на старте.
func TestStageAndApplyRestore(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	// Рабочая база с одним клиентом.
	live := filepath.Join(dir, "qd.db")
	s, _ := Open(live)
	s.PutToken(ctx, auth.Hash("старый"), auth.RoleUser, "старый")
	s.Close()

	// Снимок другой базы — с другим клиентом.
	other := filepath.Join(dir, "other.db")
	o, _ := Open(other)
	o.PutToken(ctx, auth.Hash("новый"), auth.RoleUser, "новый")
	snap := filepath.Join(dir, "snap.db")
	if err := o.Backup(ctx, snap); err != nil {
		t.Fatal(err)
	}
	o.Close()

	if err := StageRestore(ctx, live, snap); err != nil {
		t.Fatalf("отложить восстановление: %v", err)
	}
	applied, err := ApplyPendingRestore(live)
	if err != nil || !applied {
		t.Fatalf("применение: applied=%v err=%v", applied, err)
	}

	s2, err := Open(live)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.Lookup(ctx, auth.Hash("новый")); err != nil {
		t.Fatalf("клиент из снимка не подхватился: %v", err)
	}
	if _, err := s2.Lookup(ctx, auth.Hash("старый")); err == nil {
		t.Fatal("старая база не заменена")
	}
	// Прежняя база сохранена: есть куда вернуться, если в снимке не то.
	if _, err := os.Stat(live + ".prev"); err != nil {
		t.Fatalf("прежняя база не сохранена: %v", err)
	}
}

// Битый отложенный файл не должен затирать рабочую базу.
func TestApplyRejectsBrokenPending(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "qd.db")
	s, _ := Open(live)
	s.PutToken(context.Background(), auth.Hash("живой"), auth.RoleUser, "живой")
	s.Close()

	if err := os.WriteFile(live+RestoreSuffix, []byte("мусор"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyPendingRestore(live); err == nil {
		t.Fatal("битый файл применён")
	}
	s2, err := Open(live)
	if err != nil {
		t.Fatalf("рабочая база пострадала: %v", err)
	}
	defer s2.Close()
	if _, err := s2.Lookup(context.Background(), auth.Hash("живой")); err != nil {
		t.Fatalf("данные потеряны: %v", err)
	}
}

// Нет отложенного файла — обычный старт, ничего не происходит.
func TestApplyNoPendingIsNoop(t *testing.T) {
	live := filepath.Join(t.TempDir(), "qd.db")
	s, _ := Open(live)
	s.Close()
	applied, err := ApplyPendingRestore(live)
	if err != nil || applied {
		t.Fatalf("applied=%v err=%v", applied, err)
	}
}
