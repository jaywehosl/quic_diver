package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Отсутствие файла — не ошибка: первый запуск обязан подняться на дефолтах,
// иначе клиент требовал бы ручной подготовки до первого старта.
func TestMissingFileGivesDefaults(t *testing.T) {
	cfg, err := LoadFrom(filepath.Join(t.TempDir(), "нет-такого.json"))
	if err != nil {
		t.Fatalf("отсутствующий файл дал ошибку: %v", err)
	}
	if !cfg.Transport.Hybrid || cfg.Panel.Addr == "" || cfg.Capture.NAT46 != "auto" {
		t.Fatalf("дефолты не применились: %+v", cfg)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	want := Default()
	want.Node = Node{
		Entries: []Entry{{Addr: "localhost:443", SNI: "localhost:8443"}},
		Token:   "qd_secret",
	}
	want.Routing.Rules = []string{"dom:youtube.com=chain"}
	want.Transport.BrutalMbps = 700

	if err := want.SaveTo(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Node.Token != want.Node.Token || len(got.Node.Entries) != 1 ||
		got.Node.Entries[0].SNI != "localhost:8443" ||
		got.Transport.BrutalMbps != 700 || len(got.Routing.Rules) != 1 {
		t.Fatalf("после круга настройки разошлись: %+v", got)
	}
}

// Старый конфиг не должен обнулять настройки, которых в нём ещё нет: неизвестные
// клиенту поля берутся из дефолтов, а не превращаются в нули.
func TestPartialFileKeepsDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"node":{"token":"t"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Node.Token != "t" {
		t.Fatalf("токен потерян: %+v", cfg.Node)
	}
	if !cfg.Transport.Hybrid || cfg.Transport.RecvWorkers != 1 || cfg.Panel.Addr == "" {
		t.Fatalf("частичный файл затёр дефолты: %+v", cfg)
	}
}

// Запись атомарна: при сбое на месте остаётся прежний рабочий файл, а временные
// файлы не копятся в папке.
func TestSaveIsAtomicAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	first := Default()
	first.Node.Token = "первый"
	if err := first.SaveTo(path); err != nil {
		t.Fatal(err)
	}
	second := Default()
	second.Node.Token = "второй"
	if err := second.SaveTo(path); err != nil {
		t.Fatal(err)
	}
	cfg, _ := LoadFrom(path)
	if cfg.Node.Token != "второй" {
		t.Fatalf("перезапись не сработала: %q", cfg.Node.Token)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("остался временный файл %s", e.Name())
		}
	}
}

// Токен лежит в файле открытым текстом — посторонние не должны его читать.
func TestSavedFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("на Windows доступ ограничивает ACL папки, не режим файла")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Default().SaveTo(path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("права %o — файл с токеном читают посторонние", mode)
	}
}

// Битый файл не должен ронять клиента молча: возвращаем ошибку, чтобы вызывающий
// решил (показать панель, взять дефолты), а не подсовываем полупустой конфиг.
func TestBrokenFileReportsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{ это не json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFrom(path); err == nil {
		t.Fatal("битый файл разобрался без ошибки")
	}
}

// SNI отделён от адреса: идём на голый IP, представляемся доменом.
func TestEntryAuthorityPrefersSNI(t *testing.T) {
	if got := (Entry{Addr: "localhost:443", SNI: "localhost:8443"}).Authority(); got != "localhost:8443" {
		t.Fatalf("authority = %q, ожидался домен из SNI", got)
	}
	if got := (Entry{Addr: "localhost:8443"}).Authority(); got != "localhost:8443" {
		t.Fatalf("authority = %q, ожидался host из адреса", got)
	}
}

// Файл читаемый и правится руками — панель не единственный способ настройки.
func TestFileIsHumanReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Default().SaveTo(path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "\n  ") {
		t.Fatal("файл записан одной строкой — руками не поправить")
	}
	var probe map[string]any
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatalf("невалидный json: %v", err)
	}
}
