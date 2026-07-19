package config

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func sample() Bundle {
	return Bundle{
		V: 1, T: "qd_секрет", N: "моя сеть",
		E: []BundleEntry{
			{A: "203.0.113.10:443", S: "node.example", L: "Москва"},
			{A: "198.51.100.7:443", S: "node.example"},
		},
	}
}

// Ссылка переживает круг: собрали — разобрали, ничего не потеряв.
func TestBundleRoundTrip(t *testing.T) {
	got, err := ParseBundle(sample().String())
	if err != nil {
		t.Fatal(err)
	}
	if got.T != "qd_секрет" || len(got.E) != 2 {
		t.Fatalf("бандл потерялся: %+v", got)
	}
	if got.E[0].A != "203.0.113.10:443" || got.E[0].S != "node.example" {
		t.Fatalf("точка входа: %+v", got.E[0])
	}
}

// Ссылку копируют из мессенджера — она ловит переводы строк и пробелы. Ронять
// человека на невидимом символе нельзя.
func TestBundleToleratesWhitespace(t *testing.T) {
	link := sample().String()
	dirty := " " + link[:20] + "\n" + link[20:] + "\r\n"

	if _, err := ParseBundle(dirty); err != nil {
		t.Fatalf("ссылка с пробелами не разобралась: %v", err)
	}
}

// Кодировки base64 у всех разные; требовать одну — отвергать рабочие ссылки.
func TestBundleAcceptsBase64Variants(t *testing.T) {
	raw, _ := json.Marshal(sample())
	for name, enc := range map[string]*base64.Encoding{
		"raw-url": base64.RawURLEncoding,
		"url":     base64.URLEncoding,
		"raw-std": base64.RawStdEncoding,
		"std":     base64.StdEncoding,
	} {
		if _, err := ParseBundle(BundleScheme + enc.EncodeToString(raw)); err != nil {
			t.Fatalf("%s не принят: %v", name, err)
		}
	}
}

// Хвостовой слэш добавляют программы, считающие строку адресом.
func TestBundleToleratesTrailingSlash(t *testing.T) {
	if _, err := ParseBundle(sample().String() + "/"); err != nil {
		t.Fatalf("ссылка со слэшем не разобралась: %v", err)
	}
}

// Чужая строка отвергается внятно, а не превращается в пустые настройки.
func TestBundleRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "просто текст", "https://example.com", "qd://не-base64!!"} {
		if _, err := ParseBundle(s); err == nil {
			t.Fatalf("принята строка %q", s)
		}
	}
}

// Ссылка без токена или без точки входа бесполезна — говорим об этом прямо, а
// не оставляем клиента с половиной настроек.
func TestBundleRequiresTokenAndEntry(t *testing.T) {
	noToken := Bundle{V: 1, E: []BundleEntry{{A: "203.0.113.10:443"}}}
	if _, err := ParseBundle(noToken.String()); err == nil || !strings.Contains(err.Error(), "токен") {
		t.Fatalf("бандл без токена: %v", err)
	}
	noEntry := Bundle{V: 1, T: "qd_x"}
	if _, err := ParseBundle(noEntry.String()); err == nil || !strings.Contains(err.Error(), "точк") {
		t.Fatalf("бандл без точки входа: %v", err)
	}
}

// Применение заменяет точки входа целиком: ссылка описывает сеть, в которую
// приглашают, и адреса прежней рядом с ней — верный способ уйти не туда.
func TestApplyReplacesEntries(t *testing.T) {
	cfg := Default()
	cfg.Node.Entries = []Entry{{Addr: "старый.example:443"}}
	cfg.Node.Token = "старый-токен"

	cfg.Apply(sample())
	if len(cfg.Node.Entries) != 2 {
		t.Fatalf("точки входа: %+v", cfg.Node.Entries)
	}
	for _, e := range cfg.Node.Entries {
		if strings.Contains(e.Addr, "старый") {
			t.Fatal("прежняя точка входа осталась")
		}
	}
	if cfg.Node.Token != "qd_секрет" {
		t.Fatalf("токен не заменён: %q", cfg.Node.Token)
	}
}

// Прочие настройки ссылка не трогает: человек мог уже собрать роутинг.
func TestApplyKeepsOtherSettings(t *testing.T) {
	cfg := Default()
	cfg.Routing.Rules = []string{"dom:a.example=direct"}
	cfg.Transport.BrutalMbps = 700

	cfg.Apply(sample())
	if len(cfg.Routing.Rules) != 1 || cfg.Transport.BrutalMbps != 700 {
		t.Fatalf("ссылка затёрла настройки: %+v", cfg)
	}
}
