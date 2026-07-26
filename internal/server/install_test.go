package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
)

// installCfg — узел с зарегистрированным соседом и его токеном.
func installCfg(t *testing.T) (Config, *db.SQLite, string, string) {
	t.Helper()
	cfg, store := usersCfg(t)
	cfg.NodeID, cfg.Authority = "master.example", "master.example:443"

	token, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	store.PutNode(context.Background(), db.Node{
		ID: "new.example", Addr: "new.example:27015", TokenHash: auth.Hash(token), Enabled: true,
	})
	adminToken, _ := auth.Generate()
	store.PutToken(context.Background(), auth.Hash(adminToken), auth.RoleAdmin, "админ")
	return cfg, store, token, adminToken
}

// tokenReq — запрос к витрине: авторизация тут заголовком, а не сессией.
func tokenReq(target, token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		r.Header.Set(auth.HeaderToken, token)
	}
	return r
}

// Посторонний видит витрину, а не скрипт: путь установки не должен становиться
// указателем «тут не сайт».
func TestInstallHidesFromStrangers(t *testing.T) {
	cfg, _, nodeToken, _ := installCfg(t)
	site := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("витрина"))
	})
	h := installHandlers(cfg, site)[InstallPath]

	for _, tok := range []string{"", "qd_чужой"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, tokenReq(InstallPath+"?id=new.example&token="+nodeToken, tok))
		if !strings.Contains(w.Body.String(), "витрина") {
			t.Fatalf("токен %q получил не витрину: %s", tok, w.Body)
		}
	}
}

// Скрипт содержит всё, без чего узел не поднимется: свой токен, адрес мастера,
// порт из реестра и запуск через systemd.
func TestInstallScriptHasEverythingNeeded(t *testing.T) {
	cfg, _, nodeToken, adminToken := installCfg(t)
	h := installHandlers(cfg, http.NotFoundHandler())[InstallPath]

	w := httptest.NewRecorder()
	h.ServeHTTP(w, tokenReq(InstallPath+"?id=new.example&token="+nodeToken, adminToken))
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	script := w.Body.String()
	for _, want := range []string{
		nodeToken,          // токен узла — иначе он не представится сети
		"master.example",   // где брать базу
		"-master ",         // bootstrap мастера
		"LISTEN=':27015'",  // порт из реестра, а не дефолтный
		"systemctl enable", // переживает перезагрузку
		"Restart=always",   // и падение
		"LimitNOFILE",      // дефолт 1024 кончится в первый час
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("в скрипте нет %q:\n%s", want, script)
		}
	}
}

// Скрипт обязан проверить, что узел ДЕРЖИТСЯ, а не отрапортовать об успехе.
//
// Restart=always маскирует ошибку конфигурации: сервис числится запущенным,
// хотя падает каждые несколько секунд. Наступали на это вживую — установщик
// сказал «готово», а узел уходил в цикл перезапуска.
func TestInstallScriptVerifiesNodeStays(t *testing.T) {
	cfg, _, nodeToken, adminToken := installCfg(t)
	h := installHandlers(cfg, http.NotFoundHandler())[InstallPath]

	w := httptest.NewRecorder()
	h.ServeHTTP(w, tokenReq(InstallPath+"?id=new.example&token="+nodeToken, adminToken))
	script := w.Body.String()
	for _, want := range []string{"is-active", "NRestarts", "exit 1"} {
		if !strings.Contains(script, want) {
			t.Fatalf("скрипт не проверяет, что узел держится (нет %q)", want)
		}
	}
}

// Флаг -dns должен получить схему, которую он понимает: резолвер показывает
// plain://, а флаг ждёт udp://. Разошлись они молча — узел падал на разборе.
func TestInstallDNSSchemeMatchesFlag(t *testing.T) {
	if got := dnsFlagValue("plain://8.8.8.8:53"); got != "udp://8.8.8.8:53" {
		t.Fatalf("dns для флага: %q", got)
	}
	for _, keep := range []string{"https://dns.google/dns-query", "tls://1.1.1.1:853"} {
		if got := dnsFlagValue(keep); got != keep {
			t.Fatalf("%q превратился в %q", keep, got)
		}
	}
}

// Адрес мастера без порта уронил бы новый узел на разборе -master.
func TestInstallMasterAddrAlwaysHasPort(t *testing.T) {
	cfg, store, nodeToken, adminToken := installCfg(t)
	// Мастер записан без порта — так бывает, если узел запущен с -authority
	// вида "master.example".
	cfg.Authority = "master.example"
	store.PutNode(context.Background(), db.Node{ID: "master.example", Enabled: true})

	w := httptest.NewRecorder()
	installHandlers(cfg, http.NotFoundHandler())[InstallPath].
		ServeHTTP(w, tokenReq(InstallPath+"?id=new.example&token="+nodeToken, adminToken))

	if !strings.Contains(w.Body.String(), "MASTER_ADDR='master.example:443'") {
		t.Fatalf("адрес мастера без порта:\n%s", w.Body)
	}
}

// Чужой токен в скрипт не подставляется: узел с ним не смог бы представиться, а
// вылезло бы это только на первом стуке.
func TestInstallRejectsForeignToken(t *testing.T) {
	cfg, _, _, adminToken := installCfg(t)
	other, _ := auth.Generate()
	h := installHandlers(cfg, http.NotFoundHandler())[InstallPath]

	w := httptest.NewRecorder()
	h.ServeHTTP(w, tokenReq(InstallPath+"?id=new.example&token="+other, adminToken))
	if w.Code == http.StatusOK {
		t.Fatalf("чужой токен принят: %s", w.Body)
	}
}

// Незарегистрированный узел не установить: остальные не узнали бы о нём.
func TestInstallRequiresRegisteredNode(t *testing.T) {
	cfg, _, nodeToken, adminToken := installCfg(t)
	h := installHandlers(cfg, http.NotFoundHandler())[InstallPath]

	w := httptest.NewRecorder()
	h.ServeHTTP(w, tokenReq(InstallPath+"?id=нет-такого&token="+nodeToken, adminToken))
	if w.Code != http.StatusNotFound {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
}

// Проверку сертификата скрипт по умолчанию не отключает: качается исполняемый
// файл, который тут же запускается от root.
func TestInstallScriptVerifiesTLSByDefault(t *testing.T) {
	cfg, _, nodeToken, adminToken := installCfg(t)
	h := installHandlers(cfg, http.NotFoundHandler())[InstallPath]

	w := httptest.NewRecorder()
	h.ServeHTTP(w, tokenReq(InstallPath+"?id=new.example&token="+nodeToken, adminToken))
	script := w.Body.String()
	if strings.Contains(script, `INSECURE="-k"`) && !strings.Contains(script, "QD_INSECURE") {
		t.Fatal("проверка сертификата отключена без явного согласия")
	}
	if !strings.Contains(script, "QD_INSECURE") {
		t.Fatal("нет осознанного способа поставить узел со стендовым сертификатом")
	}
}

// Бинарь узла раздаётся только своим — иначе сборка утекает первому сканеру.
func TestNodeBinaryRequiresToken(t *testing.T) {
	cfg, _, _, adminToken := installCfg(t)
	site := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("витрина"))
	})
	h := installHandlers(cfg, site)[NodeBinaryPath]

	w := httptest.NewRecorder()
	h.ServeHTTP(w, tokenReq(NodeBinaryPath, ""))
	if !strings.Contains(w.Body.String(), "витрина") {
		t.Fatal("бинарь отдан без токена")
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, tokenReq(NodeBinaryPath, adminToken))
	if w.Code != http.StatusOK || w.Body.Len() == 0 {
		t.Fatalf("админу бинарь не отдан: статус %d", w.Code)
	}
}

// Регистрация сразу отдаёт готовую команду: токен показывается один раз, и
// собирать её потом руками будет не из чего.
func TestAddNodeReturnsInstallCommand(t *testing.T) {
	cfg, store := usersCfg(t)
	cfg.NodeID, cfg.Authority = "master.example", "master.example:443"

	w := httptest.NewRecorder()
	addNode(w, httptest.NewRequest(http.MethodPost, "/qd-admin/nodes",
		strings.NewReader(`{"id":"fresh.example"}`)), store, cfg)

	body := w.Body.String()
	if !strings.Contains(body, "install.sh") || !strings.Contains(body, "master.example") {
		t.Fatalf("нет команды установки: %s", body)
	}
	if !strings.Contains(body, "role=worker") {
		t.Fatalf("команда не исполняема: %s", body)
	}
}
