package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
)

// Снимок доступен только админу и приходит целым файлом базы.
func TestBackupDownload(t *testing.T) {
	cfg, store := usersCfg(t)
	store.PutToken(context.Background(), auth.Hash("к1"), auth.RoleUser, "к1")
	h := adminBackup(cfg)

	// не-админ не должен даже узнать, что эндпоинт есть
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(http.MethodGet, "/qd-admin/backup", "", auth.RoleUser))
	if ct := w.Header().Get("Content-Type"); strings.Contains(ct, "octet-stream") {
		t.Fatal("не-админ скачал базу")
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, req(http.MethodGet, "/qd-admin/backup", "", auth.RoleAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("статус %d: %s", w.Code, w.Body)
	}
	if !strings.HasPrefix(w.Body.String(), "SQLite format 3") {
		t.Fatalf("отдан не файл базы: %.30q", w.Body.String())
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "qd-backup-") {
		t.Fatalf("Content-Disposition = %q", cd)
	}
}

// Скачанный снимок принимается обратно и откладывается до перезапуска — на ходу
// подменять открытую базу нельзя.
func TestRestoreStagesSnapshot(t *testing.T) {
	cfg, store := usersCfg(t)
	ctx := context.Background()
	store.PutToken(ctx, auth.Hash("живой"), auth.RoleUser, "живой")

	// Снимаем снимок текущей базы через API.
	w := httptest.NewRecorder()
	adminBackup(cfg).ServeHTTP(w, req(http.MethodGet, "/qd-admin/backup", "", auth.RoleAdmin))
	snapshot := w.Body.Bytes()

	// Загружаем обратно.
	r := httptest.NewRequest(http.MethodPost, "/qd-admin/backup", bytes.NewReader(snapshot))
	sctx := auth.NewSessionContext(r.Context())
	auth.SessionFrom(sctx).Authorize(auth.RoleAdmin, "hash")
	w = httptest.NewRecorder()
	adminBackup(cfg).ServeHTTP(w, r.WithContext(sctx))
	if w.Code != http.StatusOK {
		t.Fatalf("загрузка: статус %d, тело %s", w.Code, w.Body)
	}
	if _, err := os.Stat(store.Path() + db.RestoreSuffix); err != nil {
		t.Fatalf("снимок не отложен: %v", err)
	}
	// Рабочая база на месте: аплоад сам по себе никого не отключает.
	if _, err := store.Lookup(ctx, auth.Hash("живой")); err != nil {
		t.Fatalf("рабочая база пострадала от загрузки: %v", err)
	}
}

// Мусор вместо базы отвергается: иначе узел остался бы без токенов, то есть без
// клиентов.
func TestRestoreRejectsGarbage(t *testing.T) {
	cfg, store := usersCfg(t)
	r := httptest.NewRequest(http.MethodPost, "/qd-admin/backup", strings.NewReader("совсем не база"))
	sctx := auth.NewSessionContext(r.Context())
	auth.SessionFrom(sctx).Authorize(auth.RoleAdmin, "hash")
	w := httptest.NewRecorder()
	adminBackup(cfg).ServeHTTP(w, r.WithContext(sctx))

	if w.Code == http.StatusOK {
		t.Fatal("мусор принят как снимок базы")
	}
	if _, err := os.Stat(store.Path() + db.RestoreSuffix); err == nil {
		t.Fatal("мусор отложен к применению")
	}
}

// Пустое тело — тоже отказ (случайный POST не должен ничего готовить).
func TestRestoreRejectsEmptyBody(t *testing.T) {
	cfg, _ := usersCfg(t)
	r := httptest.NewRequest(http.MethodPost, "/qd-admin/backup", strings.NewReader(""))
	sctx := auth.NewSessionContext(r.Context())
	auth.SessionFrom(sctx).Authorize(auth.RoleAdmin, "hash")
	w := httptest.NewRecorder()
	adminBackup(cfg).ServeHTTP(w, r.WithContext(sctx))
	if w.Code == http.StatusOK {
		t.Fatal("пустое тело принято")
	}
}

// Без confirm ничего не выполняется: случайный POST не должен уводить узел в
// перезагрузку вместе со всеми клиентами на нём.
func TestPowerRequiresConfirm(t *testing.T) {
	cfg, _ := usersCfg(t)
	h := adminPower(cfg)

	for _, body := range []string{`{"action":"reboot"}`, `{"action":"shutdown","confirm":false}`} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req(http.MethodPost, "/qd-admin/power", body, auth.RoleAdmin))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("тело %s дало статус %d, ожидался отказ", body, w.Code)
		}
	}
}

// Неизвестное действие отвергается — опечатка не должна ничего запускать.
func TestPowerRejectsUnknownAction(t *testing.T) {
	cfg, _ := usersCfg(t)
	w := httptest.NewRecorder()
	adminPower(cfg).ServeHTTP(w, req(http.MethodPost, "/qd-admin/power",
		`{"action":"снести-всё","confirm":true}`, auth.RoleAdmin))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("статус %d, ожидался отказ", w.Code)
	}
}

// Питание — только админ; прочим даже не видно, что эндпоинт существует.
func TestPowerRequiresAdmin(t *testing.T) {
	cfg, _ := usersCfg(t)
	for _, role := range []auth.Role{"", auth.RoleUser, auth.RoleNode} {
		w := httptest.NewRecorder()
		adminPower(cfg).ServeHTTP(w, req(http.MethodPost, "/qd-admin/power",
			`{"action":"reboot","confirm":true}`, role))
		if ct := w.Header().Get("Content-Type"); strings.Contains(ct, "application/json") {
			t.Fatalf("роль %q добралась до управления питанием", role)
		}
	}
}

// Отложенный снимок подхватывается следующим стартом, прежняя база сохраняется.
func TestPendingRestoreAppliedOnStart(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "qd.db")
	ctx := context.Background()

	s, _ := db.Open(live)
	s.PutToken(ctx, auth.Hash("старый"), auth.RoleUser, "старый")
	s.Close()

	other := filepath.Join(dir, "other.db")
	o, _ := db.Open(other)
	o.PutToken(ctx, auth.Hash("новый"), auth.RoleUser, "новый")
	snap := filepath.Join(dir, "snap.db")
	o.Backup(ctx, snap)
	o.Close()

	if err := db.StageRestore(ctx, live, snap); err != nil {
		t.Fatal(err)
	}
	applied, err := db.ApplyPendingRestore(live)
	if err != nil || !applied {
		t.Fatalf("applied=%v err=%v", applied, err)
	}
	s2, _ := db.Open(live)
	defer s2.Close()
	if _, err := s2.Lookup(ctx, auth.Hash("новый")); err != nil {
		t.Fatalf("снимок не применился: %v", err)
	}
	if _, err := os.Stat(live + ".prev"); err != nil {
		t.Fatal("прежняя база не сохранена — откатиться некуда")
	}
}
