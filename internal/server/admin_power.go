package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"quicdiver/internal/server/db"
	"quicdiver/internal/server/decoy"
)

// maxSnapshotSize — потолок принимаемого снимка базы. Клиентов и токенов на
// узле немного, база сжатая; всё, что заметно больше, — не наш файл.
const maxSnapshotSize = 256 << 20

// adminBackup — скачать снимок базы (GET) и загрузить его обратно (POST).
//
// Скачивание и загрузку делает АДМИНИСТРАТОР со своей машины — узел сам никуда
// файлы не отправляет. Так резервная копия остаётся у человека, а не расползается
// по инфраструктуре.
//
// Снимок берётся `VACUUM INTO`, а не копированием файла: база живёт в WAL-режиме,
// и на диске она может быть почти пустой, пока свежие записи ещё в журнале.
func adminBackup(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adminAllowed(r, cfg) {
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		store, ok := sqliteOf(cfg.Store)
		if !ok {
			http.Error(w, "хранилище не поддерживает снимки", http.StatusNotImplemented)
			return
		}
		switch r.Method {
		case http.MethodGet:
			sendBackup(w, r, store)
		case http.MethodPost:
			receiveRestore(w, r, store)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

func sendBackup(w http.ResponseWriter, r *http.Request, store *db.SQLite) {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("qd-backup-%d.db", time.Now().UnixNano()))
	defer os.Remove(tmp)

	if err := store.Backup(r.Context(), tmp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f, err := os.Open(tmp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	name := fmt.Sprintf("qd-backup-%s.db", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if st, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", fmt.Sprint(st.Size()))
	}
	_, _ = io.Copy(w, f)
}

// receiveRestore принимает снимок и откладывает его до перезапуска узла.
//
// Заменить открытую базу на ходу нельзя, поэтому файл кладётся рядом и
// применяется следующим стартом. Перезапуск администратор делает отдельно и
// осознанно (см. adminPower) — сам по себе аплоад никого не отключает.
func receiveRestore(w http.ResponseWriter, r *http.Request, store *db.SQLite) {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("qd-restore-%d.db", time.Now().UnixNano()))
	f, err := os.Create(tmp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n, err := io.Copy(f, io.LimitReader(r.Body, maxSnapshotSize))
	f.Close()
	if err != nil {
		os.Remove(tmp)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if n == 0 {
		os.Remove(tmp)
		http.Error(w, "пустое тело запроса", http.StatusBadRequest)
		return
	}
	// Проверка до подмены: подсунутый мусор оставил бы узел без токенов, то есть
	// без клиентов.
	if err := db.StageRestore(r.Context(), store.Path(), tmp); err != nil {
		os.Remove(tmp)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("восстановление базы: снимок принят (%d байт), применится при следующем запуске", n)
	writeJSON(w, map[string]any{
		"staged": true,
		"bytes":  n,
		"note":   "снимок принят; применится при следующем запуске узла (перезапустите его через /qd-admin/power)",
	})
}

// powerReq — тело запроса управления питанием.
type powerReq struct {
	// Action: restart — перезапуск серверной части; reboot/shutdown — машины.
	Action string `json:"action"`
	// Confirm — обязательное подтверждение. Без него ничего не выполняется:
	// случайный POST не должен уводить узел в перезагрузку вместе со всеми
	// клиентами на нём.
	Confirm bool `json:"confirm"`
}

// adminPower — перезапуск серверной части и питание машины.
//
// Нужен, чтобы не лезть по ssh ради рестарта (и чтобы применить восстановленную
// базу). Операции необратимые в том смысле, что рвут все живые туннели узла,
// поэтому требуют явного confirm.
func adminPower(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adminAllowed(r, cfg) {
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req powerReq
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, "битый json", http.StatusBadRequest)
			return
		}
		if !req.Confirm {
			http.Error(w, `нужно {"confirm":true} — операция оборвёт все туннели узла`, http.StatusBadRequest)
			return
		}

		var cmd string
		switch req.Action {
		case "restart":
			// Отвечаем ДО выхода: после него соединение уже не доживёт.
			writeJSON(w, map[string]any{"action": "restart", "note": "узел перезапускается"})
			log.Print("перезапуск узла по команде администратора")
			go func() {
				time.Sleep(500 * time.Millisecond) // дать ответу уйти
				// Выходим с ненулевым кодом: systemd с Restart=always поднимет
				// заново. Без такого юнита узел останется погашенным — это
				// осознанно, самому себя воскресить процесс не может.
				os.Exit(1)
			}()
			return
		case "reboot":
			cmd = "reboot"
		case "shutdown":
			cmd = "poweroff"
		default:
			http.Error(w, "action: restart | reboot | shutdown", http.StatusBadRequest)
			return
		}

		if _, err := exec.LookPath("systemctl"); err != nil {
			http.Error(w, "systemctl недоступен на этой машине", http.StatusNotImplemented)
			return
		}
		writeJSON(w, map[string]any{"action": req.Action, "note": "команда отдана системе"})
		log.Printf("%s машины по команде администратора", req.Action)
		go func() {
			time.Sleep(500 * time.Millisecond)
			if out, err := exec.Command("systemctl", cmd).CombinedOutput(); err != nil {
				log.Printf("%s не удался: %v (%s)", cmd, err, out)
			}
		}()
	})
}
