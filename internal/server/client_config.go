package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
)

// ClientConfigBackupPath — эндпоинт резервного копирования настроек клиента
const ClientConfigBackupPath = "/qd-backup"

// BackupConfigResponse — ответ сервера на запрос состояния бэкапа
type BackupConfigResponse struct {
	Exists     bool      `json:"exists"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
	ConfigJSON string    `json:"config_json,omitempty"`
}

// serveClientConfigBackup обрабатывает GET (проверка/получение бэкапа) и POST (сохранение бэкапа)
func serveClientConfigBackup(cfg Config, site http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		store, ok := sqliteOf(cfg.Store)
		if !ok {
			http.Error(w, "хранилище не поддерживает бэкап", http.StatusNotImplemented)
			return
		}

		var hash string
		if sess := auth.SessionFrom(r.Context()); sess != nil && sess.Authorized() {
			if _, h, ok := sess.Status(); ok && h != "" {
				hash = h
			}
		}
		if hash == "" {
			tok := auth.TokenFromRequest(r)
			if tok != "" {
				h := auth.Hash(tok)
				if _, err := store.Lookup(r.Context(), h); err == nil {
					hash = h
				}
			}
		}
		if hash == "" {
			site.ServeHTTP(w, r)
			return
		}

		switch r.Method {
		case http.MethodGet:
			cfgJSON, updated, err := store.GetClientConfig(r.Context(), hash)
			if errors.Is(err, db.ErrNotFound) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(BackupConfigResponse{Exists: false})
				return
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(BackupConfigResponse{
				Exists:     true,
				UpdatedAt:  updated,
				ConfigJSON: cfgJSON,
			})

		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil || len(body) == 0 {
				http.Error(w, "пустое тело запроса", http.StatusBadRequest)
				return
			}
			if err := store.PutClientConfig(r.Context(), hash, string(body)); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "message": "бэкап сохранён на сервере"})

		default:
			http.Error(w, "метод не поддерживается", http.StatusMethodNotAllowed)
		}
	})
}
