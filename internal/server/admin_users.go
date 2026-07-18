package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
	"quicdiver/internal/server/decoy"
)

// adminUsers — учёт клиентов по admin-токену: список, выдача и отзыв токенов,
// лимиты, устройства, живые сессии, потраченный трафик.
//
// Раньше всё это жило только в CLI узла (`-add-user`), то есть требовало ssh.
// Панель управления должна уметь то же самое удалённо — и через туннель, а не
// отдельным портом, чтобы наружу по-прежнему торчал один HTTPS.
//
// Открытый токен показывается РОВНО ОДИН раз — в ответе на создание. В базе
// лежит только хеш, восстановить его нельзя: утечка реплики не выдаёт доступов.
func adminUsers(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adminAllowed(r, cfg) {
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		store, ok := cfg.Store.(*db.SQLite)
		if !ok {
			http.Error(w, "хранилище не поддерживает учёт", http.StatusNotImplemented)
			return
		}
		switch r.Method {
		case http.MethodGet:
			listUsers(w, r, store)
		case http.MethodPost:
			createUser(w, r, store)
		case http.MethodPatch:
			patchUser(w, r, store)
		case http.MethodDelete:
			revokeUser(w, r, store)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

// userView — клиент в терминах панели.
type userView struct {
	Hash      string       `json:"hash"` // хеш = идентификатор клиента для API
	Label     string       `json:"label"`
	Role      string       `json:"role"`
	CreatedAt time.Time    `json:"created_at"`
	Revoked   bool         `json:"revoked"`
	ExpiresAt *time.Time   `json:"expires_at,omitempty"`
	Limits    userLimits   `json:"limits"`
	Traffic   db.Traffic   `json:"traffic"`
	Devices   []db.Device  `json:"devices,omitempty"`
	Sessions  []db.Session `json:"sessions,omitempty"`
}

type userLimits struct {
	Devices  int `json:"devices"`  // 0 — без ограничения
	Sessions int `json:"sessions"` // 0 — без ограничения
}

// listUsers отдаёт клиентов. ?hash=... — подробности одного (с устройствами и
// сессиями), без параметра — список без тяжёлых деталей.
func listUsers(w http.ResponseWriter, r *http.Request, store *db.SQLite) {
	ctx := r.Context()
	if hash := r.URL.Query().Get("hash"); hash != "" {
		u, err := userDetail(ctx, store, hash)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, u)
		return
	}
	rows, err := store.ListTokens(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]userView, 0, len(rows))
	for _, t := range rows {
		out = append(out, tokenToView(t))
	}
	writeJSON(w, out)
}

func userDetail(ctx context.Context, store *db.SQLite, hash string) (userView, error) {
	t, err := store.TokenRowByHash(ctx, hash)
	if err != nil {
		return userView{}, err
	}
	v := tokenToView(t)
	if v.Devices, err = store.ListDevices(ctx, hash); err != nil {
		return userView{}, err
	}
	if v.Sessions, err = store.ListSessions(ctx, hash); err != nil {
		return userView{}, err
	}
	if v.Traffic, err = store.TrafficOf(ctx, hash); err != nil {
		return userView{}, err
	}
	return v, nil
}

func tokenToView(t db.TokenRow) userView {
	v := userView{
		Hash: t.Hash, Label: t.Label, Role: string(t.Role),
		CreatedAt: t.CreatedAt, Revoked: t.Revoked,
		Limits: userLimits{Devices: t.LimitDevices, Sessions: t.LimitSessions},
	}
	if !t.ExpiresAt.IsZero() {
		e := t.ExpiresAt
		v.ExpiresAt = &e
	}
	return v
}

// createReq — тело POST: завести клиента.
type createReq struct {
	Label         string `json:"label"`
	Role          string `json:"role,omitempty"`           // по умолчанию user
	LimitDevices  int    `json:"limit_devices,omitempty"`  // 0 — без ограничения
	LimitSessions int    `json:"limit_sessions,omitempty"` // 0 — без ограничения
	ExpiresInDays int    `json:"expires_in_days,omitempty"`
}

func createUser(w http.ResponseWriter, r *http.Request, store *db.SQLite) {
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "битый json", http.StatusBadRequest)
		return
	}
	role := auth.Role(strings.TrimSpace(req.Role))
	if role == "" {
		role = auth.RoleUser
	}
	if role != auth.RoleUser && role != auth.RoleAdmin && role != auth.RoleNode {
		http.Error(w, "неизвестная роль", http.StatusBadRequest)
		return
	}
	token, err := auth.Generate()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hash := auth.Hash(token)
	if err := store.PutToken(r.Context(), hash, role, req.Label); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var expires time.Time
	if req.ExpiresInDays > 0 {
		expires = time.Now().AddDate(0, 0, req.ExpiresInDays)
	}
	if err := store.SetTokenLimits(r.Context(), hash, req.LimitDevices, req.LimitSessions, expires); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Открытый токен виден один раз: в базе только хеш, повторно не показать.
	writeJSON(w, map[string]any{
		"token": token,
		"hash":  hash,
		"note":  "токен показывается один раз — сохраните его сейчас",
	})
}

// patchReq — тело PATCH: правка лимитов/метки.
type patchReq struct {
	Hash          string  `json:"hash"`
	Label         *string `json:"label,omitempty"`
	LimitDevices  *int    `json:"limit_devices,omitempty"`
	LimitSessions *int    `json:"limit_sessions,omitempty"`
	ExpiresInDays *int    `json:"expires_in_days,omitempty"` // 0 — снять срок
	// Device — отзыв/возврат конкретного устройства клиента.
	Device        string `json:"device,omitempty"`
	DeviceRevoked *bool  `json:"device_revoked,omitempty"`
}

func patchUser(w http.ResponseWriter, r *http.Request, store *db.SQLite) {
	var req patchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Hash == "" {
		http.Error(w, "нужен hash", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	cur, err := store.TokenRowByHash(ctx, req.Hash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Отзыв устройства — точечная операция, токен не трогаем: увели одну машину,
	// остальные должны продолжать работать.
	if req.Device != "" && req.DeviceRevoked != nil {
		if err := store.RevokeDevice(ctx, req.Hash, req.Device, *req.DeviceRevoked); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	}
	if req.Label != nil {
		if err := store.PutToken(ctx, req.Hash, cur.Role, *req.Label); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if req.LimitDevices != nil || req.LimitSessions != nil || req.ExpiresInDays != nil {
		limD, limS, exp := cur.LimitDevices, cur.LimitSessions, cur.ExpiresAt
		if req.LimitDevices != nil {
			limD = *req.LimitDevices
		}
		if req.LimitSessions != nil {
			limS = *req.LimitSessions
		}
		if req.ExpiresInDays != nil {
			if *req.ExpiresInDays <= 0 {
				exp = time.Time{}
			} else {
				exp = time.Now().AddDate(0, 0, *req.ExpiresInDays)
			}
		}
		if err := store.SetTokenLimits(ctx, req.Hash, limD, limS, exp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	u, err := userDetail(ctx, store, req.Hash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, u)
}

// revokeUser отзывает токен целиком (?hash=...).
//
// Отзыв — tombstone, а не удаление строки: в реплицируемой сети исчезнувшую
// запись не отличить от «ещё не доехала», и отозванный доступ воскрес бы.
func revokeUser(w http.ResponseWriter, r *http.Request, store *db.SQLite) {
	hash := r.URL.Query().Get("hash")
	if hash == "" {
		http.Error(w, "нужен ?hash=", http.StatusBadRequest)
		return
	}
	if err := store.Revoke(r.Context(), hash); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	// Живые сессии отозванного клиента снимаем сразу: иначе он доработал бы до
	// собственного обрыва, хотя доступ уже закрыт.
	sessions, _ := store.ListSessions(r.Context(), hash)
	for _, s := range sessions {
		_ = store.CloseSession(r.Context(), s.ID)
	}
	writeJSON(w, map[string]any{"revoked": hash, "sessions_closed": len(sessions)})
}

// adminSessions — живые сессии сети (по admin-токену): кто подключён, откуда,
// сколько прокачал. Без ?hash= отдаёт все.
func adminSessions(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adminAllowed(r, cfg) {
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		store, ok := cfg.Store.(*db.SQLite)
		if !ok {
			http.Error(w, "хранилище не поддерживает учёт", http.StatusNotImplemented)
			return
		}
		switch r.Method {
		case http.MethodGet:
			sessions, err := store.ListSessions(r.Context(), r.URL.Query().Get("hash"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, sessions)
		case http.MethodDelete:
			id := r.URL.Query().Get("id")
			if id == "" {
				http.Error(w, "нужен ?id=", http.StatusBadRequest)
				return
			}
			if err := store.CloseSession(r.Context(), id); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]any{"closed": id})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}
