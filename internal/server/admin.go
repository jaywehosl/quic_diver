package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/decoy"
	"quicdiver/internal/server/dns"
)

// adminDNS — управление DNS-резолвером узла по admin-токену: смена upstream,
// размера кеша, политики TTL и очистка. Заготовка под будущую веб-панель; уже
// сейчас закрывает аварийный сценарий «upstream сломался» без передеплоя узла.
//
// Доступ строго admin: обычный user/node сюда не должен — иначе клиент менял бы
// резолвер узла. Не-admin (и не авторизованный) → decoy, не выдавая эндпоинт.
func adminDNS(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adminAllowed(r, cfg) {
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, dnsState(cfg.Resolver))
		case http.MethodPost:
			applyDNS(w, r, cfg.Resolver)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

// adminAllowed — авторизована ли сессия под ролью admin.
func adminAllowed(r *http.Request, cfg Config) bool {
	if cfg.Store == nil {
		return false // без БД админить нечем и некого — эндпоинт закрыт
	}
	// Сессия, авторизованная админским токеном (qdadmin и прочие инструменты,
	// которые ходят к узлу напрямую).
	if sess := auth.SessionFrom(r.Context()); sess != nil {
		if role, _, ok := sess.Status(); ok && role == auth.RoleAdmin {
			return true
		}
	}
	// Либо админский токен в заголовке запроса.
	//
	// Так ходит панель: она живёт на клиенте (так в ТЗ) и проксирует запросы
	// через УЖЕ поднятую клиентскую связь, где сессия авторизована клиентским
	// токеном. Роль сессии там навсегда «user», и без этой проверки админ-API
	// из панели недоступен вовсе — сколько заголовков ни предъявляй.
	//
	// Токен едет внутри QUIC/TLS, снаружи невидим — тем же путём, что и
	// клиентский при авторизации сессии.
	if tok := auth.TokenFromRequest(r); tok != "" {
		if store, ok := sqliteOf(cfg.Store); ok {
			if info, err := store.Lookup(r.Context(), auth.Hash(tok)); err == nil {
				return info.Role == auth.RoleAdmin
			}
		}
	}
	return false
}

// dnsPatch — тело POST: заданные поля применяются, пустые игнорируются.
type dnsPatch struct {
	Upstream  *string `json:"upstream,omitempty"`   // https://.. | tls://host:port | udp://host:port
	CacheSize *int    `json:"cache_size,omitempty"` // пересоздаёт кеш
	TTLSecs   *int    `json:"ttl_override,omitempty"`
	MinTTL    *int    `json:"min_ttl,omitempty"`
	MaxTTL    *int    `json:"max_ttl,omitempty"`
	Flush     string  `json:"flush,omitempty"` // "expired" | "all"
}

// dnsStatus — ответ GET/POST: настройки + статистика кеша.
type dnsStatus struct {
	Upstream    string `json:"upstream"`
	CacheSize   int    `json:"cache_size"`
	TTLOverride int    `json:"ttl_override"`
	MinTTL      int    `json:"min_ttl"`
	MaxTTL      int    `json:"max_ttl"`
	Cacheused   int    `json:"cache_used"`
	Hits        uint64 `json:"hits"`
	Misses      uint64 `json:"misses"`
	Flushed     int    `json:"flushed,omitempty"`
}

func dnsState(r *dns.Resolver) dnsStatus {
	s := r.Settings()
	used, hits, misses := r.Cache().Stats()
	return dnsStatus{
		Upstream:    s.Upstream,
		CacheSize:   s.CacheSize,
		TTLOverride: int(s.TTLOverride / time.Second),
		MinTTL:      int(s.MinTTL / time.Second),
		MaxTTL:      int(s.MaxTTL / time.Second),
		Cacheused:   used,
		Hits:        hits,
		Misses:      misses,
	}
}

// applyDNS применяет патч к резолверу. Смена upstream — самое ценное: чинит
// аварию (сломался upstream) на лету, без рестарта узла.
func applyDNS(w http.ResponseWriter, r *http.Request, res *dns.Resolver) {
	var p dnsPatch
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&p); err != nil {
		http.Error(w, "битый JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if p.Upstream != nil {
		up, err := dns.ParseUpstream(*p.Upstream)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		res.SetUpstream(up)
		// Кеш старого резолвера невалиден: другой upstream отдаёт другие адреса
		// (особенно smart-DNS вроде xbox-dns — разблокировочные ≠ обычным). Иначе
		// после смены висели бы ответы прежнего резолвера до истечения TTL.
		n := res.Cache().FlushAll()
		log.Printf("admin: upstream DNS → %s (кеш сброшен: %d)", up, n)
	}
	if p.CacheSize != nil {
		res.Resize(*p.CacheSize)
		log.Printf("admin: размер кеша DNS → %d", *p.CacheSize)
	}
	if p.TTLSecs != nil || p.MinTTL != nil || p.MaxTTL != nil {
		cur := res.Settings()
		ov, mn, mx := cur.TTLOverride, cur.MinTTL, cur.MaxTTL
		if p.TTLSecs != nil {
			ov = time.Duration(*p.TTLSecs) * time.Second
		}
		if p.MinTTL != nil {
			mn = time.Duration(*p.MinTTL) * time.Second
		}
		if p.MaxTTL != nil {
			mx = time.Duration(*p.MaxTTL) * time.Second
		}
		res.SetTTL(ov, mn, mx)
		log.Printf("admin: TTL DNS override=%v min=%v max=%v", ov, mn, mx)
	}

	st := dnsState(res)
	switch p.Flush {
	case "all":
		st.Flushed = res.Cache().FlushAll()
		log.Printf("admin: кеш DNS очищен полностью (%d)", st.Flushed)
	case "expired":
		st.Flushed = res.Cache().FlushExpired()
		log.Printf("admin: кеш DNS — мягкая очистка (%d)", st.Flushed)
	}
	writeJSON(w, st)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
