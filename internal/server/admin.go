package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
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
	sess := auth.SessionFrom(r.Context())
	if sess == nil {
		return false
	}
	role, _, ok := sess.Status()
	return ok && role == auth.RoleAdmin
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

// adminOutbounds — управление выходами узла по admin-токену. Изменения пишутся в
// БД и сразу применяются (Reload: поднять/закрыть цепочки, пересобрать роутер).
func adminOutbounds(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adminAllowed(r, cfg) || cfg.OutboundStore == nil || cfg.Outbounds == nil {
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			listOutbounds(w, r, cfg)
		case http.MethodPost:
			putOutbound(w, r, cfg)
		case http.MethodDelete:
			delOutbound(w, r, cfg)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

// outboundView — выход для отдачи в API. Токен НЕ отдаётся (секрет узла) — только
// флаг, задан ли он.
type outboundView struct {
	Label     string `json:"label"`
	Type      string `json:"type"`
	Addr      string `json:"addr,omitempty"`
	Authority string `json:"authority,omitempty"`
	HasToken  bool   `json:"has_token"`
	Enabled   bool   `json:"enabled"`
	Active    bool   `json:"active"` // сейчас в роутере (цепочка поднялась)
}

func listOutbounds(w http.ResponseWriter, r *http.Request, cfg Config) {
	rows, err := cfg.OutboundStore.ListOutbounds(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	active := map[string]bool{}
	for _, l := range cfg.Outbounds.Labels() {
		active[l] = true
	}
	views := []outboundView{{Label: "direct", Type: db.OutDirect, Enabled: true, Active: true}}
	for _, o := range rows {
		views = append(views, outboundView{
			Label: o.Label, Type: o.Type, Addr: o.Addr, Authority: o.Authority,
			HasToken: o.Token != "", Enabled: o.Enabled, Active: active[o.Label],
		})
	}
	writeJSON(w, views)
}

func putOutbound(w http.ResponseWriter, r *http.Request, cfg Config) {
	var in struct {
		Label     string `json:"label"`
		Type      string `json:"type"`
		Addr      string `json:"addr"`
		Authority string `json:"authority"`
		Token     string `json:"token"`
		Enabled   *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		http.Error(w, "битый JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if in.Label == "direct" {
		http.Error(w, "выход direct встроенный, не редактируется", http.StatusBadRequest)
		return
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	row := db.OutboundRow{
		Label: in.Label, Type: in.Type, Addr: in.Addr,
		Authority: in.Authority, Token: in.Token, Enabled: enabled,
	}
	if err := cfg.OutboundStore.PutOutbound(r.Context(), row); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	reloadAndReport(w, r, cfg)
}

func delOutbound(w http.ResponseWriter, r *http.Request, cfg Config) {
	label := r.URL.Query().Get("label")
	if label == "" || label == "direct" {
		http.Error(w, "нужен ?label (кроме direct)", http.StatusBadRequest)
		return
	}
	if err := cfg.OutboundStore.DeleteOutbound(r.Context(), label); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	reloadAndReport(w, r, cfg)
}

// reloadAndReport применяет изменения (поднять/закрыть цепочки, пересобрать
// роутер) и отдаёт свежий список.
func reloadAndReport(w http.ResponseWriter, r *http.Request, cfg Config) {
	if err := cfg.Outbounds.Reload(r.Context(), cfg.OutboundStore); err != nil {
		http.Error(w, "reload: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("admin: выходы обновлены → %v", cfg.Outbounds.Labels())
	listOutbounds(w, r, cfg)
}
