package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
)

// SubscriptionPath — подписка клиента: узлы сети и собственные лимиты.
const SubscriptionPath = "/qd-subscription"

// subscription — всё, что клиент узнаёт о сети и о себе.
//
// Отдаётся ТОЛЬКО по туннелю авторизованному клиенту. Публичной страницы
// подписки у нас нет намеренно: доступная всем ссылка парсится, блокируется и
// позволяет перебором узнать, какие узлы вообще существуют. Здесь же данные
// приезжают тому, кто уже доказал право их получить.
type subscription struct {
	// Client — кто спрашивает: имя, срок, лимиты. Клиент показывает это в
	// панели, чтобы человек знал, сколько у него осталось, не спрашивая.
	Client clientInfo `json:"client"`
	// Entries — КУДА подключаться, включая резервные точки.
	//
	// Главная ценность подписки: список живёт на узле, поэтому смена или
	// добавление точки входа доезжает до клиента само. Без этого адрес
	// вписывается руками, и блокировка одного IP выключает всех.
	Entries []entryInfo `json:"entries"`
	// Exits — метки для правил маршрутизации (то же, что отдаёт /qd-exits).
	Exits []exitView `json:"exits"`
	// PollSeconds — как часто обновляться. Задаёт сеть, а не клиент: узел
	// знает, насколько часто у него меняется состав.
	PollSeconds int `json:"poll_seconds"`
	// At — когда собрано.
	At time.Time `json:"at"`
}

type clientInfo struct {
	Label     string     `json:"label,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Quota     db.Quota   `json:"quota"`
	Devices   int        `json:"devices"`
}

// entryInfo — точка входа.
//
// Адрес и SNI разделены намеренно: идём на голый IP, представляемся доменом.
// DNS в подключении не участвует, а сертификат остаётся валидным — значит
// блокировка домена точку входа не выключает.
type entryInfo struct {
	Addr  string `json:"addr"`
	SNI   string `json:"sni,omitempty"`
	Label string `json:"label,omitempty"`
	Alive bool   `json:"alive"`
}

// subscriptionPoll — как часто клиенту обновлять подписку.
//
// Час: состав сети меняется редко, а список нужен заранее — к моменту, когда
// текущая точка входа ляжет, резервные уже должны быть у клиента.
const subscriptionPoll = 3600

// serveSubscription отдаёт клиенту его подписку.
func serveSubscription(cfg Config, site http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sessionAllowed(r.Context(), cfg) {
			site.ServeHTTP(w, r)
			return
		}
		store, ok := sqliteOf(cfg.Store)
		if !ok {
			http.Error(w, "хранилище не поддерживает подписку", http.StatusNotImplemented)
			return
		}
		sub := subscription{PollSeconds: subscriptionPoll, At: time.Now()}

		// О себе — только тому, чей это токен. Хеш берём из сессии, а не из
		// запроса: запрос мог бы назвать чужой.
		if sess := auth.SessionFrom(r.Context()); sess != nil {
			if _, hash, ok := sess.Status(); ok && hash != "" {
				sub.Client = clientSummary(r, store, hash)
			}
		}

		nodes, err := store.ListNodes(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sub.Entries = entriesOf(nodes, cfg)
		sub.Exits = exitsOf(nodes, cfg)
		writeJSON(w, sub)
	})
}

func clientSummary(r *http.Request, store *db.SQLite, hash string) clientInfo {
	var c clientInfo
	if row, err := store.TokenRowByHash(r.Context(), hash); err == nil {
		c.Label = row.Label
		if !row.ExpiresAt.IsZero() {
			t := row.ExpiresAt
			c.ExpiresAt = &t
		}
	}
	if q, err := store.QuotaOf(r.Context(), hash); err == nil {
		c.Quota = q
	}
	if devs, err := store.ListDevices(r.Context(), hash); err == nil {
		c.Devices = len(devs)
	}
	return c
}

// entriesOf — узлы, к которым клиент может подключиться.
//
// Берём входные и те, у кого категория не проставлена: узел без категории —
// это обычно единственный узел небольшой сети, и не дать по нему подключиться
// значило бы оставить клиента без точки входа вовсе.
func entriesOf(nodes []db.Node, cfg Config) []entryInfo {
	out := make([]entryInfo, 0, len(nodes))
	for _, n := range nodes {
		if !n.Enabled || n.Addr == "" {
			continue
		}
		if n.Category == db.CategoryExit {
			continue // выходной узел точкой входа не служит
		}
		self := n.ID == cfg.NodeID
		out = append(out, entryInfo{
			Addr: n.Addr, SNI: n.Authority(), Label: n.Label,
			Alive: self || (!n.LastSeen.IsZero() && time.Since(n.LastSeen) < nodeAliveAfter),
		})
	}
	// Узла нет в собственном реестре — обычная одиночная установка: никто себя
	// не регистрировал, потому что не с кем было объединяться. Отдать пустой
	// список значило бы лишить клиента даже той точки, через которую он сейчас
	// и спрашивает.
	if len(out) == 0 {
		if self := selfEntry(cfg); self.Addr != "" {
			out = append(out, self)
		}
	}
	return out
}

// selfEntry — этот узел как точка входа.
//
// Порт берётся из адреса прослушивания: authority у узла обычно без порта
// (домен), а клиенту нужен адрес подключения целиком.
func selfEntry(cfg Config) entryInfo {
	host := cfg.NodeID
	if host == "" {
		host = cfg.Authority
	}
	if host == "" {
		return entryInfo{}
	}
	addr := cfg.Authority
	if _, _, err := net.SplitHostPort(addr); err != nil {
		port := "443"
		if _, p, err := net.SplitHostPort(cfg.Listen); err == nil && p != "" {
			port = p
		}
		addr = net.JoinHostPort(host, port)
	}
	return entryInfo{Addr: addr, SNI: host, Label: cfg.NodeID, Alive: true}
}

// bundleLink — ссылка начальной настройки клиента.
//
// Формат общий с клиентом (internal/client/config): схема qd:// и base64 от
// компактного JSON. Собирается здесь, а не на клиенте, потому что список точек
// входа знает узел.
func bundleFor(ctx context.Context, store *db.SQLite, cfg Config, token string) string {
	type entry struct {
		A string `json:"a"`
		S string `json:"s,omitempty"`
		L string `json:"l,omitempty"`
	}
	type bundle struct {
		V int     `json:"v"`
		T string  `json:"t"`
		E []entry `json:"e"`
		N string  `json:"n,omitempty"`
	}

	b := bundle{V: 1, T: token, N: cfg.NodeID}
	if nodes, err := store.ListNodes(ctx); err == nil {
		for _, e := range entriesOf(nodes, cfg) {
			b.E = append(b.E, entry{A: e.Addr, S: e.SNI, L: e.Label})
		}
	}
	// Узла нет в реестре (одиночная установка, никто себя не регистрировал) —
	// берём собственный адрес: иначе ссылка получилась бы без точки входа и
	// была бы бесполезна.
	if len(b.E) == 0 && cfg.Authority != "" {
		b.E = append(b.E, entry{A: cfg.Authority, S: cfg.NodeID})
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return ""
	}
	return "qd://" + base64.RawURLEncoding.EncodeToString(raw)
}
