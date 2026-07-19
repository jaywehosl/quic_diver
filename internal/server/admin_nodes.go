package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
	"quicdiver/internal/server/decoy"
)

// adminNodes — реестр узлов сети по admin-токену: список, добавление, правка
// категории и тегов, вывод из сети.
//
// Аутбаундов здесь нет и не будет. Раньше связи между узлами задавались вручную
// («у A есть выход на B»), и цепочка была прибита к конфигу. Теперь узлы равны:
// каждый знает всех по реплике и ведёт транзит по метке в трафике, а реестр лишь
// отвечает на вопрос «кто есть в сети и кто из них вход, кто выход».
//
// Токен узла показывается РОВНО ОДИН раз — при добавлении. В базе только хеш,
// поэтому секрет остаётся у самого узла, а по сети расходятся одни хеши: утечка
// одного узла не открывает остальные.
func adminNodes(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adminAllowed(r, cfg) {
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		store, ok := sqliteOf(cfg.Store)
		if !ok {
			http.Error(w, "хранилище не поддерживает реестр узлов", http.StatusNotImplemented)
			return
		}
		switch r.Method {
		case http.MethodGet:
			listNodes(w, r, store, cfg)
		case http.MethodPost:
			addNode(w, r, store)
		case http.MethodPatch:
			patchNode(w, r, store)
		case http.MethodDelete:
			deleteNode(w, r, store)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

// nodeView — узел в терминах панели.
type nodeView struct {
	db.Node
	// Self — это мы сами (панель показывает узел, к которому подключена).
	Self bool `json:"self,omitempty"`
	// Alive — давал ли о себе знать недавно.
	Alive bool `json:"alive"`
}

// nodeAliveAfter — сколько молчания считаем смертью узла.
//
// Заметно больше периода heartbeat: короткий порог метил бы живые узлы мёртвыми
// на плохой связи, и балансировщик уводил бы трафик впустую.
const nodeAliveAfter = 3 * time.Minute

func listNodes(w http.ResponseWriter, r *http.Request, store *db.SQLite, cfg Config) {
	nodes, err := store.ListNodes(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]nodeView, 0, len(nodes))
	for _, n := range nodes {
		self := n.ID == cfg.NodeID
		out = append(out, nodeView{
			Node: n,
			Self: self,
			// Сам себя узел живым видит всегда: он отвечает на этот же запрос.
			// Иначе панель показывала бы мёртвым узел, который её и обслуживает.
			Alive: self || (!n.LastSeen.IsZero() && time.Since(n.LastSeen) < nodeAliveAfter),
		})
	}
	writeJSON(w, out)
}

// addNodeReq — тело POST: добавить узел в сеть.
//
// Пользователь вводит домен, всё остальное — необязательно: адрес выводится из
// домена, категорию можно назначить позже.
type addNodeReq struct {
	// ID — идентификатор узла, обычно его домен (напр. glitter.example).
	ID string `json:"id"`
	// Addr — host:port; пусто → <id>:443.
	Addr string `json:"addr,omitempty"`
	// SNI — имя для TLS; пусто → ID.
	SNI      string   `json:"sni,omitempty"`
	Label    string   `json:"label,omitempty"`
	Category string   `json:"category,omitempty"` // entry | exit
	Tags     []string `json:"tags,omitempty"`
}

func addNode(w http.ResponseWriter, r *http.Request, store *db.SQLite) {
	var req addNodeReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, "битый json", http.StatusBadRequest)
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		http.Error(w, "нужен id (домен узла)", http.StatusBadRequest)
		return
	}
	if req.Category != "" && req.Category != db.CategoryEntry && req.Category != db.CategoryExit {
		http.Error(w, "category: entry | exit", http.StatusBadRequest)
		return
	}
	if req.Addr == "" {
		req.Addr = req.ID + ":443"
	}

	// Свой токен на каждый узел: общий на всю сеть означал бы, что утечка одного
	// открывает все остальные.
	token, err := auth.Generate()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	node := db.Node{
		ID: req.ID, Label: req.Label, Category: req.Category, Tags: req.Tags,
		Addr: req.Addr, SNI: req.SNI, TokenHash: auth.Hash(token), Enabled: true,
	}
	if err := store.PutNode(r.Context(), node); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Токен нужен установщику узла и больше нигде: в базе только хеш.
	writeJSON(w, map[string]any{
		"node":  node,
		"token": token,
		"note":  "токен узла показывается один раз — он уйдёт в скрипт установки",
	})
}

// patchNodeReq — правка узла. Пустые поля не трогаются.
type patchNodeReq struct {
	ID       string   `json:"id"`
	Label    *string  `json:"label,omitempty"`
	Category *string  `json:"category,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Addr     *string  `json:"addr,omitempty"`
	SNI      *string  `json:"sni,omitempty"`
	Enabled  *bool    `json:"enabled,omitempty"`
	// Rotate — выдать узлу новый токен (старый перестанет действовать).
	Rotate bool `json:"rotate_token,omitempty"`
}

func patchNode(w http.ResponseWriter, r *http.Request, store *db.SQLite) {
	var req patchNodeReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "нужен id", http.StatusBadRequest)
		return
	}
	cur, err := store.NodeByID(r.Context(), req.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if req.Label != nil {
		cur.Label = *req.Label
	}
	if req.Category != nil {
		if *req.Category != "" && *req.Category != db.CategoryEntry && *req.Category != db.CategoryExit {
			http.Error(w, "category: entry | exit", http.StatusBadRequest)
			return
		}
		cur.Category = *req.Category
	}
	if req.Tags != nil {
		cur.Tags = req.Tags
	}
	if req.Addr != nil {
		cur.Addr = *req.Addr
	}
	if req.SNI != nil {
		cur.SNI = *req.SNI
	}
	if req.Enabled != nil {
		cur.Enabled = *req.Enabled
	}

	var fresh string
	if req.Rotate {
		fresh, err = auth.Generate()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cur.TokenHash = auth.Hash(fresh)
	} else {
		// Пустой хеш означает «не трогать»: правка метки не должна отзывать узлу
		// доступ.
		cur.TokenHash = ""
	}
	if err := store.PutNode(r.Context(), cur); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := map[string]any{"node": cur}
	if fresh != "" {
		resp["token"] = fresh
		resp["note"] = "новый токен узла: старый больше не действует, узел надо переустановить или обновить"
	}
	writeJSON(w, resp)
}

func deleteNode(w http.ResponseWriter, r *http.Request, store *db.SQLite) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "нужен ?id=", http.StatusBadRequest)
		return
	}
	if err := store.DeleteNode(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"deleted": id})
}
