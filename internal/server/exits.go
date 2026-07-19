package server

import (
	"net/http"
	"quicdiver/internal/server/db"
	"sort"
	"time"
)

// exitView — куда клиент может направить трафик.
//
// Это и есть метка для Qd-Route: либо идентификатор узла, либо auto:<тег> —
// «любой живой узел с таким тегом, выбирает сеть». Секретов здесь нет: ни
// адресов подключения, ни хешей, только то, из чего строится правило.
type exitView struct {
	// Route — что класть в метку правила.
	Route string `json:"route"`
	// Label — человеческое имя для интерфейса.
	Label string `json:"label,omitempty"`
	// Category — entry | exit.
	Category string `json:"category,omitempty"`
	// Tags — теги узла; по ним же собираются auto-метки.
	Tags []string `json:"tags,omitempty"`
	// Auto — метка не на конкретный узел, а на категорию/тег.
	Auto bool `json:"auto,omitempty"`
	// Alive — узел давал о себе знать недавно. Для auto — есть ли хоть один живой.
	Alive bool `json:"alive"`
	// Self — это узел, к которому клиент подключён.
	Self bool `json:"self,omitempty"`
}

// serveExits публикует список выходов клиенту.
//
// Мёртвые узлы не прячем: клиент вправе оставить правило на узел, который
// временно лёг, — трафик всё равно выйдет (недостижимый выход не глушит флоу),
// а видеть, что выход мёртв, полезнее, чем обнаружить исчезновение правила.
func serveExits(cfg Config, decoy http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sessionAllowed(r.Context(), cfg) {
			decoy.ServeHTTP(w, r)
			return
		}
		store, ok := sqliteOf(cfg.Store)
		if !ok {
			http.Error(w, "хранилище не поддерживает реестр узлов", http.StatusNotImplemented)
			return
		}
		nodes, err := store.ListNodes(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, exitsOf(nodes, cfg))
	})
}

// exitsOf собирает метки выходов из реестра.
//
// Общая для /qd-exits и для подписки: клиент получает один и тот же список
// обоими путями, и разъехаться они не могут.
func exitsOf(nodes []db.Node, cfg Config) []exitView {
	// direct первым: это выход без метки, «наружу здесь же».
	out := []exitView{{Route: "direct", Label: "без цепочки", Alive: true}}
	// autoAlive — есть ли живой узел под тегом/категорией.
	autoAlive := map[string]bool{}

	for _, n := range nodes {
		if !n.Enabled {
			continue // выведенный из сети узел клиенту предлагать незачем
		}
		self := n.ID == cfg.NodeID
		alive := self || (!n.LastSeen.IsZero() && time.Since(n.LastSeen) < nodeAliveAfter)
		out = append(out, exitView{
			Route: n.ID, Label: n.Label, Category: n.Category,
			Tags: n.Tags, Alive: alive, Self: self,
		})
		for _, tag := range append(n.Tags, n.Category) {
			if tag == "" {
				continue
			}
			autoAlive[tag] = autoAlive[tag] || alive
		}
	}

	// auto-метки: правило «в Германию» не должно ломаться, когда конкретный
	// немецкий узел меняют на другой.
	autos := make([]string, 0, len(autoAlive))
	for tag := range autoAlive {
		autos = append(autos, tag)
	}
	sort.Strings(autos)
	for _, tag := range autos {
		out = append(out, exitView{
			Route: "auto:" + tag, Label: tag, Auto: true, Alive: autoAlive[tag],
		})
	}
	return out
}
