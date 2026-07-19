package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"quicdiver/internal/server/db"
	"quicdiver/internal/server/decoy"
)

// clusterView — состояние кластера глазами этого узла.
type clusterView struct {
	db.Cluster
	// Self — идентификатор узла, который отвечает.
	Self string `json:"self"`
	// IsMaster — пишет ли этот узел базу. Реплики только читают.
	IsMaster bool `json:"is_master"`
}

// promoteReq — тело запроса смены мастера.
type promoteReq struct {
	// Node — кого объявляем мастером. Пусто → себя.
	Node string `json:"node"`
	// Confirm — обязательное подтверждение: промоушен при живом мастере
	// оставляет в сети двух пишущих, пока старый не узнает о смене.
	Confirm bool `json:"confirm"`
}

// adminCluster — посмотреть состояние кластера (GET) и сменить мастера (POST).
//
// Промоушен только вручную и только админским токеном. Автоматические выборы
// здесь были бы хуже отказа: при сетевом разделении каждая половина объявила бы
// мастера у себя, и обе продолжили бы писать — расхождение потом не свести.
// Человек видит картину целиком и решает сам.
func adminCluster(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adminAllowed(r, cfg) {
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		store, ok := sqliteOf(cfg.Store)
		if !ok {
			http.Error(w, "хранилище не поддерживает кластер", http.StatusNotImplemented)
			return
		}
		switch r.Method {
		case http.MethodGet:
			state, err := store.ClusterState(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, clusterView{
				Cluster: state, Self: cfg.NodeID, IsMaster: state.IsMaster(cfg.NodeID),
			})

		case http.MethodPost:
			var req promoteReq
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
				http.Error(w, "битый json", http.StatusBadRequest)
				return
			}
			if !req.Confirm {
				http.Error(w, `нужно {"confirm":true} — в сети должен быть ровно один мастер`,
					http.StatusBadRequest)
				return
			}
			node := req.Node
			if node == "" {
				node = cfg.NodeID
			}
			// Узел, которого нет в реестре, объявлять мастером нельзя: остальные
			// не будут знать, куда за снимком ходить, и сеть замрёт на старом.
			if node != cfg.NodeID {
				if _, err := store.NodeByID(r.Context(), node); err != nil {
					http.Error(w, "узел не найден в реестре: "+node, http.StatusBadRequest)
					return
				}
			}
			state, err := store.Promote(r.Context(), node)
			if errors.Is(err, db.ErrStaleEpoch) {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			log.Printf("мастером объявлен %s (поколение %d)", state.MasterID, state.Epoch)
			writeJSON(w, clusterView{
				Cluster: state, Self: cfg.NodeID, IsMaster: state.IsMaster(cfg.NodeID),
			})

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}
