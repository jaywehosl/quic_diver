package server

import (
	"context"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
	"quicdiver/internal/server/decoy"
)

// HeartbeatPath — эндпоинт, куда узлы стучатся, чтобы отметиться живыми.
const HeartbeatPath = "/qd-beat"

// heartbeatEvery — как часто узел даёт о себе знать.
//
// Заметно чаще, чем nodeAliveAfter: узел должен успеть отметиться несколько раз
// внутри окна, иначе одна потерянная попытка на плохой связи метила бы живой
// узел мёртвым, и балансировщик уводил бы с него трафик впустую.
const heartbeatEvery = time.Minute

// serveHeartbeat отмечает соседа живым.
//
// Отдельно от репликации намеренно: снимок ходит раз в четверть часа, а мёртвым
// узел считается через три минуты — без своего стука реплика числилась бы
// мёртвой большую часть времени. Здесь же передаётся текущее поколение мастера,
// поэтому смена мастера доезжает за минуту, а не со следующим снимком.
func serveHeartbeat(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !replicaAllowed(r, cfg) {
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		store, ok := sqliteOf(cfg.Store)
		if !ok {
			http.Error(w, "хранилище не поддерживает реестр узлов", http.StatusNotImplemented)
			return
		}
		sess := auth.SessionFrom(r.Context())
		_, hash, _ := sess.Status()
		node, err := store.NodeByTokenHash(r.Context(), hash)
		if err != nil {
			// Админский токен сюда тоже проходит (диагностика) — узла за ним нет,
			// отмечать нечего.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := store.TouchNode(r.Context(), node.ID); err != nil {
			log.Printf("отметка узла %s: %v", node.ID, err)
		}
		if state, err := store.ClusterState(r.Context()); err == nil {
			w.Header().Set(HeaderEpoch, strconv.FormatInt(state.Epoch, 10))
			w.Header().Set(HeaderMaster, state.MasterID)
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// Beater даёт мастеру знать, что этот узел жив.
type Beater struct {
	// Live — база: отсюда берётся текущий мастер и сюда же кладётся смена.
	Live *db.Live
	// SelfID, SelfToken — чем узел представляется.
	SelfID    string
	SelfToken string
	// RT — как достучаться до соседа.
	RT NodeRoundTripper
	// Every — период стука. 0 → heartbeatEvery.
	Every time.Duration

	// rt, closer — удерживаемая связь с мастером. Поднимать QUIC-сессию на
	// каждый удар дороже самого удара, поэтому связь живёт между ними и
	// пересоздаётся только после сбоя.
	rt     http.RoundTripper
	closer io.Closer
	// master — с кем сейчас держим связь; сменился мастер — рвём.
	master string
}

// Run стучится мастеру до отмены ctx.
func (b *Beater) Run(ctx context.Context) {
	every := b.Every
	if every <= 0 {
		every = heartbeatEvery
	}
	defer b.drop()

	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := b.beat(ctx); err != nil && ctx.Err() == nil {
			// Не шумим на каждый промах: мастер в перезагрузке — обычное дело, а
			// узел от этого работать не перестаёт. Связь роняем, чтобы следующая
			// попытка пошла по свежей.
			b.drop()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// beat — один удар.
func (b *Beater) beat(ctx context.Context) error {
	store := b.Live.DB()
	state, err := store.ClusterState(ctx)
	if err != nil {
		return err
	}
	if state.IsMaster(b.SelfID) {
		// Мастер отмечает себя сам: иначе он числился бы мёртвым в собственном
		// реестре — и в панели, и для чужой балансировки.
		return store.TouchNode(ctx, b.SelfID)
	}
	master, err := store.NodeByID(ctx, state.MasterID)
	if err != nil {
		return err
	}
	if b.master != master.ID {
		b.drop() // мастер сменился — прежняя связь ведёт не туда
	}
	if b.rt == nil {
		rt, closer, err := b.RT(ctx, master, b.SelfToken)
		if err != nil {
			return err
		}
		b.rt, b.closer, b.master = rt, closer, master.ID
	}

	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost,
		"https://"+master.Authority()+HeartbeatPath, nil)
	if err != nil {
		return err
	}
	req.Header.Set(auth.HeaderToken, b.SelfToken)
	rsp, err := b.rt.RoundTrip(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	_, _ = io.Copy(io.Discard, rsp.Body)

	// Мастер сменился — узнаём об этом сразу, а не со следующим снимком:
	// иначе узел четверть часа ходил бы за базой к тому, кто уже не мастер.
	if epoch, err := strconv.ParseInt(rsp.Header.Get(HeaderEpoch), 10, 64); err == nil {
		if id := rsp.Header.Get(HeaderMaster); id != "" && epoch > state.Epoch {
			if err := store.AdoptCluster(ctx, db.Cluster{Epoch: epoch, MasterID: id}); err == nil {
				log.Printf("мастер сети сменился на %s (поколение %d)", id, epoch)
			}
		}
	}
	return nil
}

// drop гасит удерживаемую связь.
func (b *Beater) drop() {
	if b.closer != nil {
		_ = b.closer.Close()
	}
	b.rt, b.closer, b.master = nil, nil, ""
}
