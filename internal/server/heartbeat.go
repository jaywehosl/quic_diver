package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
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
		// Заодно принимаем отчёт о расходе клиентов. Отдельный канал заводить
		// незачем: стук и так ходит регулярно, а без отчёта мастер видел бы
		// только свой трафик — расход через реплики не попадал бы ни в панель,
		// ни в лимиты.
		if rep := decodeBeat(w, r); len(rep.Traffic) > 0 {
			if err := store.ReportNodeTraffic(r.Context(), node.ID, rep.Traffic); err != nil {
				log.Printf("отчёт о трафике от %s: %v", node.ID, err)
			}
		}
		if state, err := store.ClusterState(r.Context()); err == nil {
			w.Header().Set(HeaderEpoch, strconv.FormatInt(state.Epoch, 10))
			w.Header().Set(HeaderMaster, state.MasterID)
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// beatReport — что узел сообщает мастеру вместе со стуком.
type beatReport struct {
	// Traffic — АБСОЛЮТНЫЕ счётчики узла по клиентам. Не приращения: повторно
	// доставленный отчёт тогда ничего не испортит, и помнить «что уже отослано»
	// узлу не нужно — при обрыве он просто отчитается заново.
	Traffic []db.NodeTraffic `json:"traffic,omitempty"`
}

// maxBeatBody — потолок тела стука. Клиентов на узле немного, отчёт компактный;
// всё, что заметно больше, — не наш стук.
const maxBeatBody = 4 << 20

func decodeBeat(w http.ResponseWriter, r *http.Request) beatReport {
	var rep beatReport
	if r.Body == nil {
		return rep
	}
	// Битое тело — не повод отказывать в отметке живости: узел жив, это главное.
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBeatBody)).Decode(&rep)
	return rep
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

	mu sync.Mutex
	// sent — что уже отослано мастеру, чтобы не гонять неизменившееся.
	sent map[string][2]int64
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
		// реестре — и в панели, и для чужой балансировки. Свой расход он тоже
		// кладёт в общий разрез сам: иначе сетевой итог не учитывал бы трафик,
		// прошедший через него самого.
		if rows := b.report(ctx, store); len(rows) > 0 {
			if err := store.ReportNodeTraffic(ctx, b.SelfID, rows); err != nil {
				log.Printf("свой отчёт о трафике: %v", err)
			}
		}
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

	body, err := json.Marshal(beatReport{Traffic: b.report(ctx, store)})
	if err != nil {
		return err
	}

	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost,
		"https://"+master.Authority()+HeartbeatPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set(auth.HeaderToken, b.SelfToken)
	req.Header.Set("Content-Type", "application/json")
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

// report собирает счётчики, изменившиеся с прошлого стука.
//
// Шлём только изменившееся: гонять весь список клиентов каждую минуту незачем,
// у большинства он между ударами не двигается. Помним отосланное в памяти, а не
// в базе: после перезапуска отчёт просто уйдёт целиком, и, поскольку значения
// абсолютные, итог от этого не изменится.
func (b *Beater) report(ctx context.Context, store *db.SQLite) []db.NodeTraffic {
	rows, err := store.LocalTrafficReport(ctx)
	if err != nil {
		log.Printf("сбор трафика для отчёта: %v", err)
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sent == nil {
		b.sent = map[string][2]int64{}
	}
	var changed []db.NodeTraffic
	for _, r := range rows {
		cur := [2]int64{r.BytesIn, r.BytesOut}
		if was, ok := b.sent[r.TokenHash]; ok && was == cur {
			continue
		}
		b.sent[r.TokenHash] = cur
		changed = append(changed, r)
	}
	return changed
}

// drop гасит удерживаемую связь.
func (b *Beater) drop() {
	if b.closer != nil {
		_ = b.closer.Close()
	}
	b.rt, b.closer, b.master = nil, nil, ""
}
