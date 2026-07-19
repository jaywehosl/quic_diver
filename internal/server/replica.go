package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
	"quicdiver/internal/server/decoy"
)

// ReplicaPath — эндпоинт, с которого узлы забирают снимок базы мастера.
const ReplicaPath = "/qd-replica"

// Заголовки снимка: по ним получатель понимает, чей это снимок и не отстал ли
// источник. Едут в QUIC, снаружи невидимы.
const (
	HeaderEpoch  = "Qd-Epoch"
	HeaderMaster = "Qd-Master"
)

// serveReplica отдаёт снимок базы соседнему узлу.
//
// Доступ только по node-токену (или админскому — для диагностики): снимок несёт
// хеши всех токенов сети, и открытый эндпоинт раздавал бы реестр наружу.
//
// Отдаём его и когда сами не мастер: получатель сверяет поколение в заголовке со
// своим и сам решает, применять ли. Так узел, отрезанный от мастера, может
// подтянуть данные через соседа — ровно тот случай, ради которого узлы умеют
// ретранслировать.
func serveReplica(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !replicaAllowed(r, cfg) {
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		store, ok := sqliteOf(cfg.Store)
		if !ok {
			http.Error(w, "хранилище не поддерживает снимки", http.StatusNotImplemented)
			return
		}
		state, err := store.ClusterState(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		tmp := filepath.Join(os.TempDir(), fmt.Sprintf("qd-replica-%d.db", time.Now().UnixNano()))
		defer os.Remove(tmp)
		if err := store.Backup(r.Context(), tmp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		f, err := os.Open(tmp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()

		master := state.MasterID
		if master == "" {
			master = cfg.NodeID // никого не объявляли — мастер тот, у кого спросили
		}
		w.Header().Set(HeaderEpoch, strconv.FormatInt(state.Epoch, 10))
		w.Header().Set(HeaderMaster, master)
		w.Header().Set("Content-Type", "application/octet-stream")
		if st, err := f.Stat(); err == nil {
			w.Header().Set("Content-Length", fmt.Sprint(st.Size()))
		}
		_, _ = io.Copy(w, f)
	})
}

// replicaAllowed — узел или админ.
func replicaAllowed(r *http.Request, cfg Config) bool {
	if cfg.Store == nil {
		return false
	}
	sess := auth.SessionFrom(r.Context())
	if sess == nil {
		return false
	}
	role, _, ok := sess.Status()
	return ok && (role == auth.RoleNode || role == auth.RoleAdmin)
}

// NodeRoundTripper делает HTTP-запрос к соседнему узлу от нашего имени.
//
// Живёт в main (там доступен клиентский транспорт), сюда приходит функцией — по
// той же причине, что и NodeDialer: server не должен тянуть клиентский стек.
type NodeRoundTripper func(ctx context.Context, node db.Node, selfToken string) (http.RoundTripper, io.Closer, error)

// replicaPullEvery — как часто реплика забирает свежий снимок.
//
// Смысл величины: настолько может отстать реестр узлов и список токенов на
// реплике. Отзыв клиента доезжает не мгновенно — это осознанный размен: чаще
// значит гонять базу по сети без нужды, а срочные вещи админ делает на мастере.
const replicaPullEvery = 15 * time.Minute

// replicaPullTimeout — потолок на одну попытку.
const replicaPullTimeout = 2 * time.Minute

// Replicator тянет базу с мастера и применяет её горячей подменой.
type Replicator struct {
	// Live — хранилище с подменой. Без него репликация невозможна: обычную
	// открытую базу заменить на ходу нельзя.
	Live *db.Live
	// SelfID, SelfToken — чем узел представляется мастеру.
	SelfID    string
	SelfToken string
	// RT — как достучаться до соседа.
	RT NodeRoundTripper
	// Every — период обновления. 0 → replicaPullEvery.
	Every time.Duration
	// OnUpdate вызывается после успешной подмены базы.
	//
	// Без него узел принял бы новый реестр узлов и не заметил его: связи с
	// соседями и выходы перечитываются один раз при старте, и добавленный на
	// мастере узел остался бы недостижимым до перезапуска — то есть ровно то,
	// чего горячая подмена и должна избежать.
	OnUpdate func(ctx context.Context)
}

// Run крутит обновление до отмены ctx.
//
// Неудача — не повод останавливаться и тем более не повод падать: узел
// продолжает работать на том, что у него уже есть. Мастер может быть в
// перезагрузке, сеть между площадками — моргать; реплика обязана это пережить,
// а не осыпаться следом.
func (rep *Replicator) Run(ctx context.Context) {
	every := rep.Every
	if every <= 0 {
		every = replicaPullEvery
	}
	// Первый заход сразу: свежеустановленный узел не должен ждать четверть часа,
	// прежде чем узнает о сети хоть что-то.
	if err := rep.pull(ctx); err != nil && ctx.Err() == nil {
		log.Printf("репликация: %v", err)
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := rep.pull(ctx); err != nil && ctx.Err() == nil {
				// СОБЫТИЕ ДЛЯ АЛЕРТА: узел живёт на устаревшей базе.
				log.Printf("репликация: %v", err)
			}
		}
	}
}

// pull забирает снимок у мастера и применяет его.
func (rep *Replicator) pull(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, replicaPullTimeout)
	defer cancel()

	store := rep.Live.DB()
	state, err := store.ClusterState(ctx)
	if err != nil {
		return err
	}
	if state.IsMaster(rep.SelfID) {
		return nil // мастер сам себе источник
	}
	master, err := store.NodeByID(ctx, state.MasterID)
	if err != nil {
		return fmt.Errorf("мастер %s не найден в реестре: %w", state.MasterID, err)
	}

	rt, closer, err := rep.RT(ctx, master, rep.SelfToken)
	if err != nil {
		return fmt.Errorf("связь с мастером %s: %w", master.ID, err)
	}
	defer closer.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+master.Authority()+ReplicaPath, nil)
	if err != nil {
		return err
	}
	req.Header.Set(auth.HeaderToken, rep.SelfToken)
	rsp, err := rt.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("запрос снимка у %s: %w", master.ID, err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		// Витрина вместо снимка означает, что мастер нас не признал: наш токен
		// он не знает. Настоящая беда, но глушить трафик из-за неё нельзя.
		return fmt.Errorf("мастер %s отказал: %s", master.ID, rsp.Status)
	}

	// Поколение источника ниже нашего — он отстал (например, это вернувшийся
	// старый мастер). Применить такой снимок значило бы откатить сеть назад.
	if got, err := strconv.ParseInt(rsp.Header.Get(HeaderEpoch), 10, 64); err == nil {
		if got < state.Epoch {
			return fmt.Errorf("снимок от %s поколения %d, у нас %d — не применяю",
				master.ID, got, state.Epoch)
		}
	}

	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("qd-pull-%d.db", time.Now().UnixNano()))
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(rsp.Body, maxSnapshotSize))
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("приём снимка: %w", err)
	}
	if n == 0 {
		os.Remove(tmp)
		return fmt.Errorf("мастер %s прислал пустой снимок", master.ID)
	}
	// SwapFile сам проверит файл и перенесёт локальный учёт; битый снимок сюда
	// не пройдёт, рабочая база останется на месте.
	if err := rep.Live.SwapFile(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	log.Printf("репликация: база обновлена с мастера %s (%d байт)", master.ID, n)
	if rep.OnUpdate != nil {
		rep.OnUpdate(ctx)
	}
	return nil
}
