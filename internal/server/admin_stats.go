package server

import (
	"context"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"quicdiver/internal/server/db"
	"quicdiver/internal/server/decoy"
)

// startedAt — момент запуска узла (для uptime в статистике).
var startedAt = time.Now()

// sessionSweepEvery — как часто выметать сессии, о которых давно не слышно.
const sessionSweepEvery = time.Minute

// sessionStale — молчание, после которого сессия считается мёртвой. Заметно
// больше клиентского keepalive: короткий порог убивал бы живые сессии на плохой
// связи, а лимит одновременных подключений тогда срабатывал бы впустую.
const sessionStale = 5 * time.Minute

func sweepSessions(ctx context.Context, store *db.SQLite) {
	t := time.NewTicker(sessionSweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := store.SweepSessions(ctx, sessionStale); err != nil {
				log.Printf("уборка сессий: %v", err)
			} else if n > 0 {
				log.Printf("убрано мёртвых сессий: %d", n)
			}
		}
	}
}

// nodeStats — состояние узла для панели.
type nodeStats struct {
	Node    string      `json:"node"`
	Uptime  string      `json:"uptime"`
	Started time.Time   `json:"started_at"`
	Go      goStats     `json:"go"`
	Host    hostStats   `json:"host"`
	DNS     any         `json:"dns,omitempty"`
	Clients clientStats `json:"clients"`
	Outputs []string    `json:"outbounds,omitempty"`
}

type goStats struct {
	Version    string `json:"version"`
	Goroutines int    `json:"goroutines"`
	HeapMB     uint64 `json:"heap_mb"`
	SysMB      uint64 `json:"sys_mb"`
	NumGC      uint32 `json:"num_gc"`
	CPUs       int    `json:"cpus"`
}

type hostStats struct {
	Hostname string   `json:"hostname,omitempty"`
	LoadAvg  []string `json:"load_avg,omitempty"`
	MemTotal string   `json:"mem_total,omitempty"`
	MemFree  string   `json:"mem_free,omitempty"`
}

type clientStats struct {
	Tokens   int `json:"tokens"`
	Active   int `json:"active_sessions"`
	Devices  int `json:"devices"`
	Revoked  int `json:"revoked_tokens"`
	Sessions int `json:"sessions_total"`
}

// adminStats — состояние узла по admin-токену: аптайм, память, нагрузка,
// клиенты, выходы, DNS-кеш. То, ради чего иначе пришлось бы лезть по ssh.
func adminStats(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adminAllowed(r, cfg) {
			decoy.Handler().ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		st := nodeStats{
			Node:    cfg.Authority,
			Uptime:  time.Since(startedAt).Round(time.Second).String(),
			Started: startedAt,
			Go: goStats{
				Version: runtime.Version(), Goroutines: runtime.NumGoroutine(),
				HeapMB: m.HeapAlloc >> 20, SysMB: m.Sys >> 20, NumGC: m.NumGC,
				CPUs: runtime.NumCPU(),
			},
			Host: hostSnapshot(),
		}
		if cfg.Resolver != nil {
			st.DNS = dnsState(cfg.Resolver)
		}
		if cfg.Outbounds != nil {
			st.Outputs = cfg.Outbounds.Labels()
		}
		if store, ok := cfg.Store.(*db.SQLite); ok {
			st.Clients = clientSnapshot(r.Context(), store)
		}
		writeJSON(w, st)
	})
}

func clientSnapshot(ctx context.Context, store *db.SQLite) clientStats {
	var c clientStats
	if toks, err := store.ListTokens(ctx); err == nil {
		c.Tokens = len(toks)
		for _, t := range toks {
			if t.Revoked {
				c.Revoked++
			}
			if devs, err := store.ListDevices(ctx, t.Hash); err == nil {
				c.Devices += len(devs)
			}
		}
	}
	if sessions, err := store.ListSessions(ctx, ""); err == nil {
		c.Active, c.Sessions = len(sessions), len(sessions)
	}
	return c
}

// hostSnapshot — то, что можно узнать о машине без внешних зависимостей.
// Значения читаются из /proc, поэтому на не-Linux часть полей пустует.
func hostSnapshot() hostStats {
	h := hostStats{}
	h.Hostname, _ = os.Hostname()
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) >= 3 {
			h.LoadAvg = f[:3]
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			switch {
			case strings.HasPrefix(line, "MemTotal:"):
				h.MemTotal = humanKB(line)
			case strings.HasPrefix(line, "MemAvailable:"):
				h.MemFree = humanKB(line)
			}
		}
	}
	return h
}

// humanKB превращает строку /proc/meminfo вида "MemTotal: 8039384 kB" в мегабайты.
func humanKB(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 {
		return ""
	}
	kb, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil {
		return ""
	}
	return strconv.FormatUint(kb/1024, 10) + " МБ"
}
