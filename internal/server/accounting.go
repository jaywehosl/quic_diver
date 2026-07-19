package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
	"quicdiver/internal/server/netstack"
)

// trafficFlushEvery — как часто сливать накопленный трафик в базу.
//
// Писать на каждый пакет нельзя (SQLite захлебнётся на гигабитном канале), не
// писать вовсе — потерять учёт при обрыве. Раз в полминуты: цена — потеря
// последнего интервала на аварийном обрыве, что для счётчика трафика терпимо.
const trafficFlushEvery = 30 * time.Second

// accountant ведёт учёт одной клиентской сессии.
type accountant struct {
	// cfg, а не готовая база: сессия живёт часами, а база под ней может
	// смениться (реплика применила снимок мастера). Сохранённый указатель после
	// подмены писал бы в копию, которую вот-вот закроют.
	cfg  Config
	id   string
	hash string
}

// db — база, актуальная на сейчас.
func (a *accountant) db() (*db.SQLite, bool) { return sqliteOf(a.cfg.Store) }

// newSessionID — случайный идентификатор сессии.
func newSessionID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// beginSession регистрирует подключение: отмечает устройство и открывает сессию.
//
// Возвращает nil, если учёт невозможен или не нужен (dev-узел без БД): туннель
// в этом случае работает как раньше — учёт не должен быть условием связи.
func beginSession(ctx context.Context, cfg Config, hash, hwid, remoteIP string) *accountant {
	store, ok := sqliteOf(cfg.Store)
	if !ok || hash == "" {
		return nil
	}
	// Устройство отмечаем и при отказе лимита тоже не рвём туннель: решение
	// «пускать или нет» принимает авторизация, а не бухгалтерия.
	if err := store.TouchDevice(ctx, hash, hwid, remoteIP); err != nil {
		log.Printf("учёт устройства: %v", err)
	}
	limit := 0
	if row, err := store.TokenRowByHash(ctx, hash); err == nil {
		limit = row.LimitSessions
	}
	a := &accountant{cfg: cfg, id: newSessionID(), hash: hash}
	if err := store.OpenSession(ctx, db.Session{
		ID: a.id, TokenHash: hash, HWID: hwid, RemoteIP: remoteIP, Node: cfg.Authority,
	}, limit); err != nil {
		log.Printf("учёт сессии: %v", err)
		return nil
	}
	return a
}

// run периодически сливает трафик в базу и снимает сессию с учёта при выходе.
//
// counter отдаёт нарастающие итоги (sent, received) — разницу считаем здесь,
// чтобы источник не хранил состояние учёта.
func (a *accountant) run(ctx context.Context, counter func() (sent, received uint64)) {
	if a == nil {
		return
	}
	t := time.NewTicker(trafficFlushEvery)
	defer t.Stop()

	var lastSent, lastRecv uint64
	flush := func() {
		sent, recv := counter()
		dIn, dOut := int64(recv-lastRecv), int64(sent-lastSent)
		lastSent, lastRecv = sent, recv
		// Контекст запроса к этому моменту уже мёртв — пишем на своём.
		wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		store, ok := a.db()
		if !ok {
			return
		}
		if err := store.TouchSession(wctx, a.id, a.hash, dIn, dOut); err != nil {
			log.Printf("учёт трафика: %v", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			flush() // досчитать последний интервал
			cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if store, ok := a.db(); ok {
				if err := store.CloseSession(cctx, a.id); err != nil {
					log.Printf("закрытие сессии: %v", err)
				}
			}
			cancel()
			return
		case <-t.C:
			flush()
		}
	}
}

// countingTunnel считает байты, проходящие через туннель клиента.
//
// Счётчик живёт здесь, а не в connect-ip: библиотека статистики не даёт, а
// заводить её на уровне QUIC-соединения неверно — там смешался бы служебный
// трафик и данные чужих сессий того же процесса.
type countingTunnel struct {
	inner netstack.Tunnel
	in    atomic.Uint64 // от клиента к узлу
	out   atomic.Uint64 // от узла к клиенту
}

func (c *countingTunnel) ReadPacket(b []byte) (int, error) {
	n, err := c.inner.ReadPacket(b)
	if n > 0 {
		c.in.Add(uint64(n))
	}
	return n, err
}

func (c *countingTunnel) WritePacket(b []byte) ([]byte, error) {
	c.out.Add(uint64(len(b)))
	return c.inner.WritePacket(b)
}

// totals — нарастающие итоги в терминах accountant.run: sent = отдано клиенту,
// received = принято от него.
func (c *countingTunnel) totals() (sent, received uint64) {
	return c.out.Load(), c.in.Load()
}

// hwidFrom достаёт отпечаток машины из запроса.
func hwidFrom(r *http.Request) string {
	h := r.Header.Get(auth.HeaderHWID)
	if len(h) > 128 { // чужой мусор в базу не пускаем
		return h[:128]
	}
	return h
}

// sessionHash — хеш токена текущей сессии (пусто, если не авторизована).
func sessionHash(ctx context.Context) string {
	sess := auth.SessionFrom(ctx)
	if sess == nil {
		return ""
	}
	_, hash, ok := sess.Status()
	if !ok {
		return ""
	}
	return hash
}

// remoteIPFrom — адрес клиента без порта (для учёта и лимита по IP).
func remoteIPFrom(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// sessionHWID — отпечаток машины, предъявленный при авторизации этой сессии.
//
// Берём из сессии, а не из текущего запроса: клиент шлёт заголовок один раз, на
// /qd-auth, а туннель поднимается следующим запросом — там его уже нет.
func sessionHWID(ctx context.Context) string {
	sess := auth.SessionFrom(ctx)
	if sess == nil {
		return ""
	}
	return sess.HWID()
}
