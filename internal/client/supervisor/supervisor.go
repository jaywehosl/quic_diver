// Package supervisor держит клиента живым при смене сетевых параметров (arch4).
//
// Что происходит при переезде Wi-Fi↔LTE или пересборке PPPoE: локальный адрес
// меняется, старый UDP-сокет умирает молча — QUIC об этом не узнает и будет слать
// в никуда до idle-таймаута, а приложения увидят зависшие соединения.
//
// Поэтому: заметив смену адреса, переносим сессию на новый сокет (RFC 9000 §9,
// PATH_CHALLENGE/PATH_RESPONSE) — сессия и все её стримы переживают переезд, TCP
// приложений не рвётся. Заодно пересматриваем то, что зависит от сети: системный
// DNS у нового адаптера свой (его надо снова увести на наш listener) и IPv6 мог
// появиться или пропасть.
//
// Платформонезависим: всё, что специфично (подмена DNS, синтез A), приходит
// колбэками.
package supervisor

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"quicdiver/internal/client/netwatch"
)

// ErrSessionDead — сессия умерла и миграцией не спасается: нужен новый туннель.
var ErrSessionDead = errors.New("supervisor: QUIC-сессия мертва")

// Migrator — то, что умеет перенести сессию на новый локальный сокет и сказать,
// жива ли она. Реализуется cip.Client.
type Migrator interface {
	Migrate(ctx context.Context, laddr *net.UDPAddr) error
	// Context закрывается, когда сессия умерла (idle-таймаут, CONNECTION_CLOSE).
	Context() context.Context
}

// Config — параметры supervisor'а.
type Config struct {
	// Client — сессия, которую переносим.
	Client Migrator
	// Watch — источник событий смены сети.
	Watch netwatch.Watcher
	// Initial — состояние сети на старте.
	Initial netwatch.State
	// OnNetworkChange вызывается после успешной миграции: пересмотреть то, что
	// зависит от сети (системный DNS нового адаптера, наличие IPv6).
	// Ошибку логируем, но работу не останавливаем — туннель уже переехал.
	OnNetworkChange func(netwatch.State) error
	// MigrateTimeout — сколько ждать валидации нового пути. 0 → 10s.
	MigrateTimeout time.Duration
}

// Supervisor следит за сетью и переносит сессию.
type Supervisor struct {
	cfg Config

	mu         sync.Mutex
	migrations int
	failures   int
}

// New создаёт supervisor.
func New(cfg Config) *Supervisor {
	if cfg.MigrateTimeout == 0 {
		cfg.MigrateTimeout = 10 * time.Second
	}
	return &Supervisor{cfg: cfg}
}

// Run следит за сетью и за живостью сессии.
//
// Возвращает ErrSessionDead, если сессия умерла: миграция тут уже не поможет
// (переносить нечего), нужен новый туннель. Это тот самый случай, который смена
// локального адреса не ловит: роутер пересобрал PPPoE — локальный адрес прежний,
// сменился публичный, NAT-маппинг слетел, ответы узла не доходят.
//
// По отмене ctx возвращает nil.
func (s *Supervisor) Run(ctx context.Context) error {
	ch := make(chan netwatch.State, 1)
	go s.cfg.Watch.Run(ctx, s.cfg.Initial, ch)

	dead := deadChan(s.cfg.Client)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-dead:
			return ErrSessionDead
		case st := <-ch:
			s.handle(ctx, st)
		}
	}
}

// deadChan — канал, закрывающийся со смертью сессии. Отдельной функцией, чтобы
// nil-Context (в тестах с заглушкой) не ронял select.
func deadChan(m Migrator) <-chan struct{} {
	if m == nil {
		return nil
	}
	c := m.Context()
	if c == nil {
		return nil
	}
	return c.Done()
}

// Stats — сколько переездов пережито и сколько миграций не удалось.
func (s *Supervisor) Stats() (migrations, failures int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.migrations, s.failures
}

func (s *Supervisor) handle(ctx context.Context, st netwatch.State) {
	log.Printf("supervisor: сеть сменилась — локальный адрес %s, IPv6 %v", st.Primary, st.HasIPv6)

	mctx, cancel := context.WithTimeout(ctx, s.cfg.MigrateTimeout)
	err := s.cfg.Client.Migrate(mctx, &net.UDPAddr{IP: st.Primary.AsSlice(), Port: 0})
	cancel()

	s.mu.Lock()
	if err != nil {
		s.failures++
	} else {
		s.migrations++
	}
	s.mu.Unlock()

	if err != nil {
		// Путь не подтвердился: сеть могла ещё не подняться, либо узел недоступен
		// с неё. Следующая смена адреса даст новую попытку; сессия пока живёт на
		// старом пути и умрёт по idle-таймауту, если он мёртв.
		log.Printf("supervisor: миграция на %s не удалась: %v", st.Primary, err)
		return
	}
	log.Printf("supervisor: сессия перенесена на %s без разрыва", st.Primary)

	if s.cfg.OnNetworkChange != nil {
		if err := s.cfg.OnNetworkChange(st); err != nil {
			log.Printf("supervisor: пересмотр настроек сети: %v", err)
		}
	}
}
