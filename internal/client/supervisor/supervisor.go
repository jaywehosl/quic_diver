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
	"net/netip"
	"sync"
	"time"

	"quicdiver/internal/client/netwatch"
)

// ErrSessionDead — сессия умерла и миграцией не спасается: нужен новый туннель.
var ErrSessionDead = errors.New("supervisor: QUIC-сессия мертва")

// Migrator — то, что умеет перенести сессию на новый локальный сокет, сказать,
// жива ли она, и показать счётчики трафика. Реализуется cip.Client.
//
// Счётчики отдаются примитивами, а не своим типом: иначе транспортному слою
// пришлось бы импортировать supervisor, то есть зависеть от того, кто им рулит.
type Migrator interface {
	Migrate(ctx context.Context, laddr *net.UDPAddr) error
	// Context закрывается, когда сессия умерла (idle-таймаут, CONNECTION_CLOSE).
	Context() context.Context
	// Traffic — пакетов отправлено и принято: по ним видно, что ответы перестали
	// приходить, хотя мы продолжаем слать.
	Traffic() (sent, received uint64)
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

	// ProbeEvery — как часто сверять счётчики трафика. 0 → DefaultProbeEvery.
	ProbeEvery time.Duration
	// SilenceLimit — сколько терпеть тишину в приёме, пока сами продолжаем слать,
	// прежде чем счесть путь мёртвым. 0 → DefaultSilenceLimit.
	SilenceLimit time.Duration
	// RepairEvery — пауза между попытками починки, пока путь не ожил.
	// 0 → DefaultRepairEvery.
	RepairEvery time.Duration
	// LocalAddr — с какого локального адреса переезжать при починке.
	// nil → текущий исходящий адрес машины.
	LocalAddr func() (netip.Addr, error)
	// MaxRepairs — сколько попыток починки делать за один обрыв. 0 →
	// DefaultMaxRepairs, отрицательное — без предела (тесты).
	MaxRepairs int
}

// Пороги детекта мёртвого пути.
//
// SilenceLimit должен быть заметно больше keep-alive-периода (15 с): в простое
// стороны молчат, и тишина сама по себе не беда. Признак беды — тишина в приёме
// при том, что мы продолжаем слать (в простое это keep-alive PING, на который
// обязан прийти ответ).
//
// MaxRepairs мал не из осторожности, а по устройству QUIC: каждый новый путь
// требует свежий connection ID, а выдаёт их узел — по сети, которой сейчас нет.
// Запас конечен (RFC 9000 §5.1.1, active_connection_id_limit), и каждая неудачная
// попытка сжигает один ID безвозвратно. Исчерпав их, мы теряем возможность
// переехать вообще: PATH_CHALLENGE отправить не на чем, и починка не сработает
// даже когда связь вернётся (проверено на живом узле: попытки продолжали падать
// уже при живой сети). Поэтому пробуем несколько раз — этого хватает на реальную
// причину миграции, слетевший NAT-маппинг при живой сети, — а дальше не мешаем
// сессии умереть: редайл поднимет туннель заново и connection ID ему не нужны.
const (
	DefaultProbeEvery   = time.Second
	DefaultSilenceLimit = 20 * time.Second
	DefaultRepairEvery  = 3 * time.Second
	DefaultMaxRepairs   = 2
)

// Supervisor следит за сетью и переносит сессию.
type Supervisor struct {
	cfg Config

	mu          sync.Mutex
	migrations  int
	failures    int
	repairs     int
	repairFails int
}

// New создаёт supervisor.
func New(cfg Config) *Supervisor {
	if cfg.MigrateTimeout == 0 {
		cfg.MigrateTimeout = 10 * time.Second
	}
	if cfg.ProbeEvery == 0 {
		cfg.ProbeEvery = DefaultProbeEvery
	}
	if cfg.SilenceLimit == 0 {
		cfg.SilenceLimit = DefaultSilenceLimit
	}
	if cfg.RepairEvery == 0 {
		cfg.RepairEvery = DefaultRepairEvery
	}
	if cfg.MaxRepairs == 0 {
		cfg.MaxRepairs = DefaultMaxRepairs
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
	go s.watchPath(ctx) // мёртвый путь при неизменном адресе — самый частый обрыв

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

// RepairStats — сколько раз чинили мёртвый путь и сколько попыток не удалось
// (пока сеть не вернулась, неудачи — норма).
func (s *Supervisor) RepairStats() (repairs, failed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.repairs, s.repairFails
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
