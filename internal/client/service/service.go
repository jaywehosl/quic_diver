// Package service — жизненный цикл клиента: сервис живёт всегда, трафик
// заворачивается по команде.
//
// Раньше запуск клиента означал сразу всё: туннель, перехват, подмену DNS и
// системного прокси. Отсюда следовало неудобное — чтобы открыть настройки,
// приходилось начать проксировать; чтобы обновиться, приходилось всё гасить.
//
// Здесь эти вещи разделены. Сервис поднят постоянно и отдаёт веб-панель, а
// сессия (туннель + перехват) включается и выключается отдельно. Выключенная
// сессия обязана вернуть систему в исходное состояние: DNS и прокси — общие
// для машины, и оставить их на себе означало бы отобрать у пользователя сеть.
package service

import (
	"context"
	"errors"
	"sync"
	"time"
)

// State — состояние сессии.
type State int

const (
	// StateStopped — трафик не заворачивается, система не тронута.
	StateStopped State = iota
	// StateConnecting — сессия поднимается (или переподключается после обрыва).
	StateConnecting
	// StateConnected — трафик идёт через узел.
	StateConnected
)

func (s State) String() string {
	switch s {
	case StateConnecting:
		return "подключение"
	case StateConnected:
		return "подключено"
	default:
		return "отключено"
	}
}

// Session — одна попытка работы: держит туннель и перехват, пока жив ctx, и
// обязана к возврату восстановить сетевые настройки машины.
//
// Умершая сессия поднимается заново целиком (arch4). Миграция QUIC спасает от
// смены адреса, но не от всего: если роутер пересобрал PPPoE, локальный адрес не
// менялся, а публичный сменился — NAT-маппинг слетел, ответы узла не доходят, и
// сессия умирает по idle-таймауту. Пересоздавать весь стек, а не только сессию,
// приходится потому, что со смертью QUIC умерли и все CONNECT-стримы: соединения
// приложений оборваны в любом случае. Заодно выход из сессии возвращает системе
// прокси и DNS, поэтому следующий резолв домена узла пойдёт через настоящий DNS
// провайдера, а не через наш уже неживой listener.
type Session func(ctx context.Context) error

// Status — снимок состояния для панели.
type Status struct {
	State State
	// Since — когда состояние установилось.
	Since time.Time
	// Attempts — сколько раз сессия переподнималась после обрыва.
	Attempts int
	// LastError — последняя ошибка сессии (пусто, если всё гладко).
	LastError string
}

// Service управляет сессией: запускает, гасит, показывает состояние.
type Service struct {
	session Session
	backoff Backoff

	mu       sync.Mutex
	state    State
	since    time.Time
	attempts int
	lastErr  error
	cancel   context.CancelFunc
	done     chan struct{} // закрывается, когда сессия полностью свернулась
}

// Backoff — паузы между попытками переподключения.
type Backoff struct {
	Min, Max time.Duration
	// Stable — сколько сессия должна прожить, чтобы обрыв считался разовым и
	// пауза сбрасывалась к минимальной.
	Stable time.Duration
}

// DefaultBackoff — паузы переподключения.
//
// Потолок низкий намеренно. Сюда попадаем, только когда путь не удалось починить
// миграцией и сессия всё-таки умерла; связь к этому моменту может вернуться в
// любую секунду. Ждать полминуты, когда интернет уже есть, — ровно то, что
// пользователь замечает как «висит».
//
// Stable — сколько сессия должна прожить, чтобы счесть её удавшейся и сбросить
// паузу: иначе после долгой работы первый же обрыв ждал бы максимума.
func DefaultBackoff() Backoff {
	return Backoff{Min: time.Second, Max: 5 * time.Second, Stable: time.Minute}
}

// New создаёт сервис в отключённом состоянии.
func New(session Session, b Backoff) *Service {
	if b.Min <= 0 {
		b = DefaultBackoff()
	}
	return &Service{session: session, backoff: b, since: time.Now()}
}

// ErrAlreadyConnected — Connect вызван на работающей сессии.
var ErrAlreadyConnected = errors.New("service: сессия уже запущена")

// Connect поднимает сессию и возвращается сразу: дальше она живёт сама и
// переподключается при обрывах, пока не позовут Disconnect.
//
// ctx задаёт предельное время жизни (обычно — жизнь процесса).
func (s *Service) Connect(ctx context.Context) error {
	s.mu.Lock()
	if s.state != StateStopped {
		s.mu.Unlock()
		return ErrAlreadyConnected
	}
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	s.cancel, s.done = cancel, done
	s.setStateLocked(StateConnecting)
	s.attempts = 0
	s.mu.Unlock()

	go s.loop(sctx, done)
	return nil
}

// loop держит сессию поднятой, пока не отменят.
func (s *Service) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	defer func() {
		s.mu.Lock()
		s.setStateLocked(StateStopped)
		s.cancel, s.done = nil, nil
		s.mu.Unlock()
	}()

	pause := s.backoff.Min
	for ctx.Err() == nil {
		s.mu.Lock()
		s.setStateLocked(StateConnected)
		s.attempts++
		s.mu.Unlock()

		start := time.Now()
		err := s.session(ctx)
		lived := time.Since(start)

		if ctx.Err() != nil {
			return // погасили намеренно
		}
		s.mu.Lock()
		s.lastErr = err
		s.setStateLocked(StateConnecting)
		s.mu.Unlock()
		if err == nil {
			return // сессия завершилась сама и без ошибки
		}
		// Долго прожившая сессия — обрыв разовый, начинаем паузы заново.
		if lived >= s.backoff.Stable {
			pause = s.backoff.Min
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pause):
		}
		if pause *= 2; pause > s.backoff.Max {
			pause = s.backoff.Max
		}
	}
}

// Disconnect гасит сессию и ЖДЁТ, пока она свернётся.
//
// Ожидание принципиально: сессия восстанавливает DNS и системный прокси уже
// после отмены. Вернуться раньше — значит соврать панели, что всё выключено,
// пока настройки машины ещё наши.
func (s *Service) Disconnect(ctx context.Context) error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel == nil {
		return nil // уже отключены
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		// Сессия не свернулась вовремя. Врать нельзя: сетевые настройки могли
		// остаться нашими, и звать пользователя «уже отключено» опасно.
		return errors.New("service: сессия не завершилась вовремя, сетевые настройки могли остаться изменёнными")
	}
}

// Status отдаёт снимок состояния (для панели).
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{State: s.state, Since: s.since, Attempts: s.attempts}
	if s.lastErr != nil {
		st.LastError = s.lastErr.Error()
	}
	return st
}

// State — короткая форма Status().State.
func (s *Service) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// setStateLocked меняет состояние, отмечая время. Вызывать под mu.
func (s *Service) setStateLocked(st State) {
	if s.state != st {
		s.state, s.since = st, time.Now()
	}
}
