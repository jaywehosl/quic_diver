package supervisor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"quicdiver/internal/client/netwatch"
)

// spyMigrator запоминает, куда его просили переехать, и умеет притвориться
// умершей сессией.
type spyMigrator struct {
	mu    sync.Mutex
	calls []netip.Addr
	err   error
	done  chan struct{}

	ctx  context.Context
	kill context.CancelFunc
}

// newSpy создаёт заглушку с живой сессией.
func newSpy() *spyMigrator {
	ctx, cancel := context.WithCancel(context.Background())
	return &spyMigrator{ctx: ctx, kill: cancel}
}

func (s *spyMigrator) Context() context.Context {
	if s.ctx == nil {
		return context.Background() // сессия живёт вечно
	}
	return s.ctx
}

func (s *spyMigrator) Migrate(_ context.Context, laddr *net.UDPAddr) error {
	s.mu.Lock()
	addr, _ := netip.AddrFromSlice(laddr.IP)
	s.calls = append(s.calls, addr.Unmap())
	err := s.err
	s.mu.Unlock()
	if s.done != nil {
		select {
		case s.done <- struct{}{}:
		default:
		}
	}
	return err
}

func (s *spyMigrator) seen() []netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]netip.Addr(nil), s.calls...)
}

// feed отдаёт заранее заданные состояния вместо реального опроса сети.
type feed struct{ states []netwatch.State }

func (f feed) run(ctx context.Context, ch chan<- netwatch.State) {
	for _, st := range f.states {
		select {
		case ch <- st:
		case <-ctx.Done():
			return
		}
	}
}

// Главный случай, который смена адреса НЕ ловит: роутер пересобрал PPPoE —
// локальный адрес прежний, публичный сменился, NAT-маппинг слетел, ответы узла не
// доходят и сессия умирает по idle-таймауту. Мигрировать некуда: переносить
// нечего. Supervisor обязан сказать об этом наверх, чтобы стек подняли заново.
func TestDeadSessionReported(t *testing.T) {
	spy := newSpy()
	s := New(Config{Client: spy, Watch: netwatch.Watcher{Interval: time.Hour}})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx) }()

	spy.kill() // сессия умерла

	select {
	case err := <-errc:
		if !errors.Is(err, ErrSessionDead) {
			t.Fatalf("вернулось %v, ожидался ErrSessionDead", err)
		}
	case <-ctx.Done():
		t.Fatal("смерть сессии не замечена — клиент завис бы с мёртвым туннелем")
	}
	if len(spy.seen()) != 0 {
		t.Fatal("была попытка мигрировать мёртвую сессию")
	}
}

// Живая сессия: Run завершается по отмене контекста и без ошибки.
func TestRunStopsCleanlyOnContextCancel(t *testing.T) {
	spy := newSpy()
	s := New(Config{Client: spy, Watch: netwatch.Watcher{Interval: time.Hour}})

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx) }()
	cancel()

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("штатная остановка вернула ошибку: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run не завершился по отмене контекста")
	}
}

// handle вызывается напрямую: Run — это только цикл поверх него, а вся суть
// (миграция + пересмотр настроек) здесь.
func TestMigratesToNewAddressAndReappliesSettings(t *testing.T) {
	spy := newSpy()
	var applied []netwatch.State

	s := New(Config{
		Client: spy,
		OnNetworkChange: func(st netwatch.State) error {
			applied = append(applied, st)
			return nil
		},
	})

	newNet := netwatch.State{Primary: netip.MustParseAddr("10.20.30.40"), HasIPv6: false}
	s.handle(context.Background(), newNet)

	seen := spy.seen()
	if len(seen) != 1 || seen[0] != newNet.Primary {
		t.Fatalf("миграция ушла на %v, ожидался %v", seen, newNet.Primary)
	}
	if len(applied) != 1 || applied[0] != newNet {
		t.Fatalf("настройки сети не пересмотрены: %v", applied)
	}
	if m, f := s.Stats(); m != 1 || f != 0 {
		t.Fatalf("stats: переездов %d, неудач %d", m, f)
	}
}

// Миграция провалилась (новый путь не подтвердился) — настройки трогать нельзя:
// туннель остался на старом пути, и переводить DNS на адаптер, через который
// связи нет, значило бы добить резолв.
func TestFailedMigrationSkipsSettings(t *testing.T) {
	spy := newSpy()
	spy.err = errors.New("path validation timeout")
	applied := 0

	s := New(Config{
		Client:          spy,
		OnNetworkChange: func(netwatch.State) error { applied++; return nil },
	})
	s.handle(context.Background(), netwatch.State{Primary: netip.MustParseAddr("10.0.0.1")})

	if applied != 0 {
		t.Fatal("настройки пересмотрены после неудачной миграции")
	}
	if m, f := s.Stats(); m != 0 || f != 1 {
		t.Fatalf("stats: переездов %d, неудач %d", m, f)
	}
}

// Ошибка пересмотра настроек не должна валить supervisor: туннель уже переехал,
// и работа продолжается.
func TestSettingsErrorDoesNotBreakSupervisor(t *testing.T) {
	spy := newSpy()
	s := New(Config{
		Client:          spy,
		OnNetworkChange: func(netwatch.State) error { return errors.New("реестр занят") },
	})
	s.handle(context.Background(), netwatch.State{Primary: netip.MustParseAddr("10.0.0.2")})

	if m, _ := s.Stats(); m != 1 {
		t.Fatal("переезд не засчитан, хотя миграция удалась")
	}
}

// Run реагирует на события и завершается по отмене контекста.
func TestRunHandlesEventsAndStops(t *testing.T) {
	spy := newSpy()
	spy.done = make(chan struct{}, 2)
	s := New(Config{Client: spy})

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan netwatch.State, 1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case st := <-ch:
				s.handle(ctx, st)
			}
		}
	}()

	f := feed{states: []netwatch.State{
		{Primary: netip.MustParseAddr("192.168.1.5")},
		{Primary: netip.MustParseAddr("100.64.0.7")}, // переехали на LTE (CGNAT)
	}}
	go f.run(ctx, ch)

	for i := 0; i < 2; i++ {
		select {
		case <-spy.done:
		case <-time.After(3 * time.Second):
			t.Fatalf("событие %d не обработано", i+1)
		}
	}
	cancel()

	if got := spy.seen(); len(got) != 2 {
		t.Fatalf("обработано %d событий из 2: %v", len(got), got)
	}
}
