package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func fastBackoff() Backoff {
	return Backoff{Min: time.Millisecond, Max: 5 * time.Millisecond, Stable: time.Hour}
}

// Пока не позвали Connect, сессия не запускается: сервис живёт и отдаёт панель,
// но система не тронута.
func TestIdleUntilConnect(t *testing.T) {
	var started atomic.Int32
	s := New(func(ctx context.Context) error {
		started.Add(1)
		<-ctx.Done()
		return ctx.Err()
	}, fastBackoff())

	if s.State() != StateStopped {
		t.Fatalf("состояние %v, ожидалось «отключено»", s.State())
	}
	time.Sleep(20 * time.Millisecond)
	if n := started.Load(); n != 0 {
		t.Fatalf("сессия запустилась сама %d раз(а) — трафик пошёл бы без команды", n)
	}
}

func TestConnectThenDisconnect(t *testing.T) {
	running := make(chan struct{}, 1)
	s := New(func(ctx context.Context) error {
		running <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}, fastBackoff())

	if err := s.Connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	select {
	case <-running:
	case <-time.After(2 * time.Second):
		t.Fatal("сессия не стартовала")
	}
	if s.State() != StateConnected {
		t.Fatalf("состояние %v, ожидалось «подключено»", s.State())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Disconnect(ctx); err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if s.State() != StateStopped {
		t.Fatalf("после Disconnect состояние %v", s.State())
	}
}

// Disconnect обязан ДОЖДАТЬСЯ уборки: сессия возвращает DNS и прокси уже после
// отмены, и вернуться раньше — соврать, что система свободна.
func TestDisconnectWaitsForCleanup(t *testing.T) {
	var cleaned atomic.Bool
	s := New(func(ctx context.Context) error {
		<-ctx.Done()
		time.Sleep(80 * time.Millisecond) // как restore DNS/прокси
		cleaned.Store(true)
		return ctx.Err()
	}, fastBackoff())

	s.Connect(context.Background())
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Disconnect(ctx); err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if !cleaned.Load() {
		t.Fatal("Disconnect вернулся до завершения уборки — настройки машины ещё наши")
	}
}

// Если уборка застряла, Disconnect обязан сказать об этом, а не отрапортовать
// успех: пользователю нельзя показывать «отключено», когда DNS ещё наш.
func TestDisconnectReportsStuckCleanup(t *testing.T) {
	release := make(chan struct{})
	s := New(func(ctx context.Context) error {
		<-ctx.Done()
		<-release // «зависшая» уборка
		return ctx.Err()
	}, fastBackoff())

	s.Connect(context.Background())
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := s.Disconnect(ctx)
	close(release)
	if err == nil {
		t.Fatal("Disconnect отрапортовал успех при незавершённой уборке")
	}
}

// Обрыв сессии — не повод сдаваться: сервис переподключается сам.
func TestReconnectsAfterFailure(t *testing.T) {
	var runs atomic.Int32
	s := New(func(ctx context.Context) error {
		if runs.Add(1) < 3 {
			return errors.New("обрыв")
		}
		<-ctx.Done()
		return ctx.Err()
	}, fastBackoff())

	s.Connect(context.Background())
	deadline := time.After(3 * time.Second)
	for runs.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("переподключений было всего %d", runs.Load())
		case <-time.After(2 * time.Millisecond):
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s.Disconnect(ctx)
}

// Пауза между попытками растёт и упирается в потолок: без неё падающая сессия
// молотила бы в цикле, а без потолка клиент висел бы, когда связь уже вернулась.
func TestBackoffGrowsAndIsCapped(t *testing.T) {
	var runs atomic.Int32
	b := Backoff{Min: 10 * time.Millisecond, Max: 20 * time.Millisecond, Stable: time.Hour}
	s := New(func(ctx context.Context) error {
		runs.Add(1)
		return errors.New("падаем сразу")
	}, b)

	s.Connect(context.Background())
	time.Sleep(300 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.Disconnect(ctx)

	n := runs.Load()
	// Пауза есть: без неё за 300 мс попыток были бы тысячи.
	if n > 40 {
		t.Fatalf("%d попыток за 300 мс — пауза не работает", n)
	}
	// Потолок держится: при неограниченном росте попыток было бы всего пара.
	if n < 5 {
		t.Fatalf("всего %d попыток за 300 мс — пауза растёт без потолка", n)
	}
}

// Повторный Connect не должен поднимать вторую сессию: два перехвата разом
// подрались бы за DNS и прокси.
func TestSecondConnectRejected(t *testing.T) {
	s := New(func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }, fastBackoff())
	s.Connect(context.Background())
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Disconnect(ctx)
	}()

	if err := s.Connect(context.Background()); !errors.Is(err, ErrAlreadyConnected) {
		t.Fatalf("повторный Connect дал %v, ожидался ErrAlreadyConnected", err)
	}
}

// Disconnect на отключённом сервисе безвреден (панель может нажать дважды).
func TestDisconnectWhenStoppedIsNoop(t *testing.T) {
	s := New(func(ctx context.Context) error { return nil }, fastBackoff())
	if err := s.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect в покое дал ошибку: %v", err)
	}
}

// Ошибка сессии видна панели — иначе пользователь не поймёт, почему нет связи.
func TestStatusCarriesLastError(t *testing.T) {
	s := New(func(ctx context.Context) error { return errors.New("узел недоступен") }, fastBackoff())
	s.Connect(context.Background())
	deadline := time.After(2 * time.Second)
	for {
		if st := s.Status(); st.LastError != "" {
			if st.LastError != "узел недоступен" {
				t.Fatalf("LastError = %q", st.LastError)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("ошибка сессии не доехала до Status")
		case <-time.After(2 * time.Millisecond):
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.Disconnect(ctx)
}
