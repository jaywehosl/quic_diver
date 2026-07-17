package netwatch

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestStateEqual(t *testing.T) {
	a := State{Primary: netip.MustParseAddr("192.168.1.5"), HasIPv6: false}
	if !a.Equal(a) {
		t.Fatal("состояние не равно самому себе")
	}
	if a.Equal(State{Primary: netip.MustParseAddr("192.168.1.6")}) {
		t.Fatal("разные адреса признаны равными — переезд остался бы незамеченным")
	}
	// появление IPv6 — тоже смена: включается/выключается синтез A (nat46)
	if a.Equal(State{Primary: a.Primary, HasIPv6: true}) {
		t.Fatal("появление IPv6 не считается сменой состояния")
	}
}

// Current обязан работать на живой машине: без него supervisor не узнает адрес.
func TestCurrentOnRealMachine(t *testing.T) {
	st, err := Current(func() bool { return false })
	if err != nil {
		t.Skipf("сети нет: %v", err)
	}
	if !st.Primary.IsValid() {
		t.Fatal("адрес невалиден")
	}
	t.Logf("текущий локальный адрес: %s", st.Primary)
}

// Первое (уже известное) состояние повторно не шлётся: иначе supervisor погнал бы
// миграцию на тот же самый адрес сразу после старта.
func TestWatcherDoesNotReportInitialState(t *testing.T) {
	initial, err := Current(func() bool { return false })
	if err != nil {
		t.Skipf("сети нет: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	ch := make(chan State, 1)
	go Watcher{Interval: 20 * time.Millisecond, HasIPv6: func() bool { return false }}.Run(ctx, initial, ch)

	select {
	case st := <-ch:
		t.Fatalf("сообщено о неизменившемся состоянии: %v", st)
	case <-ctx.Done():
	}
}

// Смена состояния должна долетать до канала.
func TestWatcherReportsChange(t *testing.T) {
	real, err := Current(func() bool { return false })
	if err != nil {
		t.Skipf("сети нет: %v", err)
	}
	// притворяемся, что раньше были в другой сети — watcher обязан заметить
	stale := State{Primary: netip.MustParseAddr("10.255.255.254"), HasIPv6: false}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch := make(chan State, 1)
	go Watcher{Interval: 20 * time.Millisecond, HasIPv6: func() bool { return false }}.Run(ctx, stale, ch)

	select {
	case st := <-ch:
		if st.Primary != real.Primary {
			t.Fatalf("сообщён адрес %v, на машине %v", st.Primary, real.Primary)
		}
	case <-ctx.Done():
		t.Fatal("смена сети не замечена")
	}
}
