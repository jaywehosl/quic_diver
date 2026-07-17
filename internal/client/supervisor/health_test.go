package supervisor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSession — сессия с управляемыми счётчиками: позволяет разыграть обрыв, не
// трогая настоящую сеть.
type fakeSession struct {
	sent, recv atomic.Uint64

	mu       sync.Mutex
	migrated int
	migErr   error
	onMigate func()
}

func (f *fakeSession) Traffic() (uint64, uint64) { return f.sent.Load(), f.recv.Load() }
func (f *fakeSession) Context() context.Context  { return context.Background() }
func (f *fakeSession) Migrate(context.Context, *net.UDPAddr) error {
	f.mu.Lock()
	f.migrated++
	err := f.migErr
	cb := f.onMigate
	f.mu.Unlock()
	if cb != nil {
		cb()
	}
	return err
}

func (f *fakeSession) migrations() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.migrated
}

// fixedAddr — локальный адрес для тестов: не зависим от того, есть ли на машине сеть.
func fixedAddr() func() (netip.Addr, error) {
	return func() (netip.Addr, error) { return netip.MustParseAddr("192.168.31.108"), nil }
}

// Главный случай: связь порвалась между роутером и провайдером. Локальный адрес
// не менялся — мы шлём, ответов нет. Supervisor обязан починить путь переездом на
// новый порт, не дожидаясь idle-таймаута.
func TestSilenceTriggersRepair(t *testing.T) {

	f := &fakeSession{}
	repaired := make(chan struct{}, 1)
	f.onMigate = func() {
		select {
		case repaired <- struct{}{}:
		default:
		}
	}

	s := New(Config{
		Client:       f,
		LocalAddr:    fixedAddr(),
		ProbeEvery:   5 * time.Millisecond,
		SilenceLimit: 30 * time.Millisecond,
		RepairEvery:  10 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go s.watchPath(ctx)

	// шлём (в т.ч. keep-alive), ответов нет — это и есть мёртвый путь
	go func() {
		tk := time.NewTicker(5 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				f.sent.Add(1)
			}
		}
	}()

	select {
	case <-repaired:
	case <-ctx.Done():
		t.Fatal("тишина не привела к починке пути — клиент ждал бы idle-таймаута")
	}
}

// Простой (никто не шлёт, никто не отвечает) — не повод дёргать сеть.
func TestIdleDoesNotTriggerRepair(t *testing.T) {

	f := &fakeSession{}

	s := New(Config{
		Client:       f,
		LocalAddr:    fixedAddr(),
		ProbeEvery:   5 * time.Millisecond,
		SilenceLimit: 20 * time.Millisecond,
		RepairEvery:  10 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go s.watchPath(ctx)
	<-ctx.Done()

	if n := f.migrations(); n != 0 {
		t.Fatalf("в простое сделано %d попыток починки — дёргаем сеть на ровном месте", n)
	}
}

// Живой обмен: ответы идут — чинить нечего.
func TestHealthyPathNotRepaired(t *testing.T) {

	f := &fakeSession{}

	s := New(Config{
		Client:       f,
		LocalAddr:    fixedAddr(),
		ProbeEvery:   5 * time.Millisecond,
		SilenceLimit: 20 * time.Millisecond,
		RepairEvery:  10 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go s.watchPath(ctx)

	go func() {
		tk := time.NewTicker(5 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				f.sent.Add(1)
				f.recv.Add(1) // ответы приходят
			}
		}
	}()
	<-ctx.Done()

	if n := f.migrations(); n != 0 {
		t.Fatalf("на живом пути сделано %d попыток починки", n)
	}
}

// Пока сеть лежит, починка не удаётся — повторять надо, но не чаще RepairEvery,
// иначе долбим сеть и узел.
func TestRepairRetriesButNotTooOften(t *testing.T) {

	f := &fakeSession{migErr: errors.New("path validation timeout")}

	s := New(Config{
		Client:       f,
		LocalAddr:    fixedAddr(),
		ProbeEvery:   2 * time.Millisecond,
		SilenceLimit: 10 * time.Millisecond,
		RepairEvery:  50 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	go s.watchPath(ctx)

	go func() {
		tk := time.NewTicker(2 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				f.sent.Add(1)
			}
		}
	}()
	<-ctx.Done()

	n := f.migrations()
	if n == 0 {
		t.Fatal("починку не пробовали вовсе — связь не вернулась бы сама")
	}
	// 400мс при RepairEvery=50мс — не больше ~8 попыток, с запасом на планировщик
	if n > 12 {
		t.Fatalf("починку пробовали %d раз — долбим сеть чаще RepairEvery", n)
	}
	repairs, failed := s.RepairStats()
	if repairs != n || failed != n {
		t.Fatalf("статистика врёт: попыток %d, неудач %d, реально %d", repairs, failed, n)
	}
}

// Путь ожил сам (связь вернулась до порога) — счётчик тишины обязан сброситься,
// иначе следующая короткая тишина сразу вызвала бы починку.
func TestSilenceResetsWhenTrafficReturns(t *testing.T) {

	f := &fakeSession{}

	s := New(Config{
		Client:       f,
		LocalAddr:    fixedAddr(),
		ProbeEvery:   5 * time.Millisecond,
		SilenceLimit: 60 * time.Millisecond,
		RepairEvery:  10 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go s.watchPath(ctx)

	// тишина, но короче порога
	for i := 0; i < 5; i++ {
		f.sent.Add(1)
		time.Sleep(5 * time.Millisecond)
	}
	// связь вернулась
	for i := 0; i < 10; i++ {
		f.sent.Add(1)
		f.recv.Add(1)
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)

	if n := f.migrations(); n != 0 {
		t.Fatalf("путь ожил сам, но починка всё равно сделана %d раз", n)
	}
}
