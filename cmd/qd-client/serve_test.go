package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Сессия оборвалась — клиент обязан подняться заново, а не умереть. Раньше на
// этом стоял log.Fatal, и пользователь оставался без сети до ручного перезапуска.
func TestServeRetriesAfterFailure(t *testing.T) {
	var calls atomic.Int32
	done := make(chan struct{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		serveWith(ctx, options{}, func(context.Context, options) error {
			if calls.Add(1) >= 3 {
				close(done)
				<-ctx.Done() // держим «сессию», пока тест не закончится
				return ctx.Err()
			}
			return errors.New("туннель оборван")
		})
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("клиент не переподключился: попыток %d", calls.Load())
	}
}

// Ctrl+C посреди паузы должен останавливать сразу, а не ждать её конца.
func TestServeStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})

	go func() {
		serveWith(ctx, options{}, func(context.Context, options) error {
			cancel() // сессия упала одновременно с остановкой
			return errors.New("оборван")
		})
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("serve не остановился по отмене контекста")
	}
}

// Штатное завершение run (без ошибки) повторять незачем.
func TestServeStopsOnCleanExit(t *testing.T) {
	var calls atomic.Int32
	stopped := make(chan struct{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		serveWith(ctx, options{}, func(context.Context, options) error {
			calls.Add(1)
			return nil
		})
		close(stopped)
	}()

	select {
	case <-stopped:
		if n := calls.Load(); n != 1 {
			t.Fatalf("run вызван %d раз при штатном выходе", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve не завершился при штатном выходе run")
	}
}

// Паузы должны расти: иначе при лежащем узле клиент будет долбить его без остановки.
func TestBackoffGrowsAndIsCapped(t *testing.T) {
	b := minBackoff
	for i := 0; i < 20; i++ {
		if b *= 2; b > maxBackoff {
			b = maxBackoff
		}
	}
	if b != maxBackoff {
		t.Fatalf("пауза выросла до %v, ожидался потолок %v", b, maxBackoff)
	}
	if minBackoff >= maxBackoff {
		t.Fatal("минимальная пауза не меньше максимальной")
	}
	if stableRun <= maxBackoff {
		t.Fatal("порог стабильной сессии должен быть больше максимальной паузы, " +
			"иначе счётчик сбрасывался бы на каждом обрыве")
	}
}
