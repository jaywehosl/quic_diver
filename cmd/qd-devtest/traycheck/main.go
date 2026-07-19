//go:build windows

// Проверка значка: цвета, меню, выход. Ничего не перехватывает.
package main

import (
	"log"
	"runtime"
	"time"

	"quicdiver/internal/client/tray"
)

func main() {
	runtime.LockOSThread()

	done := make(chan struct{})
	var t *tray.Tray
	t, err := tray.New(tray.Actions{
		Connect:    func() { log.Print("МЕНЮ: подключиться") },
		Disconnect: func() { log.Print("МЕНЮ: отключиться") },
		OpenPanel:  func() { log.Print("МЕНЮ: открыть панель") },
		Quit:       func() { log.Print("МЕНЮ: выйти"); close(done) },
	})
	if err != nil {
		log.Fatalf("значок: %v", err)
	}

	// Гасим значок ИЗ ДРУГОЙ горутины — ровно так это делает клиент. Раньше
	// цикл сообщений на этом висел вечно, и процесс не завершался.
	go func() {
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			log.Print("время вышло — гашу значок из чужой горутины")
		}
		t.Close()
	}()

	t.Run()
	log.Print("цикл сообщений завершён — процесс выходит")
}
