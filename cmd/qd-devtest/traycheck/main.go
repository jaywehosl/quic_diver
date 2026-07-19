// Проверка значка в лотке: цвета, меню, уведомления. Ничего не перехватывает.
package main

import (
	"log"
	"runtime"
	"time"

	"quicdiver/internal/client/tray"
)

func main() {
	runtime.LockOSThread() // окно и цикл сообщений обязаны жить в одной нити ОС

	done := make(chan struct{})
	t, err := tray.New(tray.Actions{
		Connect:    func() { log.Print("МЕНЮ: подключиться") },
		Disconnect: func() { log.Print("МЕНЮ: отключиться") },
		OpenPanel:  func() { log.Print("МЕНЮ: открыть панель") },
		Quit:       func() { log.Print("МЕНЮ: выйти"); close(done) },
	})
	if err != nil {
		log.Fatalf("значок: %v", err)
	}
	defer t.Close()

	go func() {
		states := []struct {
			s    tray.State
			note string
		}{
			{tray.State{Session: tray.Stopped}, "серый — отключено"},
			{tray.State{Session: tray.Connected}, "зелёный — работает"},
			{tray.State{Session: tray.Connecting}, "красный — связи нет"},
			{tray.State{Session: tray.Connected, Unread: 2}, "синий — есть уведомления"},
		}
		for _, st := range states {
			log.Printf("значок: %s", st.note)
			t.SetState(st.s)
			time.Sleep(3 * time.Second)
		}
		t.Notify("warn", "QUIC Diver", "проверка уведомления")
		log.Print("уведомление отправлено; правый клик — меню, выход — пункт «Выйти»")
		time.Sleep(20 * time.Second)
		close(done)
	}()

	go func() { <-done; t.Close() }()
	t.Run()
	log.Print("значок закрыт")
}
