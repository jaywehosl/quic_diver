//go:build windows

// Package sysproxy управляет системным HTTP-прокси Windows.
//
// Клиент QUIC Diver при старте отключает системный прокси (сохранив состояние),
// чтобы приложения ходили напрямую и попадали под перехват WinDivert; при выходе
// восстанавливает. Это заменяет хардкод анти-петли к системному прокси.
package sysproxy

import (
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const keyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

var (
	wininet       = windows.NewLazyDLL("wininet.dll")
	procSetOption = wininet.NewProc("InternetSetOptionW")
)

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

// notifyChange уведомляет WinINET о смене настроек, чтобы приложения подхватили
// их без перезапуска.
//
// Уведомление повторяется: браузеры перечитывают настройки не мгновенно, а
// пришедшее в момент собственного старта могут и пропустить. Тогда приложение
// продолжает ходить через прокси, которого в системе уже нет, — со стороны это
// выглядит как «клиент подключён, а адрес прежний». Повтор стоит трёх вызовов
// и снимает большую часть таких случаев.
//
// Чего он не лечит: уже открытые соединения. Держащий keep-alive к прокси
// браузер доживёт на нём до закрытия вкладки, сколько его ни уведомляй.
func notifyChange() {
	go func() {
		for _, pause := range []time.Duration{0, 300 * time.Millisecond, time.Second} {
			if pause > 0 {
				time.Sleep(pause)
			}
			procSetOption.Call(0, internetOptionSettingsChanged, 0, 0)
			procSetOption.Call(0, internetOptionRefresh, 0, 0)
		}
	}()
}

// Saved — сохранённое состояние прокси для восстановления.
type Saved struct {
	hadEnable bool
	enable    uint32
	server    string
}

// Current читает текущее состояние прокси (без изменения).
func Current() (enabled bool, server string, err error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return false, "", err
	}
	defer k.Close()
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		enabled = v != 0
	}
	server, _, _ = k.GetStringValue("ProxyServer")
	return enabled, server, nil
}

// Disable отключает системный прокси, вернув состояние для последующего Restore.
func Disable() (*Saved, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	s := &Saved{}
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		s.enable = uint32(v)
		s.hadEnable = true
	}
	s.server, _, _ = k.GetStringValue("ProxyServer")

	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return nil, err
	}
	notifyChange()
	return s, nil
}

// Restore возвращает системный прокси в исходное состояние.
func (s *Saved) Restore() error {
	if s == nil {
		return nil
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if s.hadEnable {
		if err := k.SetDWordValue("ProxyEnable", s.enable); err != nil {
			return err
		}
	}
	notifyChange()
	return nil
}
