//go:build windows

// Package sysproxy управляет системным HTTP-прокси Windows.
//
// Клиент QUIC Diver при старте отключает системный прокси (сохранив состояние),
// чтобы приложения ходили напрямую и попадали под перехват WinDivert; при выходе
// восстанавливает. Это заменяет хардкод анти-петли к системному прокси.
package sysproxy

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
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

func stashPath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	appDir := filepath.Join(dir, "quicdiver")
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return "", err
	}
	return filepath.Join(appDir, "sysproxy_stash.json"), nil
}

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
	HadEnable uint32 `json:"had_enable"`
	Enable    uint32 `json:"enable"`
	Server    string `json:"server"`
	Override  string `json:"override"`
	HadServer bool   `json:"had_server"`
}

func (s *Saved) saveStash() error {
	path, err := stashPath()
	if err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// EnsureRestored проверяет дисковый стэш от предыдущего аварийного вылета и восстанавливает прокси.
func EnsureRestored() {
	path, err := stashPath()
	if err != nil {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var s Saved
	if err := json.Unmarshal(data, &s); err == nil {
		log.Printf("sysproxy: найден стэш от предыдущего сеанса, восстанавливаем системный прокси...")
		_ = s.Restore()
	}
	_ = os.Remove(path)
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

// Disable отключает системный прокси, сохраняя состояние в стэш для последующего Restore.
func Disable() (*Saved, error) {
	// Сначала проверяем/подбираем прошлый незакрытый стэш
	EnsureRestored()

	k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	s := &Saved{}
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		s.Enable = uint32(v)
		s.HadEnable = 1
	}
	if srv, _, err := k.GetStringValue("ProxyServer"); err == nil {
		s.Server = srv
		s.HadServer = true
	}
	s.Override, _, _ = k.GetStringValue("ProxyOverride")

	_ = s.saveStash()

	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return nil, err
	}
	notifyChange()
	return s, nil
}

// Restore возвращает системный прокси в исходное состояние и чистит стэш.
func (s *Saved) Restore() error {
	if s == nil {
		return nil
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if s.HadEnable != 0 {
		_ = k.SetDWordValue("ProxyEnable", s.Enable)
	}
	if s.HadServer && s.Server != "" {
		_ = k.SetStringValue("ProxyServer", s.Server)
	}
	if s.Override != "" {
		_ = k.SetStringValue("ProxyOverride", s.Override)
	}

	if path, err := stashPath(); err == nil {
		_ = os.Remove(path)
	}

	notifyChange()
	return nil
}
