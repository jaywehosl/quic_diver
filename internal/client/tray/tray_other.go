//go:build !windows

package tray

import "errors"

// Значка нет: лоток есть только на Windows. Остальные платформы получают
// заглушку, чтобы клиент собирался и работал без неё — панель и автоподключение
// от значка не зависят.
//
// Здесь же появятся свои реализации: на macOS — пункт в строке меню, на
// Android — плитка быстрых настроек.

// Actions — что делает меню значка.
type Actions struct {
	Connect    func()
	Disconnect func()
	OpenPanel  func()
	Quit       func()
}

// Tray — значок в лотке (на этой платформе отсутствует).
type Tray struct{}

// ErrUnsupported — на этой платформе значка нет.
var ErrUnsupported = errors.New("tray: лоток поддержан только на Windows")

func New(Actions) (*Tray, error) { return nil, ErrUnsupported }

func (t *Tray) SetState(State)        {}
func (t *Tray) Notify(_, _, _ string) {}
func (t *Tray) Run()                  {}
func (t *Tray) Close()                {}
