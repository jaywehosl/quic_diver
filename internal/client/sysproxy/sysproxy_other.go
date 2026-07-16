//go:build !windows

// Package sysproxy на не-Windows — заглушка (управление системным прокси через
// TUN/iptables/pf добавится по мере поддержки платформ).
package sysproxy

// Saved — пустое состояние на не-Windows платформах.
type Saved struct{}

// Current сообщает, что прокси не управляется на этой платформе.
func Current() (enabled bool, server string, err error) { return false, "", nil }

// Disable — no-op.
func Disable() (*Saved, error) { return &Saved{}, nil }

// Restore — no-op.
func (s *Saved) Restore() error { return nil }
