//go:build windows

package sysproxy

import (
	"testing"
)

func TestSysproxyStashAndRestore(t *testing.T) {
	s, err := Disable()
	if err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if err := s.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	EnsureRestored()
}
