//go:build !windows

package config

// SetAutoStart — заглушка управления автозапуском для не-Windows платформ.
func SetAutoStart(enabled bool) error {
	return nil
}
