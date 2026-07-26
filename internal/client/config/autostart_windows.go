//go:build windows

package config

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const appName = "QUICDiver"

// SetAutoStart включает или выключает автозапуск приложения в реестре Windows.
func SetAutoStart(enabled bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if enabled {
		exePath, err := os.Executable()
		if err != nil {
			return err
		}
		return k.SetStringValue(appName, `"`+exePath+`"`)
	}
	_ = k.DeleteValue(appName)
	return nil
}
