// Package android — экспортируемый адаптер QUIC Diver для Android VpnService.
//
// Делегирует вызовы в quicdiver/internal/mobile.
package android

import (
	"quicdiver/internal/mobile"
)

// StartEngine запускает обработку трафика TUN устройства.
func StartEngine(fd int, configJSON string) error {
	return mobile.StartEngine(fd, configJSON)
}

// StopEngine полностью останавливает движок и освобождает TUN-дескриптор.
func StopEngine() error {
	return mobile.StopEngine()
}

// UpdateRules динамически обновляет маршрутные правила.
func UpdateRules(rules string) error {
	return mobile.UpdateRules(rules)
}

// GetStatus возвращает текущий статус адаптера в формате JSON.
func GetStatus() string {
	return mobile.GetStatus()
}

// ImportBundle разбирает ссылку-бандл (qd://...) и возвращает её JSON-конфиг.
func ImportBundle(bundleStr string) (string, error) {
	return mobile.ImportBundle(bundleStr)
}
