// Package engine — модель обработки трафика (data-path).
//
// Engine — единственная точка, где живёт развилка A/B. Всё под ним (packet.Source,
// uplink.Conn) — общее. Смена модели = смена реализации Engine, остальной код не
// трогается.
//
//	Модель B (connectip): passthrough — сырые IP-пакеты из Source заворачиваются
//	   в connect-ip датаграммы Conn; ответы разворачиваются и реинжектятся. gVisor
//	   на клиенте не нужен. Выбрана как основная.
//	Модель A (l4quic, позже): терминация TCP/UDP в gVisor на клиенте, per-flow
//	   потоки/датаграммы. Даёт клиентский per-flow роутинг/статистику даром ценой
//	   overhead. Добавляется отдельной реализацией Engine.
package engine

import (
	"context"

	"quicdiver/internal/packet"
	"quicdiver/internal/uplink"
)

// Engine гоняет трафик между локальным источником пакетов и uplink до узла.
type Engine interface {
	// Run обрабатывает трафик до отмены ctx или фатальной ошибки.
	// Реализация многопоточна по умолчанию (arch6).
	Run(ctx context.Context, src packet.Source, up uplink.Conn) error
}
