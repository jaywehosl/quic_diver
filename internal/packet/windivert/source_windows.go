//go:build windows

// Package windivert — реализация packet.Source поверх WinDivert (Windows).
//
// WinDivert перехватывает IP-пакеты на NETWORK-слое по filter-выражению.
// Само выражение фильтра — первая линия local-guard (arch5): в захват НЕ должны
// попадать локалка (RFC1918, loopback, link-local) и трафик к IP узлов-серверов
// (анти-петля). Второй линией служит guard.Guard уже в коде.
//
// Производительность: использовать WinDivertRecvEx/SendEx с батчами (до 0xFF
// пакетов за syscall) — это и есть batch-подход из arch6.
//
// TODO(quicdiver): подключить биндинг WinDivert (кандидат github.com/imgk/divert),
// вшить WinDivert.dll/.sys в .exe и распаковывать в %APPDATA%\QUICDiver.
package windivert

import (
	"context"
	"errors"

	"quicdiver/internal/packet"
)

// errNotImplemented — заглушка каркаса; заменяется реальным захватом на шаге PoC.
var errNotImplemented = errors.New("windivert: not implemented (skeleton)")

// Source захватывает сырые IP через WinDivert.
type Source struct {
	filter string
	mtu    int
}

// Open открывает WinDivert-хэндл по filter-выражению.
// filter формируется из настроек перехвата (per-process/port/proto/scope) и
// исключений local-guard.
func Open(filter string) (*Source, error) {
	return &Source{filter: filter, mtu: 1500}, errNotImplemented
}

func (s *Source) Recv(ctx context.Context) ([]packet.Packet, error) { return nil, errNotImplemented }
func (s *Source) Send(pkts []packet.Packet) error                   { return errNotImplemented }
func (s *Source) MTU() int                                          { return s.mtu }
func (s *Source) Close() error                                      { return nil }

var _ packet.Source = (*Source)(nil)
