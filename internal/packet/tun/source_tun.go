//go:build linux || android || darwin || ios

// Package tun — реализация packet.Source поверх TUN-устройства.
//
// На мобильных и macOS/iOS TUN-less невозможен, TUN разрешён (см. вводные по
// архитектуре). TUN отдаёт те же сырые IP-пакеты, что и WinDivert, поэтому
// контракт packet.Source один и тот же — ядро не видит разницы.
//
// TODO(quicdiver): реальное чтение/запись TUN-фрейма + батчинг (readv/writev),
// на Android — интеграция с VpnService.Builder (fd прокидывается снаружи).
package tun

import (
	"context"
	"errors"

	"quicdiver/internal/packet"
)

var errNotImplemented = errors.New("tun: not implemented (skeleton)")

// Source читает/пишет сырые IP через TUN-устройство.
type Source struct {
	mtu int
}

// Open открывает TUN-устройство по имени (или из готового fd на Android).
func Open(name string) (*Source, error) {
	return &Source{mtu: 1500}, errNotImplemented
}

func (s *Source) Recv(ctx context.Context) ([]packet.Packet, error) { return nil, errNotImplemented }
func (s *Source) Send(pkts []packet.Packet) error                   { return errNotImplemented }
func (s *Source) MTU() int                                          { return s.mtu }
func (s *Source) Close() error                                      { return nil }

var _ packet.Source = (*Source)(nil)
