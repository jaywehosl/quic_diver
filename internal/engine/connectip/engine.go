// Package connectip — модель B: passthrough сырых IP между источником пакетов и
// connect-ip туннелем до узла.
//
// Два насоса:
//   - outbound: Source.Recv (перехваченные пакеты приложений) → guard-фильтр →
//     PacketTunnel.WritePacket. Локальный/петлевой трафик (guard.Bypass) не идёт
//     в туннель, а реинжектится обратно в стек ОС.
//   - inbound: PacketTunnel.ReadPacket (ответы из туннеля) → Source.Send (инжект
//     в стек ОС как inbound).
//
// Роутинг chain/direct в модели B решает УЗЕЛ (он видит dst), поэтому клиентский
// движок его не касается — просто гонит всё, кроме bypass, в туннель.
package connectip

import (
	"context"
	"net/netip"

	"quicdiver/internal/engine"
	"quicdiver/internal/guard"
	"quicdiver/internal/packet"
)

// Engine — реализация модели B.
type Engine struct {
	guard *guard.Guard
}

// New собирает движок с local-guard (может быть nil — тогда всё идёт в туннель).
func New(g *guard.Guard) *Engine { return &Engine{guard: g} }

// Run запускает оба насоса и завершается по отмене ctx или первой ошибке.
func (e *Engine) Run(ctx context.Context, src packet.Source, tun engine.PacketTunnel) error {
	errc := make(chan error, 2)
	go e.pumpOutbound(ctx, src, tun, errc)
	go e.pumpInbound(ctx, src, tun, errc)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errc:
		return err
	}
}

func (e *Engine) pumpOutbound(ctx context.Context, src packet.Source, tun engine.PacketTunnel, errc chan<- error) {
	var reinject []packet.Packet
	for {
		pkts, err := src.Recv(ctx)
		if err != nil {
			errc <- err
			return
		}
		reinject = reinject[:0]
		for i := range pkts {
			p := &pkts[i]
			dst, ok := dstAddr(p.Data)
			if !ok {
				continue
			}
			if e.guard != nil && e.guard.Bypass(dst) {
				reinject = append(reinject, *p) // не наш трафик — вернуть в стек
				continue
			}
			if _, err := tun.WritePacket(p.Data); err != nil {
				errc <- err
				return
			}
		}
		if len(reinject) > 0 {
			if err := src.Send(reinject); err != nil {
				errc <- err
				return
			}
		}
	}
}

func (e *Engine) pumpInbound(ctx context.Context, src packet.Source, tun engine.PacketTunnel, errc chan<- error) {
	buf := make([]byte, 65600)
	for {
		n, err := tun.ReadPacket(buf)
		if err != nil {
			errc <- err
			return
		}
		if n == 0 {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		if err := src.Send([]packet.Packet{{Data: data, Dir: packet.Inbound}}); err != nil {
			errc <- err
			return
		}
	}
}

// dstAddr извлекает адрес назначения из IP-заголовка.
func dstAddr(b []byte) (netip.Addr, bool) {
	if len(b) < 1 {
		return netip.Addr{}, false
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(b[16:20])), true
	case 6:
		if len(b) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(b[24:40])), true
	default:
		return netip.Addr{}, false
	}
}

var _ engine.Engine = (*Engine)(nil)
