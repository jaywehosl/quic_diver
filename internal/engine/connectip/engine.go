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
	"encoding/binary"
	"log"
	"net/netip"
	"sync/atomic"
	"time"

	"quicdiver/internal/engine"
	"quicdiver/internal/guard"
	"quicdiver/internal/packet"
)

// clampMSSValue — верхний предел TCP MSS. IP(20)+TCP(20)+MSS должно влезать в
// connect-ip датаграмму (QUIC datagram ~1350 при path MTU 1500 минус overhead).
// 1200 — консервативно с запасом; позже уточнять по MaxDatagramSize.
const clampMSSValue = 1200

// Engine — реализация модели B.
type Engine struct {
	guard    *guard.Guard
	rewriter engine.Rewriter

	// счётчики для диагностики
	cOutRecv, cToTunnel, cBypass, cWriteErr, cOversize atomic.Uint64
	cInRecv, cInject, cInErr                           atomic.Uint64
}

// New собирает движок с local-guard (nil → всё в туннель) и опциональным
// rewriter (клиентский NAT; nil → без подмены адресов).
func New(g *guard.Guard, rw engine.Rewriter) *Engine {
	return &Engine{guard: g, rewriter: rw}
}

// Run запускает оба насоса и завершается по отмене ctx или первой ошибке.
func (e *Engine) Run(ctx context.Context, src packet.Source, tun engine.PacketTunnel) error {
	errc := make(chan error, 2)
	go e.pumpOutbound(ctx, src, tun, errc)
	go e.pumpInbound(ctx, src, tun, errc)
	go e.logStats(ctx)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errc:
		return err
	}
}

func (e *Engine) logStats(ctx context.Context) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			log.Printf("stats out: recv=%d tunnel=%d bypass=%d oversize=%d writeErr=%d | in: recv=%d inject=%d inErr=%d",
				e.cOutRecv.Load(), e.cToTunnel.Load(), e.cBypass.Load(), e.cOversize.Load(), e.cWriteErr.Load(),
				e.cInRecv.Load(), e.cInject.Load(), e.cInErr.Load())
		}
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
		e.cOutRecv.Add(uint64(len(pkts)))
		reinject = reinject[:0]
		for i := range pkts {
			p := &pkts[i]
			dst, ok := dstAddr(p.Data)
			if !ok {
				continue
			}
			if e.guard != nil && e.guard.Bypass(dst) {
				e.cBypass.Add(1)
				reinject = append(reinject, *p) // не наш трафик — вернуть в стек
				continue
			}
			clampMSS(p.Data) // TCP SYN: ужать MSS под MTU туннеля
			if e.rewriter != nil {
				e.rewriter.Outbound(p.Data) // src real→assigned (connect-ip требует)
			}
			icmp, err := tun.WritePacket(p.Data)
			if err != nil {
				e.cWriteErr.Add(1)
				continue
			}
			if len(icmp) > 0 {
				// пакет крупнее пути — узел вернул ICMP PTB; реинжектим источнику,
				// чтобы приложение уменьшило размер (PMTUD).
				e.cOversize.Add(1)
				if e.rewriter != nil {
					e.rewriter.Inbound(icmp)
				}
				reinject = append(reinject, packet.Packet{Data: icmp, Dir: packet.Inbound})
				continue
			}
			e.cToTunnel.Add(1)
		}
		if len(reinject) > 0 {
			if err := src.Send(reinject); err != nil {
				e.cInErr.Add(1)
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
		e.cInRecv.Add(1)
		data := make([]byte, n)
		copy(data, buf[:n])
		if e.rewriter != nil {
			e.rewriter.Inbound(data) // dst assigned→real
		}
		clampMSS(data) // TCP SYN-ACK: ужать MSS под MTU туннеля
		if err := src.Send([]packet.Packet{{Data: data, Dir: packet.Inbound}}); err != nil {
			e.cInErr.Add(1)
			continue
		}
		e.cInject.Add(1)
	}
}

// clampMSS ужимает опцию MSS в TCP SYN/SYN-ACK до clampMSSValue (IPv4). Правит
// TCP-контрольную сумму инкрементально (RFC 1624). Пакеты без SYN не трогает.
func clampMSS(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return // не IPv4 TCP
	}
	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl+20 {
		return
	}
	tcp := pkt[ihl:]
	if tcp[13]&0x02 == 0 {
		return // не SYN
	}
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || ihl+dataOff > len(pkt) {
		return
	}
	opts := tcp[20:dataOff]
	for i := 0; i+1 < len(opts); {
		kind := opts[i]
		if kind == 0 { // EOL
			break
		}
		if kind == 1 { // NOP
			i++
			continue
		}
		length := int(opts[i+1])
		if length < 2 || i+length > len(opts) {
			break
		}
		if kind == 2 && length == 4 { // MSS
			mss := binary.BigEndian.Uint16(opts[i+2:])
			if mss > clampMSSValue {
				old := [2]byte{opts[i+2], opts[i+3]}
				binary.BigEndian.PutUint16(opts[i+2:], clampMSSValue)
				newv := [2]byte{opts[i+2], opts[i+3]}
				csumOff := ihl + 16
				c := binary.BigEndian.Uint16(pkt[csumOff:])
				binary.BigEndian.PutUint16(pkt[csumOff:], csumUpdate(c, old[:], newv[:]))
			}
		}
		i += length
	}
}

// csumUpdate — RFC 1624: HC' = ~(~HC + ~m + m') для замены слов old→new.
func csumUpdate(hc uint16, old, new []byte) uint16 {
	sum := uint32(hc ^ 0xFFFF)
	for i := 0; i+1 < len(old); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(old[i:]) ^ 0xFFFF)
		sum += uint32(binary.BigEndian.Uint16(new[i:]))
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(sum ^ 0xFFFF)
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
