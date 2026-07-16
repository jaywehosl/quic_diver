//go:build windows

// Package windivert — реализация packet.Source поверх WinDivert (Windows).
//
// Перехват на NETWORK-слое по filter-выражению (см. BuildFilter): фильтр —
// первый рубеж local-guard (arch5) и анти-петли, драйвер не отдаёт исключённое в
// userspace. Recv/Send — батчевые (RecvEx/SendEx, до BatchMax пакетов за вызов),
// это batch-подход arch6.
//
// В модели B клиент тонкий: Recv (outbound приложений) → cip.WritePacket;
// cip.ReadPacket → Send (inbound-инжект в стек ОС). gVisor на клиенте нет.
package windivert

import (
	"context"
	"encoding/binary"
	"errors"

	"golang.org/x/sys/windows"

	"quicdiver/internal/packet"
)

const (
	recvBufBytes  = 2 * 1024 * 1024 // приёмный буфер под батч
	queueLenBoost = 8192            // длина очереди драйвера под нагрузкой
)

var (
	errShortIP   = errors.New("windivert: IP-пакет короче заголовка")
	errIPVersion = errors.New("windivert: неизвестная версия IP")
)

// Source захватывает и инжектит сырые IP через WinDivert.
type Source struct {
	h   windows.Handle
	mtu int

	recvBuf  []byte
	recvAddr []Address
	out      []packet.Packet

	sendBuf  []byte
	sendAddr []Address
}

// Open грузит WinDivert.dll (dllPath, рядом обязан лежать WinDivert64.sys) и
// открывает NETWORK-хэндл по фильтру. Требует прав администратора.
//
// flags — WinDivert-флаги: 0 для боевого отвода (перехват + реинжект), либо
// FlagSniff|FlagRecvOnly для безопасного наблюдения (копии, оригинал идёт дальше).
func Open(dllPath, filter string, flags uint64) (*Source, error) {
	if err := Load(dllPath); err != nil {
		return nil, err
	}
	h, err := open(filter, LayerNetwork, 0, flags)
	if err != nil {
		return nil, err
	}
	_ = setParam(h, ParamQueueLength, queueLenBoost)

	return &Source{
		h:        h,
		mtu:      1500,
		recvBuf:  make([]byte, recvBufBytes),
		recvAddr: make([]Address, BatchMax),
		out:      make([]packet.Packet, 0, BatchMax),
		sendBuf:  make([]byte, 0, recvBufBytes),
		sendAddr: make([]Address, 0, BatchMax),
	}, nil
}

// Recv читает батч перехваченных пакетов. Возвращённые Packet.Data валидны до
// следующего Recv (внутренний буфер переиспользуется).
func (s *Source) Recv(ctx context.Context) ([]packet.Packet, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	packetLen, addrCount, err := recvEx(s.h, s.recvBuf, s.recvAddr)
	if err != nil {
		return nil, err
	}
	return splitBatch(s.recvBuf[:packetLen], s.recvAddr[:addrCount], s.out[:0])
}

// Send инжектит батч пакетов. Пакеты из туннеля (ответы) идут как inbound.
func (s *Source) Send(pkts []packet.Packet) error {
	if len(pkts) == 0 {
		return nil
	}
	s.sendBuf = s.sendBuf[:0]
	s.sendAddr = s.sendAddr[:0]
	for i := range pkts {
		p := &pkts[i]
		s.sendBuf = append(s.sendBuf, p.Data...)
		var a Address
		a.SetLayer(LayerNetwork)
		a.SetOutbound(p.Dir == packet.Outbound)
		a.SetIfIdx(p.IfIndex)
		s.sendAddr = append(s.sendAddr, a)
	}
	// TODO(quicdiver): если пакет модифицирован — пересчитать контрольные суммы
	// (WinDivertHelperCalcChecksums). Ответы из туннеля приходят валидными.
	_, err := sendEx(s.h, s.sendBuf, s.sendAddr)
	return err
}

func (s *Source) MTU() int { return s.mtu }

// Close корректно останавливает и закрывает хэндл.
func (s *Source) Close() error {
	_ = shutdown(s.h, ShutdownBoth)
	return closeHandle(s.h)
}

// splitBatch нарезает непрерывный буфер батча на отдельные пакеты по длине из
// IP-заголовка; addrs[i] соответствует i-му пакету.
func splitBatch(buf []byte, addrs []Address, out []packet.Packet) ([]packet.Packet, error) {
	off := 0
	for i := range addrs {
		if off >= len(buf) {
			break
		}
		n, err := ipPacketLen(buf[off:])
		if err != nil {
			return out, err
		}
		if n == 0 || off+n > len(buf) {
			break
		}
		a := &addrs[i]
		dir := packet.Inbound
		if a.Outbound() {
			dir = packet.Outbound
		}
		out = append(out, packet.Packet{
			Data:    buf[off : off+n],
			Dir:     dir,
			IfIndex: a.IfIdx(),
		})
		off += n
	}
	return out, nil
}

// ipPacketLen возвращает полную длину IP-пакета из его заголовка.
func ipPacketLen(b []byte) (int, error) {
	if len(b) < 1 {
		return 0, errShortIP
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return 0, errShortIP
		}
		return int(binary.BigEndian.Uint16(b[2:4])), nil // IPv4 Total Length
	case 6:
		if len(b) < 40 {
			return 0, errShortIP
		}
		return 40 + int(binary.BigEndian.Uint16(b[4:6])), nil // 40 + Payload Length
	default:
		return 0, errIPVersion
	}
}

var _ packet.Source = (*Source)(nil)
