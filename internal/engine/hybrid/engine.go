// Package hybrid — гибридный data-path: TCP через надёжный стрим, UDP через
// датаграммы.
//
// Зачем (измерено на живом стенде):
//
//	чистый QUIC-datagram (потолок транспорта) — 560 Мбит, stddev 11%
//	TCP через надёжный стрим (H3 CONNECT)     — 494 Мбит, stddev 9%
//	TCP через connect-ip датаграммы           — 115 Мбит, пила
//
// Датаграммы QUIC не ретрансмитятся (RFC 9221 by design), а congestion туннеля
// сам создаёт ~0.25% потерь: каждая потерянная датаграмма = потерянный IP-пакет,
// и внутренний TCP рушит cwnd. Поэтому TCP-флоу терминируется локальным gVisor и
// уезжает в CONNECT-стрим (потери закрывает ретрансмит QUIC). UDP остаётся на
// датаграммах: там ретрансмит только добавил бы задержку, приложение (QUIC, DNS)
// разбирается само.
//
// Побочные выигрыши для TCP: не нужен ни NAT (стрим несёт dst отдельно), ни
// MSS-clamp (пакеты приложения не едут в датаграмме).
package hybrid

import (
	"context"
	"log"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"

	"quicdiver/internal/engine"
	"quicdiver/internal/guard"
	"quicdiver/internal/packet"
	"quicdiver/internal/server/netstack"
)

const maxInboundBatch = 128

// Engine — гибридный движок клиента.
type Engine struct {
	guard    *guard.Guard
	rewriter engine.Rewriter // NAT только для датаграммного (UDP) пути
	ns          *netstack.Stack // локальный стек: терминация TCP → CONNECT-стрим
	recvWorkers int             // потоков захвата (>1 ускоряет скачивание, но даёт reordering)
	bufPool     sync.Pool       // буферы датаграммного пути
	tcpPool     sync.Pool       // буферы TCP-моста; отдельный, чтобы пути не делили пул

	cOutRecv, cTCP, cUDP, cBypass, cWriteErr, cOversize atomic.Uint64
	cInRecv, cInject, cInErr                            atomic.Uint64
}

// New собирает движок: ns — стек с CONNECT-Dialer (TCP), rw — NAT для UDP,
// recvWorkers — потоков захвата (1 = сохранять порядок пакетов; >1 ускоряет
// скачивание ценой reordering и просадки отдачи).
func New(g *guard.Guard, rw engine.Rewriter, ns *netstack.Stack, recvWorkers int) *Engine {
	if recvWorkers < 1 {
		recvWorkers = 1
	}
	return &Engine{
		guard:       g,
		rewriter:    rw,
		ns:          ns,
		recvWorkers: recvWorkers,
		bufPool:     sync.Pool{New: func() any { return make([]byte, 65600) }},
		tcpPool:     sync.Pool{New: func() any { return make([]byte, 65600) }},
	}
}

// Run гоняет трафик до отмены ctx или фатальной ошибки.
func (e *Engine) Run(ctx context.Context, src packet.Source, tun engine.PacketTunnel) error {
	errc := make(chan error, 3)

	// Локальный стек обслуживает TCP: читает перехваченные TCP-пакеты из tt,
	// терминирует флоу, ходит наружу CONNECT-стримами, а ответные пакеты пишет
	// обратно в стек ОС через tt.WritePacket.
	tt := &tcpTunnel{
		src:  src,
		ch:   make(chan []byte, 2048),
		out:  make(chan []byte, 4096),
		pool: &e.tcpPool,
	}
	// Захват и инжект — в несколько потоков, если источник это умеет: один поток
	// упирается в потолок раньше канала (замерено: тот же путь без WinDivert даёт
	// 693 Мбит, с однопоточным WinDivert — ~300).
	// Инжектор — РОВНО ОДИН: несколько дерутся за общий канал и разваливают
	// батчи (замерено: avg падал 19 → 3.8 пак/syscall).
	//
	// Читателей — умеренно: параллельный Recv поднимает скачивание (300→450), но
	// ломает порядок пакетов, и отдача проседает от reordering (800→450). Порядок
	// внутри потока важнее пары сотен мегабит, поэтому по умолчанию читатель тоже
	// один; больше — только явным флагом, для экспериментов.
	if ms, ok := src.(packet.MultiSource); ok {
		go tt.injector(ctx, ms.NewWriter())
	} else {
		go tt.injector(ctx, src)
	}

	go func() { errc <- e.ns.Run(ctx, tt) }()

	if ms, ok := src.(packet.MultiSource); ok && e.recvWorkers > 1 {
		log.Printf("захват в %d потоков (внимание: возможен reordering)", e.recvWorkers)
		for i := 0; i < e.recvWorkers; i++ {
			go e.pumpOutboundReader(ctx, ms.NewReader(), src, tun, tt, errc)
		}
	} else {
		go e.pumpOutbound(ctx, src, tun, tt, errc)
	}
	go e.pumpInbound(ctx, src, tun, errc)
	go e.logStats(ctx, tt)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errc:
		return err
	}
}

func (e *Engine) logStats(ctx context.Context, tt *tcpTunnel) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rcvd, dropped := quic.DatagramStats()
			var pct float64
			if rcvd+dropped > 0 {
				pct = float64(dropped) * 100 / float64(rcvd+dropped)
			}
			log.Printf("stats out: recv=%d tcp→стек=%d udp→датаграмма=%d bypass=%d oversize=%d | udp-in: recv=%d inject=%d",
				e.cOutRecv.Load(), e.cTCP.Load(), e.cUDP.Load(), e.cBypass.Load(),
				e.cOversize.Load(), e.cInRecv.Load(), e.cInject.Load())
			var avgBatch float64
			if b := tt.cBatches.Load(); b > 0 {
				avgBatch = float64(tt.cWrite.Load()) / float64(b)
			}
			log.Printf("  мост: push=%d drop=%d read=%d | inject=%d батчей=%d (avg %.1f пак/syscall) outDrop=%d writeErr=%d | datagram DROPPED=%.2f%%",
				tt.cPush.Load(), tt.cDrop.Load(), tt.cRead.Load(),
				tt.cWrite.Load(), tt.cBatches.Load(), avgBatch,
				tt.cOutDrop.Load(), tt.cWriteErr.Load(), pct)
			log.Printf("  стек: %s", e.ns.DebugStats())
		}
	}
}

// pumpOutbound разводит перехваченные пакеты: TCP → локальный стек (стрим),
// остальное → датаграмма.
func (e *Engine) pumpOutbound(ctx context.Context, src packet.Source, tun engine.PacketTunnel, tt *tcpTunnel, errc chan<- error) {
	e.pumpOutboundReader(ctx, srcReader{src}, src, tun, tt, errc)
}

// srcReader адаптирует однопоточный Source к интерфейсу Reader.
type srcReader struct{ s packet.Source }

func (r srcReader) Recv(ctx context.Context) ([]packet.Packet, error) { return r.s.Recv(ctx) }

// pumpOutboundReader — тело насоса поверх одного независимого приёмника.
func (e *Engine) pumpOutboundReader(ctx context.Context, rd packet.Reader, src packet.Source, tun engine.PacketTunnel, tt *tcpTunnel, errc chan<- error) {
	var reinject []packet.Packet
	for {
		pkts, err := rd.Recv(ctx)
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
				reinject = append(reinject, *p)
				continue
			}
			if isTCP(p.Data) {
				e.cTCP.Add(1)
				tt.push(p.Data) // локальный стек терминирует и уедет CONNECT-стримом
				continue
			}
			// UDP и прочее — датаграммой, как в модели B.
			e.cUDP.Add(1)
			if e.rewriter != nil {
				e.rewriter.Outbound(p.Data)
			}
			icmp, err := tun.WritePacket(p.Data)
			if err != nil {
				e.cWriteErr.Add(1)
				continue
			}
			if len(icmp) > 0 {
				e.cOversize.Add(1)
				if e.rewriter != nil {
					e.rewriter.Inbound(icmp)
				}
				reinject = append(reinject, packet.Packet{Data: icmp, Dir: packet.Inbound})
			}
		}
		if len(reinject) > 0 {
			if err := src.Send(reinject); err != nil {
				e.cInErr.Add(1)
			}
		}
	}
}

// pumpInbound — ответные UDP-пакеты из датаграмм → инжект в стек ОС.
func (e *Engine) pumpInbound(ctx context.Context, src packet.Source, tun engine.PacketTunnel, errc chan<- error) {
	ch := make(chan []byte, 2048)
	go func() {
		defer close(ch)
		for {
			if ctx.Err() != nil {
				return
			}
			buf := e.bufPool.Get().([]byte)
			n, err := tun.ReadPacket(buf)
			if err != nil {
				errc <- err
				return
			}
			if n == 0 {
				e.bufPool.Put(buf)
				continue
			}
			e.cInRecv.Add(1)
			select {
			case ch <- buf[:n]:
			case <-ctx.Done():
				return
			}
		}
	}()

	batch := make([]packet.Packet, 0, maxInboundBatch)
	bufs := make([][]byte, 0, maxInboundBatch)
	for {
		var first []byte
		select {
		case <-ctx.Done():
			return
		case d, ok := <-ch:
			if !ok {
				return
			}
			first = d
		}
		batch, bufs = batch[:0], bufs[:0]
		e.prep(first, &batch)
		bufs = append(bufs, first)
	drain:
		for len(batch) < maxInboundBatch {
			select {
			case d, ok := <-ch:
				if !ok {
					break drain
				}
				e.prep(d, &batch)
				bufs = append(bufs, d)
			default:
				break drain
			}
		}
		if len(batch) > 0 {
			if err := src.Send(batch); err != nil {
				e.cInErr.Add(1)
			} else {
				e.cInject.Add(uint64(len(batch)))
			}
		}
		for _, b := range bufs {
			e.bufPool.Put(b[:cap(b)])
		}
	}
}

func (e *Engine) prep(data []byte, batch *[]packet.Packet) {
	if e.rewriter != nil {
		e.rewriter.Inbound(data)
	}
	*batch = append(*batch, packet.Packet{Data: data, Dir: packet.Inbound})
}

// tcpTunnel — мост между перехватом и локальным стеком: стек читает отсюда
// TCP-пакеты приложений, а свои ответные пакеты уходят на инжект в стек ОС.
//
// Ответы инжектятся ПАЧКАМИ: на download стек генерит десятки тысяч пакетов в
// секунду, и syscall на каждый (плюс аллокация) резал скорость втрое — upload,
// которому инжект не нужен, всё это время выдавал полную линию.
type tcpTunnel struct {
	src     packet.Source
	writers []packet.Writer // независимые инжекторы (по одному на поток)
	ch      chan []byte     // перехват → стек
	out     chan []byte     // стек → инжект (батчится в injector)
	pool    *sync.Pool

	cPush, cDrop, cRead, cWrite, cWriteErr, cOutDrop, cBatches atomic.Uint64
}

func (t *tcpTunnel) push(pkt []byte) {
	// первые пакеты — байтами: только так видно, что именно стек бракует
	if n := t.cPush.Load(); n < 3 {
		m := 28
		if len(pkt) < m {
			m = len(pkt)
		}
		log.Printf("  [dbg] pkt#%d len=%d ver=%d ihl=%d proto=%d hex=% x",
			n, len(pkt), pkt[0]>>4, (pkt[0]&0x0F)*4, pkt[9], pkt[:m])
	}
	buf := t.pool.Get().([]byte)
	n := copy(buf, pkt)
	select {
	case t.ch <- buf[:n]:
		t.cPush.Add(1)
	default: // стек не успевает — лучше уронить пакет, чем застопорить перехват
		t.cDrop.Add(1)
		t.pool.Put(buf)
	}
}

func (t *tcpTunnel) ReadPacket(b []byte) (int, error) {
	data, ok := <-t.ch
	if !ok {
		return 0, context.Canceled
	}
	n := copy(b, data)
	t.pool.Put(data[:cap(data)])
	t.cRead.Add(1)
	return n, nil
}

// WritePacket ставит ответный пакет в очередь на инжект (не syscall на каждый).
func (t *tcpTunnel) WritePacket(b []byte) ([]byte, error) {
	buf := t.pool.Get().([]byte)
	n := copy(buf, b)
	select {
	case t.out <- buf[:n]:
	default: // инжектор не успевает — дропаем, это обычная потеря для TCP
		t.cOutDrop.Add(1)
		t.pool.Put(buf)
	}
	return nil, nil
}

// injector собирает ответные пакеты в пачку и инжектит одним вызовом.
//
// Стек отдаёт пакеты по одному, поэтому чистый неблокирующий drain почти всегда
// собирал батч из ОДНОГО пакета — syscall на каждый, как будто батча и нет
// (профиль: sendEx съедал полъядра). Поэтому ждём короткое окно накопления:
// задержка микроскопическая, а syscall'ов кратно меньше.
const injectGather = 300 * time.Microsecond

func (t *tcpTunnel) injector(ctx context.Context, w packet.Writer) {
	batch := make([]packet.Packet, 0, maxInboundBatch)
	bufs := make([][]byte, 0, maxInboundBatch)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	if !timer.Stop() {
		<-timer.C
	}

	for {
		var first []byte
		select {
		case <-ctx.Done():
			return
		case d, ok := <-t.out:
			if !ok {
				return
			}
			first = d
		}
		batch, bufs = batch[:0], bufs[:0]
		batch = append(batch, packet.Packet{Data: first, Dir: packet.Inbound})
		bufs = append(bufs, first)

		timer.Reset(injectGather)
	drain:
		for len(batch) < maxInboundBatch {
			select {
			case d, ok := <-t.out:
				if !ok {
					break drain
				}
				batch = append(batch, packet.Packet{Data: d, Dir: packet.Inbound})
				bufs = append(bufs, d)
			case <-timer.C:
				break drain
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		if err := w.Send(batch); err != nil {
			t.cWriteErr.Add(1)
		} else {
			t.cWrite.Add(uint64(len(batch)))
		}
		t.cBatches.Add(1)
		for _, b := range bufs {
			t.pool.Put(b[:cap(b)])
		}
	}
}

func isTCP(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}
	switch pkt[0] >> 4 {
	case 4:
		return len(pkt) >= 20 && pkt[9] == 6
	case 6:
		return len(pkt) >= 40 && pkt[6] == 6
	}
	return false
}

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
	}
	return netip.Addr{}, false
}

var _ engine.Engine = (*Engine)(nil)
