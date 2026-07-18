package chain

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// PacketTunnel — сырой пакетный канал до upstream-узла (его реализует cip.Client).
// Интерфейсом, а не типом: chain не должен зависеть от транспорта, а тесты гоняют
// мультиплексор без реального QUIC.
type PacketTunnel interface {
	// WritePacket отправляет IP-пакет. Непустой icmp — ответ PTB при oversize.
	WritePacket(b []byte) (icmp []byte, err error)
	// ReadPacket читает один IP-пакет.
	ReadPacket(b []byte) (int, error)
}

// udpMux гонит UDP-флоу узла через connect-ip туннель к upstream-узлу.
//
// Узел A уже держит с B ровно такой же туннель, какой клиент держит с узлом, —
// значит для UDP в цепочку не нужен отдельный протокол: A ведёт себя как обычный
// клиент B и шлёт сырые IP-пакеты, а netstack B выпускает их наружу. Разница лишь
// в том, что у A нет готового пакета (свой netstack он уже терминировал), поэтому
// пакет собирается здесь: src = адрес, который B назначил узлу A.
//
// Мультиплексирование — по исходному порту: один туннель несёт много флоу, и
// входящий пакет находит своё флоу по dst-порту (тот самый sport, что мы выдали).
// Это обычный NAT-приём, только таблица живёт у нас, а не в ядре.
type udpMux struct {
	tun   PacketTunnel
	local netip.Addr // адрес A, назначенный узлом B

	mu    sync.Mutex
	flows map[uint16]*udpConn
	next  uint16
	// closed — насос умер (туннель порвался); новые Dial отклоняются.
	closed bool
}

// portLo/portHi — диапазон исходных портов (эфемерные, как у ядра).
const (
	portLo = 10000
	portHi = 60000
)

func newUDPMux(tun PacketTunnel, local netip.Addr) *udpMux {
	m := &udpMux{
		tun:   tun,
		local: local,
		flows: make(map[uint16]*udpConn),
		next:  portLo,
	}
	go m.run()
	return m
}

// dial заводит новое UDP-флоу через туннель.
func (m *udpMux) dial(dst netip.AddrPort) (net.Conn, error) {
	if !m.local.Is4() || !dst.Addr().Is4() {
		// Пул upstream-узла сейчас v4; v6-флоу в цепочку не уводим, чтобы не
		// выпустить его мимо цепочки с адресом A.
		return nil, fmt.Errorf("chain: UDP через цепочку пока только IPv4 (src %v dst %v)", m.local, dst.Addr())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("chain: туннель к upstream закрыт")
	}
	port, ok := m.allocLocked()
	if !ok {
		return nil, errors.New("chain: свободные порты для UDP-флоу кончились")
	}
	c := &udpConn{
		mux: m, sport: port, dst: dst,
		ch:   make(chan []byte, 64), // всплеск не должен блокировать насос
		done: make(chan struct{}),
	}
	m.flows[port] = c
	return c, nil
}

// allocLocked выдаёт свободный порт по кругу. Вызывать под mu.
func (m *udpMux) allocLocked() (uint16, bool) {
	for i := 0; i < portHi-portLo; i++ {
		p := m.next
		m.next++
		if m.next >= portHi {
			m.next = portLo
		}
		if _, busy := m.flows[p]; !busy {
			return p, true
		}
	}
	return 0, false
}

func (m *udpMux) release(port uint16) {
	m.mu.Lock()
	delete(m.flows, port)
	m.mu.Unlock()
}

// run — насос входящих: читает пакеты из туннеля и раскладывает по флоу.
func (m *udpMux) run() {
	buf := make([]byte, 65535)
	for {
		n, err := m.tun.ReadPacket(buf)
		if err != nil {
			m.shutdown()
			return
		}
		sport, payload, ok := parseUDPv4(buf[:n])
		if !ok {
			continue // не наш UDP/IPv4 (напр. ICMP от узла) — молча мимо
		}
		m.mu.Lock()
		c := m.flows[sport]
		m.mu.Unlock()
		if c == nil {
			continue // флоу уже закрыт
		}
		// Копия: buf переиспользуется следующей итерацией.
		p := make([]byte, len(payload))
		copy(p, payload)
		select {
		case c.ch <- p:
		case <-c.done:
		default: // получатель не успевает — дроп, как и положено UDP
		}
	}
}

// shutdown будит все флоу, когда туннель умер.
func (m *udpMux) shutdown() {
	m.mu.Lock()
	m.closed = true
	flows := make([]*udpConn, 0, len(m.flows))
	for _, c := range m.flows {
		flows = append(flows, c)
	}
	m.flows = map[uint16]*udpConn{}
	m.mu.Unlock()
	for _, c := range flows {
		c.closeOnce()
	}
}

// udpConn — одно UDP-флоу поверх туннеля (реализует net.Conn для netstack).
type udpConn struct {
	mux   *udpMux
	sport uint16
	dst   netip.AddrPort
	ch    chan []byte
	done  chan struct{}
	once  sync.Once
}

func (c *udpConn) Read(b []byte) (int, error) {
	select {
	case p := <-c.ch:
		return copy(b, p), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}

func (c *udpConn) Write(b []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	pkt := buildUDPv4(c.mux.local, c.dst.Addr(), c.sport, c.dst.Port(), b)
	// ICMP PTB игнорируем: UDP-датаграмма не влезла в путь — это потеря пакета,
	// а не ошибка сокета (ровно так же ведёт себя обычная сеть).
	if _, err := c.mux.tun.WritePacket(pkt); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *udpConn) Close() error {
	c.closeOnce()
	c.mux.release(c.sport)
	return nil
}

func (c *udpConn) closeOnce() { c.once.Do(func() { close(c.done) }) }

func (c *udpConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.mux.local.AsSlice(), Port: int(c.sport)}
}
func (c *udpConn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.dst) }

// Дедлайны не нужны: временем флоу управляет netstack, закрывая conn.
func (c *udpConn) SetDeadline(time.Time) error      { return nil }
func (c *udpConn) SetReadDeadline(time.Time) error  { return nil }
func (c *udpConn) SetWriteDeadline(time.Time) error { return nil }

// buildUDPv4 собирает IPv4/UDP-пакет с корректными контрольными суммами.
func buildUDPv4(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	pkt := make([]byte, 20+udpLen)

	pkt[0] = 0x45 // версия 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:], uint16(20+udpLen))
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:], checksum(pkt[:20]))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:], udpChecksum(s, d, udp))
	return pkt
}

// parseUDPv4 достаёт dst-порт (наш sport) и полезную нагрузку входящего пакета.
func parseUDPv4(pkt []byte) (dport uint16, payload []byte, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 17 {
		return 0, nil, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return 0, nil, false
	}
	udp := pkt[ihl:]
	ulen := int(binary.BigEndian.Uint16(udp[4:]))
	if ulen < 8 || ulen > len(udp) {
		return 0, nil, false
	}
	return binary.BigEndian.Uint16(udp[2:]), udp[8:ulen], true
}

// checksum — стандартная сумма по дополнению до единицы (RFC 1071).
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// udpChecksum считает сумму UDP с псевдо-заголовком IPv4 (RFC 768).
func udpChecksum(src, dst [4]byte, udp []byte) uint16 {
	var sum uint32
	for _, p := range [][]byte{src[:], dst[:]} {
		for i := 0; i+1 < len(p); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(p[i:]))
		}
	}
	sum += 17               // протокол
	sum += uint32(len(udp)) // длина UDP
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i:]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	c := ^uint16(sum)
	if c == 0 {
		c = 0xFFFF // в UDP ноль означает «сумма не считалась»
	}
	return c
}
