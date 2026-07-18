package chain

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeTunnel — пакетный туннель на каналах: записанное складывает в sent,
// прочитанное отдаёт из recv. Позволяет проверить мультиплексор без QUIC.
type fakeTunnel struct {
	mu     sync.Mutex
	sent   [][]byte
	recv   chan []byte
	closed chan struct{}
}

func newFakeTunnel() *fakeTunnel {
	return &fakeTunnel{recv: make(chan []byte, 16), closed: make(chan struct{})}
}

func (f *fakeTunnel) WritePacket(b []byte) ([]byte, error) {
	p := make([]byte, len(b))
	copy(p, b)
	f.mu.Lock()
	f.sent = append(f.sent, p)
	f.mu.Unlock()
	return nil, nil
}

func (f *fakeTunnel) ReadPacket(b []byte) (int, error) {
	select {
	case p := <-f.recv:
		return copy(b, p), nil
	case <-f.closed:
		return 0, context.Canceled
	}
}

func (f *fakeTunnel) lastSent() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return nil
	}
	return f.sent[len(f.sent)-1]
}

var localA = netip.MustParseAddr("10.8.0.7")

// Исходящий UDP собирается в корректный IPv4-пакет: адреса/порты на местах,
// контрольные суммы сходятся (иначе upstream-узел молча выбросит пакет).
func TestWriteBuildsValidPacket(t *testing.T) {
	tun := newFakeTunnel()
	defer close(tun.closed)
	m := newUDPMux(tun, localA)
	dst := netip.MustParseAddrPort("8.8.8.8:53")

	c, err := m.dial(dst)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("query")); err != nil {
		t.Fatalf("write: %v", err)
	}

	pkt := tun.lastSent()
	if pkt == nil {
		t.Fatal("пакет не ушёл в туннель")
	}
	if src := netip.AddrFrom4([4]byte(pkt[12:16])); src != localA {
		t.Fatalf("src %v, ожидался назначенный upstream-ом %v", src, localA)
	}
	if got := netip.AddrFrom4([4]byte(pkt[16:20])); got != dst.Addr() {
		t.Fatalf("dst %v, ожидался %v", got, dst.Addr())
	}
	if pkt[9] != 17 {
		t.Fatalf("протокол %d, ожидался UDP(17)", pkt[9])
	}
	if dport := binary.BigEndian.Uint16(pkt[22:]); dport != dst.Port() {
		t.Fatalf("dport %d, ожидался %d", dport, dst.Port())
	}
	// Сумма всего заголовка (включая её саму) должна давать 0.
	if s := checksum(pkt[:20]); s != 0 {
		t.Fatalf("IPv4 checksum не сходится (остаток %#04x)", s)
	}
	if payload := string(pkt[28:]); payload != "query" {
		t.Fatalf("payload %q, ожидался \"query\"", payload)
	}
}

// Ответ из туннеля находит своё флоу по dst-порту и доезжает до Read.
func TestReadRoutesReplyToFlow(t *testing.T) {
	tun := newFakeTunnel()
	defer close(tun.closed)
	m := newUDPMux(tun, localA)
	dst := netip.MustParseAddrPort("8.8.8.8:53")

	c, err := m.dial(dst)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("q")); err != nil {
		t.Fatalf("write: %v", err)
	}
	sport := binary.BigEndian.Uint16(tun.lastSent()[20:])

	// Ответ: от 8.8.8.8:53 на наш адрес и выданный порт.
	tun.recv <- buildUDPv4(dst.Addr(), localA, dst.Port(), sport, []byte("answer"))

	buf := make([]byte, 100)
	done := make(chan int, 1)
	go func() { n, _ := c.Read(buf); done <- n }()
	select {
	case n := <-done:
		if got := string(buf[:n]); got != "answer" {
			t.Fatalf("прочитано %q, ожидалось \"answer\"", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ответ не доехал до флоу (мультиплексор не нашёл его по порту)")
	}
}

// Два флоу через один туннель не путаются: каждый получает свой ответ.
func TestTwoFlowsDoNotMix(t *testing.T) {
	tun := newFakeTunnel()
	defer close(tun.closed)
	m := newUDPMux(tun, localA)
	d1 := netip.MustParseAddrPort("1.1.1.1:53")
	d2 := netip.MustParseAddrPort("8.8.8.8:53")

	c1, _ := m.dial(d1)
	defer c1.Close()
	c2, _ := m.dial(d2)
	defer c2.Close()

	c1.Write([]byte("a"))
	p1 := binary.BigEndian.Uint16(tun.lastSent()[20:])
	c2.Write([]byte("b"))
	p2 := binary.BigEndian.Uint16(tun.lastSent()[20:])
	if p1 == p2 {
		t.Fatalf("оба флоу получили порт %d — мультиплексирование сломано", p1)
	}

	tun.recv <- buildUDPv4(d2.Addr(), localA, d2.Port(), p2, []byte("для-второго"))

	buf := make([]byte, 64)
	done := make(chan string, 1)
	go func() { n, _ := c2.Read(buf); done <- string(buf[:n]) }()
	select {
	case got := <-done:
		if got != "для-второго" {
			t.Fatalf("второй флоу получил %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ответ не дошёл до второго флоу")
	}
}

// Смерть туннеля будит читателей: netstack не должен виснуть на мёртвом флоу.
func TestTunnelDeathUnblocksRead(t *testing.T) {
	tun := newFakeTunnel()
	m := newUDPMux(tun, localA)
	c, err := m.dial(netip.MustParseAddrPort("8.8.8.8:53"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	close(tun.closed) // туннель порвался

	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 10)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Read вернул успех на мёртвом туннеле")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read завис после смерти туннеля")
	}
}

// Порт возвращается в пул после Close — иначе длинная сессия исчерпает диапазон.
func TestClosedFlowReleasesPort(t *testing.T) {
	tun := newFakeTunnel()
	defer close(tun.closed)
	m := newUDPMux(tun, localA)
	c, _ := m.dial(netip.MustParseAddrPort("8.8.8.8:53"))
	c.Close()
	m.mu.Lock()
	n := len(m.flows)
	m.mu.Unlock()
	if n != 0 {
		t.Fatalf("после Close осталось %d флоу", n)
	}
}
