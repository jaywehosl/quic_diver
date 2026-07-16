package connectip

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"quicdiver/internal/guard"
	"quicdiver/internal/packet"
)

// mockSource — packet.Source на моках: отдаёт заданные батчи, собирает Send.
type mockSource struct {
	batches [][]packet.Packet
	i       int

	mu      sync.Mutex
	sent    [][]packet.Packet
	sentSig chan struct{}
}

func (m *mockSource) Recv(ctx context.Context) ([]packet.Packet, error) {
	if m.i < len(m.batches) {
		b := m.batches[m.i]
		m.i++
		return b, nil
	}
	<-ctx.Done() // батчи кончились — блокируемся до отмены
	return nil, ctx.Err()
}

func (m *mockSource) Send(pkts []packet.Packet) error {
	m.mu.Lock()
	cp := make([]packet.Packet, len(pkts))
	copy(cp, pkts)
	m.sent = append(m.sent, cp)
	m.mu.Unlock()
	if m.sentSig != nil {
		m.sentSig <- struct{}{}
	}
	return nil
}

func (m *mockSource) MTU() int     { return 1500 }
func (m *mockSource) Close() error { return nil }

func (m *mockSource) sentBatches() [][]packet.Packet {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sent
}

// mockTunnel — engine.PacketTunnel на моках.
type mockTunnel struct {
	mu       sync.Mutex
	written  [][]byte
	writeSig chan struct{}

	readCh chan []byte // источник ответных пакетов для ReadPacket
}

func (m *mockTunnel) WritePacket(b []byte) ([]byte, error) {
	m.mu.Lock()
	m.written = append(m.written, append([]byte(nil), b...))
	m.mu.Unlock()
	if m.writeSig != nil {
		m.writeSig <- struct{}{}
	}
	return nil, nil
}

func (m *mockTunnel) ReadPacket(b []byte) (int, error) {
	data, ok := <-m.readCh
	if !ok {
		<-make(chan struct{}) // закрыт — просто зависаем (тест отменит ctx)
	}
	return copy(b, data), nil
}

func (m *mockTunnel) writtenPkts() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.written
}

func ipv4To(t *testing.T, dst string) []byte {
	t.Helper()
	b := make([]byte, 20)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], 20)
	d := net.ParseIP(dst).To4()
	if d == nil {
		t.Fatalf("bad ip %q", dst)
	}
	copy(b[16:20], d)
	return b
}

// TestOutboundRoutesAndBypass: публичный dst → туннель; локальный (guard.Bypass)
// → реинжект в стек, не в туннель.
func TestOutboundRoutesAndBypass(t *testing.T) {
	pub := ipv4To(t, "8.8.8.8")
	lan := ipv4To(t, "192.168.1.1") // покрыт дефолтным bypass guard

	src := &mockSource{
		batches: [][]packet.Packet{{
			{Data: pub, Dir: packet.Outbound},
			{Data: lan, Dir: packet.Outbound},
		}},
		sentSig: make(chan struct{}, 2),
	}
	tun := &mockTunnel{writeSig: make(chan struct{}, 2), readCh: make(chan []byte)}

	e := New(guard.New(nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx, src, tun)

	// pub ушёл в туннель, lan реинжектнут.
	select {
	case <-tun.writeSig:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for tunnel write")
	}
	select {
	case <-src.sentSig:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for reinject")
	}

	written := tun.writtenPkts()
	if len(written) != 1 {
		t.Fatalf("tunnel writes: got %d, want 1", len(written))
	}
	if gotDst, _ := dstAddr(written[0]); gotDst.String() != "8.8.8.8" {
		t.Fatalf("tunnelled wrong dst: %v", gotDst)
	}

	sent := src.sentBatches()
	if len(sent) != 1 || len(sent[0]) != 1 {
		t.Fatalf("reinject batches: %+v", sent)
	}
	if gotDst, _ := dstAddr(sent[0][0].Data); gotDst.String() != "192.168.1.1" {
		t.Fatalf("reinjected wrong dst: %v", gotDst)
	}
}

// TestInboundInject: пакет из туннеля инжектится в стек как inbound.
func TestInboundInject(t *testing.T) {
	src := &mockSource{sentSig: make(chan struct{}, 1)}
	tun := &mockTunnel{readCh: make(chan []byte, 1)}

	e := New(guard.New(nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx, src, tun)

	resp := ipv4To(t, "10.20.30.40")
	tun.readCh <- resp

	select {
	case <-src.sentSig:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for inbound inject")
	}

	sent := src.sentBatches()
	if len(sent) != 1 || len(sent[0]) != 1 {
		t.Fatalf("inject batches: %+v", sent)
	}
	if sent[0][0].Dir != packet.Inbound {
		t.Fatalf("injected dir: got %d, want Inbound", sent[0][0].Dir)
	}
	if gotDst, _ := dstAddr(sent[0][0].Data); gotDst.String() != "10.20.30.40" {
		t.Fatalf("injected wrong dst: %v", gotDst)
	}
}
