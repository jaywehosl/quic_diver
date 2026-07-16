//go:build windows

package windivert

import (
	"encoding/binary"
	"testing"

	"quicdiver/internal/packet"
)

func TestAddressBits(t *testing.T) {
	var a Address
	a.SetLayer(LayerNetwork)
	a.SetOutbound(true)
	a.SetIfIdx(7)

	if a.Layer() != LayerNetwork {
		t.Fatalf("layer: got %d", a.Layer())
	}
	if !a.Outbound() {
		t.Fatal("outbound should be set")
	}
	if a.IPv6() {
		t.Fatal("ipv6 must stay unset")
	}
	if a.IfIdx() != 7 {
		t.Fatalf("ifidx: got %d", a.IfIdx())
	}

	a.SetOutbound(false)
	if a.Outbound() {
		t.Fatal("outbound should be cleared")
	}
	if a.Layer() != LayerNetwork {
		t.Fatal("clearing outbound must not touch layer")
	}
}

func TestAddressSize(t *testing.T) {
	// init() уже паникует при несовпадении; здесь фиксируем ожидание явно.
	var a Address
	if got := len(a.data) + 16; got != addrSize {
		t.Fatalf("address layout: got %d, want %d", got, addrSize)
	}
}

func TestIPPacketLenV4(t *testing.T) {
	b := make([]byte, 40)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], 28)
	n, err := ipPacketLen(b)
	if err != nil || n != 28 {
		t.Fatalf("v4: n=%d err=%v", n, err)
	}
}

func TestIPPacketLenV6(t *testing.T) {
	b := make([]byte, 60)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], 20) // payload length
	n, err := ipPacketLen(b)
	if err != nil || n != 60 { // 40 header + 20 payload
		t.Fatalf("v6: n=%d err=%v", n, err)
	}
}

func TestIPPacketLenBadVersion(t *testing.T) {
	if _, err := ipPacketLen([]byte{0x50, 0, 0, 0}); err == nil {
		t.Fatal("expected error for IP version 5")
	}
}

func TestSplitBatch(t *testing.T) {
	p1 := make([]byte, 28) // IPv4, len 28
	p1[0] = 0x45
	binary.BigEndian.PutUint16(p1[2:4], 28)
	p2 := make([]byte, 60) // IPv6, 40+20
	p2[0] = 0x60
	binary.BigEndian.PutUint16(p2[4:6], 20)

	buf := append(append([]byte{}, p1...), p2...)
	addrs := make([]Address, 2)
	addrs[0].SetOutbound(true)
	addrs[0].SetIfIdx(3)
	addrs[1].SetOutbound(false)
	addrs[1].SetIfIdx(5)

	out, err := splitBatch(buf, addrs, nil)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("packet count: got %d, want 2", len(out))
	}
	if len(out[0].Data) != 28 || out[0].Dir != packet.Outbound || out[0].IfIndex != 3 {
		t.Fatalf("pkt0: len=%d dir=%d if=%d", len(out[0].Data), out[0].Dir, out[0].IfIndex)
	}
	if len(out[1].Data) != 60 || out[1].Dir != packet.Inbound || out[1].IfIndex != 5 {
		t.Fatalf("pkt1: len=%d dir=%d if=%d", len(out[1].Data), out[1].Dir, out[1].IfIndex)
	}
}
