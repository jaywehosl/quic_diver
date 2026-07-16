package nat

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

// sum16 — свёрнутая ones-complement сумма. Для валидного checksum по всем словам
// (включая само поле) даёт 0xFFFF.
func sum16(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s > 0xFFFF {
		s = (s & 0xFFFF) + (s >> 16)
	}
	return uint16(s)
}

func ipv4Valid(pkt []byte) bool {
	ihl := int(pkt[0]&0x0F) * 4
	return sum16(pkt[:ihl]) == 0xFFFF
}

// l4Valid считает контрольную сумму TCP/UDP поверх псевдо-заголовка IPv4.
func l4Valid(pkt []byte) bool {
	ihl := int(pkt[0]&0x0F) * 4
	proto := pkt[9]
	l4 := pkt[ihl:]
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], pkt[12:16])
	copy(pseudo[4:8], pkt[16:20])
	pseudo[9] = proto
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(l4)))
	return sum16(append(pseudo, l4...)) == 0xFFFF
}

func buildV4(t *testing.T, proto byte, src, dst string, payload []byte) []byte {
	t.Helper()
	ihl := 20
	l4hdr := 20
	if proto == 17 {
		l4hdr = 8
	}
	tot := ihl + l4hdr + len(payload)
	pkt := make([]byte, tot)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(tot))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], net.ParseIP(src).To4())
	copy(pkt[16:20], net.ParseIP(dst).To4())
	fixIPv4Header(pkt)

	l4 := pkt[ihl:]
	binary.BigEndian.PutUint16(l4[0:], 12345) // src port
	binary.BigEndian.PutUint16(l4[2:], 443)   // dst port
	if proto == 6 {
		l4[12] = 5 << 4 // data offset
	} else {
		binary.BigEndian.PutUint16(l4[4:], uint16(l4hdr+len(payload))) // UDP length
	}
	copy(l4[l4hdr:], payload)

	// L4 checksum поверх псевдо-заголовка.
	csumOff := 16
	if proto == 17 {
		csumOff = 6
	}
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], pkt[12:16])
	copy(pseudo[4:8], pkt[16:20])
	pseudo[9] = proto
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(l4)))
	binary.BigEndian.PutUint16(l4[csumOff:], ^sum16(append(pseudo, l4...)))
	return pkt
}

func mkNAT() *NAT {
	return New(
		[]netip.Addr{netip.MustParseAddr("192.168.31.108")},
		[]netip.Addr{netip.MustParseAddr("10.7.0.2")},
	)
}

func TestOutboundV4TCP(t *testing.T) {
	pkt := buildV4(t, 6, "192.168.31.108", "93.184.216.34", []byte("hello"))
	if !ipv4Valid(pkt) || !l4Valid(pkt) {
		t.Fatal("built packet has invalid checksums")
	}
	mkNAT().Outbound(pkt)

	if got := net.IP(pkt[12:16]).String(); got != "10.7.0.2" {
		t.Fatalf("src not rewritten: %s", got)
	}
	if got := net.IP(pkt[16:20]).String(); got != "93.184.216.34" {
		t.Fatalf("dst changed: %s", got)
	}
	if !ipv4Valid(pkt) {
		t.Fatal("IPv4 checksum invalid after NAT")
	}
	if !l4Valid(pkt) {
		t.Fatal("TCP checksum invalid after NAT")
	}
}

func TestInboundV4UDP(t *testing.T) {
	// ответный пакет: src=сайт, dst=assigned → NAT восстанавливает real
	pkt := buildV4(t, 17, "8.8.8.8", "10.7.0.2", []byte("dns-reply"))
	if !ipv4Valid(pkt) || !l4Valid(pkt) {
		t.Fatal("built packet invalid")
	}
	mkNAT().Inbound(pkt)

	if got := net.IP(pkt[16:20]).String(); got != "192.168.31.108" {
		t.Fatalf("dst not restored: %s", got)
	}
	if !ipv4Valid(pkt) || !l4Valid(pkt) {
		t.Fatal("checksum invalid after inbound NAT")
	}
}

func TestNoMatchUnchanged(t *testing.T) {
	// src не совпадает с real → пакет не трогается
	pkt := buildV4(t, 6, "10.0.0.5", "93.184.216.34", nil)
	before := append([]byte(nil), pkt...)
	mkNAT().Outbound(pkt)
	if string(before) != string(pkt) {
		t.Fatal("packet modified despite non-matching src")
	}
}

func TestRoundTripV4TCP(t *testing.T) {
	n := mkNAT()
	pkt := buildV4(t, 6, "192.168.31.108", "1.1.1.1", []byte("xyz"))
	n.Outbound(pkt) // src → 10.7.0.2
	// смоделируем «ответ»: swap, но проще проверить обратную подмену dst
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt))) // total len не трогаем
	// сделаем dst=assigned чтобы Inbound восстановил
	copy(pkt[16:20], net.ParseIP("10.7.0.2").To4())
	fixIPv4Header(pkt)
	n.Inbound(pkt)
	if got := net.IP(pkt[16:20]).String(); got != "192.168.31.108" {
		t.Fatalf("round-trip dst: %s", got)
	}
	if !ipv4Valid(pkt) {
		t.Fatal("ipv4 invalid after round-trip")
	}
}
