package routenat

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"quicdiver/internal/client/fakeip"
	"quicdiver/internal/client/routing"
)

// buildUDP собирает IPv4/UDP-пакет с корректными контрольными суммами.
func buildUDP(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	total := 20 + udpLen
	p := make([]byte, total)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(total))
	p[8] = 64
	p[9] = 17
	s, d := src.As4(), dst.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[10:], ipCsum(p[:20]))
	binary.BigEndian.PutUint16(p[20:], sport)
	binary.BigEndian.PutUint16(p[22:], dport)
	binary.BigEndian.PutUint16(p[24:], uint16(udpLen))
	copy(p[28:], payload)
	binary.BigEndian.PutUint16(p[26:], udpCsum(p))
	return p
}

func ipCsum(h []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(h); i += 2 {
		s += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for s > 0xffff {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

func udpCsum(pkt []byte) uint16 {
	udp := pkt[20:]
	var s uint32
	for i := 12; i < 20; i += 2 {
		s += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	s += 17 + uint32(len(udp))
	for i := 0; i+1 < len(udp); i += 2 {
		s += uint32(binary.BigEndian.Uint16(udp[i:]))
	}
	if len(udp)%2 == 1 {
		s += uint32(udp[len(udp)-1]) << 8
	}
	for s > 0xffff {
		s = (s & 0xffff) + (s >> 16)
	}
	c := ^uint16(s)
	if c == 0 {
		c = 0xffff
	}
	return c
}

// checksumsOK — валидны ли IPv4 и UDP контрольные суммы (полная проверка).
func checksumsOK(t *testing.T, pkt []byte) {
	t.Helper()
	if got := ipCsum(pkt[:20]); binary.BigEndian.Uint16(pkt[10:]) != 0 {
		// пересчитать с нулём и сравнить
		save := binary.BigEndian.Uint16(pkt[10:])
		binary.BigEndian.PutUint16(pkt[10:], 0)
		want := ipCsum(pkt[:20])
		binary.BigEndian.PutUint16(pkt[10:], save)
		if want != save {
			t.Fatalf("IPv4 checksum: %04x, ожидался %04x (got helper %04x)", save, want, got)
		}
	}
	save := binary.BigEndian.Uint16(pkt[26:])
	binary.BigEndian.PutUint16(pkt[26:], 0)
	want := udpCsum(pkt)
	binary.BigEndian.PutUint16(pkt[26:], save)
	if want != save {
		t.Fatalf("UDP checksum: %04x, ожидался %04x", save, want)
	}
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func setup() (*Rewriter, *fakeip.Pool) {
	pool := fakeip.New(fakeip.DefaultPool, time.Minute)
	rules, _ := routing.ParseRules("dom:youtube.com=chain")
	return New(Config{
		RealApp: addr("192.168.1.50"),
		Assigned: map[string]netip.Addr{
			"direct": addr("10.7.0.5"),
			"chain":  addr("10.7.128.5"),
		},
		Subnets: []netip.Prefix{
			netip.MustParsePrefix("10.7.0.0/17"),
			netip.MustParsePrefix("10.7.128.0/17"),
		},
		Default: "direct",
		Fake:    pool,
		Router:  routing.NewRouter(routing.Compile(rules, "direct")),
	}), pool
}

// Исходящий UDP к fake youtube-домена: dst fake→real, src→chain-подсеть, суммы целы.
func TestOutboundDomainToChain(t *testing.T) {
	r, pool := setup()
	real := addr("142.250.1.2")
	fake, _ := pool.Assign("rr1.googlevideo.youtube.com", []netip.Addr{real})

	pkt := buildUDP(addr("192.168.1.50"), fake, 40000, 443, []byte("quic-hello"))
	r.Outbound(pkt)

	if src := netip.AddrFrom4([4]byte(pkt[12:16])); src != addr("10.7.128.5") {
		t.Fatalf("src → %v, ожидался 10.7.128.5 (chain-подсеть)", src)
	}
	if dst := netip.AddrFrom4([4]byte(pkt[16:20])); dst != real {
		t.Fatalf("dst → %v, ожидался real %v", dst, real)
	}
	checksumsOK(t, pkt)
}

// Домен без правила → выход по умолчанию (direct-подсеть).
func TestOutboundDefaultDirect(t *testing.T) {
	r, pool := setup()
	real := addr("93.184.216.34")
	fake, _ := pool.Assign("example.com", []netip.Addr{real})

	pkt := buildUDP(addr("192.168.1.50"), fake, 40001, 443, []byte("x"))
	r.Outbound(pkt)

	if src := netip.AddrFrom4([4]byte(pkt[12:16])); src != addr("10.7.0.5") {
		t.Fatalf("src → %v, ожидался 10.7.0.5 (direct)", src)
	}
	checksumsOK(t, pkt)
}

// Входящий ответ: src реального хоста → fake, dst (подсеть выхода) → адрес
// приложения. Приложение увидит ответ от того же fake, что и слало.
func TestInboundRestoresFakeAndApp(t *testing.T) {
	r, pool := setup()
	real := addr("142.250.1.2")
	fake, _ := pool.Assign("youtube.com", []netip.Addr{real})

	// ответ узла: от real-хоста на адрес клиента в chain-подсети
	pkt := buildUDP(real, addr("10.7.128.5"), 443, 40000, []byte("quic-reply"))
	r.Inbound(pkt)

	if src := netip.AddrFrom4([4]byte(pkt[12:16])); src != fake {
		t.Fatalf("src → %v, ожидался fake %v (иначе приложение отбросит)", src, fake)
	}
	if dst := netip.AddrFrom4([4]byte(pkt[16:20])); dst != addr("192.168.1.50") {
		t.Fatalf("dst → %v, ожидался адрес приложения", dst)
	}
	checksumsOK(t, pkt)
}

// Не-UDP и не-fake dst не ломаются.
func TestPassthrough(t *testing.T) {
	r, _ := setup()
	// UDP к обычному (не-fake) адресу без правил → src на direct, dst не тронут
	pkt := buildUDP(addr("192.168.1.50"), addr("8.8.8.8"), 40002, 53, []byte("dns"))
	r.Outbound(pkt)
	if dst := netip.AddrFrom4([4]byte(pkt[16:20])); dst != addr("8.8.8.8") {
		t.Fatalf("не-fake dst тронут: %v", dst)
	}
	checksumsOK(t, pkt)
}
