// Package routenat — routing-aware NAT для UDP-датаграммного пути.
//
// TCP метится через CONNECT-заголовок (routeclient), а UDP идёт сырыми IP-пакетами
// в датаграммах — здесь метка едет в src-адресе: клиент шлёт с адреса той
// подсети, чей выход нужен, узел роутит по src. Плюс подмена fake→real (домен
// приложение видит как fake, наружу надо real).
//
// Исходящий UDP:
//   - dst fake → real (по fakeip);
//   - классификация флоу (dst real + домен) → метка выхода;
//   - src приложения → адрес клиента в подсети этого выхода.
//
// Входящий UDP (ответ узла):
//   - src реального хоста → fake (приложение ждёт ответ ОТ fake, иначе отбросит);
//   - dst (адрес клиента в подсети выхода) → реальный адрес приложения.
package routenat

import (
	"encoding/binary"
	"net/netip"

	"quicdiver/internal/client/fakeip"
	"quicdiver/internal/client/nat"
	"quicdiver/internal/client/routing"
)

// Rewriter переписывает UDP-пакеты по правилам (реализует engine.Rewriter).
type Rewriter struct {
	realApp  netip.Addr            // реальный адрес приложения (src исходящих)
	assigned map[string]netip.Addr // метка выхода → адрес клиента в его подсети
	def      string                // выход по умолчанию
	subnets  []netip.Prefix        // подсети выходов (для распознавания dst входящих)
	fake     *fakeip.Pool
	router   *routing.Router
	ct       *routing.Conntrack
}

// Config — параметры Rewriter.
type Config struct {
	RealApp  netip.Addr
	Assigned map[string]netip.Addr
	Subnets  []netip.Prefix
	Default  string
	Fake     *fakeip.Pool
	Router   *routing.Router
	CT       *routing.Conntrack
}

// New создаёт rewriter.
func New(cfg Config) *Rewriter {
	ct := cfg.CT
	if ct == nil {
		ct = routing.NewConntrack(0)
	}
	return &Rewriter{
		realApp: cfg.RealApp, assigned: cfg.Assigned, def: cfg.Default,
		subnets: cfg.Subnets, fake: cfg.Fake, router: cfg.Router, ct: ct,
	}
}

// Outbound переписывает исходящий UDP: dst fake→real, src → адрес подсети выхода.
func (r *Rewriter) Outbound(pkt []byte) {
	if !isUDPv4(pkt) {
		return
	}
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	real := dst
	domain := ""
	if r.fake != nil && r.fake.Contains(dst) {
		domain = r.fake.DomainOf(dst)
		if ra, ok := r.fake.RealAddr(dst); ok {
			real = ra
		}
	}
	dstPort := binary.BigEndian.Uint16(pkt[udpOff(pkt)+2:])
	srcPort := binary.BigEndian.Uint16(pkt[udpOff(pkt):])

	label := r.def
	if r.router != nil {
		f := routing.Flow{Dst: netip.AddrPortFrom(real, dstPort), Domain: domain}
		label = r.ct.Decide(srcPort, f, r.router.Classify)
	}
	src, ok := r.assigned[label]
	if !ok {
		src = r.assigned[r.def]
	}
	nat.RewriteV4(pkt, src, real)
}

// Inbound переписывает входящий UDP: src реального хоста → fake, dst (подсеть
// выхода) → реальный адрес приложения.
func (r *Rewriter) Inbound(pkt []byte) {
	if !isUDPv4(pkt) {
		return
	}
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))

	var newSrc netip.Addr
	if r.fake != nil {
		if fk, ok := r.fake.FakeOf(src); ok {
			newSrc = fk
		}
	}
	var newDst netip.Addr
	if r.inSubnets(dst) {
		newDst = r.realApp
	}
	nat.RewriteV4(pkt, newSrc, newDst)
}

func (r *Rewriter) inSubnets(a netip.Addr) bool {
	for _, s := range r.subnets {
		if s.Contains(a) {
			return true
		}
	}
	return false
}

func isUDPv4(pkt []byte) bool {
	return len(pkt) >= 28 && pkt[0]>>4 == 4 && pkt[9] == 17
}

func udpOff(pkt []byte) int { return int(pkt[0]&0x0F) * 4 }
