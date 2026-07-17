package server

import (
	"net/netip"

	"quicdiver/internal/server/netstack"
)

// RouteHeader несёт метку выхода в CONNECT-запросе (TCP-флоу гибрида идёт
// стримом мимо IP-слоя, поэтому src-адрес там не работает). Под QUIC/TLS,
// снаружи невидим.
const RouteHeader = "Qd-Route"

// Outbound — один выход узла: direct (реальная сеть) или chain (upstream-узел).
//
// Каждому выходу отведена подсеть пула. Клиент получает один хост-номер, а адреса
// во всех подсветях с этим номером — по одному на выход; шлёт с того src, чей
// выход нужен. Узел читает src → подсеть → выход. Так «метка маршрута» едет в
// самом IP-заголовке, единообразно для TCP и UDP.
type Outbound struct {
	Label  string
	Subnet netip.Prefix
	Dialer netstack.Dialer
}

// srcRouter выбирает выход по подсети src-адреса. Порядок outbounds важен:
// первая покрывающая подсеть выигрывает.
type srcRouter struct {
	outbounds []Outbound
	fallback  netstack.Dialer // src вне известных подсетей → direct (первый выход)
}

func (r *srcRouter) For(src netip.Addr) netstack.Dialer {
	for i := range r.outbounds {
		if r.outbounds[i].Subnet.Contains(src) {
			return r.outbounds[i].Dialer
		}
	}
	return r.fallback
}

// newRouter строит роутер по списку выходов. fallback — выход по умолчанию
// (обычно direct, outbounds[0]).
func newRouter(outbounds []Outbound) netstack.Router {
	var fb netstack.Dialer
	if len(outbounds) > 0 {
		fb = outbounds[0].Dialer
	}
	return &srcRouter{outbounds: outbounds, fallback: fb}
}

// outboundDialer выбирает выход по метке (для TCP-CONNECT). Пустая/неизвестная
// метка → выход по умолчанию (direct, outbounds[0]); без outbounds — cfg.Dialer.
func (cfg Config) outboundDialer(label string) netstack.Dialer {
	if len(cfg.Outbounds) == 0 {
		return cfg.Dialer
	}
	if label != "" {
		for i := range cfg.Outbounds {
			if cfg.Outbounds[i].Label == label {
				return cfg.Outbounds[i].Dialer
			}
		}
	}
	return cfg.Outbounds[0].Dialer
}

// SplitPool делит пул на n равных подсетей (n — степень двойки): по одной на
// выход. Первая — базовая (direct), в ней аллокатор выдаёт хост-номера.
func SplitPool(pool netip.Prefix, n int) []netip.Prefix {
	add := 0
	for (1 << add) < n {
		add++
	}
	newBits := pool.Bits() + add
	if newBits > 32 {
		return nil
	}
	base := pool.Masked().Addr().As4()
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	step := uint32(1) << (32 - newBits)

	subs := make([]netip.Prefix, 0, n)
	for i := 0; i < n; i++ {
		s := v + uint32(i)*step
		a := netip.AddrFrom4([4]byte{byte(s >> 24), byte(s >> 16), byte(s >> 8), byte(s)})
		subs = append(subs, netip.PrefixFrom(a, newBits))
	}
	return subs
}

// addrsForHost возвращает адреса клиента — по одному в каждой outbound-подсети с
// общим хост-номером. Первый (в подсети выхода 0) — базовый (direct).
//
// host — смещение внутри подсети (из аллокатора). Совпадение младших битов во
// всех подсетях и делает «один клиент — один хост-номер, много выходов».
func addrsForHost(outbounds []Outbound, host uint32) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(outbounds))
	for _, o := range outbounds {
		a := addrInSubnet(o.Subnet, host)
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out
}

// addrInSubnet кладёт хост-номер в подсеть (IPv4).
func addrInSubnet(sub netip.Prefix, host uint32) netip.Addr {
	base := sub.Masked().Addr().As4()
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	v |= host & hostMask(sub.Bits())
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// hostHostFromAddr — хост-номер адреса внутри его подсети (обратное к addrInSubnet).
func hostFromAddr(sub netip.Prefix, a netip.Addr) uint32 {
	v := a.As4()
	n := uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	return n & hostMask(sub.Bits())
}

func hostMask(prefixBits int) uint32 {
	if prefixBits >= 32 {
		return 0
	}
	return (uint32(1) << (32 - prefixBits)) - 1
}
