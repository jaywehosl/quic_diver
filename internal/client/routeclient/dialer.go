// Package routeclient связывает движок правил с транспортом: классифицирует
// исходящий флоу и метит его выходом (Qd-Route для TCP-CONNECT).
//
// netstack.handleTCP зовёт DialTCP ровно раз на TCP-флоу, поэтому классификация
// здесь и есть «раз на флоу» — отдельный conntrack для TCP не нужен (он для
// датаграммного UDP-пути, где решение принимается на пакете).
package routeclient

import (
	"context"
	"net"
	"net/http"
	"net/netip"

	"github.com/quic-go/quic-go/http3"

	"quicdiver/internal/client/connectdial"
	"quicdiver/internal/client/routing"
)

// FakeResolver отдаёт домен и реальный адрес по фиктивному (fakeip.Pool). Домен
// нужен для доменных правил, реальный адрес — для подмены fake перед дозвоном
// (fake не маршрутизируется, узел должен идти на настоящий адрес).
type FakeResolver interface {
	DomainOf(addr netip.Addr) string
	RealAddr(fake netip.Addr) (netip.Addr, bool)
}

// Dialer метит TCP-флоу выходом по правилам, подменяет fake→real и открывает
// CONNECT-стрим.
type Dialer struct {
	CC     *http3.ClientConn
	Router *routing.Router
	// Fake — источник домена/реального адреса (fakeip.Pool). nil → доменные
	// правила не матчат, подмена не делается (только CIDR/порт по dst).
	Fake FakeResolver
	// Default — метка выхода по умолчанию; пустая и "direct" в Qd-Route не кладутся.
	Default string
}

// DialTCP классифицирует флоу и открывает CONNECT-стрим на реальный адрес с
// меткой выхода.
func (d Dialer) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	real, domain := d.resolve(dst)
	label := d.classify(real, domain)

	var hdr http.Header
	if label != "" && label != "direct" {
		hdr = http.Header{routing.RouteHeaderName: []string{label}}
	}
	return connectdial.Dialer{CC: d.CC, Header: hdr}.DialTCP(ctx, real)
}

// DialUDP не поддержан здесь: UDP идёт датаграммами (метка = src-адрес).
func (d Dialer) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return connectdial.Dialer{CC: d.CC}.DialUDP(ctx, dst)
}

// resolve превращает fake-адрес в реальный и достаёт домен. Не-fake dst проходит
// как есть (домен неизвестен — сработают CIDR/порт).
func (d Dialer) resolve(dst netip.AddrPort) (real netip.AddrPort, domain string) {
	if d.Fake == nil {
		return dst, ""
	}
	domain = d.Fake.DomainOf(dst.Addr())
	if ra, ok := d.Fake.RealAddr(dst.Addr()); ok {
		return netip.AddrPortFrom(ra, dst.Port()), domain
	}
	return dst, domain
}

func (d Dialer) classify(real netip.AddrPort, domain string) string {
	if d.Router == nil {
		return d.Default
	}
	return d.Router.Classify(routing.Flow{Dst: real, Domain: domain})
}
