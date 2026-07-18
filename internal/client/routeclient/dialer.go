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

// DomainResolver отдаёт домен по адресу назначения (из fake-IP/DNS), если знает.
// Пусто — домен неизвестен, доменные правила по этому флоу не сработают.
type DomainResolver interface {
	DomainOf(addr netip.Addr) string
}

// Dialer метит TCP-флоу выходом по правилам и открывает CONNECT-стрим.
type Dialer struct {
	CC     *http3.ClientConn
	Router *routing.Router
	// Domains — источник домена по dst (nat46/DNS). nil → доменные правила не
	// матчат (только процесс/CIDR/порт).
	Domains DomainResolver
	// Default — метка выхода по умолчанию; пустая метка и "direct" в Qd-Route не
	// кладутся (узел и так выведет через выход по умолчанию).
	Default string
}

// DialTCP классифицирует флоу и открывает CONNECT-стрим с меткой выхода.
func (d Dialer) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	label := d.classify(dst)
	var hdr http.Header
	if label != "" && label != "direct" {
		hdr = http.Header{routing.RouteHeaderName: []string{label}}
	}
	return connectdial.Dialer{CC: d.CC, Header: hdr}.DialTCP(ctx, dst)
}

// DialUDP не поддержан в этом диалере: UDP идёт датаграммами (метка = src-адрес),
// не CONNECT-стримом.
func (d Dialer) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return connectdial.Dialer{CC: d.CC}.DialUDP(ctx, dst)
}

func (d Dialer) classify(dst netip.AddrPort) string {
	if d.Router == nil {
		return d.Default
	}
	f := routing.Flow{Dst: dst}
	if d.Domains != nil {
		f.Domain = d.Domains.DomainOf(dst.Addr())
	}
	return d.Router.Classify(f)
}
