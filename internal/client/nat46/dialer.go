package nat46

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// Dialer оборачивает исходящий дозвон: адрес из пула подменяется настоящим
// IPv6 перед тем, как уйти в CONNECT к узлу.
//
// Реализует netstack.Dialer, поэтому встаёт в цепочку без правок forwarder'а.
type Dialer struct {
	Inner interface {
		DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
		DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	}
	Table *Table
}

// DialTCP подменяет fake-адрес на реальный v6 и дозванивается.
func (d Dialer) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	dst, err := d.translate(dst)
	if err != nil {
		return nil, err
	}
	return d.Inner.DialTCP(ctx, dst)
}

// DialUDP — то же для UDP.
func (d Dialer) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	dst, err := d.translate(dst)
	if err != nil {
		return nil, err
	}
	return d.Inner.DialUDP(ctx, dst)
}

// translate меняет адрес из пула на настоящий v6.
//
// Адрес из пула без маппинга — это протухшая или чужая запись. Наружу такой
// слать нельзя (198.18.0.0/15 в интернете не маршрутизируется, пакет просто
// сгинет), поэтому честно возвращаем ошибку: приложение увидит отказ сразу и
// переспросит DNS, а не будет ждать таймаута.
func (d Dialer) translate(dst netip.AddrPort) (netip.AddrPort, error) {
	if d.Table == nil || !d.Table.Pool().Contains(dst.Addr()) {
		return dst, nil
	}
	real, ok := d.Table.Lookup(dst.Addr())
	if !ok {
		return dst, fmt.Errorf("nat46: %s не отображён (маппинг протух)", dst.Addr())
	}
	return netip.AddrPortFrom(real, dst.Port()), nil
}
