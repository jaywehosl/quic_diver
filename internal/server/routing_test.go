package server

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"quicdiver/internal/server/netstack"
)

// markDialer — Dialer-заглушка, помеченная меткой выхода.
type markDialer struct{ mark string }

func (d markDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) { return nil, nil }
func (d markDialer) DialUDP(context.Context, netip.AddrPort) (net.Conn, error) { return nil, nil }

func TestSplitPool(t *testing.T) {
	subs := SplitPool(netip.MustParsePrefix("10.9.0.0/16"), 2)
	if len(subs) != 2 {
		t.Fatalf("подсетей %d, ожидалось 2", len(subs))
	}
	if subs[0].String() != "10.9.0.0/17" || subs[1].String() != "10.9.128.0/17" {
		t.Fatalf("подсети: %v", subs)
	}
}

// Один хост-номер должен давать адреса в каждой подсети — иначе «один клиент,
// много выходов» не работает.
func TestAddrsForHostSharesNumber(t *testing.T) {
	subs := SplitPool(netip.MustParsePrefix("10.9.0.0/16"), 2)
	outs := []Outbound{
		{Label: "direct", Subnet: subs[0]},
		{Label: "chain", Subnet: subs[1]},
	}
	// хост-номер 5: ждём 10.9.0.5 и 10.9.128.5
	addrs := addrsForHost(outs, 5)
	if len(addrs) != 2 {
		t.Fatalf("адресов %d", len(addrs))
	}
	if addrs[0].Addr() != netip.MustParseAddr("10.9.0.5") {
		t.Fatalf("direct-адрес %v", addrs[0].Addr())
	}
	if addrs[1].Addr() != netip.MustParseAddr("10.9.128.5") {
		t.Fatalf("chain-адрес %v", addrs[1].Addr())
	}
	// хост-номер из адреса читается обратно
	if h := hostFromAddr(subs[1], netip.MustParseAddr("10.9.128.5")); h != 5 {
		t.Fatalf("hostFromAddr=%d, ожидалось 5", h)
	}
}

var _ netstack.Router = (*Outbounds)(nil)
