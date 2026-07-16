package windivert

import (
	"net/netip"
	"strings"
	"testing"
)

func TestBuildFilterDefault(t *testing.T) {
	// оба семейства, все протоколы, без bypass
	if got := BuildFilter(CaptureConfig{}); got != "outbound and (ip or ipv6)" {
		t.Fatalf("default: got %q", got)
	}
}

func TestBuildFilterTCPPortsV4(t *testing.T) {
	got := BuildFilter(CaptureConfig{IPv4: true, TCP: true, Ports: []uint16{443, 80}})
	want := "outbound and tcp and (tcp.DstPort == 443 or tcp.DstPort == 80) and ip"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestBuildFilterBothProto(t *testing.T) {
	got := BuildFilter(CaptureConfig{TCP: true, UDP: true})
	want := "outbound and (tcp or udp) and (ip or ipv6)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildFilterV6Only(t *testing.T) {
	got := BuildFilter(CaptureConfig{IPv6: true, UDP: true})
	want := "outbound and udp and ipv6"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildFilterBypassRanges(t *testing.T) {
	got := BuildFilter(CaptureConfig{
		IPv4: true, IPv6: true,
		Bypass: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("fc00::/7"),
			netip.MustParsePrefix("localhost/32"),
		},
	})
	for _, want := range []string{
		"(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255)",
		"(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255)",
		"ip.DstAddr != localhost",
		"(ipv6.DstAddr < fc00:: or ipv6.DstAddr > fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff)",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("filter missing clause %q\ngot: %s", want, got)
		}
	}
	// семейства изолированы
	if !strings.Contains(got, "(ip and ") || !strings.Contains(got, "(ipv6 and ") {
		t.Fatalf("families not isolated: %s", got)
	}
}
