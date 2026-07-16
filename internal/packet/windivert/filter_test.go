package windivert

import (
	"net/netip"
	"strings"
	"testing"
)

func TestBuildFilterDefault(t *testing.T) {
	if got := BuildFilter(CaptureConfig{}); got != "outbound" {
		t.Fatalf("default: got %q, want %q", got, "outbound")
	}
}

func TestBuildFilterTCPPortsV4(t *testing.T) {
	got := BuildFilter(CaptureConfig{IPv4: true, TCP: true, Ports: []uint16{443, 80}})
	want := "outbound and ip and tcp and (tcp.DstPort == 443 or tcp.DstPort == 80)"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestBuildFilterBothProto(t *testing.T) {
	got := BuildFilter(CaptureConfig{TCP: true, UDP: true})
	want := "outbound and (tcp or udp)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildFilterV6Only(t *testing.T) {
	got := BuildFilter(CaptureConfig{IPv6: true, UDP: true})
	want := "outbound and ipv6 and udp"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildFilterPortsAllProtos(t *testing.T) {
	// протоколы не заданы → порты и по tcp, и по udp
	got := BuildFilter(CaptureConfig{IPv4: true, Ports: []uint16{53}})
	want := "outbound and ip and (tcp.DstPort == 53 or udp.DstPort == 53)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildFilterBypass(t *testing.T) {
	got := BuildFilter(CaptureConfig{
		Bypass: []netip.Prefix{
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("fc00::/7"),
		},
	})
	for _, want := range []string{
		"not ip.DstAddr == 10.0.0.0/8",
		"not ip.DstAddr == 192.168.0.0/16",
		"not ipv6.DstAddr == fc00::/7",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("filter %q missing clause %q", got, want)
		}
	}
	if !strings.HasPrefix(got, "outbound and ") {
		t.Fatalf("filter should start with outbound: %q", got)
	}
}
