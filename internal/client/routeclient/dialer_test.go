package routeclient

import (
	"net/netip"
	"testing"

	"quicdiver/internal/client/routing"
)

// Классификация dst выбирает метку по правилам; нет совпадений → default.
func TestClassifyPicksLabel(t *testing.T) {
	rules, _ := routing.ParseRules("port:443=chain;cidr:10.0.0.0/8=lan")
	d := Dialer{Router: routing.NewRouter(routing.Compile(rules, "direct")), Default: "direct"}

	cases := []struct {
		dst  string
		want string
	}{
		{"1.2.3.4:443", "chain"}, // порт 443
		{"10.1.2.3:80", "lan"},   // подсеть 10/8
		{"8.8.8.8:53", "direct"}, // нет правил → default
	}
	for _, c := range cases {
		if got := d.classify(netip.MustParseAddrPort(c.dst)); got != c.want {
			t.Errorf("classify(%s)=%q, want %q", c.dst, got, c.want)
		}
	}
}

// Без роутера — всегда default (никаких правил).
func TestNoRouterDefault(t *testing.T) {
	d := Dialer{Default: "direct"}
	if got := d.classify(netip.MustParseAddrPort("1.2.3.4:443")); got != "direct" {
		t.Fatalf("без роутера → %q, ожидался direct", got)
	}
}
