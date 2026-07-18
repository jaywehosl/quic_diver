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
		if got := d.classify(netip.MustParseAddrPort(c.dst), ""); got != c.want {
			t.Errorf("classify(%s)=%q, want %q", c.dst, got, c.want)
		}
	}
}

// Без роутера — всегда default (никаких правил).
func TestNoRouterDefault(t *testing.T) {
	d := Dialer{Default: "direct"}
	if got := d.classify(netip.MustParseAddrPort("1.2.3.4:443"), ""); got != "direct" {
		t.Fatalf("без роутера → %q, ожидался direct", got)
	}
}

// fakePool — минимальный FakeResolver для теста: fake→(domain, real).
type fakePool struct {
	domain string
	real   netip.Addr
	fake   netip.Addr
}

func (f fakePool) DomainOf(a netip.Addr) string {
	if a == f.fake {
		return f.domain
	}
	return ""
}
func (f fakePool) RealAddr(a netip.Addr) (netip.Addr, bool) {
	if a == f.fake {
		return f.real, true
	}
	return netip.Addr{}, false
}

// Доменное правило через fake-IP: флоу на fake → домен известен → метка; dst
// подменяется реальным адресом (fake не маршрутизируется).
func TestDomainRuleViaFake(t *testing.T) {
	rules, _ := routing.ParseRules("dom:youtube.com=chain")
	fp := fakePool{
		domain: "rr1.googlevideo.youtube.com",
		real:   netip.MustParseAddr("142.250.1.2"),
		fake:   netip.MustParseAddr("198.18.0.5"),
	}
	d := Dialer{Router: routing.NewRouter(routing.Compile(rules, "direct")), Fake: fp, Default: "direct"}

	// resolve: fake → real + домен
	real, domain := d.resolve(netip.MustParseAddrPort("198.18.0.5:443"))
	if real.Addr() != fp.real {
		t.Fatalf("fake не подменён на real: %v", real)
	}
	if domain != fp.domain {
		t.Fatalf("домен: %q", domain)
	}
	// классификация по домену → chain (суффикс youtube.com матчит поддомен)
	if got := d.classify(real, domain); got != "chain" {
		t.Fatalf("домен youtube → %q, ожидался chain", got)
	}
}
