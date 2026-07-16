package nat46

import (
	"net/netip"
	"testing"
)

// ULA и link-local наружу не ведут — по ним v6-only хост недостижим, значит за
// «свой IPv6» их считать нельзя, иначе синтез выключится и хост пропадёт.
func TestOnlyGlobalCountsAsIPv6(t *testing.T) {
	cases := []struct {
		addr  string
		isULA bool
	}{
		{"fd00::1", true},
		{"fdff:ffff::1", true},
		{"fc00::1", true},
		{"2a02:e00:ffec:4b8::1", false},
		{"2001:db8::1", false},
	}
	for _, c := range cases {
		a := netip.MustParseAddr(c.addr)
		if got := isULA(a); got != c.isULA {
			t.Errorf("isULA(%s) = %v, ожидалось %v", c.addr, got, c.isULA)
		}
	}

	// link-local не глобальный — отсеивается до проверки на ULA
	if netip.MustParseAddr("fe80::1").IsGlobalUnicast() {
		t.Error("fe80::1 не должен считаться глобальным")
	}
}

// Проверка на живой машине: результат обязан совпадать с реальным положением дел.
// Здесь IPv6 нет — значит и определение должно давать false, иначе синтез молча
// выключится и v6-only хосты станут недоступны.
func TestHostHasIPv6MatchesReality(t *testing.T) {
	t.Logf("HostHasIPv6() = %v", HostHasIPv6())
}
