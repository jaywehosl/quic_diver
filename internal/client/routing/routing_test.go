package routing

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func dst(ipport string) netip.AddrPort { return netip.MustParseAddrPort(ipport) }

// Доменный суффикс матчит сам домен и поддомены, но не «похожие».
func TestDomainMatch(t *testing.T) {
	cases := []struct {
		suffix, name string
		want         bool
	}{
		{"youtube.com", "youtube.com", true},
		{"youtube.com", "rr1.googlevideo.youtube.com", true},
		{"youtube.com", "notyoutube.com", false},
		{"googlevideo.com", "rr5---sn-abc.googlevideo.com", true},
	}
	for _, c := range cases {
		if got := domainMatches(c.suffix, c.name); got != c.want {
			t.Errorf("domainMatches(%q,%q)=%v, want %v", c.suffix, c.name, got, c.want)
		}
	}
}

// Порядок правил = приоритет. Конфликт из ТЗ: «весь Chrome → chain, но .cn →
// direct». Правило .cn выше — .cn-домен Chrome'а идёт direct, остальной Chrome —
// chain.
func TestRuleOrderResolvesConflict(t *testing.T) {
	rs := Compile([]Rule{
		{Match: Match{Domain: "cn"}, Out: "direct"},         // .cn выше
		{Match: Match{Process: "chrome.exe"}, Out: "chain"}, // весь Chrome ниже
	}, "direct")

	// Chrome к .cn → direct (правило .cn первое)
	if out := rs.Classify(Flow{Process: "chrome.exe", Domain: "baidu.cn"}); out != "direct" {
		t.Fatalf("chrome→.cn: %q, ожидался direct", out)
	}
	// Chrome к обычному домену → chain
	if out := rs.Classify(Flow{Process: "chrome.exe", Domain: "example.com"}); out != "chain" {
		t.Fatalf("chrome→example: %q, ожидался chain", out)
	}
}

// Нет совпадений → выход по умолчанию.
func TestDefaultOutbound(t *testing.T) {
	rs := Compile([]Rule{{Match: Match{Domain: "youtube.com"}, Out: "chain"}}, "direct")
	if out := rs.Classify(Flow{Domain: "example.com"}); out != "direct" {
		t.Fatalf("нет совпадения → %q, ожидался direct", out)
	}
}

// CIDR и порт.
func TestCIDRAndPort(t *testing.T) {
	rs := Compile([]Rule{
		{Match: Match{CIDR: netip.MustParsePrefix("10.0.0.0/8")}, Out: "lan"},
		{Match: Match{Port: 443}, Out: "https-out"},
	}, "direct")

	if out := rs.Classify(Flow{Dst: dst("10.1.2.3:80")}); out != "lan" {
		t.Fatalf("CIDR: %q", out)
	}
	if out := rs.Classify(Flow{Dst: dst("1.2.3.4:443")}); out != "https-out" {
		t.Fatalf("port: %q", out)
	}
}

// Atomic swap: замена набора видна сразу, окна без роутинга нет — читатели во
// время замены получают либо старый, либо новый ответ, но всегда валидный.
func TestSwapNoGap(t *testing.T) {
	r := NewRouter(Compile([]Rule{{Match: Match{Domain: "x.com"}, Out: "a"}}, "direct"))

	var bad atomic.Int64
	var wg sync.WaitGroup
	stop := make(chan struct{})
	// читатели крутятся во время замен
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				out := r.Classify(Flow{Domain: "x.com"})
				if out != "a" && out != "b" && out != "direct" {
					bad.Add(1) // невалидный ответ = поймали окно
				}
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		if i%2 == 0 {
			r.Swap(Compile([]Rule{{Match: Match{Domain: "x.com"}, Out: "b"}}, "direct"))
		} else {
			r.Swap(Compile([]Rule{{Match: Match{Domain: "x.com"}, Out: "a"}}, "direct"))
		}
	}
	close(stop)
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("поймано %d невалидных ответов — есть окно без роутинга", bad.Load())
	}
}

// Conntrack: правила гоняются раз на флоу, дальше из кеша.
func TestConntrackCachesPerFlow(t *testing.T) {
	ct := NewConntrack(time.Minute)
	var calls int
	classify := func(Flow) string { calls++; return "chain" }

	f := Flow{Dst: dst("1.2.3.4:443")}
	for i := 0; i < 5; i++ {
		if out := ct.Decide(40000, f, classify); out != "chain" {
			t.Fatalf("decide: %q", out)
		}
	}
	if calls != 1 {
		t.Fatalf("classify вызван %d раз, ожидался 1 (остальное из кеша)", calls)
	}
	// другой флоу (другой src-порт) — своя классификация
	_ = ct.Decide(40001, f, classify)
	if calls != 2 {
		t.Fatalf("новый флоу не классифицирован заново: calls=%d", calls)
	}
}

// Протухшие записи вычищаются.
func TestConntrackSweep(t *testing.T) {
	ct := NewConntrack(20 * time.Millisecond)
	ct.Decide(40000, Flow{Dst: dst("1.2.3.4:443")}, func(Flow) string { return "x" })
	if ct.Len() != 1 {
		t.Fatalf("len=%d", ct.Len())
	}
	time.Sleep(40 * time.Millisecond)
	if n := ct.Sweep(); n != 1 {
		t.Fatalf("sweep убрал %d, ожидалась 1", n)
	}
	if ct.Len() != 0 {
		t.Fatalf("после sweep len=%d", ct.Len())
	}
}
