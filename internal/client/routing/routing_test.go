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

func TestParseRules(t *testing.T) {
	rules, err := ParseRules("dom:youtube.com=chain; proc:telegram.exe=eu; cidr:10.0.0.0/8=lan; port:443=https")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("правил %d, ожидалось 4", len(rules))
	}
	if rules[0].Match.Domain != "youtube.com" || rules[0].Out != "chain" {
		t.Fatalf("dom: %+v", rules[0])
	}
	if rules[2].Match.CIDR.String() != "10.0.0.0/8" {
		t.Fatalf("cidr: %+v", rules[2])
	}
	if rules[3].Match.Port != 443 {
		t.Fatalf("port: %+v", rules[3])
	}
	// битое
	if _, err := ParseRules("bad:x=y"); err == nil {
		t.Fatal("неизвестный матчер принят")
	}
	if _, err := ParseRules("port:notanumber=x"); err == nil {
		t.Fatal("битый порт принят")
	}
}

func TestGeoSiteAndGeoIPAndProxyChains(t *testing.T) {
	rules, err := ParseRules(`
		geosite:youtube = node2;
		geosite:google = node1,node2;
		geoip:private = direct;
		dom:2ip.ru = path:node1;
	`)
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if len(rules) != 4 {
		t.Fatalf("ожидалось 4 правила, получено %d", len(rules))
	}
	if rules[1].Out != "path:node1,node2" {
		t.Fatalf("цепочка прокси не нормализована: %q", rules[1].Out)
	}

	rs := Compile(rules, "direct")

	// 1. YouTube -> node2 (более специфичное правило идет первым)
	if out := rs.Classify(Flow{Domain: "googlevideo.com"}); out != "node2" {
		t.Fatalf("geosite:youtube: got %q, want node2", out)
	}

	// 2. Google -> path:node1,node2
	if out := rs.Classify(Flow{Domain: "mail.google.com"}); out != "path:node1,node2" {
		t.Fatalf("geosite:google: got %q, want path:node1,node2", out)
	}

	// 3. Local IP -> direct
	if out := rs.Classify(Flow{Dst: dst("192.168.1.1:80")}); out != "direct" {
		t.Fatalf("geoip:private: got %q, want direct", out)
	}

	// 4. Domain rule -> path:node1
	if out := rs.Classify(Flow{Domain: "2ip.ru"}); out != "path:node1" {
		t.Fatalf("dom:2ip.ru: got %q, want path:node1", out)
	}
}

func TestRouterCRUD(t *testing.T) {
	r := NewRouter(Compile([]Rule{
		{Match: Match{Domain: "youtube.com"}, Out: "node1"},
		{Match: Match{Domain: "google.com"}, Out: "node2"},
	}, "direct"))

	if len(r.CurrentRuleset().Rules()) != 2 {
		t.Fatalf("len = %d, want 2", len(r.CurrentRuleset().Rules()))
	}

	// 1. AddRule
	r.AddRule(Rule{Match: Match{Process: "telegram.exe"}, Out: "node3"})
	if len(r.CurrentRuleset().Rules()) != 3 {
		t.Fatalf("AddRule: len = %d, want 3", len(r.CurrentRuleset().Rules()))
	}

	// 2. UpdateRule
	ok := r.UpdateRule(0, Rule{Match: Match{Domain: "youtube.com"}, Out: "path:node1,node2"})
	if !ok || r.CurrentRuleset().Rules()[0].Out != "path:node1,node2" {
		t.Fatalf("UpdateRule failed")
	}

	// 3. MoveRule (переставить index 1 на index 0 для правил одной категории)
	r.AddRule(Rule{Match: Match{Domain: "vk.com"}, Out: "node4"})
	ok = r.MoveRule(2, 0)
	if !ok || r.CurrentRuleset().Rules()[0].Match.Domain != "vk.com" {
		t.Fatalf("MoveRule failed: got %+v", r.CurrentRuleset().Rules()[0])
	}

	// 4. DeleteRule (удалить index 0)
	ok = r.DeleteRule(0)
	if !ok || len(r.CurrentRuleset().Rules()) != 3 {
		t.Fatalf("DeleteRule failed")
	}
}

func TestRulePriorityHierarchy(t *testing.T) {
	// Добавляем правило процесса ПЕРВЫМ в список, но доменные правила должны перевесить!
	rs := Compile([]Rule{
		{Match: Match{Process: "chrome.exe"}, Out: "process-route"},
		{Match: Match{Domain: "youtube.com"}, Out: "domain-route"},
	}, "default-route")

	// Chrome к youtube.com -> должен сработать domain-route (Домен важнее Процесса)
	if out := rs.Classify(Flow{Process: "chrome.exe", Domain: "youtube.com"}); out != "domain-route" {
		t.Fatalf("Chrome to Youtube: got %q, want domain-route", out)
	}

	// Chrome к другому сайту -> должен сработать process-route
	if out := rs.Classify(Flow{Process: "chrome.exe", Domain: "example.com"}); out != "process-route" {
		t.Fatalf("Chrome to Example: got %q, want process-route", out)
	}

	// Любое другое приложение -> должен сработать default-route
	if out := rs.Classify(Flow{Process: "vlc.exe", Domain: "example.com"}); out != "default-route" {
		t.Fatalf("VLC to Example: got %q, want default-route", out)
	}
}
