package nat46

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeUpstream отвечает по заданным записям: A и AAAA раздельно.
type fakeUpstream struct {
	a      []byte // если nil — NODATA
	aaaa   string // пусто — NODATA
	ttl    uint32
	aCalls int
	vCalls int
}

func (f *fakeUpstream) Query(_ context.Context, wire []byte) ([]byte, error) {
	q, _ := questionOf(wire)
	hdr, _ := headerOf(wire)

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, RecursionAvailable: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()

	switch q.Type {
	case dnsmessage.TypeA:
		f.aCalls++
		if f.a != nil {
			_ = b.AResource(dnsmessage.ResourceHeader{
				Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: f.ttl,
			}, dnsmessage.AResource{A: [4]byte(f.a)})
		}
	case dnsmessage.TypeAAAA:
		f.vCalls++
		if f.aaaa != "" {
			_ = b.AAAAResource(dnsmessage.ResourceHeader{
				Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: f.ttl,
			}, dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(f.aaaa).As16()})
		}
	}
	return b.Finish()
}

func query(t *testing.T, name string, typ dnsmessage.Type, id uint16) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	if err := b.Question(dnsmessage.Question{
		Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func firstA(t *testing.T, msg []byte) netip.Addr {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		t.Fatal(err)
	}
	_ = p.SkipAllQuestions()
	h, err := p.AnswerHeader()
	if err != nil {
		t.Fatalf("в ответе нет записей: %v", err)
	}
	if h.Type != dnsmessage.TypeA {
		t.Fatalf("тип %v", h.Type)
	}
	r, err := p.AResource()
	if err != nil {
		t.Fatal(err)
	}
	return netip.AddrFrom4(r.A)
}

// Главный сценарий: домен только с AAAA (как ntc.party) должен получить
// фиктивный v4, а дозвон по нему — уйти на настоящий v6.
func TestV6OnlyDomainGetsFakeV4AndDialsRealV6(t *testing.T) {
	const realV6 = "2a02:e00:ffec:4b8::1"
	up := &fakeUpstream{aaaa: realV6, ttl: 300}
	tbl := NewTable(DefaultPool, time.Minute)
	r := NewResolver(up, tbl)

	resp, err := r.Query(context.Background(), query(t, "ntc.party.", dnsmessage.TypeA, 1))
	if err != nil {
		t.Fatal(err)
	}
	fake := firstA(t, resp)
	if !DefaultPool.Contains(fake) {
		t.Fatalf("синтезированный адрес %v вне пула %v", fake, DefaultPool)
	}

	// дозвон по fake обязан уйти на настоящий v6
	spy := &spyDialer{}
	d := Dialer{Inner: spy, Table: tbl}
	if _, err := d.DialTCP(context.Background(), netip.AddrPortFrom(fake, 443)); err != nil {
		t.Fatal(err)
	}
	if got := spy.last.Addr().String(); got != realV6 {
		t.Fatalf("дозвон ушёл на %s, ожидался %s", got, realV6)
	}
	if spy.last.Port() != 443 {
		t.Fatalf("порт потерян: %d", spy.last.Port())
	}
}

// У домена с настоящим A вмешиваться нельзя: v4-трафик должен идти напрямую.
func TestDomainWithRealAIsUntouched(t *testing.T) {
	up := &fakeUpstream{a: []byte{93, 184, 216, 34}, aaaa: "2606:2800:220:1:248:1893:25c8:1946", ttl: 300}
	tbl := NewTable(DefaultPool, time.Minute)
	r := NewResolver(up, tbl)

	resp, err := r.Query(context.Background(), query(t, "example.com.", dnsmessage.TypeA, 2))
	if err != nil {
		t.Fatal(err)
	}
	if got := firstA(t, resp); got != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("A = %v, ожидался настоящий 93.184.216.34", got)
	}
	if up.vCalls != 0 {
		t.Fatal("AAAA спрашивать незачем: настоящий A есть")
	}
	if tbl.Len() != 0 {
		t.Fatal("маппинг создан на пустом месте")
	}
}

// Домена нет вовсе — синтезировать нечего, отдаём пустой ответ как есть.
func TestNonexistentDomainNotSynthesized(t *testing.T) {
	up := &fakeUpstream{ttl: 300}
	tbl := NewTable(DefaultPool, time.Minute)
	r := NewResolver(up, tbl)

	resp, err := r.Query(context.Background(), query(t, "nope.invalid.", dnsmessage.TypeA, 3))
	if err != nil {
		t.Fatal(err)
	}
	if hasAnswer(resp, dnsmessage.TypeA) {
		t.Fatal("для несуществующего домена синтезирован адрес")
	}
}

// ID запроса обязан сохраниться, иначе резолвер приложения не сопоставит ответ.
func TestSynthesizedResponseKeepsID(t *testing.T) {
	up := &fakeUpstream{aaaa: "2a02:e00:ffec:4b8::1", ttl: 300}
	r := NewResolver(up, NewTable(DefaultPool, time.Minute))

	resp, err := r.Query(context.Background(), query(t, "ntc.party.", dnsmessage.TypeA, 4242))
	if err != nil {
		t.Fatal(err)
	}
	hdr, _ := headerOf(resp)
	if hdr.ID != 4242 {
		t.Fatalf("ID = %d, ожидался 4242", hdr.ID)
	}
	if !hdr.Response {
		t.Fatal("флаг Response не выставлен")
	}
}

// Один и тот же хост должен получать один и тот же fake — иначе пул вычерпается
// на повторных запросах, а открытые соединения потеряют адрес.
func TestSameHostSameFake(t *testing.T) {
	up := &fakeUpstream{aaaa: "2a02:e00:ffec:4b8::1", ttl: 300}
	tbl := NewTable(DefaultPool, time.Minute)
	r := NewResolver(up, tbl)

	first, err := r.Query(context.Background(), query(t, "ntc.party.", dnsmessage.TypeA, 5))
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Query(context.Background(), query(t, "ntc.party.", dnsmessage.TypeA, 6))
	if err != nil {
		t.Fatal(err)
	}
	if firstA(t, first) != firstA(t, second) {
		t.Fatal("на повторный запрос выдан другой fake")
	}
	if tbl.Len() != 1 {
		t.Fatalf("маппингов %d, ожидался 1", tbl.Len())
	}
}

// Протухший маппинг наружу выпускать нельзя: 198.18/15 не маршрутизируется,
// пакет сгинул бы молча.
func TestExpiredMappingRefusesDial(t *testing.T) {
	tbl := NewTable(DefaultPool, 10*time.Millisecond)
	fake, ok := tbl.Map(netip.MustParseAddr("2a02:e00:ffec:4b8::1"))
	if !ok {
		t.Fatal("маппинг не выдан")
	}
	time.Sleep(30 * time.Millisecond)

	d := Dialer{Inner: &spyDialer{}, Table: tbl}
	if _, err := d.DialTCP(context.Background(), netip.AddrPortFrom(fake, 443)); err == nil {
		t.Fatal("дозвон по протухшему маппингу должен падать, а не уходить наружу")
	}
}

// Адрес вне пула — обычный трафик, трогать нельзя.
func TestAddressOutsidePoolPassesThrough(t *testing.T) {
	spy := &spyDialer{}
	d := Dialer{Inner: spy, Table: NewTable(DefaultPool, time.Minute)}
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	if _, err := d.DialTCP(context.Background(), dst); err != nil {
		t.Fatal(err)
	}
	if spy.last != dst {
		t.Fatalf("адрес подменён: %v", spy.last)
	}
}

// Протухшие адреса должны переиспользоваться, иначе пул кончится.
func TestPoolReusesExpired(t *testing.T) {
	small := netip.MustParsePrefix("198.18.0.0/31") // всего 2 адреса
	tbl := NewTable(small, 10*time.Millisecond)

	for i, h := range []string{"2001:db8::1", "2001:db8::2"} {
		if _, ok := tbl.Map(netip.MustParseAddr(h)); !ok {
			t.Fatalf("адрес %d не выдан", i)
		}
	}
	if _, ok := tbl.Map(netip.MustParseAddr("2001:db8::3")); ok {
		t.Fatal("пул исчерпан, но адрес выдан")
	}
	time.Sleep(30 * time.Millisecond)
	if _, ok := tbl.Map(netip.MustParseAddr("2001:db8::3")); !ok {
		t.Fatal("протухшие адреса не переиспользуются")
	}
}

type spyDialer struct{ last netip.AddrPort }

func (s *spyDialer) DialTCP(_ context.Context, dst netip.AddrPort) (net.Conn, error) {
	s.last = dst
	return nil, nil
}

func (s *spyDialer) DialUDP(_ context.Context, dst netip.AddrPort) (net.Conn, error) {
	s.last = dst
	return nil, nil
}
