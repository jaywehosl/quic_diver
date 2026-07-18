package fakeip

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestAssignStableAndReverse(t *testing.T) {
	p := New(DefaultPool, time.Minute)
	real := []netip.Addr{netip.MustParseAddr("93.184.216.34")}

	f1, ok := p.Assign("example.com", real)
	if !ok {
		t.Fatal("не выдан")
	}
	f2, _ := p.Assign("example.com", real)
	if f1 != f2 {
		t.Fatalf("нестабильно: %v != %v", f1, f2)
	}
	if !DefaultPool.Contains(f1) {
		t.Fatalf("fake %v вне пула", f1)
	}
	// reverse: fake → домен и real
	if d, ok := p.Domain(f1); !ok || d != "example.com" {
		t.Fatalf("Domain=%q ok=%v", d, ok)
	}
	if got, ok := p.Real(f1); !ok || got[0] != real[0] {
		t.Fatalf("Real=%v ok=%v", got, ok)
	}
	// другой домен → другой fake
	f3, _ := p.Assign("youtube.com", real)
	if f3 == f1 {
		t.Fatal("разным доменам один fake")
	}
}

func TestTrailingDotNormalized(t *testing.T) {
	p := New(DefaultPool, time.Minute)
	f1, _ := p.Assign("example.com.", nil)
	f2, _ := p.Assign("example.com", nil)
	if f1 != f2 {
		t.Fatal("точка на конце дала другой fake")
	}
}

// fakeUp отвечает на A/AAAA заданными адресами.
type fakeUp struct {
	a    []byte // A (4 байта) или nil
	aaaa string // AAAA-адрес или пусто
}

func (f fakeUp) Query(_ context.Context, wire []byte) ([]byte, error) {
	q, _ := questionOf(wire)
	hdr, _ := headerOf(wire)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, RecursionAvailable: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	switch q.Type {
	case dnsmessage.TypeA:
		if f.a != nil {
			_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
				dnsmessage.AResource{A: [4]byte(f.a)})
		}
	case dnsmessage.TypeAAAA:
		if f.aaaa != "" {
			_ = b.AAAAResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 300},
				dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(f.aaaa).As16()})
		}
	}
	return b.Finish()
}

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	m, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func firstA(t *testing.T, resp []byte) netip.Addr {
	t.Helper()
	as := addrsOf(resp, dnsmessage.TypeA)
	if len(as) == 0 {
		t.Fatal("нет A в ответе")
	}
	return as[0]
}

// A-запрос обычного домена → fake, real запомнены.
func TestResolverAGivesFake(t *testing.T) {
	pool := New(DefaultPool, time.Minute)
	r := NewResolver(fakeUp{a: []byte{93, 184, 216, 34}}, pool)

	resp, err := r.Query(context.Background(), query(t, "example.com.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	fake := firstA(t, resp)
	if !DefaultPool.Contains(fake) {
		t.Fatalf("A не fake: %v", fake)
	}
	if d, _ := pool.Domain(fake); d != "example.com" {
		t.Fatalf("домен по fake: %q", d)
	}
	if real, _ := pool.Real(fake); len(real) != 1 || real[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("real: %v", real)
	}
}

// v6-only домен (A пусто, AAAA есть) → fake-v4, real = v6.
func TestResolverV6OnlyGivesFake(t *testing.T) {
	pool := New(DefaultPool, time.Minute)
	r := NewResolver(fakeUp{aaaa: "2a02:e00:ffec:4b8::1"}, pool)

	resp, err := r.Query(context.Background(), query(t, "ntc.party.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	fake := firstA(t, resp)
	if !DefaultPool.Contains(fake) {
		t.Fatalf("v6-only не дал fake: %v", fake)
	}
	if real, _ := pool.Real(fake); len(real) != 1 || !real[0].Is6() {
		t.Fatalf("real не v6: %v", real)
	}
}

// AAAA-запрос → NODATA (форс v4-fake), приложение переспросит A.
func TestResolverAAAAisNoData(t *testing.T) {
	r := NewResolver(fakeUp{a: []byte{1, 2, 3, 4}, aaaa: "2001:db8::1"}, New(DefaultPool, time.Minute))
	resp, err := r.Query(context.Background(), query(t, "example.com.", dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	if len(addrsOf(resp, dnsmessage.TypeAAAA)) != 0 {
		t.Fatal("AAAA вернул адреса — не форсит v4-путь")
	}
}

// Несуществующий домен (ни A, ни AAAA) → не подменяем.
func TestResolverNXNotFaked(t *testing.T) {
	pool := New(DefaultPool, time.Minute)
	r := NewResolver(fakeUp{}, pool)
	resp, err := r.Query(context.Background(), query(t, "nope.invalid.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if len(addrsOf(resp, dnsmessage.TypeA)) != 0 {
		t.Fatal("для несуществующего выдан fake")
	}
	if pool.Len() != 0 {
		t.Fatal("маппинг создан на пустом месте")
	}
}
