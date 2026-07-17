package dns

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeUpstream считает обращения — так видно, сработал ли кеш.
type fakeUpstream struct {
	calls atomic.Int64
	ttl   uint32
	ip    [4]byte
}

func (f *fakeUpstream) String() string { return "fake" }

func (f *fakeUpstream) Exchange(_ context.Context, query []byte) ([]byte, error) {
	f.calls.Add(1)
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	_ = b.AResource(dnsmessage.ResourceHeader{
		Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: f.ttl,
	}, dnsmessage.AResource{A: f.ip})
	return b.Finish()
}

func query(t *testing.T, name string, id uint16) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func rcodeOf(t *testing.T, resp []byte) dnsmessage.RCode {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		t.Fatal(err)
	}
	return hdr.RCode
}

func TestCacheHit(t *testing.T) {
	up := &fakeUpstream{ttl: 300, ip: [4]byte{1, 2, 3, 4}}
	r := New(Config{Upstream: up, CacheSize: 100})

	if _, err := r.Query(context.Background(), query(t, "example.com.", 1)); err != nil {
		t.Fatalf("первый запрос: %v", err)
	}
	if _, err := r.Query(context.Background(), query(t, "example.com.", 2)); err != nil {
		t.Fatalf("второй запрос: %v", err)
	}
	if got := up.calls.Load(); got != 1 {
		t.Fatalf("upstream дёрнут %d раз, ожидался 1 (второй должен взяться из кеша)", got)
	}
	size, hits, _ := r.Cache().Stats()
	if size != 1 || hits != 1 {
		t.Fatalf("кеш: size=%d hits=%d", size, hits)
	}
}

// ID у каждого запроса свой — кешированный ответ обязан его подставлять,
// иначе резолвер клиента не сопоставит ответ с запросом.
func TestCachedResponseKeepsRequestID(t *testing.T) {
	up := &fakeUpstream{ttl: 300, ip: [4]byte{1, 2, 3, 4}}
	r := New(Config{Upstream: up, CacheSize: 10})

	if _, err := r.Query(context.Background(), query(t, "example.com.", 111)); err != nil {
		t.Fatal(err)
	}
	resp, err := r.Query(context.Background(), query(t, "example.com.", 222))
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.ID != 222 {
		t.Fatalf("ID кешированного ответа: got %d, want 222", hdr.ID)
	}
}

func TestCanaryNXDOMAIN(t *testing.T) {
	up := &fakeUpstream{ttl: 300}
	r := New(Config{Upstream: up, CacheSize: 10})

	resp, err := r.Query(context.Background(), query(t, canaryDomain, 7))
	if err != nil {
		t.Fatal(err)
	}
	if rc := rcodeOf(t, resp); rc != dnsmessage.RCodeNameError {
		t.Fatalf("canary: got %v, want NXDOMAIN (иначе браузер уведёт резолв в свой DoH)", rc)
	}
	if up.calls.Load() != 0 {
		t.Fatal("canary не должен ходить в upstream")
	}
}

func TestTTLOverrideAndExpiry(t *testing.T) {
	up := &fakeUpstream{ttl: 3600, ip: [4]byte{5, 6, 7, 8}}
	r := New(Config{Upstream: up, CacheSize: 10, TTLOverride: 30 * time.Millisecond})

	if _, err := r.Query(context.Background(), query(t, "short.example.", 1)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := r.Query(context.Background(), query(t, "short.example.", 2)); err != nil {
		t.Fatal(err)
	}
	if got := up.calls.Load(); got != 2 {
		t.Fatalf("upstream дёрнут %d раз: запись должна была протухнуть по TTLOverride", got)
	}
}

func TestCacheEvictionAndFlush(t *testing.T) {
	c := NewCache(2)
	c.Put("a", []byte{1}, time.Minute)
	c.Put("b", []byte{2}, time.Minute)
	c.Put("c", []byte{3}, time.Minute) // вытеснит "a" как самый давний

	if _, ok := c.Get("a"); ok {
		t.Fatal("самая давняя запись должна быть вытеснена")
	}
	if _, ok := c.Get("c"); !ok {
		t.Fatal("свежая запись пропала")
	}

	c.Put("d", []byte{4}, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if n := c.FlushExpired(); n != 1 {
		t.Fatalf("мягкая очистка выбросила %d, ожидалась 1 протухшая", n)
	}
	if n := c.FlushAll(); n == 0 {
		t.Fatal("грубая очистка должна была что-то выбросить")
	}
	if size, _, _ := c.Stats(); size != 0 {
		t.Fatalf("после грубой очистки size=%d", size)
	}
}

func TestDoHHandler(t *testing.T) {
	up := &fakeUpstream{ttl: 60, ip: [4]byte{9, 9, 9, 9}}
	h := Handler(New(Config{Upstream: up, CacheSize: 10}))

	req := httptest.NewRequest(http.MethodPost, "/dns-query",
		bytesReader(query(t, "doh.example.", 5)))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("статус %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/dns-message" {
		t.Fatalf("Content-Type: %q", ct)
	}
	if rc := rcodeOf(t, w.Body.Bytes()); rc != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode %v", rc)
	}
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// Мягкая очистка должна работать по таймеру, а не только существовать в API:
// иначе протухшие записи занимают место до вытеснения по LRU и выдавливают живые.
func TestGCEvictsExpired(t *testing.T) {
	up := &fakeUpstream{ttl: 3600, ip: [4]byte{1, 1, 1, 1}}
	r := New(Config{Upstream: up, CacheSize: 100, TTLOverride: 20 * time.Millisecond})

	if _, err := r.Query(context.Background(), query(t, "gc.example.", 1)); err != nil {
		t.Fatal(err)
	}
	if size, _, _ := r.Cache().Stats(); size != 1 {
		t.Fatalf("запись не закеширована: size=%d", size)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.RunGC(ctx, 10*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if size, _, _ := r.Cache().Stats(); size == 0 {
			return // GC выбросил протухшее
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("GC не выбросил протухшую запись — очистка мертва")
}
