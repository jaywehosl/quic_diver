package server

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"

	"quicdiver/internal/server/db"
	"quicdiver/internal/server/netstack"
)

// memStore — in-memory Store с одними outbounds (остальное не нужно менеджеру).
type memStore struct {
	db.Store
	mu   sync.Mutex
	rows map[string]db.OutboundRow
}

func newMemStore() *memStore { return &memStore{rows: map[string]db.OutboundRow{}} }

func (m *memStore) ListOutbounds(context.Context) ([]db.OutboundRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []db.OutboundRow
	for _, r := range m.rows {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memStore) PutOutbound(_ context.Context, o db.OutboundRow) error {
	m.mu.Lock()
	m.rows[o.Label] = o
	m.mu.Unlock()
	return nil
}

func (m *memStore) DeleteOutbound(_ context.Context, label string) error {
	m.mu.Lock()
	delete(m.rows, label)
	m.mu.Unlock()
	return nil
}

// nopCloser считает закрытия — так видно, что удалённый выход отпущен.
type nopCloser struct{ closed *int }

func (c nopCloser) Close() error { *c.closed++; return nil }

// fakeChain отдаёт помеченный Dialer и считает поднятия/закрытия.
func fakeChain(dials, closes *int) ChainDialer {
	return func(_ context.Context, addr, _, _ string) (netstack.Dialer, io.Closer, error) {
		*dials++
		return markDialer{addr}, nopCloser{closes}, nil
	}
}

func TestOutboundsReloadBuildsRouter(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	_ = store.PutOutbound(ctx, db.OutboundRow{Label: "eu", Type: db.OutChain, Addr: "1.2.3.4:443", Enabled: true})

	dials, closes := 0, 0
	obs := NewOutbounds(netip.MustParsePrefix("10.9.0.0/16"), markDialer{"direct"}, fakeChain(&dials, &closes))
	if err := obs.Reload(ctx, store); err != nil {
		t.Fatal(err)
	}
	if dials != 1 {
		t.Fatalf("chain поднят %d раз, ожидался 1", dials)
	}
	// две подсети: direct 10.9.0.0/17, eu 10.9.128.0/17
	if got := obs.For(netip.MustParseAddr("10.9.0.5")).(markDialer).mark; got != "direct" {
		t.Fatalf("src direct-подсети → %q", got)
	}
	if got := obs.For(netip.MustParseAddr("10.9.128.5")).(markDialer).mark; got != "1.2.3.4:443" {
		t.Fatalf("src eu-подсети → %q", got)
	}
	if got := obs.DialerForLabel("eu").(markDialer).mark; got != "1.2.3.4:443" {
		t.Fatalf("метка eu → %q", got)
	}
	if got := obs.DialerForLabel("").(markDialer).mark; got != "direct" {
		t.Fatalf("пустая метка → %q, ожидался direct", got)
	}
}

// Reload переиспользует живой chain-клиент (тот же addr) и не поднимает заново.
func TestOutboundsReloadReusesClient(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	_ = store.PutOutbound(ctx, db.OutboundRow{Label: "eu", Type: db.OutChain, Addr: "1.2.3.4:443", Enabled: true})

	dials, closes := 0, 0
	obs := NewOutbounds(netip.MustParsePrefix("10.9.0.0/16"), markDialer{"direct"}, fakeChain(&dials, &closes))
	_ = obs.Reload(ctx, store)
	_ = obs.Reload(ctx, store) // тот же выход — переиспользовать
	if dials != 1 {
		t.Fatalf("chain поднят %d раз при неизменном выходе, ожидался 1", dials)
	}
}

// Удаление выхода закрывает его chain-клиент.
func TestOutboundsRemovalClosesClient(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	_ = store.PutOutbound(ctx, db.OutboundRow{Label: "eu", Type: db.OutChain, Addr: "1.2.3.4:443", Enabled: true})

	dials, closes := 0, 0
	obs := NewOutbounds(netip.MustParsePrefix("10.9.0.0/16"), markDialer{"direct"}, fakeChain(&dials, &closes))
	_ = obs.Reload(ctx, store)

	_ = store.DeleteOutbound(ctx, "eu")
	_ = obs.Reload(ctx, store)
	if closes != 1 {
		t.Fatalf("клиент удалённого выхода закрыт %d раз, ожидался 1", closes)
	}
	// после удаления eu-подсеть отдаёт fallback direct
	if got := obs.For(netip.MustParseAddr("10.9.128.5")).(markDialer).mark; got != "direct" {
		t.Fatalf("после удаления eu src → %q, ожидался direct", got)
	}
}
