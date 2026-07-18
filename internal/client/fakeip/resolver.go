package fakeip

import (
	"context"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Exchanger — то, что резолвит по-настоящему (резолвер узла). Реализуется
// dnsforward.Forwarder.
type Exchanger interface {
	Query(ctx context.Context, wire []byte) ([]byte, error)
}

// Resolver отдаёт приложению фиктивные адреса, узнавая настоящие у узла и
// запоминая соответствие для роутинга.
//
// A-запрос → fake-v4 (real = A-адреса; если A нет, но есть AAAA — v6-only хост,
// real = AAAA, приложение всё равно пойдёт по fake-v4, а узел выйдет по v6).
// AAAA-запрос → NODATA: форсим v4-fake путь, приложение сделает fallback на A.
// Так домен известен на ЛЮБОМ флоу через один пул fake-v4.
type Resolver struct {
	inner Exchanger
	pool  *Pool
}

// NewResolver оборачивает inner.
func NewResolver(inner Exchanger, pool *Pool) *Resolver {
	return &Resolver{inner: inner, pool: pool}
}

// Query подменяет ответ фиктивным адресом (см. тип).
func (r *Resolver) Query(ctx context.Context, wire []byte) ([]byte, error) {
	q, ok := questionOf(wire)
	if !ok || q.Class != dnsmessage.ClassINET {
		return r.inner.Query(ctx, wire)
	}

	switch q.Type {
	case dnsmessage.TypeA:
		return r.answerA(ctx, wire, q)
	case dnsmessage.TypeAAAA:
		// Форсим v4-fake: отдаём NODATA, приложение переспросит A и получит fake.
		if resp, err := noData(wire, q); err == nil {
			return resp, nil
		}
		return r.inner.Query(ctx, wire)
	default:
		return r.inner.Query(ctx, wire)
	}
}

func (r *Resolver) answerA(ctx context.Context, wire []byte, q dnsmessage.Question) ([]byte, error) {
	resp, err := r.inner.Query(ctx, wire)
	if err != nil {
		return nil, err
	}
	real := addrsOf(resp, dnsmessage.TypeA)
	if len(real) == 0 {
		// A пусто — возможно v6-only: спросим AAAA, real станет v6.
		real = r.lookupAAAA(ctx, wire, q)
		if len(real) == 0 {
			return resp, nil // домена нет — отдаём как есть
		}
	}
	fake, ok := r.pool.Assign(q.Name.String(), real)
	if !ok {
		return resp, nil // пул исчерпан — не подменяем
	}
	if synth, err := buildA(wire, q, fake, defaultTTLSecs); err == nil {
		return synth, nil
	}
	return resp, nil
}

// lookupAAAA спрашивает AAAA тем же путём, возвращает адреса.
func (r *Resolver) lookupAAAA(ctx context.Context, orig []byte, q dnsmessage.Question) []netip.Addr {
	hdr, ok := headerOf(orig)
	if !ok {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, RecursionDesired: true})
	b.EnableCompression()
	if b.StartQuestions() != nil {
		return nil
	}
	if b.Question(dnsmessage.Question{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: q.Class}) != nil {
		return nil
	}
	msg, err := b.Finish()
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	resp, err := r.inner.Query(ctx, msg)
	if err != nil {
		return nil
	}
	return addrsOf(resp, dnsmessage.TypeAAAA)
}

const defaultTTLSecs = 60
