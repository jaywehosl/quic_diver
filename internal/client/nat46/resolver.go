package nat46

import (
	"context"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Exchanger — то, что умеет спросить узел (dnsproxy.Exchanger).
type Exchanger interface {
	Query(ctx context.Context, wire []byte) ([]byte, error)
}

// Resolver оборачивает резолвер узла: A-запросы к доменам без A, но с AAAA,
// получают синтезированный ответ из пула.
//
// Вмешиваемся только когда настоящего A нет. Если у домена есть и A, и AAAA
// (обычный случай) — отдаём как есть: незачем гонять v4-трафик через подмену.
type Resolver struct {
	inner Exchanger
	table *Table
}

// NewResolver оборачивает inner.
func NewResolver(inner Exchanger, t *Table) *Resolver {
	return &Resolver{inner: inner, table: t}
}

// Query проксирует запрос, подмешивая синтез для v6-only имён.
func (r *Resolver) Query(ctx context.Context, wire []byte) ([]byte, error) {
	resp, err := r.inner.Query(ctx, wire)
	if err != nil {
		return nil, err
	}
	q, ok := questionOf(wire)
	if !ok || q.Type != dnsmessage.TypeA || q.Class != dnsmessage.ClassINET {
		return resp, nil
	}
	if hasAnswer(resp, dnsmessage.TypeA) {
		return resp, nil // настоящий A есть — не вмешиваемся
	}

	// A пуст: спрашиваем AAAA тем же путём (ответ придёт из кеша узла, если он
	// его уже видел) и подставляем фиктивный v4.
	v6, ttl, ok := r.lookupAAAA(ctx, q, wire)
	if !ok {
		return resp, nil // v6 тоже нет — домена просто не существует
	}
	fake, ok := r.table.Map(v6)
	if !ok {
		return resp, nil // пул исчерпан — честнее отдать пустой ответ
	}
	synth, err := buildA(wire, q, fake, ttl)
	if err != nil {
		return resp, nil
	}
	return synth, nil
}

// lookupAAAA спрашивает AAAA для того же имени и возвращает первый адрес.
func (r *Resolver) lookupAAAA(ctx context.Context, q dnsmessage.Question, orig []byte) (netipAddr, uint32, bool) {
	hdr, ok := headerOf(orig)
	if !ok {
		return netipAddr{}, 0, false
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return netipAddr{}, 0, false
	}
	if err := b.Question(dnsmessage.Question{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: q.Class}); err != nil {
		return netipAddr{}, 0, false
	}
	msg, err := b.Finish()
	if err != nil {
		return netipAddr{}, 0, false
	}
	// собственный дедлайн: синтез не должен затягивать исходный запрос сверх
	// того, что резолвер приложения готов ждать
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	resp, err := r.inner.Query(ctx, msg)
	if err != nil {
		return netipAddr{}, 0, false
	}
	return firstAAAA(resp)
}
