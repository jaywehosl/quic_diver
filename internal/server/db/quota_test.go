package db

import (
	"context"
	"testing"
	"time"

	"quicdiver/internal/server/auth"
)

// quotaClient — клиент с лимитом и уже потраченным трафиком.
func quotaClient(t *testing.T, s *SQLite, limitBytes int64, periodDays int, spent int64) string {
	t.Helper()
	ctx := context.Background()
	hash := auth.Hash("клиент")
	s.PutToken(ctx, hash, auth.RoleUser, "клиент")
	if err := s.SetTrafficLimit(ctx, hash, limitBytes, periodDays); err != nil {
		t.Fatal(err)
	}
	if spent > 0 {
		s.ReportNodeTraffic(ctx, "bitter", []NodeTraffic{{TokenHash: hash, BytesIn: spent}})
	}
	return hash
}

// Без лимита ничего не ограничиваем.
func TestNoLimitNeverExceeded(t *testing.T) {
	s := nodeStore(t)
	hash := quotaClient(t, s, 0, 0, 1<<40)

	q, err := s.QuotaOf(context.Background(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if q.Exceeded() {
		t.Fatalf("клиент без лимита признан превысившим: %+v", q)
	}
	if q.Left() != -1 {
		t.Fatalf("остаток без лимита: %d", q.Left())
	}
}

// Расход считается по СЕТЕВОМУ итогу: клиент ходит через разные узлы, и ни один
// не видит целого.
func TestQuotaCountsAllNodes(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	hash := quotaClient(t, s, 300, 0, 0)
	s.ReportNodeTraffic(ctx, "bitter", []NodeTraffic{{TokenHash: hash, BytesIn: 100, BytesOut: 50}})
	s.ReportNodeTraffic(ctx, "glitter", []NodeTraffic{{TokenHash: hash, BytesIn: 80, BytesOut: 20}})

	q, _ := s.QuotaOf(ctx, hash)
	if q.Used != 250 {
		t.Fatalf("расход %d, ожидался 250", q.Used)
	}
	if q.Exceeded() {
		t.Fatal("250 из 300 — уже превышение?")
	}
	if q.Left() != 50 {
		t.Fatalf("остаток %d", q.Left())
	}
}

// Достиг лимита — превысил.
func TestQuotaExceeded(t *testing.T) {
	s := nodeStore(t)
	hash := quotaClient(t, s, 100, 0, 100)

	q, _ := s.QuotaOf(context.Background(), hash)
	if !q.Exceeded() {
		t.Fatalf("лимит выбран, но не признан превышенным: %+v", q)
	}
	if q.Left() != 0 {
		t.Fatalf("остаток %d при исчерпанном лимите", q.Left())
	}
}

// Период кончился — счёт начинается заново.
//
// Обнулить сам счётчик нельзя: узлы шлют абсолютные значения, и следующий отчёт
// вернул бы стёртое. Поэтому двигается база отсчёта.
func TestPeriodResetsUsage(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	hash := quotaClient(t, s, 1000, 30, 900)

	q, _ := s.QuotaOf(ctx, hash) // первое обращение заводит период
	if q.Used != 0 {
		t.Fatalf("первое обращение должно стартовать период с нуля: %+v", q)
	}
	// Ещё 200 внутри периода.
	s.ReportNodeTraffic(ctx, "bitter", []NodeTraffic{{TokenHash: hash, BytesIn: 1100}})
	if q, _ = s.QuotaOf(ctx, hash); q.Used != 200 {
		t.Fatalf("расход внутри периода: %+v", q)
	}

	// Отматываем срок сброса в прошлое — период истёк.
	s.setTrafficBase(ctx, hash, 900, time.Now().Add(-time.Hour).UnixNano())
	q, _ = s.QuotaOf(ctx, hash)
	if q.Used != 0 {
		t.Fatalf("после конца периода расход не обнулился: %+v", q)
	}
	if q.ResetAt.Before(time.Now()) {
		t.Fatalf("новый срок сброса в прошлом: %v", q.ResetAt)
	}
	// Абсолютный счётчик при этом никуда не делся.
	if total, _ := s.NetworkTrafficOf(ctx, hash); total.BytesIn != 1100 {
		t.Fatalf("сброс периода стёр историю: %+v", total)
	}
}

// Долгий простой не должен выдавать клиенту пачку просроченных периодов разом.
func TestLongOutageSkipsMissedPeriods(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	hash := quotaClient(t, s, 1000, 1, 0)
	s.QuotaOf(ctx, hash)

	// Срок сброса — десять периодов назад.
	s.setTrafficBase(ctx, hash, 0, time.Now().Add(-10*24*time.Hour).UnixNano())
	q, _ := s.QuotaOf(ctx, hash)
	if q.ResetAt.Before(time.Now()) {
		t.Fatalf("срок сброса остался в прошлом: %v", q.ResetAt)
	}
	if q.ResetAt.After(time.Now().Add(25 * time.Hour)) {
		t.Fatalf("срок сброса улетел дальше одного периода: %v", q.ResetAt)
	}
}

// Администратор продлил тариф посреди периода — счёт начинается заново сразу.
func TestManualResetStartsFresh(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	hash := quotaClient(t, s, 1000, 30, 900)
	s.QuotaOf(ctx, hash)
	s.ReportNodeTraffic(ctx, "bitter", []NodeTraffic{{TokenHash: hash, BytesIn: 1800}})

	if err := s.ResetTraffic(ctx, hash); err != nil {
		t.Fatal(err)
	}
	q, _ := s.QuotaOf(ctx, hash)
	if q.Used != 0 {
		t.Fatalf("ручной сброс не обнулил расход: %+v", q)
	}
}

// Счётчик узла упал ниже базы (переустановка, откат из снимка) — расход не
// должен уходить в минус, и клиент за чужую аварию не отвечает.
func TestCounterRollbackDoesNotGoNegative(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	hash := quotaClient(t, s, 1000, 0, 800)
	s.setTrafficBase(ctx, hash, 800, 0)

	// Узел переустановлен: его абсолютный счётчик начался заново.
	s.ReportNodeTraffic(ctx, "bitter", []NodeTraffic{{TokenHash: hash, BytesIn: 50}})
	q, err := s.QuotaOf(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if q.Used < 0 {
		t.Fatalf("расход ушёл в минус: %+v", q)
	}
	if q.Used != 0 {
		t.Fatalf("после отката счётчика расход %d, ожидался 0", q.Used)
	}
}

// Снятие лимита должно работать: клиент оплатил безлимит.
func TestClearingLimit(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	hash := quotaClient(t, s, 100, 0, 500)
	if q, _ := s.QuotaOf(ctx, hash); !q.Exceeded() {
		t.Fatal("лимит не сработал до снятия")
	}

	if err := s.SetTrafficLimit(ctx, hash, 0, 0); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.QuotaOf(ctx, hash); q.Exceeded() {
		t.Fatal("лимит остался после снятия")
	}
}
