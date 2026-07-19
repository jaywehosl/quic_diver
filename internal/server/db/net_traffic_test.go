package db

import (
	"context"
	"testing"

	"quicdiver/internal/server/auth"
)

// Сетевой итог — сумма по узлам. Локального счётчика мало: клиент ходит через
// разные узлы, и ни один из них не видит целого, поэтому лимит по трафику
// нельзя было ни показать, ни применить.
func TestNetworkTrafficSumsNodes(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	hash := auth.Hash("клиент")
	s.PutToken(ctx, hash, auth.RoleUser, "клиент")

	s.ReportNodeTraffic(ctx, "bitter", []NodeTraffic{{TokenHash: hash, BytesIn: 100, BytesOut: 50}})
	s.ReportNodeTraffic(ctx, "glitter", []NodeTraffic{{TokenHash: hash, BytesIn: 30, BytesOut: 20}})

	total, err := s.NetworkTrafficOf(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if total.BytesIn != 130 || total.BytesOut != 70 {
		t.Fatalf("сетевой итог: %+v", total)
	}
}

// Отчёты абсолютные, а не приращения: повторная доставка не должна удваивать
// расход, иначе узлу пришлось бы помнить, что он уже отослал.
func TestRepeatedReportIsIdempotent(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	hash := auth.Hash("клиент")
	s.PutToken(ctx, hash, auth.RoleUser, "клиент")

	rows := []NodeTraffic{{TokenHash: hash, BytesIn: 100, BytesOut: 50}}
	s.ReportNodeTraffic(ctx, "bitter", rows)
	s.ReportNodeTraffic(ctx, "bitter", rows)
	s.ReportNodeTraffic(ctx, "bitter", rows)

	total, _ := s.NetworkTrafficOf(ctx, hash)
	if total.BytesIn != 100 || total.BytesOut != 50 {
		t.Fatalf("повтор удвоил расход: %+v", total)
	}
}

// Свежий отчёт узла заменяет прежний, а не складывается с ним.
func TestReportReplacesPrevious(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	hash := auth.Hash("клиент")
	s.PutToken(ctx, hash, auth.RoleUser, "клиент")

	s.ReportNodeTraffic(ctx, "bitter", []NodeTraffic{{TokenHash: hash, BytesIn: 100}})
	s.ReportNodeTraffic(ctx, "bitter", []NodeTraffic{{TokenHash: hash, BytesIn: 180}})

	total, _ := s.NetworkTrafficOf(ctx, hash)
	if total.BytesIn != 180 {
		t.Fatalf("итог %d, ожидался 180", total.BytesIn)
	}
}

// Разбивка по узлам — чтобы в панели было видно, где клиент ходит.
func TestTrafficByNode(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	hash := auth.Hash("клиент")
	s.PutToken(ctx, hash, auth.RoleUser, "клиент")
	s.ReportNodeTraffic(ctx, "glitter", []NodeTraffic{{TokenHash: hash, BytesIn: 30}})
	s.ReportNodeTraffic(ctx, "bitter", []NodeTraffic{{TokenHash: hash, BytesIn: 100}})

	rows, err := s.NodeTrafficOf(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Node != "bitter" || rows[1].Node != "glitter" {
		t.Fatalf("разбивка: %+v", rows)
	}
}

// Клиент, которого ещё не было в сети, — не ошибка: просто ноль.
func TestNetworkTrafficOfUnknownIsZero(t *testing.T) {
	s := nodeStore(t)
	total, err := s.NetworkTrafficOf(context.Background(), "нет-такого")
	if err != nil {
		t.Fatalf("неизвестный клиент дал ошибку: %v", err)
	}
	if total.BytesIn != 0 || total.BytesOut != 0 {
		t.Fatalf("итог не нулевой: %+v", total)
	}
}

// Клиент, которого мастер не знает, не должен ронять весь отчёт.
//
// Реплика отстаёт от мастера на интервал репликации, поэтому вполне может
// отчитаться о токене, удалённом на мастере минуту назад. Уронить из-за этого
// весь пакет значило бы потерять учёт всех остальных клиентов узла.
func TestReportSurvivesUnknownToken(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	live := auth.Hash("живой")
	s.PutToken(ctx, live, auth.RoleUser, "живой")

	err := s.ReportNodeTraffic(ctx, "bitter", []NodeTraffic{
		{TokenHash: live, BytesIn: 100},
		{TokenHash: auth.Hash("которого-нет"), BytesIn: 500},
	})
	if err != nil {
		t.Fatalf("отчёт упал из-за незнакомого клиента: %v", err)
	}
	if total, _ := s.NetworkTrafficOf(ctx, live); total.BytesIn != 100 {
		t.Fatalf("живой клиент не учтён: %+v", total)
	}
	// Строка о неизвестном клиенте не оседает мусором.
	if total, _ := s.NetworkTrafficOf(ctx, auth.Hash("которого-нет")); total.BytesIn != 0 {
		t.Fatalf("расход неизвестного клиента остался: %+v", total)
	}
}

// Отзыв клиента историю расхода не стирает: токен остаётся надгробием, и
// администратор должен видеть, сколько тот успел прокачать.
func TestRevokedKeepsTraffic(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	hash := auth.Hash("отозванный")
	s.PutToken(ctx, hash, auth.RoleUser, "отозванный")
	s.ReportNodeTraffic(ctx, "bitter", []NodeTraffic{{TokenHash: hash, BytesIn: 400}})

	if err := s.Revoke(ctx, hash); err != nil {
		t.Fatal(err)
	}
	// Ещё один отчёт от другого узла — уборка не должна снести историю.
	s.ReportNodeTraffic(ctx, "glitter", []NodeTraffic{})

	if total, _ := s.NetworkTrafficOf(ctx, hash); total.BytesIn != 400 {
		t.Fatalf("расход отозванного клиента потерян: %+v", total)
	}
}

// Отчёт собирается из локального счётчика — то, что узел видел сам.
func TestLocalReportCollectsTraffic(t *testing.T) {
	s := nodeStore(t)
	ctx := context.Background()
	busy, idle := auth.Hash("ходил"), auth.Hash("не ходил")
	s.PutToken(ctx, busy, auth.RoleUser, "ходил")
	s.PutToken(ctx, idle, auth.RoleUser, "не ходил")
	s.OpenSession(ctx, Session{ID: "s1", TokenHash: busy}, 0)
	s.TouchSession(ctx, "s1", busy, 700, 300)

	rows, err := s.LocalTrafficReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Клиент без расхода в отчёт не попадает — гонять нули по сети незачем.
	if len(rows) != 1 || rows[0].TokenHash != busy {
		t.Fatalf("отчёт: %+v", rows)
	}
	if rows[0].BytesIn != 700 || rows[0].BytesOut != 300 {
		t.Fatalf("счётчики: %+v", rows[0])
	}
}
