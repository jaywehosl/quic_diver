package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Quota — лимит трафика клиента и его расход за текущий период.
type Quota struct {
	// Limit — предел за период, байт. 0 — без ограничения.
	Limit int64 `json:"limit"`
	// Used — израсходовано за текущий период.
	Used int64 `json:"used"`
	// PeriodDays — длина периода. 0 — период не кончается.
	PeriodDays int `json:"period_days,omitempty"`
	// ResetAt — когда счётчик начнётся заново.
	ResetAt time.Time `json:"reset_at,omitempty"`
}

// Exceeded — израсходован ли лимит.
func (q Quota) Exceeded() bool { return q.Limit > 0 && q.Used >= q.Limit }

// Left — сколько осталось. Без лимита — -1.
func (q Quota) Left() int64 {
	if q.Limit <= 0 {
		return -1
	}
	if q.Used >= q.Limit {
		return 0
	}
	return q.Limit - q.Used
}

// QuotaOf считает расход клиента за текущий период и при необходимости
// начинает новый.
//
// Период сдвигается лениво, при обращении, а не по расписанию: отдельный
// планировщик пришлось бы держать на мастере и синхронизировать с репликами,
// тогда как проверка всё равно происходит на каждом подключении.
func (s *SQLite) QuotaOf(ctx context.Context, hash string) (Quota, error) {
	var q Quota
	var resetAt, base int64
	err := s.db.QueryRowContext(ctx,
		`SELECT limit_traffic, traffic_period, traffic_reset_at, traffic_base
		   FROM tokens WHERE hash = ?`, hash).
		Scan(&q.Limit, &q.PeriodDays, &resetAt, &base)
	if errors.Is(err, sql.ErrNoRows) {
		return Quota{}, ErrNotFound
	}
	if err != nil {
		return Quota{}, fmt.Errorf("db: квота: %w", err)
	}

	total, err := s.NetworkTrafficOf(ctx, hash)
	if err != nil {
		return Quota{}, err
	}
	used := total.BytesIn + total.BytesOut

	// Счётчик ушёл ниже базы — узел явно потерял свою историю (переустановка,
	// восстановление из старого снимка). Отрицательного расхода быть не должно,
	// поэтому просто опускаем базу: клиент не виноват в чужой аварии.
	if used < base {
		base = used
		if err := s.setTrafficBase(ctx, hash, base, resetAt); err != nil {
			return Quota{}, err
		}
	}

	if q.PeriodDays > 0 {
		next := time.Unix(0, resetAt)
		if resetAt == 0 {
			// Первое обращение: период стартует сейчас.
			next = time.Now().Add(time.Duration(q.PeriodDays) * 24 * time.Hour)
			base = used
			if err := s.setTrafficBase(ctx, hash, base, next.UnixNano()); err != nil {
				return Quota{}, err
			}
		} else if now := time.Now(); now.After(next) {
			// Период кончился: счётчик начинается заново от текущего итога.
			//
			// Сколько периодов пропущено, считаем арифметикой, а не циклом с
			// проверкой «пока в прошлом»: время внутри такого цикла успевает
			// уйти вперёд, и граничный случай оставлял бы срок сброса ровно в
			// прошлом. Плюс при годовом простое и суточном периоде это был бы
			// цикл на сотни итераций.
			period := time.Duration(q.PeriodDays) * 24 * time.Hour
			missed := now.Sub(next)/period + 1
			next = next.Add(missed * period)
			base = used
			if err := s.setTrafficBase(ctx, hash, base, next.UnixNano()); err != nil {
				return Quota{}, err
			}
		}
		q.ResetAt = next
	}

	q.Used = used - base
	if q.Used < 0 {
		q.Used = 0
	}
	return q, nil
}

func (s *SQLite) setTrafficBase(ctx context.Context, hash string, base, resetAt int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE tokens SET traffic_base = ?, traffic_reset_at = ?, updated_at = ?
		  WHERE hash = ?`, base, resetAt, time.Now().UnixNano(), hash)
	if err != nil {
		return fmt.Errorf("db: сброс периода: %w", err)
	}
	return nil
}

// SetTrafficLimit задаёт предел и длину периода. 0/0 — снять ограничение.
func (s *SQLite) SetTrafficLimit(ctx context.Context, hash string, limit int64, periodDays int) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE tokens SET limit_traffic = ?, traffic_period = ?, updated_at = ?
		  WHERE hash = ?`, limit, periodDays, time.Now().UnixNano(), hash)
	if err != nil {
		return fmt.Errorf("db: лимит трафика: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ResetTraffic начинает период заново прямо сейчас.
//
// Нужен администратору: клиент оплатил продление посреди периода, и ждать
// автоматического сброса неправильно.
func (s *SQLite) ResetTraffic(ctx context.Context, hash string) error {
	total, err := s.NetworkTrafficOf(ctx, hash)
	if err != nil {
		return err
	}
	var days int
	if err := s.db.QueryRowContext(ctx,
		`SELECT traffic_period FROM tokens WHERE hash = ?`, hash).Scan(&days); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("db: сброс трафика: %w", err)
	}
	var resetAt int64
	if days > 0 {
		resetAt = time.Now().Add(time.Duration(days) * 24 * time.Hour).UnixNano()
	}
	return s.setTrafficBase(ctx, hash, total.BytesIn+total.BytesOut, resetAt)
}
