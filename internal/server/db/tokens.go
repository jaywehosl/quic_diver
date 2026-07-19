package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"quicdiver/internal/server/auth"
)

// TokenRow — полная строка токена для панели управления.
//
// Открытого токена здесь нет и быть не может: в базе лежит только хеш, поэтому
// показать доступ повторно нельзя — его показывают ровно один раз при выдаче.
type TokenRow struct {
	Hash          string
	Role          auth.Role
	Label         string
	CreatedAt     time.Time
	Revoked       bool
	LimitDevices  int
	LimitSessions int
	// LimitTraffic — предел трафика за период, байт. 0 — без ограничения.
	LimitTraffic int64
	// TrafficPeriod — длина периода в днях. 0 — лимит разовый.
	TrafficPeriod int
	ExpiresAt     time.Time // нулевое — бессрочно
}

// ListTokens — все токены узла, свежие сверху.
func (s *SQLite) ListTokens(ctx context.Context) ([]TokenRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT hash, role, label, created_at, revoked, limit_devices, limit_sessions, expires_at, limit_traffic, traffic_period
		 FROM tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("db: токены: %w", err)
	}
	defer rows.Close()

	var out []TokenRow
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TokenRowByHash — один токен со всеми полями.
func (s *SQLite) TokenRowByHash(ctx context.Context, hash string) (TokenRow, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT hash, role, label, created_at, revoked, limit_devices, limit_sessions, expires_at, limit_traffic, traffic_period
		 FROM tokens WHERE hash = ?`, hash)
	t, err := scanToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenRow{}, ErrNotFound
	}
	return t, err
}

// scanner — общий вид *sql.Row и *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

func scanToken(sc scanner) (TokenRow, error) {
	var t TokenRow
	var role string
	var created, expires int64
	var revoked int
	if err := sc.Scan(&t.Hash, &role, &t.Label, &created, &revoked,
		&t.LimitDevices, &t.LimitSessions, &expires,
		&t.LimitTraffic, &t.TrafficPeriod); err != nil {
		return TokenRow{}, err
	}
	t.Role, t.Revoked, t.CreatedAt = auth.Role(role), revoked != 0, time.Unix(0, created)
	if expires != 0 {
		t.ExpiresAt = time.Unix(0, expires)
	}
	return t, nil
}

// SetTokenLimits задаёт лимиты и срок действия. Нулевые значения означают «без
// ограничения» — так узел для своих не требует заводить лимиты вручную.
func (s *SQLite) SetTokenLimits(ctx context.Context, hash string, devices, sessions int, expires time.Time) error {
	var exp int64
	if !expires.IsZero() {
		exp = expires.UnixNano()
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE tokens SET limit_devices = ?, limit_sessions = ?, expires_at = ?, updated_at = ?
		 WHERE hash = ?`,
		devices, sessions, exp, time.Now().UnixNano(), hash)
	if err != nil {
		return fmt.Errorf("db: лимиты токена: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Expired — истёк ли срок действия токена.
func (t TokenRow) Expired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt)
}
