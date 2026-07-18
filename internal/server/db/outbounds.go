package db

import (
	"context"
	"fmt"
	"time"
)

// Outbound types.
const (
	OutDirect = "direct"
	OutChain  = "chain"
)

// OutboundRow — запись о выходе узла (мета; живой Dialer строит server-слой).
type OutboundRow struct {
	ID        int64
	Label     string
	Type      string // direct | chain
	Addr      string // chain: host:port
	Authority string // chain: authority
	Token     string // chain: node-токен (секрет)
	Enabled   bool
}

// ListOutbounds возвращает включённые выходы, по label (стабильный порядок для
// нарезки подсетей).
func (s *SQLite) ListOutbounds(ctx context.Context) ([]OutboundRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, label, type, addr, authority, token, enabled
		FROM outbounds WHERE enabled = 1 ORDER BY label`)
	if err != nil {
		return nil, fmt.Errorf("db: список выходов: %w", err)
	}
	defer rows.Close()
	var out []OutboundRow
	for rows.Next() {
		var o OutboundRow
		var en int
		if err := rows.Scan(&o.ID, &o.Label, &o.Type, &o.Addr, &o.Authority, &o.Token, &en); err != nil {
			return nil, err
		}
		o.Enabled = en == 1
		out = append(out, o)
	}
	return out, rows.Err()
}

// PutOutbound добавляет или обновляет выход по label. chain обязан нести addr;
// direct — нет.
func (s *SQLite) PutOutbound(ctx context.Context, o OutboundRow) error {
	switch o.Type {
	case OutDirect:
	case OutChain:
		if o.Addr == "" {
			return fmt.Errorf("db: chain-выход %q без addr", o.Label)
		}
	default:
		return fmt.Errorf("db: неизвестный тип выхода %q", o.Type)
	}
	if o.Label == "" {
		return fmt.Errorf("db: выход без label")
	}
	en := 0
	if o.Enabled {
		en = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO outbounds(label, type, addr, authority, token, enabled, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(label) DO UPDATE SET
			type=excluded.type, addr=excluded.addr, authority=excluded.authority,
			token=excluded.token, enabled=excluded.enabled, updated_at=excluded.updated_at`,
		o.Label, o.Type, o.Addr, o.Authority, o.Token, en, time.Now().UnixNano())
	if err != nil {
		return fmt.Errorf("db: сохранить выход: %w", err)
	}
	return nil
}

// DeleteOutbound удаляет выход по label.
func (s *SQLite) DeleteOutbound(ctx context.Context, label string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM outbounds WHERE label = ?`, label)
	if err != nil {
		return fmt.Errorf("db: удалить выход: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
