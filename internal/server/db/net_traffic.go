package db

import (
	"context"
	"fmt"
	"time"
)

// NodeTraffic — сколько клиент прокачал через ОДИН узел.
//
// Структура ездит в обе стороны: узел отчитывается ею мастеру и она же уходит в
// панель. Поэтому token_hash обязан сериализоваться — без него отчёт приходит
// обезличенным, и мастеру некуда его записать. Секретом хеш не является:
// клиенты и так перечисляются по нему в admin-API.
type NodeTraffic struct {
	Node      string    `json:"node,omitempty"`
	TokenHash string    `json:"token_hash,omitempty"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	Updated   time.Time `json:"updated_at,omitempty"`
}

// ReportNodeTraffic принимает отчёт узла о расходе клиентов.
//
// Значения АБСОЛЮТНЫЕ, поэтому запись идёт заменой, а не сложением: повторно
// доставленный отчёт ничего не испортит, и узлу не нужно помнить, что он уже
// отослал. При обрыве связи он просто отчитается заново — итог сойдётся.
//
// Внешнего ключа на tokens здесь намеренно нет: отчёт приходит целиком, и один
// удалённый на мастере клиент не должен ронять весь пакет. Осиротевшие строки
// подчищаются тут же.
func (s *SQLite) ReportNodeTraffic(ctx context.Context, node string, rows []NodeTraffic) error {
	if node == "" {
		return fmt.Errorf("db: отчёт о трафике без узла")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("db: отчёт о трафике: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UnixNano()
	for _, r := range rows {
		if r.TokenHash == "" {
			continue
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO node_traffic (node_id, token_hash, bytes_in, bytes_out, updated_at)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(node_id, token_hash) DO UPDATE SET
			   bytes_in = excluded.bytes_in, bytes_out = excluded.bytes_out,
			   updated_at = excluded.updated_at`,
			node, r.TokenHash, r.BytesIn, r.BytesOut, now)
		if err != nil {
			return fmt.Errorf("db: отчёт о трафике: %w", err)
		}
	}
	// Клиентов, которых больше нет, в отчётах держать незачем.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM node_traffic WHERE token_hash NOT IN (SELECT hash FROM tokens)`); err != nil {
		return fmt.Errorf("db: уборка отчётов: %w", err)
	}
	return tx.Commit()
}

// NetworkTrafficOf — сколько клиент прокачал по ВСЕЙ сети.
//
// Сумма по узлам: каждый видит только свою долю, а лимит и панель оперируют
// общим расходом.
func (s *SQLite) NetworkTrafficOf(ctx context.Context, tokenHash string) (Traffic, error) {
	var t Traffic
	var in, out, upd *int64
	err := s.db.QueryRowContext(ctx,
		`SELECT SUM(bytes_in), SUM(bytes_out), MAX(updated_at)
		   FROM node_traffic WHERE token_hash = ?`, tokenHash).Scan(&in, &out, &upd)
	if err != nil {
		return Traffic{}, fmt.Errorf("db: сетевой трафик: %w", err)
	}
	// Ни одного отчёта — не ошибка: клиент ещё никуда не ходил.
	if in != nil {
		t.BytesIn = *in
	}
	if out != nil {
		t.BytesOut = *out
	}
	if upd != nil {
		t.Updated = time.Unix(0, *upd)
	}
	return t, nil
}

// NodeTrafficOf — расход клиента с разбивкой по узлам (для панели: видно, через
// какой узел он ходит).
func (s *SQLite) NodeTrafficOf(ctx context.Context, tokenHash string) ([]NodeTraffic, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT node_id, bytes_in, bytes_out, updated_at FROM node_traffic
		  WHERE token_hash = ? ORDER BY node_id`, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("db: трафик по узлам: %w", err)
	}
	defer rows.Close()

	var out []NodeTraffic
	for rows.Next() {
		var n NodeTraffic
		var upd int64
		if err := rows.Scan(&n.Node, &n.BytesIn, &n.BytesOut, &upd); err != nil {
			return nil, err
		}
		n.TokenHash, n.Updated = tokenHash, time.Unix(0, upd)
		out = append(out, n)
	}
	return out, rows.Err()
}

// LocalTrafficReport — что узел отчитывает мастеру: его собственные счётчики.
func (s *SQLite) LocalTrafficReport(ctx context.Context) ([]NodeTraffic, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT token_hash, bytes_in, bytes_out FROM traffic WHERE bytes_in > 0 OR bytes_out > 0`)
	if err != nil {
		return nil, fmt.Errorf("db: локальный трафик: %w", err)
	}
	defer rows.Close()

	var out []NodeTraffic
	for rows.Next() {
		var n NodeTraffic
		if err := rows.Scan(&n.TokenHash, &n.BytesIn, &n.BytesOut); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
