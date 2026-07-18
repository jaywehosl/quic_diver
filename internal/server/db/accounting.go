package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Device — устройство клиента (машина, с которой он подключается).
type Device struct {
	HWID      string    `json:"hwid"`
	Label     string    `json:"label,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	LastIP    string    `json:"last_ip,omitempty"`
	Revoked   bool      `json:"revoked,omitempty"`
}

// Session — активное подключение.
type Session struct {
	ID        string    `json:"id"`
	TokenHash string    `json:"token_hash"`
	HWID      string    `json:"hwid,omitempty"`
	RemoteIP  string    `json:"remote_ip,omitempty"`
	Node      string    `json:"node,omitempty"`
	StartedAt time.Time `json:"started_at"`
	LastSeen  time.Time `json:"last_seen"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
}

// Traffic — накопленный трафик клиента.
type Traffic struct {
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
	Updated  time.Time `json:"updated_at"`
}

// ErrDeviceLimit — у токена уже столько устройств, сколько разрешено.
var ErrDeviceLimit = errors.New("db: превышен лимит устройств")

// ErrDeviceRevoked — устройство отозвано администратором.
var ErrDeviceRevoked = errors.New("db: устройство отозвано")

// TouchDevice отмечает устройство живым, заводя его при первом появлении.
//
// Здесь же держится лимит: новое устройство сверх разрешённого не заводится, а
// уже известное пускается всегда — иначе смена IP выглядела бы как новая машина
// и выедала бы квоту.
func (s *SQLite) TouchDevice(ctx context.Context, tokenHash, hwid, ip string) error {
	if hwid == "" {
		return nil // клиент старой версии — учёт устройств не ведём
	}
	now := time.Now()

	var revoked int
	err := s.db.QueryRowContext(ctx,
		`SELECT revoked FROM devices WHERE token_hash = ? AND hwid = ?`, tokenHash, hwid).Scan(&revoked)
	switch {
	case err == nil:
		if revoked != 0 {
			return ErrDeviceRevoked
		}
		_, err = s.db.ExecContext(ctx,
			`UPDATE devices SET last_seen = ?, last_ip = ?, updated_at = ?
			 WHERE token_hash = ? AND hwid = ?`,
			now.UnixNano(), ip, now.UnixNano(), tokenHash, hwid)
		return err
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("db: устройство: %w", err)
	}

	// Новое устройство: проверяем лимит.
	var limit int
	if err := s.db.QueryRowContext(ctx,
		`SELECT limit_devices FROM tokens WHERE hash = ?`, tokenHash).Scan(&limit); err != nil {
		return fmt.Errorf("db: лимит устройств: %w", err)
	}
	if limit > 0 {
		var n int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM devices WHERE token_hash = ? AND revoked = 0`, tokenHash).Scan(&n); err != nil {
			return fmt.Errorf("db: счёт устройств: %w", err)
		}
		if n >= limit {
			return ErrDeviceLimit
		}
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO devices (token_hash, hwid, first_seen, last_seen, last_ip, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		tokenHash, hwid, now.UnixNano(), now.UnixNano(), ip, now.UnixNano())
	return err
}

// ListDevices — устройства токена.
func (s *SQLite) ListDevices(ctx context.Context, tokenHash string) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT hwid, label, first_seen, last_seen, last_ip, revoked
		 FROM devices WHERE token_hash = ? ORDER BY last_seen DESC`, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("db: устройства: %w", err)
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		var d Device
		var first, last, rev int64
		if err := rows.Scan(&d.HWID, &d.Label, &first, &last, &d.LastIP, &rev); err != nil {
			return nil, err
		}
		d.FirstSeen, d.LastSeen, d.Revoked = time.Unix(0, first), time.Unix(0, last), rev != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

// RevokeDevice закрывает устройству доступ, не трогая сам токен: у клиента могло
// увести одну машину, остальные должны продолжать работать.
func (s *SQLite) RevokeDevice(ctx context.Context, tokenHash, hwid string, revoked bool) error {
	v := 0
	if revoked {
		v = 1
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE devices SET revoked = ?, updated_at = ? WHERE token_hash = ? AND hwid = ?`,
		v, time.Now().UnixNano(), tokenHash, hwid)
	if err != nil {
		return fmt.Errorf("db: отзыв устройства: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ErrSessionLimit — у токена уже столько живых сессий, сколько разрешено.
var ErrSessionLimit = errors.New("db: превышен лимит одновременных сессий")

// OpenSession регистрирует подключение.
//
// Лимит сессий проверяется здесь, потому что hwid подделывается, а живое
// соединение — нет: даже с одинаковым отпечатком больше разрешённого числа
// сессий не открыть.
func (s *SQLite) OpenSession(ctx context.Context, sess Session, limitSessions int) error {
	if limitSessions > 0 {
		var n int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sessions WHERE token_hash = ?`, sess.TokenHash).Scan(&n); err != nil {
			return fmt.Errorf("db: счёт сессий: %w", err)
		}
		if n >= limitSessions {
			return ErrSessionLimit
		}
	}
	now := time.Now()
	if sess.StartedAt.IsZero() {
		sess.StartedAt = now
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO sessions (id, token_hash, hwid, remote_ip, node, started_at, last_seen, bytes_in, bytes_out)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)`,
		sess.ID, sess.TokenHash, sess.HWID, sess.RemoteIP, sess.Node,
		sess.StartedAt.UnixNano(), now.UnixNano())
	if err != nil {
		return fmt.Errorf("db: открыть сессию: %w", err)
	}
	return nil
}

// TouchSession продлевает сессию и добавляет трафик — и к ней, и к общему счёту
// клиента (тот обязан пережить обрыв и перезапуск узла).
func (s *SQLite) TouchSession(ctx context.Context, id, tokenHash string, deltaIn, deltaOut int64) error {
	now := time.Now().UnixNano()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen = ?, bytes_in = bytes_in + ?, bytes_out = bytes_out + ? WHERE id = ?`,
		now, deltaIn, deltaOut, id); err != nil {
		return fmt.Errorf("db: продлить сессию: %w", err)
	}
	if deltaIn == 0 && deltaOut == 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO traffic (token_hash, bytes_in, bytes_out, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(token_hash) DO UPDATE SET
		   bytes_in = bytes_in + excluded.bytes_in,
		   bytes_out = bytes_out + excluded.bytes_out,
		   updated_at = excluded.updated_at`,
		tokenHash, deltaIn, deltaOut, now)
	if err != nil {
		return fmt.Errorf("db: учёт трафика: %w", err)
	}
	return nil
}

// CloseSession снимает сессию с учёта.
func (s *SQLite) CloseSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// ListSessions — живые сессии; пустой tokenHash отдаёт все (для админа).
func (s *SQLite) ListSessions(ctx context.Context, tokenHash string) ([]Session, error) {
	q := `SELECT id, token_hash, hwid, remote_ip, node, started_at, last_seen, bytes_in, bytes_out FROM sessions`
	args := []any{}
	if tokenHash != "" {
		q += ` WHERE token_hash = ?`
		args = append(args, tokenHash)
	}
	q += ` ORDER BY started_at DESC`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("db: сессии: %w", err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var s Session
		var started, last int64
		if err := rows.Scan(&s.ID, &s.TokenHash, &s.HWID, &s.RemoteIP, &s.Node, &started, &last, &s.BytesIn, &s.BytesOut); err != nil {
			return nil, err
		}
		s.StartedAt, s.LastSeen = time.Unix(0, started), time.Unix(0, last)
		out = append(out, s)
	}
	return out, rows.Err()
}

// SweepSessions убирает сессии, о которых давно не слышно.
//
// Нужен, потому что узел может умереть, не закрыв их: без уборки «активные
// сессии» в панели превратились бы в кладбище, а лимит одновременных
// подключений заклинило бы навсегда.
func (s *SQLite) SweepSessions(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan).UnixNano()
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE last_seen < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("db: уборка сессий: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// TrafficOf — накопленный трафик клиента.
func (s *SQLite) TrafficOf(ctx context.Context, tokenHash string) (Traffic, error) {
	var t Traffic
	var upd int64
	err := s.db.QueryRowContext(ctx,
		`SELECT bytes_in, bytes_out, updated_at FROM traffic WHERE token_hash = ?`, tokenHash).
		Scan(&t.BytesIn, &t.BytesOut, &upd)
	if errors.Is(err, sql.ErrNoRows) {
		return Traffic{}, nil // ещё не ходил — не ошибка
	}
	if err != nil {
		return Traffic{}, fmt.Errorf("db: трафик: %w", err)
	}
	t.Updated = time.Unix(0, upd)
	return t, nil
}
