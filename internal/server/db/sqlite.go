// Package db — персистентное хранилище узла на SQLite (один файл).
//
// Бэкап = копия файла, редеплой = restore (arch3). После переезда узла на новую
// VM с тем же доменом восстановленная БД возвращает токены — клиенты
// переподключаются после смены A-записи, ничего не меняя.
//
// Движок modernc.org/sqlite — чистый Go, без cgo: узел кросс-собирается под любую
// платформу одной командой.
//
// Схема заложена под будущую репликацию между узлами (arch2), хотя сейчас узел
// один:
//   - у каждой строки updated_at (версия по времени) — основа для отзыва и для
//     будущего разрешения конфликтов;
//   - удаление не физическое, а пометкой revoked + tombstone: иначе отзыв токена
//     не доехал бы до реплики (отсутствие строки не отличить от «ещё не пришла»).
//
// Кто пишет — вопрос репликации (single-writer против multi-master), решается при
// её постройке. Форма схемы совместима с обоими.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	_ "modernc.org/sqlite"

	"quicdiver/internal/server/auth"
)

// ErrNotFound — записи нет (или она отозвана).
var ErrNotFound = errors.New("db: не найдено")

// SQLite — хранилище узла.
type SQLite struct {
	db   *sql.DB
	path string
}

const schema = `
CREATE TABLE IF NOT EXISTS tokens (
	hash       TEXT PRIMARY KEY,          -- SHA-256 токена (открытого токена в БД нет)
	role       TEXT NOT NULL,             -- user | admin | node
	label      TEXT NOT NULL DEFAULT '',  -- человеко-читаемое имя (для панели)
	created_at INTEGER NOT NULL,          -- unix-наносекунды
	updated_at INTEGER NOT NULL,          -- версия строки (репликация/отзыв)
	revoked    INTEGER NOT NULL DEFAULT 0 -- tombstone: 1 = отозван
);
CREATE INDEX IF NOT EXISTS tokens_role ON tokens(role);

-- Адрес, назначаемый клиенту. Стабилен по токену, из пула узла.
CREATE TABLE IF NOT EXISTS assignments (
	token_hash TEXT PRIMARY KEY REFERENCES tokens(hash) ON DELETE CASCADE,
	addr       TEXT NOT NULL,             -- голый IP, напр. 10.7.0.5
	updated_at INTEGER NOT NULL
);
-- Один адрес — одному клиенту: страховка от гонки аллокатора на уровне схемы.
CREATE UNIQUE INDEX IF NOT EXISTS assignments_addr ON assignments(addr);
`

// Open открывает (создаёт) БД по пути и накатывает схему.
func Open(path string) (*SQLite, error) {
	// _pragma в DSN: WAL — конкурентное чтение при записи (репликация будет
	// читать под записью админа); busy_timeout — не падать на кратком локе;
	// foreign_keys — чтобы ON DELETE CASCADE работал.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", path)
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("открыть БД %s: %w", path, err)
	}
	// SQLite — один писатель; пул из многих коннектов на запись только плодит
	// «database is locked». Читателей WAL пускает параллельно и так.
	sdb.SetMaxOpenConns(1)
	if _, err := sdb.ExecContext(context.Background(), schema); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("схема: %w", err)
	}
	return &SQLite{db: sdb, path: path}, nil
}

// Close закрывает хранилище.
func (s *SQLite) Close() error { return s.db.Close() }

// TokenInfo — то, что узел знает о токене.
type TokenInfo struct {
	Role  auth.Role
	Label string
}

// PutToken добавляет/обновляет токен по его хешу (открытый токен сюда не попадает).
func (s *SQLite) PutToken(ctx context.Context, hash string, role auth.Role, label string) error {
	if !role.Valid() {
		return fmt.Errorf("db: неизвестная роль %q", role)
	}
	now := time.Now().UnixNano()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tokens(hash, role, label, created_at, updated_at, revoked)
		VALUES(?, ?, ?, ?, ?, 0)
		ON CONFLICT(hash) DO UPDATE SET role=excluded.role, label=excluded.label,
			updated_at=excluded.updated_at, revoked=0`,
		hash, string(role), label, now, now)
	if err != nil {
		return fmt.Errorf("db: сохранить токен: %w", err)
	}
	return nil
}

// Lookup возвращает роль токена по его хешу. Отозванный — как ненайденный.
//
// Горячий путь авторизации: вызывается на каждый коннект. Один индексированный
// SELECT по первичному ключу — дёшево; кеш добавим, если станет узким местом.
func (s *SQLite) Lookup(ctx context.Context, hash string) (TokenInfo, error) {
	var role, label string
	var revoked int
	err := s.db.QueryRowContext(ctx,
		`SELECT role, label, revoked FROM tokens WHERE hash = ?`, hash).
		Scan(&role, &label, &revoked)
	if errors.Is(err, sql.ErrNoRows) || revoked == 1 {
		return TokenInfo{}, ErrNotFound
	}
	if err != nil {
		return TokenInfo{}, fmt.Errorf("db: поиск токена: %w", err)
	}
	return TokenInfo{Role: auth.Role(role), Label: label}, nil
}

// Revoke помечает токен отозванным (tombstone, не удаляет строку — иначе отзыв
// не доехал бы до реплики).
func (s *SQLite) Revoke(ctx context.Context, hash string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE tokens SET revoked = 1, updated_at = ? WHERE hash = ?`,
		time.Now().UnixNano(), hash)
	if err != nil {
		return fmt.Errorf("db: отзыв токена: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetAssignment задаёт адрес, назначаемый клиенту.
func (s *SQLite) SetAssignment(ctx context.Context, hash, addr string) error {
	now := time.Now().UnixNano()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO assignments(token_hash, addr, updated_at) VALUES(?, ?, ?)
		ON CONFLICT(token_hash) DO UPDATE SET addr=excluded.addr, updated_at=excluded.updated_at`,
		hash, addr, now)
	if err != nil {
		return fmt.Errorf("db: назначить адрес: %w", err)
	}
	return nil
}

// ErrPoolExhausted — в пуле не осталось свободных адресов.
var ErrPoolExhausted = errors.New("db: пул адресов исчерпан")

// AllocateAddress возвращает адрес клиента по хешу токена, выделяя новый из пула
// при первом обращении.
//
// Адрес стабилен: тот же токен всегда получает тот же адрес — это нужно для
// роутинга по клиенту и осмысленных логов, и переживает переподключение и
// переезд на другой узел (адрес едет в реплике БД).
//
// Выделение атомарно (одна транзакция под single-writer'ом): читаем занятые,
// берём первый свободный, вставляем. UNIQUE(addr) страхует от гонки на уровне
// схемы, даже если аллокатор кто-то позовёт из другого процесса.
func (s *SQLite) AllocateAddress(ctx context.Context, hash string, pool netip.Prefix) (netip.Addr, error) {
	if !pool.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("db: пул должен быть IPv4, дан %s", pool)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	defer tx.Rollback() // no-op после Commit

	// уже назначен — вернуть тот же
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT addr FROM assignments WHERE token_hash=?`, hash).Scan(&existing)
	if err == nil {
		addr, perr := netip.ParseAddr(existing)
		if perr != nil {
			return netip.Addr{}, fmt.Errorf("db: битый адрес в БД: %q", existing)
		}
		return addr, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return netip.Addr{}, err
	}

	taken, err := takenAddrs(ctx, tx)
	if err != nil {
		return netip.Addr{}, err
	}
	addr, ok := firstFree(pool, taken)
	if !ok {
		return netip.Addr{}, ErrPoolExhausted
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO assignments(token_hash, addr, updated_at) VALUES(?, ?, ?)`,
		hash, addr.String(), time.Now().UnixNano()); err != nil {
		return netip.Addr{}, fmt.Errorf("db: выделить адрес: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

// takenAddrs — множество уже занятых адресов пула.
func takenAddrs(ctx context.Context, tx *sql.Tx) (map[netip.Addr]struct{}, error) {
	rows, err := tx.QueryContext(ctx, `SELECT addr FROM assignments`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	taken := make(map[netip.Addr]struct{})
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		if addr, err := netip.ParseAddr(a); err == nil {
			taken[addr] = struct{}{}
		}
	}
	return taken, rows.Err()
}

// firstFree — первый свободный адрес пула. Первые два (сеть и адрес узла-шлюза)
// пропускаются: .0 — сетевой, .1 держит сам узел.
func firstFree(pool netip.Prefix, taken map[netip.Addr]struct{}) (netip.Addr, bool) {
	pool = pool.Masked()
	addr := pool.Addr().Next() // .1
	addr = addr.Next()         // .2 — первый клиентский
	for pool.Contains(addr) {
		if _, busy := taken[addr]; !busy {
			return addr, true
		}
		addr = addr.Next()
	}
	return netip.Addr{}, false
}

// Assignment возвращает адрес клиента, если задан.
func (s *SQLite) Assignment(ctx context.Context, hash string) (string, error) {
	var addr string
	err := s.db.QueryRowContext(ctx,
		`SELECT addr FROM assignments WHERE token_hash = ?`, hash).Scan(&addr)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("db: адрес клиента: %w", err)
	}
	return addr, nil
}

// CountByRole — сколько живых (не отозванных) токенов каждой роли. Для панели.
func (s *SQLite) CountByRole(ctx context.Context) (map[auth.Role]int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT role, COUNT(*) FROM tokens WHERE revoked = 0 GROUP BY role`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[auth.Role]int)
	for rows.Next() {
		var role string
		var n int
		if err := rows.Scan(&role, &n); err != nil {
			return nil, err
		}
		out[auth.Role(role)] = n
	}
	return out, rows.Err()
}
