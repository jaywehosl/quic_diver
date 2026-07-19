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

-- Выходы узла (arch: роутинг/цепочки). direct — выход в реальную сеть; chain —
-- через upstream-узел (addr/authority/token — куда и чем авторизоваться).
--
-- token тут ОТКРЫТЫЙ (node-токен, узел предъявляет его upstream'у) — это секрет
-- узла, в отличие от клиентских токенов (только хеш). Поэтому outbounds
-- локальны узлу и НЕ реплицируются: расходятся по сети хеши клиентских токенов,
-- а секреты выходов у каждого узла свои.
CREATE TABLE IF NOT EXISTS outbounds (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	label      TEXT UNIQUE NOT NULL,        -- метка (Qd-Route / подсеть выхода)
	type       TEXT NOT NULL,               -- direct | chain
	addr       TEXT NOT NULL DEFAULT '',    -- chain: host:port upstream-узла
	authority  TEXT NOT NULL DEFAULT '',    -- chain: authority upstream-узла
	token      TEXT NOT NULL DEFAULT '',    -- chain: node-токен (секрет)
	enabled    INTEGER NOT NULL DEFAULT 1,
	updated_at INTEGER NOT NULL
);

-- Состояние кластера: кто мастер и какого он поколения.
--
-- Поколение (epoch) — защита от split-brain. Мастер пишет БД, реплики только
-- читают. Когда мастер лёг и админ поднял на его месте другой узел, тот берёт
-- epoch+1. Правило: узел, увидевший поколение выше своего, немедленно уходит в
-- read-only, а вернувшийся старый мастер сам себя демотирует. Без этого два
-- мастера писали бы расходящиеся базы, и слить их потом нельзя.
--
-- Строка ровно одна (id=1).
CREATE TABLE IF NOT EXISTS cluster (
	id         INTEGER PRIMARY KEY CHECK (id = 1),
	epoch      INTEGER NOT NULL DEFAULT 1,
	master_id  TEXT NOT NULL DEFAULT '',   -- идентификатор узла-мастера
	updated_at INTEGER NOT NULL DEFAULT 0
);

-- Узлы сети. Реплицируется целиком: каждый узел знает всех соседей и может
-- принимать клиентов и вести транзит без ручной настройки связей.
--
-- Секретов здесь НЕТ. token_hash — хеш node-токена узла, а сам токен остаётся
-- только у него: подключаясь к соседу, узел предъявляет СВОЙ токен, а сосед
-- проверяет его по этому хешу. Поэтому утечка одного узла не даёт доступа к
-- остальным (общий node-токен на всю сеть — давал), и копировать секреты между
-- узлами не нужно.
CREATE TABLE IF NOT EXISTS nodes (
	id         TEXT PRIMARY KEY,            -- идентификатор узла (обычно его домен)
	label      TEXT NOT NULL DEFAULT '',    -- человеческое имя для панели
	category   TEXT NOT NULL DEFAULT '',    -- entry | exit (задаёт админ)
	tags       TEXT NOT NULL DEFAULT '',    -- через запятую; для глаз и для auto:<тег>
	addr       TEXT NOT NULL DEFAULT '',    -- host:port для подключения
	sni        TEXT NOT NULL DEFAULT '',    -- имя для TLS/:authority (может быть иным, чем addr)
	token_hash TEXT NOT NULL DEFAULT '',    -- хеш node-токена ЭТОГО узла
	enabled    INTEGER NOT NULL DEFAULT 1,
	last_seen  INTEGER NOT NULL DEFAULT 0,  -- heartbeat: когда узел давал о себе знать
	updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nodes_category ON nodes(category);

-- Устройства клиента. Против шаринга токена: их число ограничено (limit_devices
-- у токена), лишние админ отзывает поимённо.
--
-- hwid считает КЛИЕНТ, поэтому пропатченный клиент его подделает — это заслон от
-- бытового шаринга, а не защита. Настоящий предел ставит учёт сессий ниже.
CREATE TABLE IF NOT EXISTS devices (
	token_hash TEXT NOT NULL REFERENCES tokens(hash) ON DELETE CASCADE,
	hwid       TEXT NOT NULL,               -- отпечаток машины, считает клиент
	label      TEXT NOT NULL DEFAULT '',    -- имя от пользователя (для панели)
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	last_ip    TEXT NOT NULL DEFAULT '',
	revoked    INTEGER NOT NULL DEFAULT 0,  -- tombstone: не пускать это устройство
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (token_hash, hwid)
);
CREATE INDEX IF NOT EXISTS devices_token ON devices(token_hash);

-- Активные сессии: кто подключён прямо сейчас и с какого адреса. Живут недолго,
-- их чистит узел; нужны для «показать активные сессии» и для лимита по IP,
-- который работает даже с подделанным hwid.
CREATE TABLE IF NOT EXISTS sessions (
	id         TEXT PRIMARY KEY,            -- случайный идентификатор сессии
	token_hash TEXT NOT NULL REFERENCES tokens(hash) ON DELETE CASCADE,
	hwid       TEXT NOT NULL DEFAULT '',
	remote_ip  TEXT NOT NULL DEFAULT '',
	node       TEXT NOT NULL DEFAULT '',    -- какой узел обслуживает (для сети нод)
	started_at INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	bytes_in   INTEGER NOT NULL DEFAULT 0,
	bytes_out  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_token ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS sessions_seen ON sessions(last_seen);

-- Накопленный трафик по клиенту. Отдельно от сессий: те приходят и уходят, а
-- счётчик обязан пережить и обрыв, и перезапуск узла.
CREATE TABLE IF NOT EXISTS traffic (
	token_hash TEXT PRIMARY KEY REFERENCES tokens(hash) ON DELETE CASCADE,
	bytes_in   INTEGER NOT NULL DEFAULT 0,
	bytes_out  INTEGER NOT NULL DEFAULT 0,
	updated_at INTEGER NOT NULL
);
`

// migrations — доводка схемы на уже существующих БД. ALTER TABLE в SQLite не
// умеет IF NOT EXISTS, поэтому ошибку «столбец уже есть» глотаем: гонять этот
// список на каждом старте безопасно.
var migrations = []string{
	// Сколько устройств разрешено токену. 0 — без ограничения.
	`ALTER TABLE tokens ADD COLUMN limit_devices INTEGER NOT NULL DEFAULT 0`,
	// Предел одновременных сессий. Работает даже там, где hwid подделан.
	`ALTER TABLE tokens ADD COLUMN limit_sessions INTEGER NOT NULL DEFAULT 0`,
	// До какого момента токен действителен (unix-наносекунды, 0 — бессрочно).
	`ALTER TABLE tokens ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0`,
}

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
	// Доводка старых БД. Ошибки глотаем осознанно: единственная ожидаемая — это
	// «столбец уже существует» на свежей базе, а падать из-за неё нельзя, иначе
	// узел не поднимется после обновления.
	for _, m := range migrations {
		_, _ = sdb.ExecContext(context.Background(), m)
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
