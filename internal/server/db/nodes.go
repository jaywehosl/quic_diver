package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Категории узла. Задаёт администратор; на них строятся правила и балансировка.
const (
	// CategoryEntry — входной узел: к нему подключаются клиенты.
	CategoryEntry = "entry"
	// CategoryExit — выходной узел: с него трафик уходит наружу.
	CategoryExit = "exit"
)

// Node — узел сети.
//
// Секрета здесь нет: TokenHash — хеш node-токена узла, сам токен остаётся только
// у него. Поэтому запись безопасно реплицировать на всю сеть.
type Node struct {
	ID        string    `json:"id"`
	Label     string    `json:"label,omitempty"`
	Category  string    `json:"category,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	Addr      string    `json:"addr,omitempty"`
	SNI       string    `json:"sni,omitempty"`
	TokenHash string    `json:"-"` // наружу не отдаём даже хеш
	Enabled   bool      `json:"enabled"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Authority — имя для TLS и :authority при подключении к узлу.
//
// Отдельно от Addr намеренно: адрес может быть голым IP, а имя — настоящим
// доменом. Тогда сертификат валиден, DNS в подключении не участвует, и
// блокировка домена обходится.
func (n Node) Authority() string {
	if n.SNI != "" {
		return n.SNI
	}
	host, _, err := splitHostPort(n.Addr)
	if err != nil {
		return n.Addr
	}
	return host
}

// HasTag — есть ли у узла такая метка (для auto:<тег>).
func (n Node) HasTag(tag string) bool {
	for _, t := range n.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

// ListNodes — все узлы сети.
func (s *SQLite) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, label, category, tags, addr, sni, token_hash, enabled, last_seen, updated_at
		 FROM nodes ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("db: узлы: %w", err)
	}
	defer rows.Close()

	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// NodeByID — один узел.
func (s *SQLite) NodeByID(ctx context.Context, id string) (Node, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, label, category, tags, addr, sni, token_hash, enabled, last_seen, updated_at
		 FROM nodes WHERE id = ?`, id)
	n, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	return n, err
}

// NodeByTokenHash — узел, предъявивший этот токен.
//
// Так сосед узнаёт, кто к нему пришёл: секрета у него нет, есть только хеши из
// реплики. Отключённый узел не признаётся — иначе выключение в панели ничего бы
// не значило для транзита.
func (s *SQLite) NodeByTokenHash(ctx context.Context, hash string) (Node, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, label, category, tags, addr, sni, token_hash, enabled, last_seen, updated_at
		 FROM nodes WHERE token_hash = ? AND enabled = 1`, hash)
	n, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	return n, err
}

// PutNode добавляет или обновляет узел.
func (s *SQLite) PutNode(ctx context.Context, n Node) error {
	enabled := 0
	if n.Enabled {
		enabled = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO nodes (id, label, category, tags, addr, sni, token_hash, enabled, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   label=excluded.label, category=excluded.category, tags=excluded.tags,
		   addr=excluded.addr, sni=excluded.sni, enabled=excluded.enabled,
		   -- хеш токена обновляем только если прислали непустой: правка метки не
		   -- должна отзывать доступ узлу.
		   token_hash=CASE WHEN excluded.token_hash <> '' THEN excluded.token_hash ELSE nodes.token_hash END,
		   updated_at=excluded.updated_at`,
		n.ID, n.Label, n.Category, strings.Join(n.Tags, ","), n.Addr, n.SNI,
		n.TokenHash, enabled, time.Now().UnixNano())
	if err != nil {
		return fmt.Errorf("db: сохранить узел: %w", err)
	}
	return nil
}

// TouchNode отмечает узел живым (heartbeat).
func (s *SQLite) TouchNode(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE nodes SET last_seen = ? WHERE id = ?`, time.Now().UnixNano(), id)
	return err
}

// DeleteNode убирает узел из сети.
func (s *SQLite) DeleteNode(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("db: удалить узел: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanNode(sc scanner) (Node, error) {
	var n Node
	var tags string
	var enabled int
	var lastSeen, updated int64
	if err := sc.Scan(&n.ID, &n.Label, &n.Category, &tags, &n.Addr, &n.SNI,
		&n.TokenHash, &enabled, &lastSeen, &updated); err != nil {
		return Node{}, err
	}
	n.Enabled = enabled != 0
	if tags != "" {
		n.Tags = strings.Split(tags, ",")
	}
	if lastSeen != 0 {
		n.LastSeen = time.Unix(0, lastSeen)
	}
	n.UpdatedAt = time.Unix(0, updated)
	return n, nil
}

// splitHostPort — обёртка, чтобы пакет не тянул net в шапку ради одной строки.
func splitHostPort(addr string) (string, string, error) { return net.SplitHostPort(addr) }
