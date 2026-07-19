package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Локальные данные узла — то, что снимок мастера не содержит и содержать не
// может: узел наблюдает их сам.
//
//   - devices   — кто и с какой машины подключался ИМЕННО СЮДА;
//   - sessions  — живые подключения этого узла;
//   - traffic   — счётчик, который обязан пережить и обрыв, и подмену базы.
//
// Всё остальное (tokens, assignments, nodes, cluster) принадлежит мастеру и
// приезжает снимком целиком.
//
// Без переноса реплика теряла бы весь учёт каждые несколько минут — ровно с той
// частотой, с какой тянет обновления.
func carryLocal(ctx context.Context, dst, src string) error {
	sdb, err := sql.Open("sqlite", "file:"+dst+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return fmt.Errorf("db: перенос локальных данных: %w", err)
	}
	defer sdb.Close()
	sdb.SetMaxOpenConns(1)

	// Путь литералом: ATTACH не принимает параметр. Кавычки удваиваем, чтобы имя
	// файла не могло сломать запрос.
	attach := fmt.Sprintf("ATTACH DATABASE '%s' AS prev", strings.ReplaceAll(src, "'", "''"))
	if _, err := sdb.ExecContext(ctx, attach); err != nil {
		return fmt.Errorf("db: подключить прежнюю базу: %w", err)
	}
	defer sdb.ExecContext(ctx, "DETACH DATABASE prev")

	for _, q := range carryQueries {
		// Строки, чей токен мастер уже отозвал, отсеет внешний ключ — и это
		// верно: клиента больше нет, тащить его учёт в свежую базу незачем.
		if _, err := sdb.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("db: перенос локальных данных: %w", err)
		}
	}
	return nil
}

var carryQueries = []string{
	// Устройства: наблюдение — наше, а вот revoked ставит администратор на
	// мастере. Поэтому чужие строки не трогаем, а свои добавляем.
	`INSERT OR IGNORE INTO devices
	   (token_hash, hwid, label, first_seen, last_seen, last_ip, revoked, updated_at)
	 SELECT token_hash, hwid, label, first_seen, last_seen, last_ip, revoked, updated_at
	   FROM prev.devices
	  WHERE token_hash IN (SELECT hash FROM main.tokens)`,
	// ...и подтягиваем время последней встречи, если локально оно свежее.
	// Отзыв при этом остаётся мастерский — снимать его мы не вправе.
	`UPDATE devices SET
	   last_seen = (SELECT p.last_seen FROM prev.devices p
	                 WHERE p.token_hash = devices.token_hash AND p.hwid = devices.hwid),
	   last_ip   = (SELECT p.last_ip   FROM prev.devices p
	                 WHERE p.token_hash = devices.token_hash AND p.hwid = devices.hwid)
	 WHERE EXISTS (SELECT 1 FROM prev.devices p
	                WHERE p.token_hash = devices.token_hash AND p.hwid = devices.hwid
	                  AND p.last_seen > devices.last_seen)`,

	// Живые сессии: обрыв туннелей при подмене — как раз то, чего мы избегаем,
	// поэтому они обязаны пережить её вместе с соединениями.
	`INSERT OR IGNORE INTO sessions
	   (id, token_hash, hwid, remote_ip, node, started_at, last_seen, bytes_in, bytes_out)
	 SELECT id, token_hash, hwid, remote_ip, node, started_at, last_seen, bytes_in, bytes_out
	   FROM prev.sessions
	  WHERE token_hash IN (SELECT hash FROM main.tokens)`,

	// Счётчик трафика: берём больший из двух. Мастер про наш расход пока не
	// знает, но когда узлы начнут досылать итоги ему, снимок окажется полнее
	// локального — и затирать его меньшим числом нельзя.
	`INSERT INTO traffic (token_hash, bytes_in, bytes_out, updated_at)
	 SELECT token_hash, bytes_in, bytes_out, updated_at FROM prev.traffic
	  WHERE token_hash IN (SELECT hash FROM main.tokens)
	 ON CONFLICT(token_hash) DO UPDATE SET
	   bytes_in  = MAX(traffic.bytes_in,  excluded.bytes_in),
	   bytes_out = MAX(traffic.bytes_out, excluded.bytes_out),
	   updated_at = MAX(traffic.updated_at, excluded.updated_at)`,
}
