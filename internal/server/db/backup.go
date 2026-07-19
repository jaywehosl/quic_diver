package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Backup делает целостный снимок базы в файл.
//
// `VACUUM INTO` берёт снимок под транзакцией и включает всё, что лежит в WAL, —
// поэтому копировать сам файл базы недостаточно: в WAL-режиме основной файл
// может быть почти пустым, а свежие записи ещё не перенесены (наступали на это
// вживую). Заодно снимок выходит сжатым и без мусора страниц.
//
// Тот же снимок — заготовка репликации: узлам расходится ровно такой файл.
func (s *SQLite) Backup(ctx context.Context, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("db: папка снимка: %w", err)
	}
	// VACUUM INTO отказывается писать в существующий файл.
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("db: очистка места под снимок: %w", err)
	}
	// Путь подставляем литералом: VACUUM INTO не принимает параметр.
	// Кавычки внутри пути удваиваем, чтобы имя файла не могло сломать запрос.
	q := fmt.Sprintf("VACUUM INTO '%s'", strings.ReplaceAll(dst, "'", "''"))
	if _, err := s.db.ExecContext(ctx, q); err != nil {
		return fmt.Errorf("db: снимок: %w", err)
	}
	return nil
}

// Path — файл базы (для восстановления и диагностики).
func (s *SQLite) Path() string { return s.path }

// ErrNotSnapshot — файл не похож на нашу базу.
var ErrNotSnapshot = errors.New("db: файл не похож на базу QUIC Diver")

// ValidateSnapshot проверяет, что файл — целая база с нашей схемой.
//
// Обязательный шаг перед восстановлением: подсунутый мусор затёр бы рабочую
// базу, и узел остался бы без токенов, то есть без клиентов. Проверяем и
// целостность страниц, и наличие ключевых таблиц — битый файл с верным
// заголовком иначе прошёл бы.
func ValidateSnapshot(ctx context.Context, path string) error {
	sdb, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(3000)&mode=ro")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotSnapshot, err)
	}
	defer sdb.Close()

	var res string
	if err := sdb.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&res); err != nil {
		return fmt.Errorf("%w: %v", ErrNotSnapshot, err)
	}
	if res != "ok" {
		return fmt.Errorf("%w: повреждён (%s)", ErrNotSnapshot, res)
	}
	for _, table := range []string{"tokens", "assignments"} {
		var name string
		err := sdb.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: нет таблицы %s", ErrNotSnapshot, table)
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrNotSnapshot, err)
		}
	}
	return nil
}

// RestoreSuffix — расширение файла, приготовленного к восстановлению.
//
// Заменить открытую базу на ходу нельзя: часть соединений продолжила бы писать в
// старый файл. Поэтому снимок кладётся рядом, а подменяет его следующий запуск
// узла (см. ApplyPendingRestore) — это переживает и падение посередине.
const RestoreSuffix = ".restore"

// StageRestore кладёт проверенный снимок рядом с базой, чтобы его применил
// следующий запуск узла.
func StageRestore(ctx context.Context, dbPath, snapshot string) error {
	if err := ValidateSnapshot(ctx, snapshot); err != nil {
		return err
	}
	return os.Rename(snapshot, dbPath+RestoreSuffix)
}

// ApplyPendingRestore применяет отложенный снимок, если он есть. Вызывается на
// старте узла до открытия базы.
//
// Прежняя база не удаляется, а отодвигается в .prev: если в снимке окажется не
// то, у администратора остаётся способ вернуться.
func ApplyPendingRestore(dbPath string) (applied bool, err error) {
	pending := dbPath + RestoreSuffix
	if _, err := os.Stat(pending); os.IsNotExist(err) {
		return false, nil
	}
	if err := ValidateSnapshot(context.Background(), pending); err != nil {
		// Не трогаем рабочую базу и не поднимаемся молча: битый файл лучше
		// заметить в журнале, чем потерять клиентов.
		return false, err
	}
	if _, err := os.Stat(dbPath); err == nil {
		if err := os.Rename(dbPath, dbPath+".prev"); err != nil {
			return false, fmt.Errorf("db: отложить прежнюю базу: %w", err)
		}
	}
	// Хвосты WAL относятся к прежней базе — со снимком они несовместимы.
	for _, ext := range []string{"-wal", "-shm"} {
		_ = os.Remove(dbPath + ext)
	}
	if err := os.Rename(pending, dbPath); err != nil {
		return false, fmt.Errorf("db: применить снимок: %w", err)
	}
	return true, nil
}

// openRaw открывает файл как SQLite без нашей схемы (нужно тестам, чтобы
// изготовить «чужую» базу).
func openRaw(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path)
}
