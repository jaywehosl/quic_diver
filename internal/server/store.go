package server

import "quicdiver/internal/server/db"

// sqliteOf разворачивает хранилище до конкретной базы.
//
// Store бывает обёрткой с горячей подменой (db.Live): реплика применяет снимок
// мастера, не перезапуская узел, — иначе рестарт каждые несколько минут рвал бы
// все туннели. Разворачивать нужно НА КАЖДОМ обращении: сохранённый указатель
// после подмены смотрел бы в снятую с эксплуатации копию, которая вот-вот
// закроется.
func sqliteOf(store db.Store) (*db.SQLite, bool) {
	switch s := store.(type) {
	case *db.SQLite:
		return s, true
	case interface{ DB() *db.SQLite }:
		return s.DB(), true
	}
	return nil, false
}
