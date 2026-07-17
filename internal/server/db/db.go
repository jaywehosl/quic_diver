// Package db — персистентное хранилище узла.
//
// Реализация — SQLite (sqlite.go). Этот файл держит контракт: слои узла зависят
// от интерфейса, а не от движка, чтобы его можно было подменить (напр. на
// реплицируемый бэкенд) без правок вызывающих.
package db

import "context"

// Store — контракт хранилища узла.
type Store interface {
	// Lookup — роль токена по хешу (горячий путь авторизации). Отозванный токен
	// возвращает ErrNotFound.
	Lookup(ctx context.Context, hash string) (TokenInfo, error)
	// Assignment — адрес, назначенный клиенту (пустой + ErrNotFound, если нет).
	Assignment(ctx context.Context, hash string) (string, error)
	// Close закрывает хранилище.
	Close() error
}

var _ Store = (*SQLite)(nil)
