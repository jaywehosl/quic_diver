// Package db — персистентное хранилище узла.
//
// Реализация — SQLite (sqlite.go). Этот файл держит контракт: слои узла зависят
// от интерфейса, а не от движка, чтобы его можно было подменить (напр. на
// реплицируемый бэкенд) без правок вызывающих.
package db

import (
	"context"
	"net/netip"
)

// Store — контракт хранилища узла.
type Store interface {
	// Lookup — роль токена по хешу (горячий путь авторизации). Отозванный токен
	// возвращает ErrNotFound.
	Lookup(ctx context.Context, hash string) (TokenInfo, error)
	// Assignment — адрес, назначенный клиенту (пустой + ErrNotFound, если нет).
	Assignment(ctx context.Context, hash string) (string, error)
	// AllocateAddress — стабильный адрес клиента из пула по хешу токена (выделяет
	// при первом обращении). ErrPoolExhausted, если свободных нет.
	AllocateAddress(ctx context.Context, hash string, pool netip.Prefix) (netip.Addr, error)
	// Close закрывает хранилище.
	Close() error
}

var _ Store = (*SQLite)(nil)
