//go:build !windows

package main

import (
	"context"
	"errors"
)

// run на не-Windows пока не реализован (нужен TUN + платформенный sysproxy).
func run(ctx context.Context, o options) error {
	return errors.New("qd-client: боевой захват реализован только на Windows (WinDivert)")
}

// ensureElevated/holdOnExit — оба про повадки Windows: подъём прав для загрузки
// драйвера и удержание окна консоли, чтобы при запуске двойным кликом было
// видно причину выхода. На прочих системах пусто, но объявить обязаны — иначе
// клиент не собирается под них вовсе.
func ensureElevated() {}

func holdOnExit() {}
