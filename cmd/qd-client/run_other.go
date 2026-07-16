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
