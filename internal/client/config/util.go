package config

import (
	"net"
	"runtime"
)

func splitHostPort(addr string) (string, string, error) { return net.SplitHostPort(addr) }

// isWindows — на Windows права файла в unix-смысле не действуют, и Chmod там
// возвращает ошибку не всегда осмысленно; ограничение доступа даёт ACL папки.
func isWindows() bool { return runtime.GOOS == "windows" }
