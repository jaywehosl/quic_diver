package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// CircularLogger — логгер с цикличной ротацией по предельному размеру файла.
type CircularLogger struct {
	mu     sync.Mutex
	file   *os.File
	path   string
	maxBytes int64
	curBytes int64
}

// SetupLogging настраивает файловый логгер с ротацией по размеру (MaxMB).
func SetupLogging(cfg Logging) error {
	if !cfg.Enabled {
		log.SetOutput(os.Stderr)
		return nil
	}

	dir, err := Dir()
	if err != nil {
		return err
	}
	logPath := filepath.Join(dir, "client.log")
	maxBytes := int64(cfg.MaxMB) * 1024 * 1024
	if maxBytes <= 0 {
		maxBytes = 1024 * 1024 // 1 МБ по умолчанию
	}

	cl, err := newCircularLogger(logPath, maxBytes)
	if err != nil {
		return err
	}
	log.SetOutput(cl)
	log.Printf("logger: активировано файловое логирование (макс %d МБ, уровень %s)", cfg.MaxMB, cfg.Level)
	return nil
}

func newCircularLogger(path string, maxBytes int64) (*CircularLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("logger open: %w", err)
	}
	info, err := f.Stat()
	var cur int64
	if err == nil {
		cur = info.Size()
	}

	return &CircularLogger{
		file:     f,
		path:     path,
		maxBytes: maxBytes,
		curBytes: cur,
	}, nil
}

func (c *CircularLogger) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.curBytes+int64(len(p)) > c.maxBytes {
		// Цикличная срезка: обрезаем файл до начала при достижении 1 МБ
		_ = c.file.Close()
		f, err := os.OpenFile(c.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return 0, err
		}
		c.file = f
		c.curBytes = 0
	}

	n, err = c.file.Write(p)
	c.curBytes += int64(n)
	return n, err
}
