package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"quicdiver/internal/client/config"
	"quicdiver/internal/client/routing"
)

var (
	mu          sync.Mutex
	activeEngine *Engine
)

// Engine — контекст локального мобильного стека QUIC Diver для Android/iOS.
type Engine struct {
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	tunFile   *os.File
	server    string
	token     string
	router    *routing.Router
	bytesIn   uint64
	bytesOut  uint64
	startedAt time.Time
}

// MobileStatus — JSON структура текущего статуса для отображения в Android UI.
type MobileStatus struct {
	Connected  bool   `json:"connected"`
	Server     string `json:"server"`
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	UptimeSec  int64  `json:"uptime_sec"`
	LastError  string `json:"last_error,omitempty"`
}

// StartEngine открывает мобильный стек QUIC Diver поверх файлового дескриптора TUN Android VpnService.
func StartEngine(tunFd int, serverAddr string, token string, rulesRaw string) error {
	mu.Lock()
	defer mu.Unlock()

	if activeEngine != nil {
		return errors.New("мобильный движок уже запущен")
	}

	if tunFd <= 0 {
		return errors.New("невалидный файловый дескриптор TUN")
	}

	if strings.TrimSpace(serverAddr) == "" {
		return errors.New("адрес узла не может быть пустым")
	}

	tunFile := os.NewFile(uintptr(tunFd), "tun")
	if tunFile == nil {
		return errors.New("не удалось обернуть файловый дескриптор TUN")
	}

	ctx, cancel := context.WithCancel(context.Background())

	rules, err := routing.ParseRules(rulesRaw)
	if err != nil {
		rules = nil
	}
	r := routing.NewRouter(routing.Compile(rules, "direct"))

	eng := &Engine{
		ctx:       ctx,
		cancel:    cancel,
		tunFile:   tunFile,
		server:    serverAddr,
		token:     token,
		router:    r,
		startedAt: time.Now(),
	}

	activeEngine = eng

	// Запускаем фоновый цикл обработки пакетов из TUN
	go eng.packetLoop()

	log.Printf("[mobile] Движок QUIC Diver запущен поверх TUN fd=%d к узлу %s", tunFd, serverAddr)
	return nil
}

// StopEngine останавливает мобильный движок и закрывает сокет TUN.
func StopEngine() error {
	mu.Lock()
	defer mu.Unlock()

	if activeEngine == nil {
		return nil
	}

	activeEngine.cancel()
	_ = activeEngine.tunFile.Close()
	activeEngine = nil

	log.Println("[mobile] Мобильный движок QUIC Diver остановлен")
	return nil
}

// UpdateRules динамически обновляет правила роутинга на лету без перезапуска VPN.
func UpdateRules(rulesRaw string) error {
	mu.Lock()
	defer mu.Unlock()

	if activeEngine == nil {
		return errors.New("мобильный движок не запущен")
	}

	rules, err := routing.ParseRules(rulesRaw)
	if err != nil {
		return fmt.Errorf("ошибка парсинга правил: %w", err)
	}

	activeEngine.router.Swap(routing.Compile(rules, "direct"))
	log.Println("[mobile] Правила маршрутизации успешно обновлены в памяти")
	return nil
}

// GetStatus возвращает JSON-строку с метриками и состоянием соединения для Android UI.
func GetStatus() string {
	mu.Lock()
	defer mu.Unlock()

	if activeEngine == nil {
		data, _ := json.Marshal(MobileStatus{Connected: false})
		return string(data)
	}

	activeEngine.mu.Lock()
	st := MobileStatus{
		Connected: true,
		Server:    activeEngine.server,
		BytesIn:   activeEngine.bytesIn,
		BytesOut:  activeEngine.bytesOut,
		UptimeSec: int64(time.Since(activeEngine.startedAt).Seconds()),
	}
	activeEngine.mu.Unlock()

	data, _ := json.Marshal(st)
	return string(data)
}

// ImportBundle парсит подписочную ссылку qd:// и возвращает JSON конфигурацию.
func ImportBundle(link string) (string, error) {
	bundle, err := config.ParseBundle(link)
	if err != nil {
		return "", fmt.Errorf("битая ссылка подписки: %w", err)
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (e *Engine) packetLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-e.ctx.Done():
			return
		default:
			n, err := e.tunFile.Read(buf)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
					return
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}

			if n > 0 {
				e.mu.Lock()
				e.bytesOut += uint64(n)
				e.mu.Unlock()
			}
		}
	}
}
