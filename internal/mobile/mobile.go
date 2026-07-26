// Package mobile — адаптер QUIC Diver для Android (gomobile / Go-mobile).
//
// Интегрирует Android VpnService через файловый дескриптор TUN (fd) с движком
// connectip (модель B) и локальным/серверным netstack stack.
package mobile

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yosida95/uritemplate/v3"

	"quicdiver/internal/client/config"
	"quicdiver/internal/client/routing"
	"quicdiver/internal/engine/connectip"
	"quicdiver/internal/guard"
	"quicdiver/internal/packet"
	"quicdiver/internal/server/netstack"
	"quicdiver/internal/transport/cip"
)

// StatusInfo — снимок состояния адаптера для передачи на Android (JSON).
type StatusInfo struct {
	State         string `json:"state"`
	Since         string `json:"since"`
	Attempts      int    `json:"attempts"`
	LastError     string `json:"last_error,omitempty"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
	ActiveRules   int    `json:"active_rules"`
}

type mobileAdapter struct {
	mu        sync.Mutex
	running   bool
	ctx       context.Context
	cancel    context.CancelFunc
	cfg       config.Config
	router    *routing.Router
	guard     *guard.Guard
	tunSource packet.Source
	cipClient *cip.Client
	state     string
	since     time.Time
	attempts  int
	lastErr   string
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
}

var (
	adapterLock   sync.Mutex
	globalAdapter *mobileAdapter
)

// StartEngine запускает обработку трафика TUN устройства.
//
//   - fd: файловый дескриптор TUN устройства от Android VpnService.
//   - configJSON: JSON-конфигурация или ссылка-бандл (qd://...).
func StartEngine(fd int, configJSON string) error {
	adapterLock.Lock()
	defer adapterLock.Unlock()

	if globalAdapter != nil && globalAdapter.running {
		_ = stopEngineLocked()
	}

	var cfg config.Config
	configJSON = strings.TrimSpace(configJSON)

	if strings.HasPrefix(strings.ToLower(configJSON), config.BundleScheme) {
		bundle, err := config.ParseBundle(configJSON)
		if err != nil {
			return fmt.Errorf("mobile: parse bundle: %w", err)
		}
		cfg = config.Default()
		cfg.Apply(bundle)
	} else if configJSON != "" && configJSON != "{}" {
		cfg = config.Default()
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return fmt.Errorf("mobile: unmarshal config: %w", err)
		}
	} else {
		cfg = config.Default()
	}

	if fd < 0 {
		return ErrInvalidFD
	}

	tunSource, err := NewFDSource(fd, cfg.Transport.MTU)
	if err != nil {
		return fmt.Errorf("mobile: create fd source: %w", err)
	}

	var rules []routing.Rule
	if len(cfg.Routing.Rules) > 0 {
		rulesStr := strings.Join(cfg.Routing.Rules, "\n")
		parsedRules, err := routing.ParseRules(rulesStr)
		if err == nil {
			rules = parsedRules
		}
	}
	rs := routing.Compile(rules, cfg.Routing.Default)
	router := routing.NewRouter(rs)

	var serverIPs []netip.Addr
	for _, entry := range cfg.Node.Entries {
		host, _, err := net.SplitHostPort(entry.Addr)
		if err != nil {
			host = entry.Addr
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			serverIPs = append(serverIPs, ip)
		}
	}
	g := guard.New(serverIPs)
	for _, b := range cfg.Capture.Bypass {
		if p, err := netip.ParsePrefix(b); err == nil {
			g.AddBypass(p)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	a := &mobileAdapter{
		running:   true,
		ctx:       ctx,
		cancel:    cancel,
		cfg:       cfg,
		router:    router,
		guard:     g,
		tunSource: tunSource,
		state:     "connecting",
		since:     time.Now(),
	}

	globalAdapter = a
	go a.runEngineWorker()

	return nil
}

// StopEngine полностью останавливает движок и освобождает TUN-дескриптор.
func StopEngine() error {
	adapterLock.Lock()
	defer adapterLock.Unlock()
	return stopEngineLocked()
}

func stopEngineLocked() error {
	if globalAdapter == nil {
		return nil
	}
	globalAdapter.mu.Lock()
	if !globalAdapter.running && globalAdapter.state == "stopped" {
		globalAdapter.mu.Unlock()
		globalAdapter = nil
		return nil
	}
	globalAdapter.running = false
	globalAdapter.state = "stopped"
	if globalAdapter.cancel != nil {
		globalAdapter.cancel()
	}
	if globalAdapter.tunSource != nil {
		_ = globalAdapter.tunSource.Close()
	}
	if globalAdapter.cipClient != nil {
		_ = globalAdapter.cipClient.Close()
	}
	globalAdapter.mu.Unlock()
	globalAdapter = nil
	return nil
}

// UpdateRules динамически обновляет маршрутные правила.
func UpdateRules(rules string) error {
	adapterLock.Lock()
	defer adapterLock.Unlock()

	if globalAdapter == nil {
		return errors.New("mobile: engine is not running")
	}

	parsed, err := routing.ParseRules(rules)
	if err != nil {
		return fmt.Errorf("mobile: parse rules: %w", err)
	}

	globalAdapter.mu.Lock()
	defer globalAdapter.mu.Unlock()

	rs := routing.Compile(parsed, globalAdapter.cfg.Routing.Default)
	globalAdapter.router.Swap(rs)
	globalAdapter.cfg.Routing.Rules = strings.Split(rules, "\n")

	return nil
}

// GetStatus возвращает текущий статус адаптера в формате JSON.
func GetStatus() string {
	adapterLock.Lock()
	a := globalAdapter
	adapterLock.Unlock()

	if a == nil {
		info := StatusInfo{
			State: "stopped",
			Since: time.Now().UTC().Format(time.RFC3339),
		}
		b, _ := json.Marshal(info)
		return string(b)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	activeRules := 0
	if a.router != nil && a.router.CurrentRuleset() != nil {
		activeRules = len(a.router.CurrentRuleset().Rules())
	}

	info := StatusInfo{
		State:         a.state,
		Since:         a.since.UTC().Format(time.RFC3339),
		Attempts:      a.attempts,
		LastError:     a.lastErr,
		BytesSent:     a.bytesSent.Load(),
		BytesReceived: a.bytesRecv.Load(),
		ActiveRules:   activeRules,
	}

	b, _ := json.Marshal(info)
	return string(b)
}

// ImportBundle разбирает ссылку-бандл (qd://...) и возвращает её JSON-конфиг.
func ImportBundle(bundleStr string) (string, error) {
	bundle, err := config.ParseBundle(bundleStr)
	if err != nil {
		return "", fmt.Errorf("mobile: import bundle: %w", err)
	}
	cfg := config.Default()
	cfg.Apply(bundle)
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("mobile: marshal config: %w", err)
	}
	return string(b), nil
}

func (a *mobileAdapter) runEngineWorker() {
	defer func() {
		a.mu.Lock()
		a.running = false
		a.state = "stopped"
		a.mu.Unlock()
	}()

	eng := connectip.New(a.guard, nil)

	if len(a.cfg.Node.Entries) > 0 && a.cfg.Node.Token != "" {
		a.mu.Lock()
		a.attempts++
		a.mu.Unlock()

		entry := a.cfg.Node.Entries[0]
		tmpl := uritemplate.MustNew(fmt.Sprintf("https://%s/connect-ip", entry.Addr))
		tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: entry.Authority()}

		client, rsp, err := cip.DialAuth(a.ctx, entry.Addr, tmpl, tlsConf, a.cfg.Node.Token, "")
		if err != nil {
			a.mu.Lock()
			a.lastErr = err.Error()
			a.mu.Unlock()
			// Falls back to netstack local processing if node dial fails
			a.runNetstackFallback(eng)
			return
		}
		defer client.Close()
		if rsp != nil && rsp.Body != nil {
			_ = rsp.Body.Close()
		}

		a.mu.Lock()
		a.cipClient = client
		a.state = "connected"
		a.mu.Unlock()

		_ = eng.Run(a.ctx, a.tunSource, client)
	} else {
		a.runNetstackFallback(eng)
	}
}

func (a *mobileAdapter) runNetstackFallback(eng *connectip.Engine) {
	ns, err := netstack.New(directDialer{})
	if err != nil {
		a.mu.Lock()
		a.lastErr = err.Error()
		a.state = "stopped"
		a.mu.Unlock()
		return
	}

	clientEp, serverEp := newNetstackTunnelPair()
	defer clientEp.Close()
	defer serverEp.Close()

	a.mu.Lock()
	a.state = "connected"
	a.mu.Unlock()

	go func() {
		_ = ns.Run(a.ctx, serverEp)
	}()

	_ = eng.Run(a.ctx, a.tunSource, clientEp)
}
