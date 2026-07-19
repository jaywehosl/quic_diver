// Command panelcheck — панель на поддельных данных: посмотреть вёрстку и
// поведение без поднятого туннеля и WinDivert.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"quicdiver/internal/client/api"
	"quicdiver/internal/client/config"
	"quicdiver/internal/client/control"
	"quicdiver/internal/client/notify"
	"quicdiver/internal/client/panel"
	"quicdiver/internal/client/service"
)

type fakeSvc struct {
	mu sync.Mutex
	st service.State
}

func (s *fakeSvc) Connect(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st = service.StateConnected
	return nil
}

func (s *fakeSvc) Disconnect(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st = service.StateStopped
	return nil
}

func (s *fakeSvc) Status() service.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return service.Status{State: s.st}
}

// fakeCtl отвечает за узел: выходы, реестр, клиенты, статистика.
type fakeCtl struct{}

func (fakeCtl) Status() control.Status {
	return control.Status{Online: true, Node: "node.example", SRTT: "12ms"}
}

func (fakeCtl) SetNode([]config.Entry, string) {}

func (fakeCtl) Do(ctx context.Context, r *http.Request) (*http.Response, error) {
	body := "[]"
	switch {
	case strings.HasSuffix(r.URL.Path, "/qd-exits"):
		body = `[{"route":"direct","label":"без цепочки","alive":true},
		{"route":"ru.example","label":"Москва","category":"entry","tags":["ru"],"alive":true,"self":true},
		{"route":"de.example","label":"Франкфурт","category":"exit","tags":["de","eu"],"alive":true},
		{"route":"nl.example","label":"Амстердам","category":"exit","tags":["nl","eu"],"alive":false},
		{"route":"auto:de","label":"de","auto":true,"alive":true},
		{"route":"auto:eu","label":"eu","auto":true,"alive":true}]`
	case strings.HasSuffix(r.URL.Path, "/qd-admin/nodes"):
		body = `[{"id":"ru.example","label":"Москва","category":"entry","tags":["ru"],"alive":true,"self":true},
		{"id":"de.example","label":"Франкфурт","category":"exit","tags":["de","eu"],"alive":true},
		{"id":"nl.example","label":"Амстердам","category":"exit","tags":["nl"],"alive":false}]`
	case strings.HasSuffix(r.URL.Path, "/qd-admin/users"):
		body = `[{"hash":"ab6242b5c1a12ee12b82fded5bb416e6","label":"ноутбук","role":"user",
		"network_traffic":{"bytes_in":8123456789,"bytes_out":1234567890},
		"quota":{"limit":32212254720,"used":9358024679,"period_days":30}},
		{"hash":"cd7353c6d2b23ff23c93gfed6cc527f7","label":"телефон","role":"user",
		"network_traffic":{"bytes_in":512345678,"bytes_out":91234567},"quota":{}}]`
	case strings.HasSuffix(r.URL.Path, "/qd-admin/cluster"):
		body = `{"epoch":3,"master_id":"ru.example","self":"ru.example","is_master":true}`
	case strings.HasSuffix(r.URL.Path, "/qd-admin/stats"):
		body = `{"node":"ru.example","uptime":"18h42m","clients":{"tokens":7,"active_sessions":2},
		"go":{"heap_mb":41,"goroutines":128},"peers":["de.example","nl.example"],
		"metrics":[{"node":"de.example","srtt":"28ms","rtt_var":"4ms","loss":0.0003,"score":"36ms","fresh":true},
		{"node":"nl.example","srtt":"31ms","rtt_var":"19ms","loss":0.012,"score":"93ms","fresh":true}]}`
	}
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

type memCfg struct {
	mu  sync.Mutex
	cfg config.Config
}

func (c *memCfg) Get() config.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg
}

func (c *memCfg) Save(cfg config.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg = cfg
	b, _ := json.Marshal(cfg.Routing)
	log.Printf("сохранено: %s", b)
	return nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8765", "адрес панели")
	flag.Parse()

	cfg := config.Default()
	// Ненастроенный клиент — чтобы увидеть экран первого запуска. Ссылку ниже
	// можно вставить в него и проверить переход в основной интерфейс.
	if os.Getenv("QD_CONFIGURED") != "" {
		cfg.Node.Entries = []config.Entry{{Addr: "203.0.113.10:443", SNI: "node.example"}}
		cfg.Node.Token = "qd_демонстрационный"
	}
	cfg.Routing.Rules = []string{
		"# банк мимо туннеля",
		"dom:bank.example = direct",
		"dom:youtube.com = auto:de",
		"cidr:192.168.0.0/16 = direct",
	}
	cfg.Routing.Default = "direct"

	notices := notify.New()
	notices.Post(notify.Warn, "выход недоступен", "правило вело на de.example — трафик выпущен здесь")
	notices.Post(notify.Info, "узел сменился", "auto:eu → nl.example")
	notices.Post(notify.Error, "нет связи с узлом", "ru.example не отвечает")

	tok := api.Token("demo-panel-key")
	h := api.Handler(tok, api.Deps{
		Service: &fakeSvc{}, Control: fakeCtl{},
		Config: &memCfg{cfg: cfg}, Notices: notices,
		Quit: func() { log.Print("нажали «Выйти»") },
	}, panel.Handler())

	log.Printf("панель: http://%s/?token=%s", *addr, tok)
	log.Fatal(panel.Server(*addr, h).ListenAndServe())
}
