// Package subscribe — обновление подписки клиента: узлы сети, резервные точки
// входа и собственные лимиты.
//
// Ссылка-бандл даёт начальную точку входа, дальше сеть рассказывает о себе сама.
// Без этого адрес узла оставался бы тем, что вписали руками, и блокировка одного
// адреса выключала бы всех разом.
package subscribe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"quicdiver/internal/client/config"
)

// Doer — как сходить к узлу (управляющая связь клиента).
type Doer interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// Store — настройки клиента.
type Store interface {
	Get() config.Config
	Save(config.Config) error
}

// Subscription — что прислал узел.
type Subscription struct {
	Client      ClientInfo `json:"client"`
	Entries     []Entry    `json:"entries"`
	Exits       []Exit     `json:"exits"`
	PollSeconds int        `json:"poll_seconds"`
	At          time.Time  `json:"at"`
}

type ClientInfo struct {
	Label     string     `json:"label,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Quota     Quota      `json:"quota"`
	Devices   int        `json:"devices"`
}

type Quota struct {
	Limit      int64     `json:"limit"`
	Used       int64     `json:"used"`
	PeriodDays int       `json:"period_days,omitempty"`
	ResetAt    time.Time `json:"reset_at,omitempty"`
}

type Entry struct {
	Addr  string `json:"addr"`
	SNI   string `json:"sni,omitempty"`
	Label string `json:"label,omitempty"`
	Alive bool   `json:"alive"`
}

type Exit struct {
	Route    string   `json:"route"`
	Label    string   `json:"label,omitempty"`
	Category string   `json:"category,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Auto     bool     `json:"auto,omitempty"`
	Alive    bool     `json:"alive"`
}

// defaultPoll — как часто обновляться, если узел не сказал своё.
const defaultPoll = time.Hour

// retryAfter — пауза после неудачи.
//
// Заметно короче обычной: неудача чаще всего означает, что узел недоступен, и
// свежий список точек входа нужен как раз тогда.
const retryAfter = 5 * time.Minute

// Client тянет подписку и держит её последнюю копию.
type Client struct {
	doer  Doer
	store Store

	mu   sync.Mutex
	last *Subscription
	err  error
}

func New(d Doer, s Store) *Client { return &Client{doer: d, store: s} }

// Last — последняя полученная подписка (nil, если ещё не приходила).
func (c *Client) Last() (*Subscription, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last, c.err
}

// Run обновляет подписку до отмены ctx.
//
// Первый заход сразу: только что настроенный клиент не должен ждать час, чтобы
// узнать о сети хоть что-то.
func (c *Client) Run(ctx context.Context) {
	wait := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		sub, err := c.Fetch(ctx)
		switch {
		case err != nil:
			wait = retryAfter
		case sub.PollSeconds > 0:
			wait = time.Duration(sub.PollSeconds) * time.Second
		default:
			wait = defaultPoll
		}
	}
}

// Fetch забирает подписку и применяет её к настройкам.
func (c *Client) Fetch(ctx context.Context) (*Subscription, error) {
	cfg := c.store.Get()
	if len(cfg.Node.Entries) == 0 {
		return nil, errNotConfigured
	}
	authority := cfg.Node.Entries[0].Authority()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+authority+subscriptionPath, nil)
	if err != nil {
		return nil, err
	}
	rsp, err := c.doer.Do(ctx, req)
	if err != nil {
		c.fail(err)
		return nil, err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		err := errStatus(rsp.StatusCode)
		c.fail(err)
		return nil, err
	}

	var sub Subscription
	if err := json.NewDecoder(rsp.Body).Decode(&sub); err != nil {
		c.fail(err)
		return nil, err
	}

	c.mu.Lock()
	c.last, c.err = &sub, nil
	c.mu.Unlock()

	c.applyEntries(sub.Entries)
	return &sub, nil
}

// applyEntries сохраняет точки входа, полученные от сети.
//
// Текущая точка остаётся ПЕРВОЙ, если сеть её ещё знает: перебор идёт по
// порядку, и переставлять рабочее соединение в конец списка на каждом обновлении
// значило бы дёргать клиента без повода.
//
// Мёртвые точки не выбрасываем: узел мог просто не успеть отметиться, а список
// без резерва хуже списка с сомнительным резервом.
func (c *Client) applyEntries(entries []Entry) {
	if len(entries) == 0 {
		return // пустой список — повод оставить то, что работает
	}
	cfg := c.store.Get()
	var current config.Entry
	if len(cfg.Node.Entries) > 0 {
		current = cfg.Node.Entries[0]
	}

	next := make([]config.Entry, 0, len(entries))
	var head []config.Entry
	for _, e := range entries {
		if e.Addr == "" {
			continue
		}
		ce := config.Entry{Addr: e.Addr, SNI: e.SNI}
		if ce.Addr == current.Addr {
			head = append(head, ce)
			continue
		}
		next = append(next, ce)
	}
	next = append(head, next...)

	if sameEntries(cfg.Node.Entries, next) {
		return // ничего не изменилось — не трогаем файл
	}
	cfg.Node.Entries = next
	if err := c.store.Save(cfg); err != nil {
		log.Printf("подписка: точки входа не сохранены: %v", err)
		return
	}
	log.Printf("подписка: точек входа %d", len(next))
}

func sameEntries(a, b []config.Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (c *Client) fail(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
}

// subscriptionPath — путь подписки на узле.
const subscriptionPath = "/qd-subscription"

var errNotConfigured = errors.New("subscribe: узел не настроен")

// errStatus — узел ответил не тем.
//
// Витрина вместо подписки означает, что узел не признал токен: доступ отозван
// или истёк. Об этом нужно сказать прямо — иначе выглядит как «сеть молчит».
func errStatus(code int) error {
	if code == http.StatusOK {
		return nil
	}
	return fmt.Errorf("subscribe: узел ответил %d (токен отозван или истёк?)", code)
}
