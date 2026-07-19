package subscribe

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"quicdiver/internal/client/config"
)

type fakeDoer struct {
	mu    sync.Mutex
	body  string
	code  int
	err   error
	calls int
}

func (d *fakeDoer) Do(ctx context.Context, r *http.Request) (*http.Response, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if d.err != nil {
		return nil, d.err
	}
	code := d.code
	if code == 0 {
		code = http.StatusOK
	}
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader(d.body)),
	}, nil
}

type memStore struct {
	mu    sync.Mutex
	cfg   config.Config
	saves int
}

func (s *memStore) Get() config.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func (s *memStore) Save(c config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg, s.saves = c, s.saves+1
	return nil
}

func store(addrs ...string) *memStore {
	cfg := config.Default()
	for _, a := range addrs {
		cfg.Node.Entries = append(cfg.Node.Entries, config.Entry{Addr: a, SNI: "node.example"})
	}
	cfg.Node.Token = "qd_клиент"
	return &memStore{cfg: cfg}
}

const twoEntries = `{"entries":[
	{"addr":"203.0.113.10:443","sni":"node.example","alive":true},
	{"addr":"198.51.100.7:443","sni":"node.example","alive":true}],
	"poll_seconds":3600,"client":{"label":"я"}}`

// Резервные точки приезжают от сети — ради этого подписка и нужна: блокировка
// одного адреса иначе выключает всех разом.
func TestFetchStoresEntries(t *testing.T) {
	st := store("203.0.113.10:443")
	c := New(&fakeDoer{body: twoEntries}, st)

	sub, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sub.Client.Label != "я" {
		t.Fatalf("сведения о клиенте: %+v", sub.Client)
	}
	if got := st.Get().Node.Entries; len(got) != 2 {
		t.Fatalf("точки входа не сохранены: %+v", got)
	}
}

// Рабочая точка остаётся первой: перебор идёт по порядку, и переставлять живое
// соединение в конец на каждом обновлении — дёргать клиента без повода.
func TestCurrentEntryStaysFirst(t *testing.T) {
	st := store("198.51.100.7:443") // сейчас работаем со второй по списку узла
	c := New(&fakeDoer{body: twoEntries}, st)

	if _, err := c.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := st.Get().Node.Entries
	if len(got) != 2 || got[0].Addr != "198.51.100.7:443" {
		t.Fatalf("рабочая точка не первая: %+v", got)
	}
}

// Неизменившийся список не переписывает файл: подписка ходит по кругу, и
// сохранять одно и то же каждый час незачем.
func TestUnchangedListNotSaved(t *testing.T) {
	st := store("203.0.113.10:443", "198.51.100.7:443")
	c := New(&fakeDoer{body: twoEntries}, st)

	c.Fetch(context.Background())
	first := st.saves
	c.Fetch(context.Background())
	if st.saves != first {
		t.Fatalf("файл переписан без изменений (%d → %d)", first, st.saves)
	}
}

// Пустой список от узла не должен обнулять настройки: остаться без адреса
// хуже, чем остаться со старым.
func TestEmptyListKeepsEntries(t *testing.T) {
	st := store("203.0.113.10:443")
	c := New(&fakeDoer{body: `{"entries":[],"poll_seconds":3600}`}, st)

	if _, err := c.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := st.Get().Node.Entries; len(got) != 1 {
		t.Fatalf("точки входа затёрты: %+v", got)
	}
}

// Отказ узла объясняется, а не выглядит как «сеть молчит»: витрина вместо
// подписки означает отозванный или истёкший доступ.
func TestRejectedTokenExplained(t *testing.T) {
	st := store("203.0.113.10:443")
	c := New(&fakeDoer{code: http.StatusOK - 100}, st) // любой не-200

	_, err := c.Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "токен") {
		t.Fatalf("непонятный отказ: %v", err)
	}
}

// Неудача попадает в статус: панель обязана показать причину, а не пустоту.
func TestFailureVisibleInStatus(t *testing.T) {
	st := store("203.0.113.10:443")
	c := New(&fakeDoer{err: errors.New("узел недоступен")}, st)

	c.Fetch(context.Background())
	if _, err := c.Last(); err == nil {
		t.Fatal("причина неудачи потеряна")
	}
}

// Ненастроенный клиент не ходит в сеть впустую.
func TestUnconfiguredDoesNotFetch(t *testing.T) {
	st := &memStore{cfg: config.Default()}
	d := &fakeDoer{body: twoEntries}
	c := New(d, st)

	if _, err := c.Fetch(context.Background()); err == nil {
		t.Fatal("запрос без настроенного узла прошёл")
	}
	if d.calls != 0 {
		t.Fatalf("сходили в сеть %d раз без настроек", d.calls)
	}
}
