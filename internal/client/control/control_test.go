package control

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"quicdiver/internal/client/config"
)

// fakeLink — связь, которую можно заставить отвечать или падать.
type fakeLink struct {
	mu     sync.Mutex
	fail   bool
	calls  int
	bodies []string
	closed bool
	entry  config.Entry
}

func (l *fakeLink) RoundTrip(r *http.Request) (*http.Response, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if r.Body != nil {
		b := make([]byte, 64)
		n, _ := r.Body.Read(b)
		l.bodies = append(l.bodies, string(b[:n]))
	}
	if l.fail {
		return nil, errors.New("связь оборвалась")
	}
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

func (l *fakeLink) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}

func (l *fakeLink) Stats() (time.Duration, time.Duration, float64, bool) {
	return 12 * time.Millisecond, time.Millisecond, 0, true
}

// dialer возвращает диалер и счётчик попыток.
func dialer(links ...*fakeLink) (Dialer, *int) {
	var n int
	var mu sync.Mutex
	i := 0
	return func(ctx context.Context, e config.Entry, token string) (Link, error) {
		mu.Lock()
		defer mu.Unlock()
		n++
		if i >= len(links) {
			return nil, errors.New("узел недоступен")
		}
		l := links[i]
		i++
		if l == nil {
			return nil, errors.New("узел недоступен")
		}
		l.entry = e
		return l, nil
	}, &n
}

func req(t *testing.T, body string) *http.Request {
	t.Helper()
	if body == "" {
		r, _ := http.NewRequest(http.MethodGet, "https://node/qd-exits", nil)
		return r
	}
	r, _ := http.NewRequest(http.MethodPost, "https://node/x", strings.NewReader(body))
	return r
}

func настроенный(t *testing.T, d Dialer) *Control {
	t.Helper()
	c := New(d)
	c.SetNode([]config.Entry{{Addr: "203.0.113.10:443", SNI: "node.example"}}, "qd_токен")
	return c
}

// Связь поднимается один раз и переиспользуется: панель опрашивает состояние
// часто, и поднимать сессию на каждый запрос — дороже самого запроса.
func TestReusesLink(t *testing.T) {
	link := &fakeLink{}
	d, dials := dialer(link, link)
	c := настроенный(t, d)

	for i := 0; i < 3; i++ {
		if _, err := c.Do(context.Background(), req(t, "")); err != nil {
			t.Fatal(err)
		}
	}
	if *dials != 1 {
		t.Fatalf("связь поднималась %d раз", *dials)
	}
}

// Оборвалась связь — молча пробуем ещё раз: узел мог перезапуститься, и
// заставлять пользователя жать «обновить» из-за этого незачем.
func TestRetriesOnceAfterDrop(t *testing.T) {
	dead, alive := &fakeLink{fail: true}, &fakeLink{}
	d, dials := dialer(dead, alive)
	c := настроенный(t, d)

	rsp, err := c.Do(context.Background(), req(t, `{"a":1}`))
	if err != nil {
		t.Fatalf("повтор не сработал: %v", err)
	}
	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("статус %d", rsp.StatusCode)
	}
	if *dials != 2 {
		t.Fatalf("попыток подъёма: %d (ожидалось 2)", *dials)
	}
	if !dead.closed {
		t.Fatal("оборванная связь не закрыта")
	}
}

// Тело повторяемого запроса не должно потеряться: первая попытка его уже
// прочитала, и на узел ушло бы пустое.
func TestRetryKeepsBody(t *testing.T) {
	dead, alive := &fakeLink{fail: true}, &fakeLink{}
	d, _ := dialer(dead, alive)
	c := настроенный(t, d)

	if _, err := c.Do(context.Background(), req(t, `{"важное":"тело"}`)); err != nil {
		t.Fatal(err)
	}
	alive.mu.Lock()
	defer alive.mu.Unlock()
	if len(alive.bodies) == 0 || !strings.Contains(alive.bodies[0], "важное") {
		t.Fatalf("тело не доехало при повторе: %+v", alive.bodies)
	}
}

// Лежащий узел не должен получать шквал попыток: панель опрашивает состояние
// часто, и без паузы каждый её запрос стучался бы заново.
func TestFailedNodeNotHammered(t *testing.T) {
	d, dials := dialer(nil)
	c := настроенный(t, d)

	for i := 0; i < 10; i++ {
		if _, err := c.Do(context.Background(), req(t, "")); err == nil {
			t.Fatal("недоступный узел ответил успехом")
		}
	}
	if *dials > 1 {
		t.Fatalf("узел получил %d попыток подряд", *dials)
	}
}

// Резервные точки входа перебираются по порядку: первая доступная становится
// текущей.
func TestFallsBackToNextEntry(t *testing.T) {
	alive := &fakeLink{}
	d, _ := dialer(nil, alive)
	c := New(d)
	c.SetNode([]config.Entry{
		{Addr: "203.0.113.10:443", SNI: "первый"},
		{Addr: "203.0.113.20:443", SNI: "второй"},
	}, "qd_токен")

	if _, err := c.Do(context.Background(), req(t, "")); err != nil {
		t.Fatalf("резервная точка не подхватила: %v", err)
	}
	if got := c.Status().Node; got != "второй" {
		t.Fatalf("текущая точка входа: %q", got)
	}
}

// Смена узла рвёт связь: держать её на прежнем после того, как пользователь
// выбрал другой, значит показывать в панели чужие данные.
func TestChangingNodeDropsLink(t *testing.T) {
	link := &fakeLink{}
	d, _ := dialer(link, &fakeLink{})
	c := настроенный(t, d)
	c.Do(context.Background(), req(t, ""))

	c.SetNode([]config.Entry{{Addr: "198.51.100.5:443", SNI: "другой"}}, "qd_токен")
	if !link.closed {
		t.Fatal("связь с прежним узлом осталась")
	}
	if c.Online() {
		t.Fatal("канал числится онлайн после смены узла")
	}
}

// Те же настройки связь не рвут: панель сохраняет конфиг целиком, и любая
// правка гасила бы рабочий канал.
func TestSameNodeKeepsLink(t *testing.T) {
	link := &fakeLink{}
	d, _ := dialer(link)
	c := настроенный(t, d)
	c.Do(context.Background(), req(t, ""))

	c.SetNode([]config.Entry{{Addr: "203.0.113.10:443", SNI: "node.example"}}, "qd_токен")
	if link.closed || !c.Online() {
		t.Fatal("связь оборвана при сохранении тех же настроек")
	}
}

// Ненастроенный клиент отвечает внятно, а не «нет связи»: на первом запуске
// узел ещё не задан, и панель должна сказать об этом.
func TestUnconfiguredSaysSo(t *testing.T) {
	c := New(func(context.Context, config.Entry, string) (Link, error) {
		t.Fatal("диал не должен вызываться без настроек")
		return nil, nil
	})
	_, err := c.Do(context.Background(), req(t, ""))
	if err == nil || !strings.Contains(err.Error(), "не настроен") {
		t.Fatalf("ошибка: %v", err)
	}
}

// Причина отсутствия связи попадает в статус: молчаливое «нет связи»
// пользователю бесполезно.
func TestStatusCarriesReason(t *testing.T) {
	d, _ := dialer(nil)
	c := настроенный(t, d)
	c.Do(context.Background(), req(t, ""))

	st := c.Status()
	if st.Online || st.Error == "" {
		t.Fatalf("статус без причины: %+v", st)
	}
}

// Живая связь показывает задержку — по ней видно, что канал не просто «есть».
func TestStatusShowsLatency(t *testing.T) {
	d, _ := dialer(&fakeLink{})
	c := настроенный(t, d)
	c.Do(context.Background(), req(t, ""))

	if st := c.Status(); !st.Online || st.SRTT == "" {
		t.Fatalf("статус живой связи: %+v", st)
	}
}
