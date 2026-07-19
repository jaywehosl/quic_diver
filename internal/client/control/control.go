// Package control — управляющий туннель клиента: связь с узлом, живущая
// независимо от перехвата трафика.
//
// По ТЗ запуск клиента и заворачивание трафика — разные вещи. Сервис поднялся:
// панель открыта, список узлов виден, статистика приезжает, обновления
// проверяются — а система не тронута, DNS и прокси на месте, перехвата нет.
// «Подключить» включает уже перехват.
//
// Раньше туннель поднимался только вместе с перехватом, и из этого следовало
// неудобное: чтобы посмотреть узлы или зайти в админку, приходилось начать
// проксировать весь трафик машины.
package control

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"quicdiver/internal/client/config"
	"quicdiver/internal/transport/cip"
)

// Link — авторизованная сессия с узлом без connect-ip.
//
// Управляющему каналу туннель для пакетов не нужен: он ходит обычными
// HTTP-запросами (список узлов, статистика, админ-API). Поднимать ради этого
// connect-ip значило бы занимать адрес из клиентского пула впустую.
type Link interface {
	RoundTrip(*http.Request) (*http.Response, error)
	Close() error
	Stats() (srtt, rttVar time.Duration, loss float64, ok bool)
}

// Dialer поднимает управляющую связь с узлом. Подменяется в тестах.
type Dialer func(ctx context.Context, e config.Entry, token string) (Link, error)

// ErrNoLink — связи с узлом сейчас нет.
var ErrNoLink = errors.New("control: нет связи с узлом")

// retryAfter — пауза между попытками поднять управляющую связь.
//
// Короткая: канал нужен панели, и «висит» здесь замечают сразу. Держать больше
// смысла нет — трафик через него не идёт, дорогого переподключения не будет.
const retryAfter = 5 * time.Second

// Control держит управляющую связь с узлом входа.
type Control struct {
	dial Dialer

	mu      sync.Mutex
	entries []config.Entry
	token   string
	link    Link
	// current — с какой точкой входа сейчас на связи.
	current config.Entry
	// lastErr — почему связи нет (для панели: молчаливое «нет связи» бесполезно).
	lastErr  error
	failedAt time.Time
}

// New создаёт управляющий канал. Связь поднимается лениво, при первом
// обращении: клиент должен стартовать мгновенно, даже когда узел недоступен.
func New(dial Dialer) *Control {
	return &Control{dial: dial}
}

// SetNode задаёт точки входа и токен.
//
// Смена точек рвёт текущую связь: держать её на прежнем узле после того, как
// пользователь выбрал другой, значит показывать в панели чужие данные.
func (c *Control) SetNode(entries []config.Entry, token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	same := c.token == token && len(entries) == len(c.entries)
	if same {
		for i := range entries {
			if entries[i] != c.entries[i] {
				same = false
				break
			}
		}
	}
	c.entries, c.token = append([]config.Entry(nil), entries...), token
	if !same {
		c.dropLocked()
	}
}

// Do выполняет запрос к узлу через управляющую связь.
//
// Связь поднимается по надобности и переиспользуется. Один повтор после обрыва
// делается молча: узел мог перезапуститься, и заставлять пользователя нажимать
// «обновить» из-за этого незачем.
func (c *Control) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	link, err := c.linkFor(ctx)
	if err != nil {
		return nil, err
	}
	rsp, err := link.RoundTrip(req)
	if err == nil {
		return rsp, nil
	}
	c.drop(link)

	// Тело запроса уже прочитано первой попыткой — повторять можно только то,
	// что умеет перемотаться. Иначе на узел уйдёт пустое тело.
	if req.GetBody == nil {
		return nil, err
	}
	body, berr := req.GetBody()
	if berr != nil {
		return nil, err
	}
	retry := req.Clone(ctx)
	retry.Body = body

	link, err2 := c.linkFor(ctx)
	if err2 != nil {
		return nil, err
	}
	return link.RoundTrip(retry)
}

// Online — есть ли связь прямо сейчас.
func (c *Control) Online() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.link != nil
}

// Status — что показать в панели.
type Status struct {
	// Online — связь есть.
	Online bool `json:"online"`
	// Node — с какой точкой входа на связи (или к какой пытаемся).
	Node string `json:"node,omitempty"`
	// SRTT — задержка до узла; 0, если замерять ещё нечего.
	SRTT string `json:"srtt,omitempty"`
	// Error — почему связи нет. Молчаливое «нет связи» пользователю бесполезно.
	Error string `json:"error,omitempty"`
}

// Status отдаёт снимок состояния канала.
func (c *Control) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()

	st := Status{Online: c.link != nil, Node: c.current.Authority()}
	if c.lastErr != nil {
		st.Error = c.lastErr.Error()
	}
	if c.link != nil {
		if srtt, _, _, ok := c.link.Stats(); ok {
			st.SRTT = srtt.Round(time.Millisecond).String()
		}
	}
	return st
}

// Close гасит связь.
func (c *Control) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropLocked()
	return nil
}

// linkFor отдаёт живую связь, поднимая её при необходимости.
func (c *Control) linkFor(ctx context.Context) (Link, error) {
	c.mu.Lock()
	if c.link != nil {
		link := c.link
		c.mu.Unlock()
		return link, nil
	}
	entries, token := c.entries, c.token
	// Недавняя неудача — не долбим узел на каждый запрос панели: она опрашивает
	// состояние часто, и без паузы лежащий узел получал бы шквал попыток.
	if !c.failedAt.IsZero() && time.Since(c.failedAt) < retryAfter {
		err := c.lastErr
		c.mu.Unlock()
		if err == nil {
			err = ErrNoLink
		}
		return nil, err
	}
	c.mu.Unlock()

	if len(entries) == 0 || token == "" {
		return nil, errors.New("control: узел не настроен")
	}

	// Точки входа перебираем по порядку: они и заданы как «основная, потом
	// резервные». Первая, к которой достучались, и становится текущей.
	var lastErr error
	for _, e := range entries {
		link, err := c.dial(ctx, e, token)
		if err != nil {
			lastErr = err
			continue
		}
		c.mu.Lock()
		// Пока поднимали, связь мог открыть и параллельный запрос — лишнюю гасим.
		if c.link != nil {
			cur := c.link
			c.mu.Unlock()
			_ = link.Close()
			return cur, nil
		}
		c.link, c.current = link, e
		c.lastErr, c.failedAt = nil, time.Time{}
		c.mu.Unlock()
		return link, nil
	}

	c.mu.Lock()
	c.lastErr, c.failedAt = lastErr, time.Now()
	c.mu.Unlock()
	if lastErr == nil {
		lastErr = ErrNoLink
	}
	return nil, lastErr
}

// drop гасит связь, если она всё ещё текущая.
func (c *Control) drop(link Link) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.link == link {
		c.dropLocked()
	}
}

func (c *Control) dropLocked() {
	if c.link != nil {
		_ = c.link.Close()
		c.link = nil
	}
}

// DialNode — управляющая связь поверх cip.Link.
//
// Живёт здесь, а не в вызывающем коде, чтобы точка входа настраивалась одним
// местом: SNI отделён от адреса намеренно — идём на голый IP, представляемся
// доменом, и DNS в подключении не участвует.
func DialNode(insecure bool) Dialer {
	return func(ctx context.Context, e config.Entry, token string) (Link, error) {
		authority := e.Authority()
		sni := authority
		if h, _, err := net.SplitHostPort(authority); err == nil {
			sni = h
		}
		link, err := cip.DialLink(ctx, e.Addr,
			&tls.Config{ServerName: sni, InsecureSkipVerify: insecure},
			token, "https://"+authority+"/qd-auth")
		if err != nil {
			return nil, err
		}
		return &cipLink{link: link, authority: authority}, nil
	}
}

// cipLink приводит cip.Link к интерфейсу Link.
type cipLink struct {
	link      *cip.Link
	authority string
}

func (l *cipLink) RoundTrip(r *http.Request) (*http.Response, error) {
	return l.link.H3Conn().RoundTrip(r)
}

func (l *cipLink) Close() error { return l.link.Close() }

func (l *cipLink) Stats() (time.Duration, time.Duration, float64, bool) {
	return l.link.Stats()
}

var _ io.Closer = (*Control)(nil)
