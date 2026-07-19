package connectudp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// Dialer открывает UDP-флоу к узлу через существующее H3-соединение.
type Dialer struct {
	CC *http3.ClientConn
	// Authority — имя узла в :authority. Пусто → берётся из адреса соединения.
	Authority string
	// Header — дополнительные заголовки запроса (метка маршрута, hop-limit).
	// Едут под QUIC/TLS, снаружи не видны.
	Header http.Header
}

// Dial просит узел открыть UDP-флоу к dst и отдаёт его как net.Conn.
//
// Контекст ограничивает только фазу дозвона: сам флоу живёт на собственном
// контексте и гаснет при Close. Отдать сюда ctx запроса нельзя — вызывающий
// (netstack.handleUDP) отменяет его сразу после дозвона, что убило бы флоу.
func (d Dialer) Dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if d.CC == nil {
		return nil, errors.New("connectudp: нет соединения с узлом")
	}
	authority := d.Authority
	if authority == "" {
		return nil, errors.New("connectudp: не задан authority узла")
	}

	rs, err := d.CC.OpenRequestStream(context.Background())
	if err != nil {
		return nil, fmt.Errorf("connectudp: открыть стрим: %w", err)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		// Расширенный CONNECT (RFC 9220): метод CONNECT + непустой :protocol.
		// Обычный CONNECT сюда не годится — он адресуется authority-form и не
		// несёт пути, а RFC 9298 кладёт цель именно в путь.
		Proto:  Protocol,
		URL:    &url.URL{Scheme: "https", Host: authority, Path: Path(dst)},
		Host:   authority,
		Header: make(http.Header),
	}
	for k, vs := range d.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	if err := rs.SendRequestHeader(req); err != nil {
		rs.Close()
		return nil, fmt.Errorf("connectudp: запрос: %w", err)
	}

	type result struct {
		rsp *http.Response
		err error
	}
	ch := make(chan result, 1)
	go func() {
		rsp, err := rs.ReadResponse()
		ch <- result{rsp, err}
	}()

	select {
	case <-ctx.Done():
		rs.Close()
		return nil, fmt.Errorf("connectudp: %s: %w", dst, ctx.Err())
	case r := <-ch:
		if r.err != nil {
			rs.Close()
			return nil, fmt.Errorf("connectudp: %s: %w", dst, r.err)
		}
		// 2xx — узел согласился (RFC 9298 §3). Всё прочее — отказ.
		if r.rsp.StatusCode/100 != 2 {
			rs.Close()
			return nil, fmt.Errorf("connectudp: %s: статус %d", dst, r.rsp.StatusCode)
		}
		return newConn(rs, dst), nil
	}
}

// datagramStream — то, что нужно flowConn от стрима: датаграммы и закрытие.
// Интерфейсом, чтобы одинаково обслуживать клиентскую и серверную стороны.
type datagramStream interface {
	SendDatagram(b []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
}

// flowConn — одно UDP-флоу как net.Conn.
type flowConn struct {
	str    datagramStream
	closer func() error
	remote net.Addr

	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func newConn(rs *http3.RequestStream, dst netip.AddrPort) *flowConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &flowConn{
		str:    rs,
		closer: rs.Close,
		ctx:    ctx,
		cancel: cancel,
		remote: net.UDPAddrFromAddrPort(dst),
	}
}

// Read отдаёт ровно одну датаграмму — границы пакетов сохраняются.
//
// Датаграммы с чужим Context ID пропускаем, а не роняем флоу: это
// несогласованное расширение, и по RFC его полагается игнорировать.
func (c *flowConn) Read(b []byte) (int, error) {
	for {
		raw, err := c.str.ReceiveDatagram(c.ctx)
		if err != nil {
			return 0, err
		}
		payload, err := decode(raw)
		if errors.Is(err, ErrForeignContext) {
			continue
		}
		if err != nil {
			continue // битый заголовок — тоже мимо, как потерянный пакет
		}
		return copy(b, payload), nil
	}
}

func (c *flowConn) Write(b []byte) (int, error) {
	if err := c.str.SendDatagram(encode(b)); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *flowConn) Close() error {
	var err error
	c.once.Do(func() {
		c.cancel()
		err = c.closer()
	})
	return err
}

func (c *flowConn) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (c *flowConn) RemoteAddr() net.Addr { return c.remote }

// Дедлайны не нужны: временем флоу управляет тот, кто его открыл, закрывая conn.
func (c *flowConn) SetDeadline(time.Time) error      { return nil }
func (c *flowConn) SetReadDeadline(time.Time) error  { return nil }
func (c *flowConn) SetWriteDeadline(time.Time) error { return nil }
