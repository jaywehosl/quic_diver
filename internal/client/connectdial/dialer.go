// Package connectdial — исходящие TCP-соединения клиента через надёжный
// QUIC-стрим (HTTP/3 CONNECT, RFC 9114) до узла.
//
// Это клиентская половина гибрида: TCP-флоу терминируется локальным gVisor и
// уезжает в CONNECT-стрим, где потери туннеля закрывает ретрансмит QUIC —
// внутренний TCP приложения их не видит (в отличие от датаграмм connect-ip).
// UDP уезжает CONNECT-UDP потоком (RFC 9298): датаграммы внутри стрима, без
// ретрансмита — для UDP он только навредил бы. Прежде UDP шёл сырым пакетом в
// connect-ip датаграмме, а метка маршрута жила в src-адресе; это упиралось в
// нарезку пула и рвало флоу при каждом изменении набора выходов.
//
// Реализует netstack.Dialer, поэтому серверный forwarder-код переиспользуется
// на клиенте без изменений — меняется только способ выхода наружу.
package connectdial

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/quic-go/quic-go/http3"

	"quicdiver/internal/transport/connectudp"
)

// Dialer открывает CONNECT-стримы через существующее H3-соединение с узлом.
type Dialer struct {
	CC *http3.ClientConn
	// Authority — имя узла в :authority. Нужно UDP-потокам (RFC 9298): целевой
	// адрес у них лежит в пути запроса, а адресуется запрос узлу.
	Authority string
	// Header — дополнительные заголовки CONNECT-запроса (напр. hop-limit при
	// chain). Едут под QUIC/TLS, наружу невидимы. nil — без добавок.
	Header http.Header
}

// DialTCP просит узел соединиться с dst и отдаёт поток как net.Conn.
//
// ВАЖНО: стрим живёт ровно столько, сколько живёт контекст запроса, поэтому
// переданный ctx НЕЛЬЗЯ отдавать в запрос — вызывающий (netstack.handleTCP)
// отменяет его сразу после дозвона (что верно для net.Dial, но убило бы стрим).
// Здесь ctx ограничивает только фазу дозвона, а стрим завязан на собственный
// контекст, который отменяется при Close.
func (d Dialer) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	sctx, scancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	req := (&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: dst.String()},
		Host:   dst.String(),
		Header: make(http.Header),
		Body:   pr,
	}).WithContext(sctx)
	for k, vs := range d.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	type result struct {
		resp *http.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := d.CC.RoundTrip(req)
		ch <- result{resp, err}
	}()

	select {
	case <-ctx.Done(): // не уложились в дозвон
		scancel()
		pw.Close()
		return nil, fmt.Errorf("CONNECT %s: %w", dst, ctx.Err())
	case r := <-ch:
		if r.err != nil {
			scancel()
			pw.Close()
			return nil, fmt.Errorf("CONNECT %s: %w", dst, r.err)
		}
		if r.resp.StatusCode != http.StatusOK {
			scancel()
			pw.Close()
			r.resp.Body.Close()
			return nil, fmt.Errorf("CONNECT %s: статус %d", dst, r.resp.StatusCode)
		}
		return &streamConn{
			r:      r.resp.Body,
			w:      pw,
			cancel: scancel,
			remote: net.TCPAddrFromAddrPort(dst),
		}, nil
	}
}

// DialUDP открывает UDP-поток до узла (RFC 9298).
//
// Движок отдаёт UDP локальному стеку так же, как TCP, и стек приходит сюда. Без
// этой реализации UDP-флоу молча упирался в отказ: пакеты уходили в стек и
// пропадали. Снаружи это выглядело как «интернет есть, а голосовая связь
// молчит» — TCP-приложения работали, UDP-овые нет.
func (d Dialer) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return connectudp.Dialer{CC: d.CC, Authority: d.Authority, Header: d.Header}.Dial(ctx, dst)
}

// streamConn — net.Conn поверх CONNECT-стрима (чтение из тела ответа, запись в
// тело запроса).
type streamConn struct {
	r      io.ReadCloser
	w      *io.PipeWriter
	cancel context.CancelFunc // отменяет контекст стрима при Close
	remote net.Addr
}

func (c *streamConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *streamConn) Write(b []byte) (int, error) { return c.w.Write(b) }

// CloseWrite закрывает только сторону записи (полу-закрытие TCP): узел увидит
// EOF и дошлёт остаток ответа.
func (c *streamConn) CloseWrite() error { return c.w.Close() }

func (c *streamConn) Close() error {
	c.w.Close()
	err := c.r.Close()
	c.cancel() // теперь стрим можно гасить
	return err
}

func (c *streamConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

// Дедлайны на CONNECT-стриме не нужны: временем управляет ctx запроса и
// закрытие соединения.
func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }
