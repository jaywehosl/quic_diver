// Package cip — слой connect-ip (RFC 9484) модели B: транспорт сырых IP-пакетов
// между клиентом и узлом поверх QUIC/HTTP3.
//
// Стек клиента:
//
//	packet.Source ──> cip.Client ──> connectip.Conn (ReadPacket/WritePacket)
//	                                       │
//	                              http3.ClientConn
//	                                       │
//	                          quicconn.Conn.QUIC() (*quic.Conn + миграция arch4)
//
// Миграция живёт на quic-объекте (quicconn.Conn.Migrate), поэтому http3 и
// connect-ip переживают смену пути прозрачно.
package cip

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"quicdiver/internal/client/hwid"
	"quicdiver/internal/server/auth"
	"quicdiver/internal/uplink/quicconn"
)

// Client — клиентский конец connect-ip туннеля.
type Client struct {
	qc *quicconn.Conn
	h3 *http3.Transport
	cc *http3.ClientConn
	ip *connectip.Conn
}

// H3Conn — то же HTTP/3-соединение, поверх которого поднят connect-ip. Гибрид
// открывает через него CONNECT-стримы для TCP-флоу, поэтому и датаграммы, и
// стримы делят одну QUIC-сессию: один handshake, один congestion-control.
func (c *Client) H3Conn() *http3.ClientConn { return c.cc }

// Dial устанавливает туннель к узлу.
//   - endpoint: host:port (host — доменное имя, arch3);
//   - tmpl: URI Template connect-ip эндпоинта на узле;
//   - tlsConf: TLS клиента (ALPN дополняется h3; должен нести ServerName).
func Dial(ctx context.Context, endpoint string, tmpl *uritemplate.Template, tlsConf *tls.Config) (*Client, *http.Response, error) {
	return DialAuth(ctx, endpoint, tmpl, tlsConf, "", "")
}

// DialAuth — Dial с авторизацией: token предъявляется узлу по authURL до
// connect-ip, помечая QUIC-сессию доверенной. Пустой token/authURL → без auth
// (dev-узел без БД).
//
// Авторизуем сессию до connect-ip намеренно: connect-ip-go не даёт положить
// заголовок в свой запрос, а так проверка идёт один раз на всю сессию, и туннель
// с CONNECT-стримами внутри неё наследуют доверие.
func DialAuth(ctx context.Context, endpoint string, tmpl *uritemplate.Template, tlsConf *tls.Config, token, authURL string) (*Client, *http.Response, error) {
	qcAny, err := quicconn.Dialer{TLS: ensureH3(tlsConf)}.Dial(ctx, endpoint)
	if err != nil {
		return nil, nil, err
	}
	qc := qcAny.(*quicconn.Conn)

	h3tr := &http3.Transport{EnableDatagrams: true}
	cc := h3tr.NewClientConn(qc.QUIC())

	// Авторизуемся, если задан authURL — независимо от того, пуст ли токен.
	// Узел без БД (dev) ответит 204 и на пустой; узел с БД пустой/битый токен
	// отклонит (decoy), и мы упадём здесь с понятной ошибкой, а не позже на кривой
	// капсуле connect-ip.
	if authURL != "" {
		if err := authorize(ctx, cc, token, authURL); err != nil {
			h3tr.Close()
			qc.Close()
			return nil, nil, err
		}
	}

	ipConn, rsp, err := connectip.Dial(ctx, cc, tmpl)
	if err != nil {
		h3tr.Close()
		qc.Close()
		return nil, nil, err
	}
	return &Client{qc: qc, h3: h3tr, cc: cc, ip: ipConn}, rsp, nil
}

// authorize предъявляет токен узлу и ждёт 204. Не признав токен, узел отвечает
// decoy-страницей (200 с HTML) — по коду и отличаем принятие от отказа.
func authorize(ctx context.Context, cc *http3.ClientConn, token, authURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set(auth.HeaderToken, token)
	// Отпечаток машины — для учёта устройств на узле. Едет внутри
	// зашифрованного H3-запроса, снаружи не виден. Пустой (систему не опознали)
	// просто не отправляем: узел тогда учёт по устройствам не ведёт.
	if id := hwid.Get(); id != "" {
		req.Header.Set(auth.HeaderHWID, id)
	}
	rsp, err := cc.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("авторизация: %w", err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("авторизация отклонена узлом (токен неверен или отозван)")
	}
	return nil
}

// WritePacket отправляет сырой IP-пакет в туннель. Если пакет превышает путь,
// возвращает готовый ICMP (PTB) для отправки обратно источнику — MTU-инженерия B.
func (c *Client) WritePacket(b []byte) (icmp []byte, err error) { return c.ip.WritePacket(b) }

// ReadPacket читает один сырой IP-пакет из туннеля в b.
func (c *Client) ReadPacket(b []byte) (int, error) { return c.ip.ReadPacket(b) }

// LocalPrefixes — адреса, назначенные узлом этому клиенту (ADDRESS_ASSIGN).
func (c *Client) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	return c.ip.LocalPrefixes(ctx)
}

// Migrate переносит сессию на новый локальный сокет без разрыва (arch4).
func (c *Client) Migrate(ctx context.Context, laddr *net.UDPAddr) error {
	return c.qc.Migrate(ctx, laddr)
}

// Context закрывается со смертью QUIC-сессии (idle-таймаут, CONNECTION_CLOSE).
// По нему supervisor понимает, что путь мёртв и туннель надо поднимать заново.
func (c *Client) Context() context.Context { return c.qc.QUIC().Context() }

// Traffic — пакетов отправлено и принято: по ним supervisor замечает мёртвый путь
// раньше idle-таймаута.
func (c *Client) Traffic() (sent, received uint64) {
	t := c.qc.Traffic()
	return t.Sent, t.Received
}

// Close закрывает туннель и весь стек под ним.
func (c *Client) Close() error {
	err := c.ip.Close()
	c.h3.Close()
	c.qc.Close()
	return err
}

// ensureH3 гарантирует ALPN "h3" (обязателен для connect-ip поверх HTTP/3).
func ensureH3(t *tls.Config) *tls.Config {
	if t == nil {
		t = &tls.Config{}
	} else {
		t = t.Clone()
	}
	if len(t.NextProtos) == 0 {
		t.NextProtos = []string{http3.NextProtoH3}
	}
	return t
}
