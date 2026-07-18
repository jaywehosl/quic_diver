// Package chain — выход узла наружу через upstream-узел (цепочка).
//
// Узел master=slave: между собой узлы говорят по тому же connect-ip/QUIC, что и
// клиент с узлом, — разница лишь в токене (у узла сервисный node-токен). Поэтому
// цепочка A→B устроена так же, как клиент→A: A предъявляет B node-токен и открывает
// CONNECT-стримы, а B дозванивается наружу. Клиент об этом не знает — для него A
// обычный узел.
//
// Защита от петли — hop-limit (по образцу IP TTL, RFC 791): каждый транзитный
// узел уменьшает счётчик, на нуле проброс запрещён. Без него цепочка A→B→A
// закольцевала бы трафик до исчерпания стримов.
//
// TCP уводится CONNECT-стримом, UDP — сырыми пакетами по тому же connect-ip
// туннелю, которым A подключён к B (см. udpmux.go): отдельного протокола для UDP
// не понадобилось, узел A для этого просто ведёт себя как обычный клиент B.
package chain

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/quic-go/quic-go/http3"

	"quicdiver/internal/client/connectdial"
)

// HopHeader несёт остаток hop-limit в CONNECT-запросе (под QUIC/TLS, для DPI
// невидим). Отсутствие заголовка = запрос от клиента (не транзит).
const HopHeader = "Qd-Hops"

// DefaultHops — стартовый лимит транзитов. 8 с запасом: реальные цепочки короткие,
// а большего и не нужно — это потолок против случайной петли, не фича.
const DefaultHops = 8

// ErrUDPUnsupported — UDP в цепочку не уведён (туннель не передан в New).
// Отдельная ошибка, а не «просто не вышло»: молчаливый фолбэк наружу выдал бы
// адрес узла A вместо адреса цепочки.
var ErrUDPUnsupported = errors.New("chain: UDP через цепочку недоступен (нет пакетного туннеля)")

// Dialer выводит трафик узла через upstream-узел B.
//
// TCP уезжает CONNECT-стримом (надёжность даёт QUIC), UDP — сырыми пакетами по
// тому же connect-ip туннелю, которым узел A и так подключён к B: отдельного
// протокола для UDP не нужно, A просто ведёт себя как обычный клиент B.
type Dialer struct {
	// cc — H3-соединение к upstream-узлу (A как клиент B).
	cc *http3.ClientConn
	// mux — UDP-флоу поверх пакетного туннеля; nil → UDP в цепочку не уводим.
	mux *udpMux
}

// New строит chain-диалер поверх соединения с upstream-узлом.
//
// tun — пакетный туннель к B (cip.Client), local — адрес, который B назначил
// узлу A: с него уйдут собранные UDP-пакеты. Пустой tun оставляет UDP
// неподдержанным (TCP работает как прежде).
func New(cc *http3.ClientConn, tun PacketTunnel, local netip.Addr) Dialer {
	d := Dialer{cc: cc}
	if tun != nil && local.IsValid() {
		d.mux = newUDPMux(tun, local)
	}
	return d
}

type hopsKey struct{}

// WithHops кладёт в контекст остаток hop-limit для этого флоу. serveConnect
// вычисляет его из входящего запроса и передаёт вниз в Dialer.
func WithHops(ctx context.Context, hops int) context.Context {
	return context.WithValue(ctx, hopsKey{}, hops)
}

// hopsFrom достаёт остаток hop-limit (DefaultHops, если не задан — прямой вызов).
func hopsFrom(ctx context.Context) int {
	if v, ok := ctx.Value(hopsKey{}).(int); ok {
		return v
	}
	return DefaultHops
}

// DialTCP пробрасывает TCP-флоу в upstream-узел CONNECT-стримом, ставя остаток
// hop-limit из контекста.
func (d Dialer) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	hops := hopsFrom(ctx)
	if hops <= 0 {
		return nil, errors.New("chain: hop-limit исчерпан (петля?)")
	}
	inner := connectdial.Dialer{
		CC:     d.cc,
		Header: http.Header{HopHeader: []string{strconv.Itoa(hops)}},
	}
	return inner.DialTCP(ctx, dst)
}

// DialUDP заводит UDP-флоу через upstream-узел сырыми пакетами в туннеле.
//
// Hop-limit здесь не едет: у датаграмм нет заголовков CONNECT. Петля по UDP
// невозможна иначе — пакет уходит на адрес, назначенный узлом B, и вернуться в
// A может только как ответ этого же флоу.
func (d Dialer) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if d.mux == nil {
		return nil, ErrUDPUnsupported
	}
	return d.mux.dial(dst)
}

// HopsFromRequest читает оставшийся hop-limit из входящего CONNECT.
//
// Запрос без заголовка — от клиента (первый узел цепочки): выдаём полный лимит.
// С заголовком — транзит от другого узла: берём присланное значение (оно уже
// уменьшено отправителем).
func HopsFromRequest(r *http.Request) (hops int, fromClient bool) {
	v := r.Header.Get(HopHeader)
	if v == "" {
		return DefaultHops, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, false
}
