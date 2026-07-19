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
// И TCP, и UDP уводятся стримами (CONNECT и CONNECT-UDP): метка маршрута и
// остаток hop-limit едут заголовками, поэтому следующий узел решает сам, он ли
// выход. У сырых датаграмм заголовков нет — на них цепочка дальше двух звеньев
// не строилась.
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
	"quicdiver/internal/routing"
	"quicdiver/internal/transport/connectudp"
)

// HopHeader несёт остаток hop-limit в CONNECT-запросе (под QUIC/TLS, для DPI
// невидим). Отсутствие заголовка = запрос от клиента (не транзит).
const HopHeader = "Qd-Hops"

// DefaultHops — стартовый лимит транзитов. 8 с запасом: реальные цепочки короткие,
// а большего и не нужно — это потолок против случайной петли, не фича.
const DefaultHops = 8

// Dialer выводит трафик узла через соседний узел.
type Dialer struct {
	// cc — H3-соединение к upstream-узлу (A как клиент B).
	cc *http3.ClientConn
	// authority — имя upstream-узла для :authority в CONNECT-UDP.
	authority string
}

// New строит chain-диалер поверх соединения с upstream-узлом.
//
// authority — имя upstream-узла: CONNECT-UDP кладёт цель в путь, поэтому
// authority нужен отдельно.
func New(cc *http3.ClientConn, authority string) Dialer {
	return Dialer{cc: cc, authority: authority}
}

type hopsKey struct{}

// WithHops кладёт в контекст остаток hop-limit для этого флоу. serveConnect
// вычисляет его из входящего запроса и передаёт вниз в Dialer.
func WithHops(ctx context.Context, hops int) context.Context {
	return context.WithValue(ctx, hopsKey{}, hops)
}

type routeKey struct{}

// WithRoute кладёт в контекст метку маршрута для этого флоу.
//
// Через контекст, а не полем Dialer: диалер создаётся один раз на соседний узел
// и живёт долго, а метка своя у каждого флоу. Без неё следующий узел не узнал бы,
// куда вести дальше, — ровно та поломка, из-за которой метку потреблял первый же
// узел, а маршрут дальше задавался его конфигом.
func WithRoute(ctx context.Context, route string) context.Context {
	return context.WithValue(ctx, routeKey{}, route)
}

// routeFrom достаёт метку маршрута (пусто — вести некуда, выпускать на месте).
func routeFrom(ctx context.Context) string {
	v, _ := ctx.Value(routeKey{}).(string)
	return v
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
	hdr := http.Header{HopHeader: []string{strconv.Itoa(hops)}}
	// Метку передаём дальше: следующий узел решает сам, он ли выход.
	if route := routeFrom(ctx); route != "" {
		hdr.Set(routing.HeaderName, route)
	}
	inner := connectdial.Dialer{CC: d.cc, Header: hdr}
	return inner.DialTCP(ctx, dst)
}

// DialUDP уводит UDP-флоу в upstream-узел тем же CONNECT-UDP, что и клиент.
//
// Раньше здесь шли сырые пакеты по connect-ip туннелю, и это работало, пока
// цепочка была двухзвенной: у датаграмм нет заголовков, значит следующий узел не
// узнал бы ни метку маршрута, ни остаток hop-limit — дальше двух хопов трафик
// вести было нечем. Со стримом UDP получает ровно ту же машинерию, что TCP.
func (d Dialer) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	hops := hopsFrom(ctx)
	if hops <= 0 {
		return nil, errors.New("chain: hop-limit исчерпан (петля?)")
	}
	hdr := http.Header{HopHeader: []string{strconv.Itoa(hops)}}
	if route := routeFrom(ctx); route != "" {
		hdr.Set(routing.HeaderName, route)
	}
	return connectudp.Dialer{CC: d.cc, Authority: d.authority, Header: hdr}.Dial(ctx, dst)
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
