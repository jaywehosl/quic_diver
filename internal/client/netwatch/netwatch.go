// Package netwatch следит за сетевыми параметрами машины и сообщает об их смене.
//
// Нужен supervisor'у (arch4): при переезде Wi-Fi↔LTE или пересборке PPPoE
// локальный адрес меняется, старый сокет умирает, и QUIC-сессию надо перевести на
// новый путь — иначе соединения приложений оборвутся.
//
// Опрос, а не события ОС: подписка на изменения устроена у каждой платформы
// по-своему (NotifyIpInterfaceChange, NWPathMonitor, ConnectivityManager), а
// опрос одинаков везде и стоит один UDP-сокет без трафика. Задержка до Interval
// ничем не грозит: QUIC держит сессию keep-alive'ом 15 с и idle-таймаутом 30 с.
package netwatch

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// DefaultInterval — как часто сверять состояние.
const DefaultInterval = 2 * time.Second

// State — то, от чего зависят наши решения при смене сети.
type State struct {
	// Primary — локальный адрес, с которого уходит трафик наружу. Его смена и
	// означает переезд в другую сеть.
	Primary netip.Addr
	// HasIPv6 — есть ли свой глобальный IPv6. От этого зависит, нужен ли синтез
	// A для v6-only хостов (nat46).
	HasIPv6 bool
}

// Equal — совпадают ли состояния.
func (s State) Equal(o State) bool {
	return s.Primary == o.Primary && s.HasIPv6 == o.HasIPv6
}

// Current снимает текущее состояние.
func Current(hasIPv6 func() bool) (State, error) {
	addr, err := primaryAddr()
	if err != nil {
		return State{}, err
	}
	return State{Primary: addr, HasIPv6: hasIPv6()}, nil
}

// Watcher периодически снимает состояние и сообщает об изменениях.
type Watcher struct {
	// Interval — период опроса. 0 → DefaultInterval.
	Interval time.Duration
	// HasIPv6 — проверка наличия своего IPv6 (nat46.HostHasIPv6).
	HasIPv6 func() bool
}

// Run шлёт в ch новое состояние при каждом изменении и блокируется до отмены ctx.
//
// Первое состояние не шлёт: оно уже известно вызывающему на старте, а лишний
// «переезд» вызвал бы миграцию на тот же самый адрес.
func (w Watcher) Run(ctx context.Context, initial State, ch chan<- State) {
	interval := w.Interval
	if interval == 0 {
		interval = DefaultInterval
	}
	hasV6 := w.HasIPv6
	if hasV6 == nil {
		hasV6 = func() bool { return false }
	}

	t := time.NewTicker(interval)
	defer t.Stop()

	last := initial
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur, err := Current(hasV6)
		if err != nil {
			// Сети сейчас нет вовсе (переезд в процессе). Не считаем это
			// состоянием: как только адрес появится, увидим его следующим тиком.
			continue
		}
		if cur.Equal(last) {
			continue
		}
		last = cur
		select {
		case ch <- cur:
		case <-ctx.Done():
			return
		}
	}
}

// primaryAddr — адрес, с которого уходит трафик по маршруту наружу. Сокет ничего
// не шлёт: UDP-connect только выбирает маршрут.
func primaryAddr() (netip.Addr, error) {
	c, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errNoAddr
	}
	a, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.Addr{}, errNoAddr
	}
	return a.Unmap(), nil
}

type errString string

func (e errString) Error() string { return string(e) }

const errNoAddr = errString("netwatch: не определить локальный адрес")
