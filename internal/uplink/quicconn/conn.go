// Package quicconn — реализация uplink.Conn/Dialer поверх quic-go (v0.60).
//
// Это транспортный кирпич модели B: одна QUIC-сессия несёт весь трафик клиента.
// Датаграммы (RFC 9221) переносят IP-пакеты (позже — обёрнутые в connect-ip),
// потоки — крупные payload и будущая модель A. Conn держит собственный
// quic.Transport, поэтому умеет мигрировать на новый локальный сокет без разрыва
// сессии (arch4): смена Wi-Fi↔LTE, пересборка PPPoE.
package quicconn

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"

	"quicdiver/internal/uplink"
)

// ALPN — идентификатор протокола QUIC Diver в TLS-хендшейке.
const ALPN = "qd/1"

// defaultMaxDatagram — консервативная оценка лимита датаграммы до первого
// уточнения из DatagramTooLargeError (IPv6 min MTU 1280 минус заголовки).
const defaultMaxDatagram = 1200

// transportSocket — пара «транспорт + его сокет» для одного сетевого пути.
type transportSocket struct {
	tr *quic.Transport
	pc net.PacketConn
}

// Conn — одна QUIC-сессия до узла.
type Conn struct {
	qc *quic.Conn

	mu       sync.Mutex
	tr       *quic.Transport   // активный транспорт (сокет текущего пути)
	pc       net.PacketConn    // сокет активного пути
	prev     []transportSocket // старые пути после миграции, живут до Close
	remote   net.Addr
	maxDgram atomic.Int64
}

// SendDatagram шлёт ненадёжную датаграмму. При превышении лимита обновляет
// известный MaxDatagramSize (для MTU-инженерии модели B) и возвращает ошибку.
func (c *Conn) SendDatagram(b []byte) error {
	err := c.qc.SendDatagram(b)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		c.maxDgram.Store(tooLarge.MaxDatagramPayloadSize)
	}
	return err
}

// RecvDatagram принимает ненадёжную датаграмму.
func (c *Conn) RecvDatagram(ctx context.Context) ([]byte, error) {
	return c.qc.ReceiveDatagram(ctx)
}

// OpenStream открывает надёжный двунаправленный поток.
func (c *Conn) OpenStream(ctx context.Context) (uplink.Stream, error) {
	s, err := c.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil // *quic.Stream реализует io.ReadWriteCloser
}

// MaxDatagramSize — текущий известный лимит полезной датаграммы в байтах.
func (c *Conn) MaxDatagramSize() int {
	if v := c.maxDgram.Load(); v > 0 {
		return int(v)
	}
	return defaultMaxDatagram
}

// QUIC возвращает нижележащее *quic.Conn для слоёв поверх (http3/connect-ip).
// Миграция (Migrate) работает на этом же объекте, поэтому слои сверху переживают
// смену пути прозрачно — объект conn при миграции не пересоздаётся.
func (c *Conn) QUIC() *quic.Conn { return c.qc }

// Migrate переносит сессию на новый локальный UDP-сокет без разрыва (arch4).
// Открывает сокет на laddr, добавляет путь, валидирует его (PATH_CHALLENGE),
// переключается и закрывает старый транспорт.
func (c *Conn) Migrate(ctx context.Context, laddr *net.UDPAddr) error {
	pc, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	newTr := &quic.Transport{Conn: pc}

	path, err := c.qc.AddPath(newTr)
	if err != nil {
		newTr.Close()
		return err
	}
	if err := path.Probe(ctx); err != nil {
		path.Close()
		newTr.Close()
		return err
	}
	if err := path.Switch(); err != nil {
		path.Close()
		newTr.Close()
		return err
	}

	c.mu.Lock()
	c.prev = append(c.prev, transportSocket{tr: c.tr, pc: c.pc})
	c.tr, c.pc = newTr, pc
	c.mu.Unlock()

	// ВНИМАНИЕ: старый транспорт НЕ закрываем здесь — Transport.Close() рвёт все
	// свои соединения, включая нашу (только что мигрировавшую) сессию. Держим его
	// в c.prev, пока жива Conn.
	// TODO(quicdiver): grace-освобождение старых путей (ретайр connID + close по
	// таймеру), иначе при частой миграции на мобильном копятся сокеты (arch4).
	return nil
}

// Close закрывает сессию и все транспорты (активный + оставшиеся от миграций).
func (c *Conn) Close() error {
	err := c.qc.CloseWithError(0, "")
	c.mu.Lock()
	tr := c.tr
	prev := c.prev
	c.prev = nil
	c.mu.Unlock()
	if tr != nil {
		tr.Close()
	}
	for _, ts := range prev {
		if ts.tr != nil {
			ts.tr.Close()
		}
	}
	return err
}

var _ uplink.Conn = (*Conn)(nil)

// Dialer устанавливает Conn до узла.
type Dialer struct {
	// TLS — конфиг клиента. NextProtos дополняется ALPN, если пуст.
	TLS *tls.Config
	// QUIC — конфиг сессии. nil → DefaultConfig.
	QUIC *quic.Config
}

// Dial резолвит endpoint (host:port по домену — arch3) и устанавливает сессию.
func (d Dialer) Dial(ctx context.Context, endpoint string) (uplink.Conn, error) {
	raddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: pc}

	qc, err := tr.Dial(ctx, raddr, ensureALPN(d.TLS), configOrDefault(d.QUIC))
	if err != nil {
		tr.Close()
		return nil, err
	}
	c := &Conn{qc: qc, tr: tr, pc: pc, remote: raddr}
	c.maxDgram.Store(defaultMaxDatagram)
	return c, nil
}

var _ uplink.Dialer = Dialer{}

// DefaultConfig — базовый quic.Config для QUIC Diver.
func DefaultConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	}
}

func configOrDefault(c *quic.Config) *quic.Config {
	if c == nil {
		return DefaultConfig()
	}
	return c
}

func ensureALPN(t *tls.Config) *tls.Config {
	if t == nil {
		t = &tls.Config{}
	} else {
		t = t.Clone()
	}
	if len(t.NextProtos) == 0 {
		t.NextProtos = []string{ALPN}
	}
	return t
}
