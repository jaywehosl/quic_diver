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

// udpBufSize — размер буферов UDP-сокета. Слишком малые теряют датаграммы при
// всплесках; слишком большие дают bufferbloat (очередь копится → RTT под
// нагрузкой растёт). Ориентир — покрыть BDP (800Мбит×15мс ≈ 1.4МБ) с запасом,
// не больше. ОС может урезать до системного лимита (Linux net.core.rmem_max).
const udpBufSize = 2 << 20

func setUDPBuffers(pc *net.UDPConn) {
	_ = pc.SetReadBuffer(udpBufSize)
	_ = pc.SetWriteBuffer(udpBufSize)
}

// retiredBufSize — до скольки урезать буферы покинутого сокета (см. retire).
const retiredBufSize = 4 << 10

// transportSocket — «транспорт + сокет + путь» для одного сетевого пути.
// path == nil у исходного пути: он создан через Dial, объекта Path у него нет.
type transportSocket struct {
	tr   *quic.Transport
	pc   net.PacketConn
	path *quic.Path
}

// Conn — одна QUIC-сессия до узла.
type Conn struct {
	qc *quic.Conn

	mu       sync.Mutex
	tr       *quic.Transport   // активный транспорт (сокет текущего пути)
	pc       net.PacketConn    // сокет активного пути
	path     *quic.Path        // путь активного транспорта (nil у исходного)
	prev     []transportSocket // покинутые пути: живут до Close, но разоружены
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

// Traffic — счётчики пакетов сессии. По ним видно «мы шлём, а в ответ тишина»:
// именно так выглядит слетевший NAT-маппинг, когда сессия формально ещё жива.
type Traffic struct {
	Sent, Received uint64
}

// Traffic отдаёт текущие счётчики.
func (c *Conn) Traffic() Traffic {
	st := c.qc.ConnectionStats()
	return Traffic{Sent: st.PacketsSent, Received: st.PacketsReceived}
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
	setUDPBuffers(pc)
	newTr := &quic.Transport{Conn: pc}

	path, err := c.qc.AddPath(newTr)
	if err != nil {
		// AddPath не удался — сессия в этот транспорт не попала, закрывать безопасно
		newTr.Close()
		return err
	}
	// С этого момента сессия зарегистрирована в newTr, и закрывать его нельзя:
	// Transport.Close() делает destroy всем своим соединениям, то есть убьёт ту
	// самую сессию, которую мы переносим. Откатываемся через abandon.
	if err := path.Probe(ctx); err != nil {
		c.abandon(newTr, pc, path)
		return err
	}
	if err := path.Switch(); err != nil {
		c.abandon(newTr, pc, path)
		return err
	}

	c.mu.Lock()
	old := transportSocket{tr: c.tr, pc: c.pc, path: c.path}
	c.prev = append(c.prev, old)
	c.tr, c.pc, c.path = newTr, pc, path
	c.mu.Unlock()

	c.retire(old)
	return nil
}

// abandon откатывает неудавшийся переезд, не тронув сессию.
//
// Закрыть транспорт нельзя (destroy убьёт сессию), поэтому путь бросаем, сокет
// разоружаем и держим до Close. Это цена попытки: при мёртвой сети supervisor
// пробует чинить раз в несколько секунд, и каждая неудача оставляет сокет — но
// разоружённый он стоит килобайты, а не мегабайты буферов.
//
// Раньше здесь стоял newTr.Close(), и первая же неудачная попытка обрывала
// связь: сессия умирала с «transport closed» вместо того, чтобы дождаться
// возврата сети.
func (c *Conn) abandon(tr *quic.Transport, pc net.PacketConn, path *quic.Path) {
	_ = path.Close()
	disarm(pc)
	c.mu.Lock()
	c.prev = append(c.prev, transportSocket{tr: tr, pc: pc, path: path})
	c.mu.Unlock()
}

// disarm урезает буферы сокета, который больше не нужен: память ядра
// возвращается, сам сокет остаётся жить до конца сессии.
func disarm(pc net.PacketConn) {
	if u, ok := pc.(*net.UDPConn); ok {
		_ = u.SetReadBuffer(retiredBufSize)
		_ = u.SetWriteBuffer(retiredBufSize)
	}
}

// retire разоружает путь, с которого мы ушли.
//
// Закрыть его нельзя: Transport.Close() рвёт ВСЕ соединения своего транспорта —
// включая ту самую сессию, которую мы только что перевезли (проверено тестом:
// после закрытия сессия отдаёт «transport closed»). Отвязать сессию от транспорта
// quic-go v0.60 не позволяет, поэтому сокет живёт до конца сессии.
//
// Но держать на нём буферы незачем: их 2 МБ на сокет (см. udpBufSize), а на
// мобильном за поездку набегают десятки переездов — это сотни мегабайт в ядре ни
// за чем. Поэтому урезаем буферы до минимума: память возвращается, сокет и его
// читающая горутина остаются (несколько КБ на путь).
//
// Path.Close() дополнительно говорит quic-go больше этот путь не использовать.
// У исходного пути (из Dial) объекта Path нет — он просто остаётся простаивать.
func (c *Conn) retire(old transportSocket) {
	if old.path != nil {
		// активный путь закрыть нельзя, но этот уже покинут — ошибка тут означала
		// бы, что переключение не состоялось
		if err := old.path.Close(); err != nil {
			return
		}
	}
	disarm(old.pc)
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
	setUDPBuffers(pc)
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
//
// Окна — чуть выше BDP и НЕ больше: BDP пути ≈ 768 Мбит × 14 мс ≈ 1.3 МБ.
// Раздутые окна (пробовали 32/64 МБ) разрешают держать в полёте десятки
// мегабайт — они встают в очередь на пути, и это классический bufferbloat:
// замерено RTT под нагрузкой p95 3.4 с (против 32 мс) и throughput 117 Мбит
// (против 560). Стартовое окно чуть больше дефолтных 512 КБ, чтобы не ждать
// авто-тюнинг, потолок оставляем близким к дефолту quic-go.
func DefaultConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
		// Idle — компромисс между двумя видами обрыва.
		//
		// Короткий (роутер пересобрал PPPoE за десяток секунд): сессию убивать
		// нельзя — оборвались бы все TCP приложений, хотя связь вот-вот вернётся и
		// QUIC доедет сам. Значит таймаут должен быть заметно больше типичного
		// обрыва.
		//
		// Длинный (сети нет минуту и дольше): держать мёртвую сессию незачем —
		// починить её нечем. Каждый переезд требует нового connection ID, а выдаёт
		// их узел по сети, которой нет; запас конечен и после него не помогает даже
		// вернувшаяся связь. Спасает только новый туннель, а чтобы его поднять,
		// сессия должна сперва умереть. Значит таймаут должен быть и не слишком
		// большим: всё это время пользователь сидит без интернета, который уже есть.
		MaxIdleTimeout: 45 * time.Second,
		// Keep-alive заметно короче типичного NAT-таймаута (30-60 с): молчащий
		// маппинг роутер выбрасывает, и путь ломался бы на ровном месте.
		KeepAlivePeriod:                15 * time.Second,
		InitialStreamReceiveWindow:     2 << 20, // ~1.5x BDP
		MaxStreamReceiveWindow:         6 << 20, // дефолт quic-go
		InitialConnectionReceiveWindow: 3 << 20,
		MaxConnectionReceiveWindow:     15 << 20, // дефолт quic-go
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
