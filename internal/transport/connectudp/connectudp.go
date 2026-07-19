// Package connectudp — проксирование UDP-флоу через HTTP/3 по RFC 9298
// (CONNECT-UDP) поверх HTTP-датаграмм (RFC 9297).
//
// Зачем он вместо прежней схемы. Раньше UDP клиента ехал сырыми IP-пакетами в
// connect-ip датаграммах, а метка выхода жила в src-адресе: пул узла нарезался
// на подсети, по одной на выход, и клиенту выдавался адрес в каждой. Схема
// упиралась в два потолка — клиенту нужен адрес на каждый выход (пул кончается),
// а при изменении набора узлов адреса уезжали и живые UDP-флоу рвались. Для
// балансировки, которая меняет выход на лету, это смертельно.
//
// Здесь UDP-флоу терминируется локальным стеком (как уже делается с TCP) и
// уезжает отдельным стримом, а метка маршрута едет ТЕМ ЖЕ заголовком, что у
// TCP. Отсюда главное: маршрутизация, транзит через промежуточные узлы и
// правила пишутся один раз на оба протокола, а смена выхода ничего не стоит
// адресации.
//
// Полезная нагрузка идёт HTTP-датаграммами, а не байтами стрима: UDP не должен
// получать ретрансмит и переупорядочивание — потеря обязана остаться потерей,
// иначе внутри туннеля образуется «надёжный UDP», ломающий тайминги приложений
// (тот же довод, по которому в гибриде UDP не ушёл в CONNECT-стрим). Стрим несёт
// только управление флоу: заголовки и время жизни.
//
// Границы датаграмм сохраняются: одна датаграмма = один UDP-пакет, поэтому пара
// Read/Write на возвращаемом net.Conn отображается в пакет один к одному.
package connectudp

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/quicvarint"
)

// Protocol — значение псевдо-заголовка :protocol расширенного CONNECT (RFC 9220).
const Protocol = "connect-udp"

// contextIDUDP — Context ID «обычной» UDP-нагрузки (RFC 9298, §5). Нулевой
// контекст зарезервирован под немодифицированные пейлоады; расширения (напр.
// сжатие заголовков) заняли бы другие ID, и такие датаграммы мы обязаны молча
// игнорировать, а не считать ошибкой соединения.
const contextIDUDP = 0

// pathPrefix — префикс URI-шаблона RFC 9298 (§3).
const pathPrefix = "/.well-known/masque/udp/"

// ErrForeignContext — датаграмма с чужим Context ID (несогласованное расширение).
var ErrForeignContext = errors.New("connectudp: чужой context ID")

// Path строит путь запроса для целевого адреса по шаблону RFC 9298.
func Path(dst netip.AddrPort) string {
	host := dst.Addr().String()
	// В сегменте пути двоеточия IPv6-литерала недопустимы — RFC 9298 требует
	// percent-encoding; квадратные скобки в сегмент не входят.
	if dst.Addr().Is6() {
		host = strings.ReplaceAll(host, ":", "%3A")
	}
	return pathPrefix + host + "/" + strconv.Itoa(int(dst.Port())) + "/"
}

// ParsePath разбирает путь CONNECT-UDP обратно в целевой адрес.
//
// Принимаем только адрес-литерал: узел не должен резолвить имя из чужого пути.
// Резолв уже сделан там, где известны правила клиента, и повторный на транзитном
// узле мог бы увести флоу на другой адрес.
func ParsePath(path string) (netip.AddrPort, error) {
	rest, ok := strings.CutPrefix(path, pathPrefix)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("connectudp: путь %q не по шаблону RFC 9298", path)
	}
	rest = strings.TrimSuffix(rest, "/")
	hostStr, portStr, ok := strings.Cut(rest, "/")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("connectudp: в пути %q нет порта", path)
	}
	hostStr = strings.ReplaceAll(hostStr, "%3A", ":")
	hostStr = strings.ReplaceAll(hostStr, "%3a", ":")
	addr, err := netip.ParseAddr(hostStr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("connectudp: адрес %q: %w", hostStr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("connectudp: порт %q: %w", portStr, err)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// encode упаковывает UDP-пейлоад в HTTP-датаграмму (Context ID + данные).
func encode(payload []byte) []byte {
	b := make([]byte, 0, quicvarint.Len(contextIDUDP)+len(payload))
	b = quicvarint.Append(b, contextIDUDP)
	return append(b, payload...)
}

// decode распаковывает HTTP-датаграмму. Чужой контекст → ErrForeignContext.
func decode(b []byte) ([]byte, error) {
	id, n, err := quicvarint.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("connectudp: битый context ID: %w", err)
	}
	if id != contextIDUDP {
		return nil, ErrForeignContext
	}
	return b[n:], nil
}
