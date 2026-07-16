package nat46

import (
	"net"
	"net/netip"
)

// HostHasIPv6 — есть ли у машины собственный глобальный IPv6-адрес.
//
// Синтез нужен ровно тогда, когда его нет: с настоящим v6 приложение само пойдёт
// по AAAA (Happy Eyeballs, RFC 8305), а фиктивный A только вычерпывал бы пул и
// добавлял лишний AAAA-запрос на каждое v6-only имя.
//
// Считаем только глобальные (2000::/3). Link-local (fe80::/10) есть всегда и
// наружу не ведёт; ULA (fc00::/7) живёт внутри локалки и до интернета тоже не
// достаёт — по обоим v6-only хост недостижим, значит синтез всё равно нужен.
//
// Смотрим на адреса, а не на реальную достижимость: проверка связностью стоила бы
// секунд на старте. Адрес есть, а v6 не работает («broken IPv6») — редкий случай,
// и его лечит Happy Eyeballs на стороне приложения.
func HostHasIPv6() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.Is6() && addr.IsGlobalUnicast() && !isULA(addr) {
				return true
			}
		}
	}
	return false
}

// isULA — fc00::/7 (RFC 4193). IsGlobalUnicast() их не отсеивает.
func isULA(a netip.Addr) bool {
	return a.Is6() && a.As16()[0]&0xfe == 0xfc
}
