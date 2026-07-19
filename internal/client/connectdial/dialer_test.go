package connectdial

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"quicdiver/internal/client/nat46"
	"quicdiver/internal/server/netstack"
)

// Клиентский диалер обязан уметь UDP, а не только TCP.
//
// Движок отдаёт локальному стеку и TCP, и UDP — с тех пор как UDP перевели с
// сырых датаграмм на CONNECT-UDP. Стек приходит с UDP-флоу сюда, и отказ здесь
// означал, что UDP молча пропадал: TCP-приложения работали, а голосовая связь
// молчала. Ровно это и наблюдалось вживую.
//
// Живого соединения тут нет, поэтому дозвон всё равно не удастся; важно, ЧЕМ
// именно он не удастся — «не поддерживается» означает, что метод не реализован.
func TestDialerImplementsUDP(t *testing.T) {
	var d netstack.Dialer = Dialer{Authority: "node.example"}

	_, err := d.DialUDP(context.Background(), netip.MustParseAddrPort("8.8.8.8:53"))
	if err == nil {
		t.Fatal("дозвон без соединения прошёл — проверка ни о чём")
	}
	if notImplemented(err) {
		t.Fatalf("UDP не реализован — флоу будет молча пропадать: %v", err)
	}
}

// Тот же контракт для nat46: он оборачивает диалер и обязан пропускать UDP
// внутрь, иначе IPv6-only хосты теряют UDP так же тихо.
func TestNAT46PassesUDPThrough(t *testing.T) {
	var d netstack.Dialer = nat46.Dialer{Inner: Dialer{Authority: "node.example"}}

	_, err := d.DialUDP(context.Background(), netip.MustParseAddrPort("8.8.8.8:53"))
	if err != nil && notImplemented(err) {
		t.Fatalf("nat46 не пропускает UDP: %v", err)
	}
}

// UDP-потоку нужен authority узла: целевой адрес у него в пути запроса, а сам
// запрос адресуется узлу.
func TestUDPRequiresAuthority(t *testing.T) {
	_, err := Dialer{}.DialUDP(context.Background(), netip.MustParseAddrPort("8.8.8.8:53"))
	if err == nil {
		t.Fatal("дозвон без настроек прошёл")
	}
}

func notImplemented(err error) bool {
	s := err.Error()
	return strings.Contains(s, "не CONNECT-стримом") || strings.Contains(s, "не поддерж")
}
