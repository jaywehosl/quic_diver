package chain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// Запрос от клиента (без hop-заголовка) получает полный лимит и помечается как
// не-транзит: первый узел цепочки не должен принять его за петлю.
func TestHopsFromClientRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodConnect, "//1.2.3.4:443", nil)
	hops, fromClient := HopsFromRequest(r)
	if !fromClient {
		t.Fatal("клиентский запрос принят за транзит")
	}
	if hops != DefaultHops {
		t.Fatalf("hops=%d, ожидался DefaultHops=%d", hops, DefaultHops)
	}
}

// Транзит от другого узла несёт остаток лимита — берём как есть (он уже уменьшен
// отправителем).
func TestHopsFromTransitRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodConnect, "//1.2.3.4:443", nil)
	r.Header.Set(HopHeader, "3")
	hops, fromClient := HopsFromRequest(r)
	if fromClient {
		t.Fatal("транзит принят за клиентский запрос")
	}
	if hops != 3 {
		t.Fatalf("hops=%d, ожидалось 3", hops)
	}
}

// Транзит с нулём/мусором — петля или порча: hops<=0, узел обязан отказать.
func TestHopsExhaustedOrGarbage(t *testing.T) {
	for _, v := range []string{"0", "-1", "мусор"} {
		r := httptest.NewRequest(http.MethodConnect, "//1.2.3.4:443", nil)
		r.Header.Set(HopHeader, v)
		hops, fromClient := HopsFromRequest(r)
		if fromClient {
			t.Fatalf("%q принят за клиентский", v)
		}
		if hops > 0 {
			t.Fatalf("%q дал hops=%d, ожидался <=0 (отказ)", v, hops)
		}
	}
}

// На исчерпанном лимите Dialer не открывает стрим — иначе петля A→B→A крутилась
// бы, пока не кончатся стримы.
func TestDialTCPRefusesAtZeroHops(t *testing.T) {
	d := New(nil, nil, netip.Addr{}) // cc не нужен: до него не дойдёт
	ctx := WithHops(context.Background(), 0)
	if _, err := d.DialTCP(ctx, mustAddrPort()); err == nil {
		t.Fatal("dial при нулевом hop-limit прошёл — защита от петли не работает")
	}
}

// Без пакетного туннеля UDP обязан ОТКАЗАТЬ, а не выйти мимо цепочки: иначе
// UDP-выход выдал бы адрес транзитного узла вместо адреса цепочки.
func TestDialUDPRefusedWithoutTunnel(t *testing.T) {
	d := New(nil, nil, netip.Addr{})
	if _, err := d.DialUDP(context.Background(), mustAddrPort()); err != ErrUDPUnsupported {
		t.Fatalf("DialUDP вернул %v, ожидался ErrUDPUnsupported", err)
	}
}

func mustAddrPort() netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr("1.2.3.4"), 443) }
