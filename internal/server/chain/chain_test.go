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
	d := New(nil, "upstream.example") // cc не нужен: до него не дойдёт
	ctx := WithHops(context.Background(), 0)
	if _, err := d.DialTCP(ctx, mustAddrPort()); err == nil {
		t.Fatal("dial при нулевом hop-limit прошёл — защита от петли не работает")
	}
}

// UDP защищён от петли так же, как TCP: он тоже идёт стримом с hop-limit, а не
// сырыми датаграммами, у которых заголовков нет.
func TestDialUDPRefusesAtZeroHops(t *testing.T) {
	d := New(nil, "upstream.example")
	ctx := WithHops(context.Background(), 0)
	if _, err := d.DialUDP(ctx, mustAddrPort()); err == nil {
		t.Fatal("UDP-dial при нулевом hop-limit прошёл — защита от петли не работает")
	}
}

// Метка маршрута доезжает из контекста в заголовок: без этого следующий узел не
// узнал бы, куда вести дальше, и выпустил бы флоу у себя.
func TestRouteTravelsInContext(t *testing.T) {
	ctx := WithRoute(context.Background(), "n4")
	if got := routeFrom(ctx); got != "n4" {
		t.Fatalf("метка из контекста = %q", got)
	}
	if got := routeFrom(context.Background()); got != "" {
		t.Fatalf("без метки получено %q", got)
	}
}

func mustAddrPort() netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr("1.2.3.4"), 443) }
