package connectudp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

// Путь строится и разбирается обратно без потерь — иначе узел уведёт флоу не туда.
func TestPathRoundTrip(t *testing.T) {
	for _, s := range []string{"8.8.8.8:53", "1.1.1.1:443", "192.168.1.1:19302"} {
		want := netip.MustParseAddrPort(s)
		got, err := ParsePath(Path(want))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if got != want {
			t.Fatalf("%s → %s", want, got)
		}
	}
}

// IPv6 в сегменте пути обязан быть percent-encoded (RFC 9298): двоеточия ломают
// разбор пути.
func TestPathEncodesIPv6(t *testing.T) {
	want := netip.MustParseAddrPort("[2001:4860:4860::8888]:53")
	p := Path(want)
	if strings.Contains(strings.TrimPrefix(p, pathPrefix), ":") {
		t.Fatalf("двоеточия не закодированы: %s", p)
	}
	got, err := ParsePath(p)
	if err != nil {
		t.Fatalf("разбор %s: %v", p, err)
	}
	if got != want {
		t.Fatalf("%s → %s", want, got)
	}
}

// Чужой путь не должен приниматься за наш.
func TestParsePathRejectsForeign(t *testing.T) {
	for _, p := range []string{
		"/",
		"/index.html",
		"/.well-known/masque/udp/8.8.8.8/", // нет порта
		"/.well-known/masque/udp/не-адрес/53/", // не адрес
	} {
		if _, err := ParsePath(p); err == nil {
			t.Fatalf("путь %q принят", p)
		}
	}
}

// Датаграмма кодируется с нулевым контекстом и разбирается обратно.
func TestDatagramRoundTrip(t *testing.T) {
	payload := []byte("тестовый UDP-пейлоад")
	got, err := decode(encode(payload))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %q", got)
	}
}

// Пустой пейлоад — валидная UDP-датаграмма, а не ошибка.
func TestEmptyPayloadSurvives(t *testing.T) {
	got, err := decode(encode(nil))
	if err != nil || len(got) != 0 {
		t.Fatalf("пустая датаграмма: %q, %v", got, err)
	}
}

// Чужой Context ID — согласованное расширение, которого мы не знаем: такие
// датаграммы полагается игнорировать, а не рвать флоу.
func TestForeignContextRecognised(t *testing.T) {
	// Context ID 1 + данные.
	raw := append([]byte{0x01}, []byte("чужое")...)
	if _, err := decode(raw); !errors.Is(err, ErrForeignContext) {
		t.Fatalf("чужой контекст дал %v", err)
	}
}

// Распознавание запроса: наш — только расширенный CONNECT с нашим :protocol.
// Обычный CONNECT (TCP-флоу гибрида) и connect-ip идут другими путями.
func TestIsRequestDistinguishesProtocols(t *testing.T) {
	ours := &http.Request{
		Method: http.MethodConnect, Proto: Protocol,
		URL:  &url.URL{Scheme: "https", Host: "node.example", Path: Path(netip.MustParseAddrPort("8.8.8.8:53"))},
		Host: "node.example",
	}
	if !IsRequest(ours) {
		t.Fatal("наш запрос не распознан")
	}

	plain := httptest.NewRequest(http.MethodConnect, "https://host.example:443", nil)
	plain.Proto = "HTTP/3.0"
	if IsRequest(plain) {
		t.Fatal("обычный CONNECT принят за CONNECT-UDP")
	}

	connectIP := httptest.NewRequest(http.MethodConnect, "https://node.example/connect-ip", nil)
	connectIP.Proto = "connect-ip"
	if IsRequest(connectIP) {
		t.Fatal("connect-ip принят за CONNECT-UDP")
	}

	get := httptest.NewRequest(http.MethodGet, "https://node.example/", nil)
	if IsRequest(get) {
		t.Fatal("GET принят за CONNECT-UDP")
	}
}

// Цель достаётся из запроса — по ней узел решает, выпускать наружу или вести
// транзитом дальше.
func TestTargetFromRequest(t *testing.T) {
	want := netip.MustParseAddrPort("8.8.4.4:53")
	// Запрос собираем как его увидит узел: у расширенного CONNECT цель лежит в
	// :path. httptest.NewRequest для CONNECT разбирает цель как authority-form и
	// путь исказил бы.
	r := &http.Request{
		Method: http.MethodConnect,
		Proto:  Protocol,
		URL:    &url.URL{Scheme: "https", Host: "node.example", Path: Path(want)},
		Host:   "node.example",
	}
	got, err := Target(r)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("цель %s, ожидалась %s", got, want)
	}
}
