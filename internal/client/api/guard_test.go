package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// okHandler отмечает, что запрос дошёл до сути.
func okHandler() (http.Handler, *bool) {
	reached := false
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}), &reached
}

func panelReq(method, target, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.RemoteAddr = "127.0.0.1:54321"
	return r
}

// Без ключа панель не отвечает: иначе любая открытая в браузере страница
// управляла бы клиентом — включала перехват, читала конфиг с токеном доступа.
func TestRejectsWithoutToken(t *testing.T) {
	h, reached := okHandler()
	w := httptest.NewRecorder()
	guard("секрет", h).ServeHTTP(w, panelReq(http.MethodGet, "/api/status", ""))

	if *reached {
		t.Fatal("запрос без ключа дошёл до обработчика")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("статус %d", w.Code)
	}
}

// Ключ принимается и заголовком, и из адреса: первый заход делается ссылкой,
// куда заголовок положить неоткуда.
func TestAcceptsTokenFromHeaderAndQuery(t *testing.T) {
	for _, name := range []string{"заголовок", "адрес"} {
		h, reached := okHandler()
		r := panelReq(http.MethodGet, "/api/status", "")
		if name == "заголовок" {
			r.Header.Set(HeaderPanelToken, "секрет")
		} else {
			r = panelReq(http.MethodGet, "/api/status?token=секрет", "")
		}
		guard("секрет", h).ServeHTTP(httptest.NewRecorder(), r)
		if !*reached {
			t.Fatalf("ключ через %s не принят", name)
		}
	}
}

// Чужой ключ не подходит.
func TestRejectsWrongToken(t *testing.T) {
	h, reached := okHandler()
	r := panelReq(http.MethodGet, "/api/status", "")
	r.Header.Set(HeaderPanelToken, "не тот")
	guard("секрет", h).ServeHTTP(httptest.NewRecorder(), r)

	if *reached {
		t.Fatal("чужой ключ принят")
	}
}

// Снаружи машины панели просто нет — даже с верным ключом.
func TestRejectsRemoteAddress(t *testing.T) {
	h, reached := okHandler()
	r := panelReq(http.MethodGet, "/api/status", "")
	r.RemoteAddr = "203.0.113.10:40000"
	r.Header.Set(HeaderPanelToken, "секрет")

	w := httptest.NewRecorder()
	guard("секрет", h).ServeHTTP(w, r)
	if *reached {
		t.Fatal("запрос снаружи дошёл до обработчика")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("статус %d — снаружи панели не должно быть видно вовсе", w.Code)
	}
}

// Сторонний сайт не управляет клиентом, даже если ключ ему известен: браузер
// помечает такие запросы, и метка важнее ключа.
func TestRejectsCrossSite(t *testing.T) {
	for _, site := range []string{"cross-site", "same-site"} {
		h, reached := okHandler()
		r := panelReq(http.MethodPost, "/api/connect", "{}")
		r.Header.Set(HeaderPanelToken, "секрет")
		r.Header.Set("Sec-Fetch-Site", site)

		w := httptest.NewRecorder()
		guard("секрет", h).ServeHTTP(w, r)
		if *reached {
			t.Fatalf("запрос с %s дошёл до обработчика", site)
		}
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: статус %d", site, w.Code)
		}
	}
}

// Чужой Origin — отказ.
func TestRejectsForeignOrigin(t *testing.T) {
	h, reached := okHandler()
	r := panelReq(http.MethodPost, "/api/connect", "{}")
	r.Header.Set(HeaderPanelToken, "секрет")
	r.Header.Set("Origin", "https://evil.example")

	guard("секрет", h).ServeHTTP(httptest.NewRecorder(), r)
	if *reached {
		t.Fatal("запрос с чужого Origin принят")
	}
}

// Свой Origin проходит: панель работает.
func TestAcceptsOwnOrigin(t *testing.T) {
	h, reached := okHandler()
	r := panelReq(http.MethodPost, "/api/connect", "{}")
	r.Header.Set(HeaderPanelToken, "секрет")
	r.Header.Set("Origin", "http://127.0.0.1:8765")
	r.Header.Set("Sec-Fetch-Site", "same-origin")

	guard("секрет", h).ServeHTTP(httptest.NewRecorder(), r)
	if !*reached {
		t.Fatal("запрос от самой панели отклонён")
	}
}

// Изменяющий запрос без JSON-тела не проходит: форма со стороннего сайта умеет
// слать только простые типы, а на application/json браузер обязан сделать
// preflight, которого мы не разрешаем.
func TestRejectsNonJSONWrites(t *testing.T) {
	h, reached := okHandler()
	r := httptest.NewRequest(http.MethodPost, "/api/connect",
		strings.NewReader("a=1"))
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set(HeaderPanelToken, "секрет")

	w := httptest.NewRecorder()
	guard("секрет", h).ServeHTTP(w, r)
	if *reached {
		t.Fatal("форма со стороннего сайта прошла бы этим путём")
	}
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("статус %d", w.Code)
	}
}

// Чтение без тела — проходит: это обычный GET панели.
func TestAllowsPlainReads(t *testing.T) {
	h, reached := okHandler()
	r := panelReq(http.MethodGet, "/api/status", "")
	r.Header.Set(HeaderPanelToken, "секрет")

	guard("секрет", h).ServeHTTP(httptest.NewRecorder(), r)
	if !*reached {
		t.Fatal("обычное чтение отклонено")
	}
}

// Ключ на каждый запуск свой: перезапуск клиента обязан обесценить оставленные
// открытыми вкладки, иначе они остаются действующим пультом.
func TestTokensAreUniquePerRun(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewToken()
	if a == b || a == "" {
		t.Fatalf("ключи повторяются: %q / %q", a, b)
	}
}
