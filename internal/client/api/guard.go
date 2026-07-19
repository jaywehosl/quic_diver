// Package api — локальное HTTP-API клиента: на нём стоит веб-панель.
//
// Панель по ТЗ единственный GUI, и она же — панель управления СЕРВЕРОМ (по
// админ-токену). Браузер не может ходить в admin-API узла напрямую: там QUIC,
// токены в заголовках и сертификаты, которых он не знает. Поэтому запросы идут
// сюда, а клиент проксирует их в узел по уже поднятому туннелю.
package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
)

// Token — ключ доступа к панели, живущий одну сессию клиента.
//
// Слушать 127.0.0.1 недостаточно: ЛЮБАЯ открытая в браузере страница может
// слать запросы на localhost, и без ключа она управляла бы клиентом — включала
// перехват, читала конфиг с токеном доступа, гасила туннель. Ключ появляется
// в адресе, который клиент сам открывает, и наружу не уходит.
type Token string

// NewToken выдаёт ключ на текущий запуск.
//
// Не сохраняем на диск: перезапуск клиента обязан обесценить старые вкладки,
// иначе оставленная открытой панель остаётся действующим пультом.
func NewToken() (Token, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return Token(hex.EncodeToString(b[:])), nil
}

// Equal сравнивает ключи за постоянное время.
func (t Token) Equal(other string) bool {
	return subtle.ConstantTimeCompare([]byte(t), []byte(other)) == 1
}

// guard — три замка на локальном API.
//
// Каждый закрывает свою дыру, и по отдельности ни один не достаточен:
//
//  1. Адрес. Слушаем только петлю, но этого мало — см. ниже.
//  2. Ключ сессии. Отсекает чужие страницы, которые знают адрес, но не ключ.
//  3. Origin/Sec-Fetch-Site. Отсекает случай, когда ключ всё-таки утёк в
//     историю браузера или в чужую вкладку: запрос со стороннего сайта не
//     пройдёт, даже предъявив верный ключ.
//
// Плюс требование JSON-тела на изменяющих запросах: форма со стороннего сайта
// умеет слать только «простые» типы, а на application/json браузер обязан
// сделать preflight — который мы не разрешаем.
func guard(tok Token, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !fromLoopback(r) {
			http.NotFound(w, r) // снаружи панели просто нет
			return
		}
		if !originAllowed(r) {
			http.Error(w, "запрос со стороннего источника", http.StatusForbidden)
			return
		}
		if !tok.Equal(tokenFrom(r)) {
			http.Error(w, "нужен ключ панели", http.StatusUnauthorized)
			return
		}
		if changes(r.Method) && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			// Отсекает форму со стороннего сайта: она не умеет слать JSON, а
			// значит браузер сделает preflight, которого мы не разрешаем.
			http.Error(w, "нужен Content-Type: application/json", http.StatusUnsupportedMediaType)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// fromLoopback — пришёл ли запрос с этой же машины.
func fromLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// tokenFrom достаёт ключ из заголовка или из адреса.
//
// Из адреса — потому что первый заход в панель делается ссылкой, и положить
// заголовок туда неоткуда. Дальше страница носит ключ в заголовке.
func tokenFrom(r *http.Request) string {
	if v := r.Header.Get(HeaderPanelToken); v != "" {
		return v
	}
	return r.URL.Query().Get("token")
}

// HeaderPanelToken — заголовок с ключом панели.
const HeaderPanelToken = "X-Qd-Panel"

// originAllowed — пришёл ли запрос от самой панели, а не со стороннего сайта.
//
// Пустой Origin оставляем: его нет у обычной навигации (открыли ссылку) и у
// curl, а межсайтовые запросы браузер всегда помечает.
func originAllowed(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "cross-site", "same-site":
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	host, err := hostOf(origin)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func hostOf(origin string) (string, error) {
	origin = strings.TrimPrefix(strings.TrimPrefix(origin, "http://"), "https://")
	if h, _, err := net.SplitHostPort(origin); err == nil {
		return h, nil
	}
	return origin, nil
}

func changes(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}
