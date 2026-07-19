package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// BundleScheme — схема ссылки-бандла.
const BundleScheme = "qd://"

// Bundle — начальная конфигурация клиента одной строкой.
//
// Пользователю дают приложение и ссылку; он вставляет её — и клиент знает, куда
// подключаться и чем представляться. Всё остальное (узлы сети, лимиты,
// резервные точки) приезжает потом подпиской по туннелю.
//
// Публичной страницы подписки у нас нет намеренно: доступная всем ссылка
// парсится, блокируется и позволяет перебором узнать состав сети. Поэтому
// бандл несёт данные сам и передаётся человеку напрямую.
//
// Поля короткие: ссылку носят в мессенджере и в QR-коде, и каждый лишний байт
// удлиняет её без всякой пользы.
type Bundle struct {
	// V — версия формата. Позволит менять состав, не ломая старые ссылки.
	V int `json:"v"`
	// T — токен доступа.
	T string `json:"t"`
	// E — точки входа: адрес и SNI.
	E []BundleEntry `json:"e"`
	// N — имя (для показа человеку: «сеть такая-то»).
	N string `json:"n,omitempty"`
}

// BundleEntry — точка входа в короткой записи.
type BundleEntry struct {
	// A — адрес host:port.
	A string `json:"a"`
	// S — SNI: настоящий домен, когда адрес задан голым IP. Тогда DNS в
	// подключении не участвует, а сертификат остаётся валидным.
	S string `json:"s,omitempty"`
	// L — человеческое имя точки.
	L string `json:"l,omitempty"`
}

// ErrNotBundle — строка не похожа на ссылку-бандл.
var ErrNotBundle = errors.New("config: это не ссылка QUIC Diver")

// ParseBundle разбирает ссылку вида qd://<base64url>.
//
// Пробелы и переводы строк срезаются: ссылку копируют из мессенджера, где она
// легко ловит и то, и другое, а ронять человека на невидимом символе — худший
// способ начать знакомство с программой.
func ParseBundle(s string) (Bundle, error) {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)

	if !strings.HasPrefix(strings.ToLower(s), BundleScheme) {
		return Bundle{}, ErrNotBundle
	}
	payload := s[len(BundleScheme):]
	// Хвостовой слэш появляется, когда ссылку прогоняют через что-то, считающее
	// её адресом.
	payload = strings.TrimSuffix(payload, "/")

	raw, err := decodeBase64(payload)
	if err != nil {
		return Bundle{}, fmt.Errorf("%w: %v", ErrNotBundle, err)
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return Bundle{}, fmt.Errorf("%w: %v", ErrNotBundle, err)
	}
	if b.T == "" {
		return Bundle{}, errors.New("config: в ссылке нет токена")
	}
	if len(b.E) == 0 || b.E[0].A == "" {
		return Bundle{}, errors.New("config: в ссылке нет точки входа")
	}
	return b, nil
}

// decodeBase64 принимает обе разновидности base64 и с дополнением, и без.
//
// Мессенджеры и панели кодируют по-разному; требовать одну разновидность
// значило бы отвергать половину рабочих ссылок.
func decodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("не разбирается как base64")
}

// String собирает ссылку обратно.
func (b Bundle) String() string {
	if b.V == 0 {
		b.V = 1
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return ""
	}
	return BundleScheme + base64.RawURLEncoding.EncodeToString(raw)
}

// Apply переносит бандл в настройки.
//
// Точки входа заменяются целиком, а не дополняются: ссылка описывает сеть, в
// которую человека приглашают, и оставлять рядом адреса прежней — верный способ
// подключиться не туда.
func (c *Config) Apply(b Bundle) {
	entries := make([]Entry, 0, len(b.E))
	for _, e := range b.E {
		if e.A == "" {
			continue
		}
		entries = append(entries, Entry{Addr: e.A, SNI: e.S})
	}
	c.Node.Entries = entries
	c.Node.Token = b.T
}
