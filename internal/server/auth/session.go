package auth

import (
	"context"
	"net/http"
	"sync"
)

// HeaderToken — прикладной заголовок с токеном. Едет в QUIC/TLS, для DPI невидим.
// Имя нейтральное: под шифром его не видно, но и в отладочных дампах не кричит.
const HeaderToken = "X-Qd-Token"

// HeaderHWID — отпечаток машины клиента, для учёта устройств. Едет там же, под
// шифрованием, снаружи не виден.
//
// Считает его КЛИЕНТ, поэтому пропатченный клиент подделает: это заслон от
// бытовой раздачи токена знакомым, а не защита. Настоящий предел ставит лимит
// одновременных сессий — живое соединение подделать нельзя.
const HeaderHWID = "X-Qd-Hwid"

// Session — авторизация одной QUIC-сессии. Узел проверяет токен ОДИН раз на
// сессию (не на каждый стрим): connect-ip туннель и все CONNECT-стримы идут по
// одной QUIC-сессии и наследуют её доверие. Дёшево (один поход в БД) и не
// зависит от того, дал ли connect-ip-go положить заголовок в свой запрос.
type Session struct {
	mu   sync.Mutex
	role Role
	hash string
	// hwid — отпечаток машины, предъявленный при авторизации.
	//
	// Живёт здесь, а не читается из текущего запроса: клиент шлёт его один раз,
	// на /qd-auth, а нужен он позже — когда поднимается туннель (это уже другой
	// запрос, и заголовка в нём нет).
	hwid  string
	ready bool
}

// Authorize отмечает сессию авторизованной с данной ролью. Хеш нужен дальше для
// назначения адреса из БД (пул адресов привязан к токену).
func (s *Session) Authorize(role Role, hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.role, s.hash, s.ready = role, hash, true
}

// SetHWID запоминает отпечаток машины, предъявленный при авторизации.
func (s *Session) SetHWID(hwid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hwid = hwid
}

// HWID — отпечаток машины этой сессии (пусто, если клиент его не прислал).
func (s *Session) HWID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hwid
}

// Status — авторизована ли сессия, и если да — роль и хеш токена.
func (s *Session) Status() (role Role, hash string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.role, s.hash, s.ready
}

// Authorized — короткая проверка доступа.
func (s *Session) Authorized() bool {
	_, _, ok := s.Status()
	return ok
}

type ctxKey struct{}

// NewSessionContext вешает свежую (неавторизованную) сессию на контекст QUIC-
// соединения. Ставится из http3.Server.ConnContext, поэтому доходит до каждого
// хендлера этой сессии.
func NewSessionContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, &Session{})
}

// SessionFrom достаёт сессию из контекста запроса. nil, если auth не смонтирован.
func SessionFrom(ctx context.Context) *Session {
	s, _ := ctx.Value(ctxKey{}).(*Session)
	return s
}

// TokenFromRequest достаёт предъявленный токен из запроса. Пусто, если нет или
// не похож на наш — чтобы не ходить в БД за заведомым мусором.
func TokenFromRequest(r *http.Request) string {
	tok := r.Header.Get(HeaderToken)
	if !LooksLikeToken(tok) {
		return ""
	}
	return tok
}
