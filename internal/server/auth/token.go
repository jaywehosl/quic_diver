// Package auth — токены доступа к узлу.
//
// Одна сущность = один токен. Роль внутри токена не зашита: она лежит в БД рядом
// с хешем. Токен предъявляется в прикладном слое (Extended CONNECT заголовок),
// уже под QUIC/TLS, поэтому для DPI невидим — «не в заголовках пакетов» из ТЗ
// значит не в QUIC/IP-заголовках, а здесь прикладной уровень под шифром.
//
// В БД лежит ТОЛЬКО хеш. Разбор: каждый предъявляет свой токен (клиент — из
// конфига, узел — из деплой-параметров, админ — у человека), а проверяющий
// держит хеш. Значит чужой токен в открытом виде не нужен никому, и реплика БД,
// утёкшая с чужого VPS, бесполезна: войти по хешу нельзя, брутфорс высоко-
// энтропийного токена невозможен.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Role — что токену позволено. Network-wide: токен действует на любом узле сети
// (клиент может подключаться к разным входным узлам — arch2).
type Role string

const (
	// RoleUser — клиент: туннель, DNS. Массовый, отзывается через БД.
	RoleUser Role = "user"
	// RoleAdmin — администратор: управление узлом и его БД. Единый на всю сеть.
	RoleAdmin Role = "admin"
	// RoleNode — соседний узел: цепочки, healthcheck, репликация БД (чтение).
	// Намеренно НЕ управляет: компрометация узла не должна давать право писать.
	RoleNode Role = "node"
)

// Valid — известная ли роль.
func (r Role) Valid() bool {
	switch r {
	case RoleUser, RoleAdmin, RoleNode:
		return true
	}
	return false
}

// prefix — узнаваемая метка токена (как у ghp_/sk-): помогает отсеять мусор до
// обращения в БД и заметить утечку в логах/репозиториях.
const prefix = "qd_"

// tokenBytes — энтропия токена. 32 байта = 256 бит: брутфорс невозможен, поэтому
// хеш без соли и без argon2 (лишняя латентность на каждый коннект не нужна).
const tokenBytes = 32

// Generate выпускает новый токен в открытом виде. Показывается один раз при
// создании; в БД уходит только его Hash.
func Generate() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("генерация токена: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Hash возвращает hex SHA-256 токена — то, что хранится в БД. SHA-256 достаточно:
// вход высокоэнтропийный, словарной атаки нет.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// LooksLikeToken — грубая проверка формы до похода в БД (не признак валидности).
func LooksLikeToken(s string) bool {
	return strings.HasPrefix(s, prefix) && len(s) > len(prefix)+16
}

// EqualHash сравнивает два хеша за постоянное время — чтобы по времени ответа
// нельзя было подбирать хеш побайтно.
func EqualHash(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
