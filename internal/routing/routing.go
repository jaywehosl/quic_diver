// Package routing — метка маршрута, общая для клиента и узла.
//
// Клиент по своим правилам решает, каким выходом уйти флоу, и кладёт метку в
// заголовок запроса (одинаково для TCP-CONNECT и CONNECT-UDP). Каждый узел на
// пути читает её и решает сам: он и есть указанный выход — выпускать наружу,
// иначе вести транзитом дальше, ПЕРЕДАВАЯ метку следующему.
//
// Раньше метку потреблял первый же узел: он выбирал себе аутбаунд из БД, а к
// следующему узлу шёл обычный запрос без метки. Второй хоп задавался не меткой,
// а конфигом первого — то есть узел был репитером по жёстко прописанной связи.
// Здесь узел становится свичем: маршрут живёт в трафике, а не в настройках.
package routing

import (
	"fmt"
	"strings"
)

// HeaderName — заголовок метки. Едет внутри QUIC/TLS, снаружи не виден.
const HeaderName = "Qd-Route"

// autoPrefix — метка «любой лучший узел из категории».
const autoPrefix = "auto:"

// Route — куда вести флоу.
//
// Нулевое значение — «наружу прямо здесь»: клиент без правил и старый клиент без
// метки должны обслуживаться, а не отвергаться.
type Route struct {
	// Node — идентификатор выходного узла. Пусто → выпускать здесь.
	Node string
	// Tag — категория для автоматического выбора («любой лучший из этих»).
	// Значим, когда Auto.
	Tag string
	// Auto — выбирать узел по категории, а не по имени.
	Auto bool
}

// Direct — выпустить наружу на текущем узле.
var Direct = Route{}

// Node строит метку на конкретный узел.
func Node(id string) Route { return Route{Node: id} }

// Auto строит метку «любой лучший узел из категории».
func Auto(tag string) Route { return Route{Tag: tag, Auto: true} }

// IsDirect — выпускать наружу здесь.
func (r Route) IsDirect() bool { return !r.Auto && r.Node == "" }

// String сериализует метку для заголовка.
func (r Route) String() string {
	switch {
	case r.Auto:
		return autoPrefix + r.Tag
	case r.Node == "":
		return "direct"
	default:
		return r.Node
	}
}

// Parse разбирает метку из заголовка.
//
// Пустая строка — не ошибка: так выглядит запрос клиента без правил и запрос
// старого клиента, не знающего про метки. Оба означают «выпускай здесь».
func Parse(s string) (Route, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || s == "direct":
		return Direct, nil
	case strings.HasPrefix(s, autoPrefix):
		tag := strings.TrimSpace(strings.TrimPrefix(s, autoPrefix))
		if tag == "" {
			return Route{}, fmt.Errorf("routing: пустая категория в метке %q", s)
		}
		return Auto(tag), nil
	default:
		// Идентификатор узла. Двоеточие зарезервировано под префиксы вроде
		// auto: — иначе неизвестный префикс молча приняли бы за имя узла и
		// увели флоу не туда.
		if strings.Contains(s, ":") {
			return Route{}, fmt.Errorf("routing: неизвестный вид метки %q", s)
		}
		return Node(s), nil
	}
}

// Decision — что делать узлу с флоу.
type Decision int

const (
	// Exit — выпустить наружу с этого узла.
	Exit Decision = iota
	// Transit — вести дальше, к узлу Decide.Next.
	Transit
)

// Decide решает судьбу флоу на узле.
//
// selfID — идентификатор текущего узла; pick выбирает лучший узел категории
// (возвращает пусто, если подходящих нет).
//
// Категория без живых узлов НЕ означает отказ: выпускаем наружу здесь. Глушить
// флоу из-за того, что резерв не нашёлся, — худшее из решений; пользователь
// останется без связи там, где мог бы выйти напрямую.
func (r Route) Decide(selfID string, pick func(tag string) string) (Decision, string) {
	target := r.Node
	if r.Auto {
		if pick == nil {
			return Exit, ""
		}
		target = pick(r.Tag)
	}
	if target == "" || target == selfID {
		return Exit, ""
	}
	return Transit, target
}
