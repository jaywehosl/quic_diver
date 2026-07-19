// Package tray — значок в системном лотке: состояние одним взглядом и меню
// из четырёх команд.
//
// Клиент работает сервисом без окна, поэтому значок — единственное, что
// пользователь видит постоянно. Он обязан отвечать на вопрос «works или нет»
// цветом, без открывания панели.
package tray

// Look — как выглядит значок.
type Look int

const (
	// Grey — перехват выключен. Система не тронута, трафик идёт мимо нас.
	Grey Look = iota
	// Green — перехват включён и связь в порядке.
	Green
	// Red — перехват включён, но связи нет: трафик приложений сейчас не идёт
	// никуда. Самое важное состояние — пользователь должен узнать о нём сам,
	// а не по «интернет не работает».
	Red
	// Blue — всё работает, но есть непрочитанные уведомления.
	Blue
)

func (l Look) String() string {
	switch l {
	case Green:
		return "green"
	case Red:
		return "red"
	case Blue:
		return "blue"
	default:
		return "grey"
	}
}

// Session — состояние перехвата (совпадает со значениями API панели).
type Session string

const (
	Stopped    Session = "stopped"
	Connecting Session = "connecting"
	Connected  Session = "connected"
)

// State — из чего складывается вид значка.
type State struct {
	// Session — перехват: выключен, поднимается, работает.
	Session Session
	// Unread — непрочитанные уведомления.
	Unread int
}

// LookOf выбирает вид значка.
//
// Порядок проверок важен и не произволен:
//
//  1. Перехват выключен — серый. Уведомления не красят: они относятся к работе,
//     а работы сейчас нет, и синий значок при выключенном клиенте сбивал бы с
//     толку сильнее, чем помогал.
//  2. Связи нет — красный. Это перекрывает уведомления: когда трафик никуда не
//     идёт, важнее показать именно это, а не «есть что почитать».
//  3. Есть непрочитанные — синий.
//  4. Иначе зелёный.
func LookOf(s State) Look {
	switch {
	case s.Session == Stopped || s.Session == "":
		return Grey
	case s.Session == Connecting:
		return Red
	case s.Unread > 0:
		return Blue
	default:
		return Green
	}
}

// Hint — подсказка под курсором. Цвет отвечает «работает или нет», текст — «что
// именно происходит».
func Hint(s State) string {
	switch LookOf(s) {
	case Green:
		return "QUIC Diver: подключено"
	case Red:
		return "QUIC Diver: связи нет, восстанавливаю"
	case Blue:
		return "QUIC Diver: подключено, есть уведомления"
	default:
		return "QUIC Diver: отключено"
	}
}
