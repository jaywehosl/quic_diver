package tray

import "testing"

// Значок обязан отвечать «работает или нет» цветом, без открывания панели.
func TestLookByState(t *testing.T) {
	cases := []struct {
		name  string
		state State
		want  Look
	}{
		{"перехват выключен", State{Session: Stopped}, Grey},
		{"состояние ещё не известно", State{}, Grey},
		{"работает", State{Session: Connected}, Green},
		{"связи нет", State{Session: Connecting}, Red},
		{"работает, есть уведомления", State{Session: Connected, Unread: 3}, Blue},
	}
	for _, c := range cases {
		if got := LookOf(c.state); got != c.want {
			t.Fatalf("%s: значок %s, ожидался %s", c.name, got, c.want)
		}
	}
}

// Уведомления не красят выключенный клиент: синий значок при выключенном
// перехвате сбивает с толку сильнее, чем помогает.
func TestUnreadDoesNotColorStopped(t *testing.T) {
	if got := LookOf(State{Session: Stopped, Unread: 10}); got != Grey {
		t.Fatalf("значок %s при выключенном перехвате", got)
	}
}

// Отсутствие связи важнее уведомлений: когда трафик приложений никуда не идёт,
// показать надо именно это, а не «есть что почитать».
func TestNoLinkBeatsUnread(t *testing.T) {
	if got := LookOf(State{Session: Connecting, Unread: 5}); got != Red {
		t.Fatalf("значок %s — потеря связи затерялась за уведомлениями", got)
	}
}

// Подсказка объясняет то, что цвет только обозначает.
func TestHintExplainsColor(t *testing.T) {
	cases := map[Look]State{
		Grey:  {Session: Stopped},
		Green: {Session: Connected},
		Red:   {Session: Connecting},
		Blue:  {Session: Connected, Unread: 1},
	}
	seen := map[string]bool{}
	for look, st := range cases {
		h := Hint(st)
		if h == "" {
			t.Fatalf("%s: пустая подсказка", look)
		}
		if seen[h] {
			t.Fatalf("%s: подсказка повторяет другое состояние (%q)", look, h)
		}
		seen[h] = true
	}
}
