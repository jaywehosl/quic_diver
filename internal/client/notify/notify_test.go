package notify

import (
	"sync"
	"testing"
	"time"
)

// Свежие сверху: пользователь смотрит на последнее, а не листает к нему.
func TestListNewestFirst(t *testing.T) {
	c := New()
	c.Post(Info, "первое", "")
	c.Post(Warn, "второе", "")

	list := c.List()
	if len(list) != 2 || list[0].Title != "второе" {
		t.Fatalf("порядок: %+v", list)
	}
}

// Повторы внутри окна подавляются: мигающий узел иначе выдал бы десятки
// одинаковых строк за минуту и приучил бы не смотреть на уведомления вовсе.
func TestDuplicatesSuppressed(t *testing.T) {
	c := New()
	for i := 0; i < 5; i++ {
		c.Post(Warn, "узел недоступен", "de.example")
	}
	if got := len(c.List()); got != 1 {
		t.Fatalf("уведомлений %d, ожидалось 1", got)
	}
}

// Но время у подавленного обновляется: иначе в списке висело бы «час назад»
// у события, которое происходит прямо сейчас.
func TestSuppressedRefreshesTime(t *testing.T) {
	c := New()
	first := c.Post(Warn, "узел недоступен", "")
	time.Sleep(2 * time.Millisecond)
	second := c.Post(Warn, "узел недоступен", "")

	if !second.At.After(first.At) {
		t.Fatalf("время не обновилось: %v → %v", first.At, second.At)
	}
	if second.ID != first.ID {
		t.Fatal("подавленный повтор создал новую запись")
	}
}

// Разные сообщения не склеиваются.
func TestDifferentMessagesKept(t *testing.T) {
	c := New()
	c.Post(Warn, "узел недоступен", "de.example")
	c.Post(Warn, "узел недоступен", "ru.example")
	c.Post(Error, "узел недоступен", "de.example")

	if got := len(c.List()); got != 3 {
		t.Fatalf("уведомлений %d, ожидалось 3", got)
	}
}

// Непрочитанные считаются: по ним трей красит иконку.
func TestUnreadCount(t *testing.T) {
	c := New()
	a := c.Post(Info, "первое", "")
	c.Post(Warn, "второе", "")
	if c.Unread() != 2 {
		t.Fatalf("непрочитанных %d", c.Unread())
	}

	c.MarkRead(a.ID)
	if c.Unread() != 1 {
		t.Fatalf("после отметки одного: %d", c.Unread())
	}
	c.MarkRead(0) // все
	if c.Unread() != 0 {
		t.Fatalf("после отметки всех: %d", c.Unread())
	}
}

// Список не растёт без предела: он для человека, а не журнал.
func TestListIsBounded(t *testing.T) {
	c := New()
	for i := 0; i < maxKept+50; i++ {
		c.Post(Info, "событие", string(rune('a'+i%26))+string(rune('0'+i/26)))
	}
	if got := len(c.List()); got > maxKept {
		t.Fatalf("накопилось %d уведомлений", got)
	}
}

// Уведомление уходит наружу (всплывающее окно ОС), а не только в список.
func TestSinkReceivesEvents(t *testing.T) {
	c := New()
	var mu sync.Mutex
	var got []Event
	c.AddSink(func(e Event) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	})

	c.Post(Error, "нет связи", "узел не отвечает")
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Title != "нет связи" {
		t.Fatalf("получатель не сработал: %+v", got)
	}
}

// Подавленный повтор наружу не уходит: всплывающее окно каждые пять секунд —
// худшее, что можно сделать с вниманием пользователя.
func TestSuppressedNotSentToSink(t *testing.T) {
	c := New()
	var mu sync.Mutex
	n := 0
	c.AddSink(func(Event) {
		mu.Lock()
		n++
		mu.Unlock()
	})

	for i := 0; i < 5; i++ {
		c.Post(Warn, "узел недоступен", "")
	}
	mu.Lock()
	defer mu.Unlock()
	if n != 1 {
		t.Fatalf("наружу ушло %d уведомлений вместо 1", n)
	}
}

// Показ окна ОС не должен держать лок: он небыстрый, и на нём подвисли бы все,
// кто в этот момент читает список.
func TestSinkDoesNotHoldLock(t *testing.T) {
	c := New()
	done := make(chan struct{})
	c.AddSink(func(Event) {
		// Изнутри получателя список обязан читаться без взаимоблокировки.
		c.List()
		c.Unread()
		close(done)
	})

	c.Post(Info, "проверка", "")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("получатель заблокировал центр уведомлений")
	}
}

func TestClear(t *testing.T) {
	c := New()
	c.Post(Info, "раз", "")
	c.Clear()
	if len(c.List()) != 0 || c.Unread() != 0 {
		t.Fatal("очистка не сработала")
	}
}
