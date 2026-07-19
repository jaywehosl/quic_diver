// Package notify — уведомления клиента: то, о чём пользователь обязан узнать
// сам, не листая журнал.
//
// Система намеренно отступает от буквального исполнения правил там, где иначе
// оставила бы человека без связи: выход недостижим — трафик уходит наружу с
// текущего узла, узел лёг — берётся резервный. Каждое такое отступление обязано
// быть замечено. Молчаливая подмена хуже отказа: пользователь считает, что
// сидит в Германии, а сидит дома.
package notify

import (
	"sync"
	"time"
)

// Level — насколько срочно.
type Level string

const (
	// Info — что-то произошло, вмешательства не требует (узел сменился).
	Info Level = "info"
	// Warn — работает не так, как настроено (правило вело на мёртвый узел).
	Warn Level = "warn"
	// Error — не работает (нет связи, токен отозван).
	Error Level = "error"
)

// Event — одно уведомление.
type Event struct {
	ID    int64     `json:"id"`
	At    time.Time `json:"at"`
	Level Level     `json:"level"`
	Title string    `json:"title"`
	Text  string    `json:"text,omitempty"`
	// Read — пользователь его видел. Непрочитанные красят иконку трея.
	Read bool `json:"read"`
}

// Sink — куда уведомление уходит помимо списка (всплывающее окно ОС).
type Sink func(Event)

// maxKept — сколько уведомлений держим.
//
// Список для человека, а не журнал: сотня — уже больше, чем кто-либо
// пролистает, а расти без предела он не должен.
const maxKept = 100

// dedupeWindow — окно подавления повторов.
//
// Без него мигающий узел за минуту выдал бы десятки одинаковых уведомлений и
// приучил бы не смотреть на них вовсе. Повтор внутри окна только обновляет
// время у прежнего.
const dedupeWindow = 5 * time.Minute

// Center хранит уведомления и раздаёт их панели и трею.
type Center struct {
	mu     sync.Mutex
	events []Event
	nextID int64
	sinks  []Sink
}

func New() *Center { return &Center{nextID: 1} }

// AddSink подключает получателя (всплывающие окна ОС).
func (c *Center) AddSink(s Sink) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sinks = append(c.sinks, s)
}

// Post добавляет уведомление и возвращает его.
//
// Одинаковые сообщения внутри окна подавляются: у прежнего обновляется время, а
// нового не появляется. Иначе мигающий узел за минуту выдал бы десятки строк.
func (c *Center) Post(level Level, title, text string) Event {
	c.mu.Lock()
	now := time.Now()
	for i := len(c.events) - 1; i >= 0; i-- {
		e := &c.events[i]
		if e.Level == level && e.Title == title && e.Text == text {
			if now.Sub(e.At) < dedupeWindow {
				e.At = now
				dup := *e
				c.mu.Unlock()
				return dup
			}
			break
		}
	}
	ev := Event{ID: c.nextID, At: now, Level: level, Title: title, Text: text}
	c.nextID++
	c.events = append(c.events, ev)
	if len(c.events) > maxKept {
		c.events = c.events[len(c.events)-maxKept:]
	}
	sinks := append([]Sink(nil), c.sinks...)
	c.mu.Unlock()

	// Вне мьютекса: показ окна ОС — дело небыстрое, и держать на нём лок значит
	// подвесить всех, кто в этот момент читает список.
	for _, s := range sinks {
		s(ev)
	}
	return ev
}

// List отдаёт уведомления, свежие сверху.
func (c *Center) List() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Event, 0, len(c.events))
	for i := len(c.events) - 1; i >= 0; i-- {
		out = append(out, c.events[i])
	}
	return out
}

// Unread — сколько непрочитанных. По нему трей решает, красить ли иконку.
func (c *Center) Unread() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.events {
		if !e.Read {
			n++
		}
	}
	return n
}

// MarkRead помечает прочитанным одно уведомление (0 — все).
func (c *Center) MarkRead(id int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.events {
		if id == 0 || c.events[i].ID == id {
			c.events[i].Read = true
		}
	}
}

// Clear убирает все уведомления.
func (c *Center) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = nil
}
