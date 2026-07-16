// Package connectip — модель B: passthrough сырых IP через MASQUE connect-ip.
//
// Горячий путь тонкий: Source.Recv → guard/route → Conn.SendDatagram (IP внутри
// connect-ip); обратно Conn.RecvDatagram → Source.Send. Никакой терминации L4 на
// клиенте — end-to-end TCP хоста сохраняется.
//
// Открытые узкие места (решаются на шаге PoC, не в каркасе):
//   - MTU: IP-пакет + overhead connect-ip не всегда влезает в датаграмму
//     (MaxDatagramSize). Нужны MSS-clamp на TCP SYN + эмуляция ICMP PTB, а для
//     крупных non-TCP — stream-fallback через Conn.OpenStream.
//   - Многопоточность: рабочие пулы на оба направления (arch6).
//
// TODO(quicdiver): подключить masque-go connect-ip (RFC 9484) и реализовать Run.
package connectip

import (
	"context"

	"quicdiver/internal/engine"
	"quicdiver/internal/guard"
	"quicdiver/internal/packet"
	"quicdiver/internal/routing"
	"quicdiver/internal/uplink"
)

// Engine — реализация модели B.
type Engine struct {
	guard  *guard.Guard
	router routing.Router
}

// New собирает движок модели B из local-guard и роутера.
func New(g *guard.Guard, r routing.Router) *Engine {
	return &Engine{guard: g, router: r}
}

// Run — скелет цикла обработки. Реальная реализация — на шаге PoC.
func (e *Engine) Run(ctx context.Context, src packet.Source, up uplink.Conn) error {
	// TODO(quicdiver): пул воркеров uplink→source и source→uplink,
	// guard.Bypass для отсева локалки/петли, routing.Route для chain-решения,
	// MTU-инженерия при SendDatagram.
	<-ctx.Done()
	return ctx.Err()
}

var _ engine.Engine = (*Engine)(nil)
