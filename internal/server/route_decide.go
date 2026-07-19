package server

import (
	"context"
	"log"
	"net/http"

	"quicdiver/internal/routing"
	"quicdiver/internal/server/chain"
	"quicdiver/internal/server/netstack"
)

// routeFlow решает, что узлу делать с флоу, и отдаёт готовый диалер.
//
// Здесь и живёт разница между репитером и свичем. Раньше метку потреблял первый
// же узел: он выбирал себе аутбаунд, а к соседу шёл запрос уже без метки, и
// второй хоп определялся конфигом первого. Теперь узел сверяет метку с собой —
// он выход, значит выпускает наружу; не он, значит ведёт транзитом, ПЕРЕДАВАЯ
// метку дальше, и решение принимает уже следующий.
//
// Второй результат — контекст для транзита: в нём уменьшенный hop-limit и метка.
func routeFlow(ctx context.Context, cfg Config, r *http.Request, hops int) (netstack.Dialer, context.Context) {
	raw := r.Header.Get(RouteHeader)
	route, err := routing.Parse(raw)
	if err != nil {
		// Битая метка — не повод рвать связь: выпускаем здесь. Но молчать нельзя,
		// иначе поломка клиента выглядела бы как «просто работает не так».
		log.Printf("метка маршрута %q не разобрана (выпускаю здесь): %v", raw, err)
		route = routing.Direct
	}

	decision, next := route.Decide(cfg.NodeID, cfg.pickNode)
	if decision == routing.Exit {
		return cfg.exitDialer(), ctx
	}

	dialer := cfg.transitDialer(next)
	if dialer == nil {
		// Узел из метки нам неизвестен: выпускаем наружу здесь, а не глушим —
		// остаться без связи хуже, чем выйти не из той страны.
		log.Printf("узел %q неизвестен (выпускаю здесь)", next)
		return cfg.exitDialer(), ctx
	}
	// Метку передаём как есть: для auto следующий узел выберет сам, и это верно —
	// у него свежее представление о живых соседях.
	return dialer, chain.WithRoute(chain.WithHops(ctx, hops-1), raw)
}

// exitDialer — выход наружу с этого узла.
func (cfg Config) exitDialer() netstack.Dialer {
	if cfg.Outbounds != nil {
		return cfg.Outbounds.Direct()
	}
	return cfg.Dialer
}

// transitDialer — соединение к соседнему узлу (nil, если такого не знаем).
func (cfg Config) transitDialer(node string) netstack.Dialer {
	if cfg.Outbounds == nil || node == "" {
		return nil
	}
	return cfg.Outbounds.Transit(node)
}

// pickNode выберет лучший узел категории, когда появится реестр узлов.
//
// Пока выбирать не из чего: пусто означает «подходящих нет», и флоу выйдет на
// текущем узле — то же поведение, что при недоступной категории.
func (cfg Config) pickNode(tag string) string { return "" }
