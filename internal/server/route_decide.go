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
// ⚠️ ГЛАВНОЕ ПРАВИЛО, отличающее нас от строгих правил Xray: недостижимый выход
// НИКОГДА не глушит флоу — трафик уходит наружу с текущего узла. Пользователь
// остаётся со связью, пусть и не из той страны. Каждое такое отступление обязано
// дойти до администратора уведомлением (см. память: quic-diver-alerts) — с тем,
// ЧТО система предприняла, а не только с тем, что сломалось. Пока алертов нет,
// такие случаи пишутся в журнал: молчать о них нельзя.
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

	dialer := cfg.transitDialer(ctx, next)
	if dialer == nil {
		// Узел из метки нам неизвестен: выпускаем наружу здесь, а не глушим —
		// остаться без связи хуже, чем выйти не из той страны.
		// СОБЫТИЕ ДЛЯ АЛЕРТА: «правило вело на узел X, он недоступен/неизвестен —
		// выпустил наружу здесь». Админ должен узнать об этом сам, а не по жалобе
		// пользователя, что он «вышел не из той страны».
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

// transitDialer — соединение к соседнему узлу (nil, если вести туда нечем).
//
// Сначала реестр: узлы равны, связь поднимается по адресу из общей реплики, а
// представляемся своим токеном. Аутбаунды остаются запасным путём, пока стенды
// живут на них, — уйдут вместе с последней ручной связью.
func (cfg Config) transitDialer(ctx context.Context, node string) netstack.Dialer {
	if node == "" {
		return nil
	}
	if cfg.Links != nil {
		if d := cfg.Links.Dialer(ctx, node); d != nil {
			return d
		}
	}
	if cfg.Outbounds != nil {
		return cfg.Outbounds.Transit(node)
	}
	return nil
}

// pickNode выбирает узел категории для метки auto:<тег>.
//
// Пусто означает «подходящих нет» — флоу выйдет на текущем узле, а не умрёт.
func (cfg Config) pickNode(tag string) string {
	if cfg.Links == nil {
		return ""
	}
	return cfg.Links.pickByCategory(tag)
}
