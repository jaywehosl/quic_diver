// Command qd-server — узел QUIC Diver. master = slave: роль определяется
// конфигом/наличием БД, не кодовой базой. Единый admin-токен коннектится к любому
// узлу; узел может дозваниваться до upstream-узла как chain-аутбаунд.
//
// Пока каркас: поднимает decoy-обработчик, остальное (QUIC/H3-listener, gVisor+
// netstack, БД, DNS, admin-API) — на следующих шагах.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"quicdiver/internal/server/decoy"
)

func main() {
	cfg := flag.String("config", "", "путь к конфигу узла")
	flag.Parse()

	log.SetPrefix("qd-server: ")
	log.Printf("старт (config=%q)", *cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	_ = decoy.Handler() // TODO(quicdiver): смонтировать на HTTP/3-listener :443

	// TODO(quicdiver): открыть db.Store (SQLite), поднять MASQUE-listener с
	// auth-роутингом (валидный токен→прокси, иначе→decoy), gVisor+netstack для
	// выхода в интернет, chain-аутбаунды, DNS (DNS/DoT/DoH)+кеш, admin-API.
	log.Print("каркас: сетевые слои узла ещё не подключены")

	<-ctx.Done()
	log.Print("остановка")
}
