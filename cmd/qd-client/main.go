// Command qd-client — клиентский сервис QUIC Diver (без GUI).
//
// GUI подаётся отдельно как локальная веб-страница (переиспользует HTTP-слой
// decoy). Релизная сборка — один .exe: web-ассеты и WinDivert .dll/.sys вшиты,
// распаковываются в %APPDATA%\QUICDiver.
//
// Пока каркас: собирает local-guard и движок модели B, но захват/uplink — заглушки.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"quicdiver/internal/engine/connectip"
	"quicdiver/internal/guard"
	"quicdiver/internal/routing"
)

func main() {
	cfg := flag.String("config", "", "путь к конфигу (по умолчанию %APPDATA%\\QUICDiver)")
	flag.Parse()

	log.SetPrefix("qd-client: ")
	log.Printf("старт (config=%q)", *cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	g := guard.New(nil) // IP узлов добавятся после резолва конфига
	eng := connectip.New(g, routing.Default{})

	// TODO(quicdiver): открыть packet.Source (WinDivert/TUN) и uplink.Conn,
	// затем eng.Run(ctx, src, up). Сейчас — только каркас wiring.
	_ = eng
	log.Print("каркас: захват и uplink ещё не подключены")

	<-ctx.Done()
	log.Print("остановка")
}
