// Command qd-client — клиентский сервис QUIC Diver (без GUI).
//
// Боевой поток (Windows): sysproxy off → WinDivert capture → connect-ip туннель к
// узлу → NAT (assigned src) → engine перегоняет трафик; при выходе sysproxy
// restore. Требует прав администратора (WinDivert грузит драйвер).
//
// GUI — отдельная веб-страница (переиспользует HTTP-слой decoy) — следующий кирпич.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
)

type options struct {
	server    string // UDP endpoint узла, host:port
	authority string // :authority в connect-ip URI (по умолчанию = server)
	dll       string // путь к WinDivert.dll
	noProxy   bool   // не трогать системный прокси
}

func main() {
	var o options
	flag.StringVar(&o.server, "server", "localhost:8443", "endpoint узла (host:port)")
	flag.StringVar(&o.authority, "authority", "", "authority в connect-ip URI (по умолчанию = server)")
	flag.StringVar(&o.dll, "dll", `C:\Users\jaywehosl\Downloads\WinDivert-2.2.2-A\x64\WinDivert.dll`, "путь к WinDivert.dll")
	flag.BoolVar(&o.noProxy, "no-proxy", false, "не отключать системный прокси")
	flag.Parse()
	if o.authority == "" {
		o.authority = o.server
	}

	log.SetPrefix("qd-client: ")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := run(ctx, o); err != nil && ctx.Err() == nil {
		log.Fatalf("run: %v", err)
	}
	log.Print("остановлен")
}
