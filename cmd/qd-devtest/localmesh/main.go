// Command localmesh — запуск локального стенда из двух узлов (Вход + Выход) для отладки.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
)

func main() {
	dir := flag.String("dir", filepath.Join(os.TempDir(), "qd-localmesh"), "папка данных локального стенда")
	flag.Parse()

	if err := os.MkdirAll(*dir, 0755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	adminToken := "qd_local_admin_token_12345"
	node1Token := "node1_token_dev_123"
	node2Token := "node2_token_dev_456"

	dbPath := filepath.Join(*dir, "master.db")
	_ = os.Remove(dbPath) // свежая база для локальной отладки

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	sqlite, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("открытие БД: %v", err)
	}
	defer sqlite.Close()

	if err := sqlite.PutToken(ctx, auth.Hash(adminToken), auth.RoleAdmin, "local-admin"); err != nil {
		log.Fatalf("PutToken admin: %v", err)
	}

	if err := sqlite.PutNode(ctx, db.Node{
		ID:       "local-entry",
		Label:    "Local Entry Node",
		Category: "entry",
		Tags:     []string{"local", "entry"},
		Addr:     "127.0.0.1:8443",
		SNI:      "localhost",
		Enabled:  true,
	}); err != nil {
		log.Fatalf("PutNode 1: %v", err)
	}

	if err := sqlite.PutNode(ctx, db.Node{
		ID:       "local-exit",
		Label:    "Local Exit Node",
		Category: "exit",
		Tags:     []string{"local", "exit"},
		Addr:     "127.0.0.1:8444",
		SNI:      "localhost",
		Enabled:  true,
	}); err != nil {
		log.Fatalf("PutNode 2: %v", err)
	}

	fmt.Println("==================================================================")
	fmt.Println("🚀 Локальный стенд QUIC Diver (2 узла)")
	fmt.Println("==================================================================")
	fmt.Printf("Админ-токен : %s\n", adminToken)
	fmt.Printf("Узел 1 (Вход): %s (ID: local-entry, token: %s)\n", "127.0.0.1:8443", node1Token)
	fmt.Printf("Узел 2 (Выход): %s (ID: local-exit, token: %s)\n", "127.0.0.1:8444", node2Token)
	fmt.Println("------------------------------------------------------------------")
	fmt.Println("Строка подключения для клиента (qd://):")
	fmt.Printf("qd://%s@127.0.0.1:8443?sni=localhost&node=local-entry\n", adminToken)
	fmt.Println("==================================================================")
	fmt.Println("Нажмите Ctrl+C для завершения локального стенда.")

	<-ctx.Done()
	log.Print("Локальный стенд остановлен.")
}
