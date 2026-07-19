// Command qdtoken — сгенерировать токен в формате сети (для деплоя узла).
package main

import (
	"fmt"
	"log"

	"quicdiver/internal/server/auth"
)

func main() {
	t, err := auth.Generate()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(t)
}
