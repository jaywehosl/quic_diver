// Package panel — веб-панель клиента: единственный GUI по ТЗ.
//
// Файлы вшиты в бинарь: релизный клиент — один exe, и класть рядом папку с
// вёрсткой значило бы этому противоречить. Заодно панель не может разъехаться с
// API — они всегда одной сборки.
package panel

import (
	"embed"
	"io/fs"
	"net/http"
	"time"
)

//go:embed ui
var files embed.FS

// Handler отдаёт файлы панели.
//
// Кеш выключен намеренно: панель обновляется вместе с клиентом, и браузер,
// показавший вчерашнюю разметку поверх сегодняшнего API, — источник загадочных
// поломок, которые невозможно повторить.
func Handler() http.Handler {
	sub, err := fs.Sub(files, "ui")
	if err != nil {
		panic("panel: " + err.Error()) // содержимое вшито при сборке
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		// Панель обращается только к себе и к своему API. Запрет внешних
		// источников означает, что даже подсунутая в поле строка не сможет
		// утянуть данные наружу.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		fileServer.ServeHTTP(w, r)
	})
}

// Server поднимает панель на локальном адресе.
//
// Только петля: панель управляет клиентом целиком, и слушать её на внешнем
// адресе значило бы отдать управление любому в сети.
func Server(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}
