// Command benchsrv — тестовый сервер пропускной способности для профилирования.
// Разворачивается рядом с узлом (на VM). /zero отдаёт бесконечный поток нулей
// (download-тест), /sink поглощает тело запроса (upload-тест).
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", ":8080", "адрес прослушивания")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/zero", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		buf := make([]byte, 256*1024)
		for {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/sink", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
		_ = n
	})

	log.Printf("benchsrv на %s (/zero, /sink)", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
