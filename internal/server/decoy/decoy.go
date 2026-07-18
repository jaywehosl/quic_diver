// Package decoy — «under construction» сайт на :443.
//
// Отдаётся всем, кто пришёл на узел без валидного токена (см. auth): снаружи узел
// выглядит как обычный HTTPS-сайт-заглушка. Тот же HTTP-слой переиспользуется
// клиентской частью для локальной веб-панели настроек и (по admin-токену)
// панели управления узлом.
//
// Страницы ошибок оформлены в том же стиле, что и главная. Голая строка
// «Too Many Requests» от net/http выдавала бы, что за доменом не сайт, а
// заглушка перед чем-то другим: у настоящего сайта ошибки выглядят его частью.
package decoy

import (
	"fmt"
	"html"
	"net/http"
)

// tmpl — общий каркас страниц: одна вёрстка на главную и на ошибки.
const tmpl = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>
 body{font-family:system-ui,sans-serif;background:#0e0f12;color:#c9ccd3;
      display:grid;place-items:center;height:100vh;margin:0}
 main{text-align:center;max-width:32rem;padding:2rem}
 h1{font-weight:600;letter-spacing:.02em}
 p{color:#8a8f99}
 .code{color:#4a4f59;font-size:.85rem;letter-spacing:.08em;margin-top:1.5rem}
</style></head><body><main>
 <h1>%s</h1>
 <p>%s</p>
 %s
</main></body></html>`

// page собирает страницу. code==0 — без строки с кодом (главная).
func page(title, text string, code int) string {
	var codeLine string
	if code != 0 {
		codeLine = fmt.Sprintf(`<div class="code">ERROR %d</div>`, code)
	}
	return fmt.Sprintf(tmpl, html.EscapeString(title), html.EscapeString(title), html.EscapeString(text), codeLine)
}

// Handler возвращает http.Handler главной decoy-страницы.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writePage(w, http.StatusOK, "Under construction",
			"This site is being set up. Please check back later.")
	})
}

// writePage отдаёт страницу с нужным статусом в общем оформлении.
func writePage(w http.ResponseWriter, status int, title, text string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	code := status
	if status == http.StatusOK {
		code = 0
	}
	_, _ = w.Write([]byte(page(title, text, code)))
}
