// Command qdadmin — управление узлом по admin-токену через его HTTP/3 API.
//
// Пока — резолвер: показать настройки, сменить upstream/размер кеша/TTL, очистить
// кеш. Всё на лету, без рестарта узла (чинит аварию «upstream сломался»).
//
//	qdadmin -server localhost:8443 -token qd_admin... -get
//	qdadmin ... -upstream udp://1.1.1.1:53
//	qdadmin ... -flush all
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"quicdiver/internal/server/auth"
)

func main() {
	srv := flag.String("server", "localhost:8443", "endpoint узла")
	authority := flag.String("authority", "", "authority (пусто → host из -server)")
	token := flag.String("token", "", "admin-токен")
	get := flag.Bool("get", false, "показать текущие настройки резолвера")
	upstream := flag.String("upstream", "", "сменить upstream DNS (https://|tls://host:port|udp://host:port)")
	cacheSize := flag.Int("cache", -1, "новый размер кеша (записей)")
	ttl := flag.Int("ttl", -1, "TTL override, секунд (0 — из ответа)")
	flush := flag.String("flush", "", "очистить кеш: expired | all")
	// Узлы сети (прежние ручные выходы убраны — маршрут живёт в метке трафика).
	nodes := flag.Bool("nodes", false, "показать узлы сети")
	// Универсальный вызов: под каждый новый admin-эндпоинт заводить свой флаг —
	// плодить сущности, а API растёт (клиенты, сессии, состояние узла).
	path := flag.String("path", "", "произвольный admin-путь, напр. /qd-admin/users")
	method := flag.String("method", http.MethodGet, "метод для -path")
	reqBody := flag.String("body", "", "тело запроса (json) для -path")
	flag.Parse()

	if *authority == "" {
		h, _, _ := net.SplitHostPort(*srv)
		*authority = h
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sni, _, _ := net.SplitHostPort(*srv)
	qconn, err := quic.DialAddr(ctx, *srv, &tls.Config{
		InsecureSkipVerify: true, ServerName: sni,
		NextProtos: []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		log.Fatalf("quic: %v", err)
	}
	defer qconn.CloseWithError(0, "")
	tr := &http3.Transport{}
	defer tr.Close()
	cc := tr.NewClientConn(qconn)

	if err := doAuth(ctx, cc, *authority, *token); err != nil {
		log.Fatalf("auth: %v", err)
	}

	if *path != "" {
		var b []byte
		if *reqBody != "" {
			b = []byte(*reqBody)
		}
		show(ctx, cc, strings.ToUpper(*method), "https://"+*authority+*path, b)
		return
	}

	if *nodes {
		show(ctx, cc, http.MethodGet, "https://"+*authority+"/qd-admin/nodes", nil)
		return
	}

	url := "https://" + *authority + "/qd-admin/dns"
	if *get || (*upstream == "" && *cacheSize < 0 && *ttl < 0 && *flush == "") {
		show(ctx, cc, http.MethodGet, url, nil)
		return
	}

	patch := map[string]any{}
	if *upstream != "" {
		patch["upstream"] = *upstream
	}
	if *cacheSize >= 0 {
		patch["cache_size"] = *cacheSize
	}
	if *ttl >= 0 {
		patch["ttl_override"] = *ttl
	}
	if *flush != "" {
		patch["flush"] = *flush
	}
	body, _ := json.Marshal(patch)
	show(ctx, cc, http.MethodPost, url, body)
}

func doAuth(ctx context.Context, cc *http3.ClientConn, authority, token string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+authority+"/qd-auth", nil)
	req.Header.Set(auth.HeaderToken, token)
	rsp, err := cc.RoundTrip(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("узел отклонил admin-токен (%d)", rsp.StatusCode)
	}
	return nil
}

func show(ctx context.Context, cc *http3.ClientConn, method, url string, body []byte) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, _ := http.NewRequestWithContext(ctx, method, url, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rsp, err := cc.RoundTrip(req)
	if err != nil {
		log.Fatalf("%s %s: %v", method, url, err)
	}
	defer rsp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(rsp.Body, 8192))
	if rsp.StatusCode != http.StatusOK {
		log.Fatalf("узел вернул %d: %s", rsp.StatusCode, out)
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, out, "", "  ") == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(out))
	}
}
