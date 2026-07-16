// Package dnsforward — клиентский форвардер DNS: гонит запросы приложений на
// резолвер узла по DoH (RFC 8484) через то же HTTP/3-соединение, что и туннель.
//
// Платформонезависимое ядро. Разница платформ — только в том, откуда прилетает
// запрос:
//   - Windows: локальный listener на 127.0.0.1:53 + подмена системного DNS
//     (иначе резолв уходит на роутер, а он в guard-bypass как локальный трафик —
//     запрос утекает провайдеру, и тот отдаёт адрес своей заглушки);
//   - Android/iOS: DNS-адрес задаётся самим VPN-профилем (VpnService.addDnsServer,
//     NEDNSSettings), запрос приходит в TUN — подменять ничего не нужно.
//
// Кеш живёт на узле, а не здесь: так он переживает смену сети у клиента
// (Wi-Fi↔LTE, пересборка PPPoE) и настраивается централизованно.
package dnsforward

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

// MaxMessageSize — предел DNS-сообщения (RFC 8484 §6).
const MaxMessageSize = 65535

// Forwarder отправляет DNS-запросы на узел.
type Forwarder struct {
	cc  *http3.ClientConn
	url string
}

// New создаёт форвардер поверх H3-соединения с узлом.
// url — DoH-эндпоинт узла, напр. "https://bitter.example/dns-query".
func New(cc *http3.ClientConn, url string) *Forwarder {
	return &Forwarder{cc: cc, url: url}
}

// Query пересылает DNS-сообщение узлу и возвращает ответ.
func (f *Forwarder) Query(ctx context.Context, wire []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := f.cc.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("DoH к узлу: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH к узлу: статус %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, MaxMessageSize))
}
