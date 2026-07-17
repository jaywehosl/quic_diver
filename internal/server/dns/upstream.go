package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Upstream — куда узел ходит за резолвом. Реализации: plain (UDP:53), DoT
// (TLS:853), DoH (HTTPS, RFC 8484) — выбор за конфигом узла (arch).
type Upstream interface {
	Exchange(ctx context.Context, query []byte) ([]byte, error)
	String() string
}

// --- plain UDP ---

type plainUpstream struct {
	addr string
	d    net.Dialer
}

// NewPlain — обычный DNS по UDP (быстро, но провайдер видит запросы).
func NewPlain(addr string) Upstream { return &plainUpstream{addr: addr} }

func (u *plainUpstream) String() string { return "plain://" + u.addr }

func (u *plainUpstream) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	conn, err := u.d.DialContext(ctx, "udp", u.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// --- DoT (RFC 7858) ---

type dotUpstream struct {
	addr string
	sni  string
}

// NewDoT — DNS поверх TLS: содержимое запросов скрыто от сети.
func NewDoT(addr, sni string) Upstream { return &dotUpstream{addr: addr, sni: sni} }

func (u *dotUpstream) String() string { return "tls://" + u.addr }

func (u *dotUpstream) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	d := tls.Dialer{Config: &tls.Config{ServerName: u.sni}}
	conn, err := d.DialContext(ctx, "tcp", u.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	// DNS поверх потока: перед сообщением идёт его длина (RFC 1035 §4.2.2)
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint16(len(query)))
	buf.Write(query)
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	resp := make([]byte, length)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// --- DoH (RFC 8484) ---

type dohUpstream struct {
	url string
	c   *http.Client
}

// NewDoH — DNS поверх HTTPS: наименее заметен для сети, дороже по задержке.
func NewDoH(url string) Upstream {
	return &dohUpstream{
		url: url,
		c:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (u *dohUpstream) String() string { return u.url }

func (u *dohUpstream) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := u.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH %s: статус %d", u.url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

// ParseUpstream разбирает адрес upstream-DNS по схеме: https:// (DoH),
// tls://host:port (DoT), udp://host:port (plain). Общий для флага -dns и admin-API.
func ParseUpstream(s string) (Upstream, error) {
	switch {
	case strings.HasPrefix(s, "https://"):
		return NewDoH(s), nil
	case strings.HasPrefix(s, "tls://"):
		addr := strings.TrimPrefix(s, "tls://")
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("tls:// ждёт host:port: %w", err)
		}
		return NewDoT(addr, host), nil
	case strings.HasPrefix(s, "udp://"):
		return NewPlain(strings.TrimPrefix(s, "udp://")), nil
	default:
		return nil, fmt.Errorf("неизвестная схема %q (нужно https://, tls:// или udp://)", s)
	}
}
