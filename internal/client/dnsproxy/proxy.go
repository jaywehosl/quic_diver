// Package dnsproxy — локальный DNS-listener клиента: принимает запросы приложений
// (UDP и TCP, RFC 1035) и отдаёт их наверх — резолверу узла через туннель.
//
// Платформонезависимо. На Windows слушаем 127.0.0.1:53 и подменяем системный DNS
// (см. sysdns); на Android/iOS тот же Exchange вызывается из обработчика TUN.
package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Exchanger — то, что умеет спросить узел. Реализуется dnsforward.Forwarder.
type Exchanger interface {
	Query(ctx context.Context, wire []byte) ([]byte, error)
}

// Config — параметры listener'а.
type Config struct {
	// Addrs — где слушать. На Windows это оба loopback'а ("127.0.0.1:53" и
	// "[::1]:53"): системный DNS подменяется у обоих стеков, и запрос придёт на
	// любой из них.
	Addrs []string
	// Exchange — резолвер узла.
	Exchange Exchanger
	// Timeout — предел на один запрос.
	Timeout time.Duration
}

// Proxy — локальный DNS-listener.
type Proxy struct {
	cfg  Config
	udps []*net.UDPConn
	tcps []net.Listener
	wg   sync.WaitGroup
	pool sync.Pool

	queries atomic.Int64
	fails   atomic.Int64
}

const (
	// maxUDPQuery — потолок запроса по UDP с EDNS0 (RFC 6891).
	maxUDPQuery = 4096
	// maxTCPMessage — потолок DNS-сообщения по TCP (RFC 1035 §4.2.2).
	maxTCPMessage = 65535
)

// New поднимает listener'ы на UDP и TCP каждого адреса (RFC 1035 требует оба:
// увидев флаг TC, резолвер дозапрашивает длинный ответ по TCP).
func New(cfg Config) (*Proxy, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if len(cfg.Addrs) == 0 {
		return nil, errors.New("dnsproxy: не задан адрес прослушивания")
	}
	p := &Proxy{
		cfg:  cfg,
		pool: sync.Pool{New: func() any { b := make([]byte, maxUDPQuery); return &b }},
	}
	for _, addr := range cfg.Addrs {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			p.closeAll()
			return nil, err
		}
		udp, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			p.closeAll()
			return nil, fmt.Errorf("занять %s/udp: %w", addr, err)
		}
		tcp, err := net.Listen("tcp", addr)
		if err != nil {
			udp.Close()
			p.closeAll()
			return nil, fmt.Errorf("занять %s/tcp: %w", addr, err)
		}
		p.udps = append(p.udps, udp)
		p.tcps = append(p.tcps, tcp)
	}
	return p, nil
}

// Addrs — на чём фактически слушаем (порт может быть выбран ОС).
func (p *Proxy) Addrs() []string {
	out := make([]string, 0, len(p.udps))
	for _, u := range p.udps {
		out = append(out, u.LocalAddr().String())
	}
	return out
}

func (p *Proxy) closeAll() {
	for _, u := range p.udps {
		u.Close()
	}
	for _, t := range p.tcps {
		t.Close()
	}
}

// Run обслуживает запросы до отмены ctx.
func (p *Proxy) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		p.closeAll()
	}()

	errc := make(chan error, len(p.udps))
	for i := range p.udps {
		udp, tcp := p.udps[i], p.tcps[i]
		p.wg.Add(2)
		go func() {
			defer p.wg.Done()
			p.serveTCP(ctx, tcp)
		}()
		go func() {
			defer p.wg.Done()
			errc <- p.serveUDP(ctx, udp)
		}()
	}
	p.wg.Wait()
	close(errc)
	if ctx.Err() != nil {
		return nil
	}
	for err := range errc {
		if err != nil {
			return err
		}
	}
	return nil
}

// Stats — сколько запросов обслужено и сколько провалено.
func (p *Proxy) Stats() (queries, fails int64) {
	return p.queries.Load(), p.fails.Load()
}

func (p *Proxy) serveUDP(ctx context.Context, udp *net.UDPConn) error {
	for {
		bufp := p.pool.Get().(*[]byte)
		n, addr, err := udp.ReadFromUDP(*bufp)
		if err != nil {
			p.pool.Put(bufp)
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		// копия: буфер вернётся в пул, а горутина живёт дольше
		q := make([]byte, n)
		copy(q, (*bufp)[:n])
		p.pool.Put(bufp)

		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			resp, err := p.exchange(ctx, q)
			if err != nil {
				return
			}
			_, _ = udp.WriteToUDP(resp, addr)
		}()
	}
}

func (p *Proxy) serveTCP(ctx context.Context, tcp net.Listener) {
	for {
		c, err := tcp.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer c.Close()
			p.handleTCP(ctx, c)
		}()
	}
}

// handleTCP: по TCP сообщения идут с 2-байтным префиксом длины и в одном
// соединении их может быть несколько подряд (RFC 7766).
func (p *Proxy) handleTCP(ctx context.Context, c net.Conn) {
	var hdr [2]byte
	for {
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(hdr[:])
		if n == 0 || int(n) > maxTCPMessage {
			return
		}
		q := make([]byte, n)
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp, err := p.exchange(ctx, q)
		if err != nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		_ = c.SetWriteDeadline(time.Now().Add(p.cfg.Timeout))
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

func (p *Proxy) exchange(ctx context.Context, q []byte) ([]byte, error) {
	p.queries.Add(1)
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	resp, err := p.cfg.Exchange.Query(ctx, q)
	if err != nil {
		p.fails.Add(1)
		if n := p.fails.Load(); n <= 3 || n%100 == 0 {
			log.Printf("dns: запрос не прошёл (%d всего): %v", n, err)
		}
		// Молчим вместо SERVFAIL: резолвер клиента переспросит, а туннель к тому
		// времени может уже подняться. SERVFAIL он бы закешировал как отказ.
		return nil, err
	}
	return resp, nil
}
