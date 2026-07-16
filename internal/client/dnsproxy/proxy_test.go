package dnsproxy

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// echoExchanger отвечает фиксированным A-адресом, сохраняя ID запроса.
type echoExchanger struct{ ip [4]byte }

func (e echoExchanger) Query(_ context.Context, wire []byte) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(wire)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	_ = b.AResource(dnsmessage.ResourceHeader{
		Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60,
	}, dnsmessage.AResource{A: e.ip})
	return b.Finish()
}

func mustQuery(t *testing.T, name string, id uint16) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	if err := b.Question(dnsmessage.Question{
		Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func firstA(t *testing.T, resp []byte) net.IP {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		t.Fatal(err)
	}
	_ = p.SkipAllQuestions()
	h, err := p.AnswerHeader()
	if err != nil {
		t.Fatalf("нет ответа: %v", err)
	}
	if h.Type != dnsmessage.TypeA {
		t.Fatalf("тип %v", h.Type)
	}
	r, err := p.AResource()
	if err != nil {
		t.Fatal(err)
	}
	return net.IP(r.A[:])
}

// start поднимает прокси на свободном порту loopback.
func start(t *testing.T) (*Proxy, string) {
	t.Helper()
	// порт 0 не годится: UDP и TCP получили бы разные порты — берём свободный
	// через временный listener.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	p, err := New(Config{Addrs: []string{addr}, Exchange: echoExchanger{ip: [4]byte{1, 2, 3, 4}}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go p.Run(ctx)
	return p, addr
}

func TestUDPQuery(t *testing.T) {
	_, addr := start(t)

	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(mustQuery(t, "example.com.", 42)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxUDPQuery)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := firstA(t, buf[:n]); !got.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("A = %v", got)
	}
}

// По TCP сообщение идёт с 2-байтным префиксом длины, и в одном соединении их
// может быть несколько подряд (RFC 7766) — резолвер Windows так и делает.
func TestTCPQueryPipelined(t *testing.T) {
	_, addr := start(t)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for _, id := range []uint16{7, 8} {
		q := mustQuery(t, "example.com.", id)
		out := make([]byte, 2+len(q))
		binary.BigEndian.PutUint16(out, uint16(len(q)))
		copy(out[2:], q)
		if _, err := c.Write(out); err != nil {
			t.Fatal(err)
		}

		var hdr [2]byte
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := readFull(c, hdr[:]); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := readFull(c, resp); err != nil {
			t.Fatal(err)
		}
		var p dnsmessage.Parser
		h, err := p.Start(resp)
		if err != nil {
			t.Fatal(err)
		}
		if h.ID != id {
			t.Fatalf("ID ответа %d, ждали %d", h.ID, id)
		}
	}
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		if err != nil {
			return n, err
		}
		n += m
	}
	return n, nil
}
