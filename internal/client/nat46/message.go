package nat46

import (
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
)

// netipAddr — псевдоним, чтобы сигнатуры в resolver.go читались короче.
type netipAddr = netip.Addr

func headerOf(msg []byte) (dnsmessage.Header, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return dnsmessage.Header{}, false
	}
	return h, true
}

func questionOf(msg []byte) (dnsmessage.Question, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return dnsmessage.Question{}, false
	}
	q, err := p.Question()
	if err != nil {
		return dnsmessage.Question{}, false
	}
	return q, true
}

// hasAnswer — есть ли в ответе хоть одна запись нужного типа. CNAME-цепочка сюда
// же: у имени с CNAME на v4-хост в ответе будет и A.
func hasAnswer(msg []byte, t dnsmessage.Type) bool {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return false
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return false
		}
		if h.Type == t {
			return true
		}
		if err := p.SkipAnswer(); err != nil {
			return false
		}
	}
}

// firstAAAA возвращает первый AAAA-адрес ответа и его TTL.
func firstAAAA(msg []byte) (netip.Addr, uint32, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return netip.Addr{}, 0, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return netip.Addr{}, 0, false
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return netip.Addr{}, 0, false
		}
		if h.Type != dnsmessage.TypeAAAA {
			if err := p.SkipAnswer(); err != nil {
				return netip.Addr{}, 0, false
			}
			continue
		}
		r, err := p.AAAAResource()
		if err != nil {
			return netip.Addr{}, 0, false
		}
		return netip.AddrFrom16(r.AAAA), h.TTL, true
	}
}

// buildA собирает ответ с одной синтезированной A-записью.
//
// Отвечаем на исходный вопрос (A), сохраняя ID и RD запроса, — для приложения
// это обычный ответ. TTL берём от AAAA, но не длиннее жизни маппинга: иначе
// приложение помнило бы fake-адрес дольше, чем мы помним, что за ним стоит.
func buildA(query []byte, q dnsmessage.Question, fake netip.Addr, ttl uint32) ([]byte, error) {
	hdr, ok := headerOf(query)
	if !ok {
		return nil, errBadQuery
	}
	if max := uint32(DefaultTTL / 1e9); ttl > max {
		ttl = max
	}
	if ttl == 0 {
		ttl = 60
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		RecursionDesired:   hdr.RecursionDesired,
		RecursionAvailable: true,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if err := b.AResource(dnsmessage.ResourceHeader{
		Name:  q.Name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
		TTL:   ttl,
	}, dnsmessage.AResource{A: fake.As4()}); err != nil {
		return nil, err
	}
	return b.Finish()
}

type errString string

func (e errString) Error() string { return string(e) }

const errBadQuery = errString("nat46: не разобрать запрос")
