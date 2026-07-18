package fakeip

import (
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
)

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

// addrsOf собирает адреса указанного типа (A или AAAA) из ответа.
func addrsOf(msg []byte, t dnsmessage.Type) []netip.Addr {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil
	}
	var out []netip.Addr
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return out
		}
		switch {
		case h.Type == dnsmessage.TypeA && t == dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return out
			}
			out = append(out, netip.AddrFrom4(r.A))
		case h.Type == dnsmessage.TypeAAAA && t == dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return out
			}
			out = append(out, netip.AddrFrom16(r.AAAA))
		default:
			if err := p.SkipAnswer(); err != nil {
				return out
			}
		}
	}
}

// buildA собирает ответ с одной синтезированной A-записью (fake), сохраняя ID/RD
// запроса.
func buildA(query []byte, q dnsmessage.Question, fake netip.Addr, ttl uint32) ([]byte, error) {
	hdr, ok := headerOf(query)
	if !ok {
		return nil, errBadQuery
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: hdr.ID, Response: true, RecursionDesired: hdr.RecursionDesired, RecursionAvailable: true,
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
		Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl,
	}, dnsmessage.AResource{A: fake.As4()}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// noData — успешный ответ без записей (NOERROR/0 answers): «имя есть, записей
// нужного типа нет». Так AAAA-запрос заставляет приложение переспросить A.
func noData(query []byte, q dnsmessage.Question) ([]byte, error) {
	hdr, ok := headerOf(query)
	if !ok {
		return nil, errBadQuery
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: hdr.ID, Response: true, RecursionDesired: hdr.RecursionDesired, RecursionAvailable: true,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	return b.Finish()
}

type errString string

func (e errString) Error() string { return string(e) }

const errBadQuery = errString("fakeip: не разобрать запрос")
