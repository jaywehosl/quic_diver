// Command qdprobe — шлёт один DNS-запрос на указанный резолвер и разбирает ответ
// по полям. Нужен, чтобы сверять наш ответ с эталонным (публичный резолвер).
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: qdprobe <resolver addr> [domain]")
		return
	}
	addr := os.Args[1]
	domain := "instagram.com."
	if len(os.Args) > 2 {
		domain = os.Args[2] + "."
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 99, RecursionDesired: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{
		Name: dnsmessage.MustNewName(domain), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	})
	q, _ := b.Finish()

	c, err := net.Dial("udp", addr)
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	defer c.Close()
	if _, err := c.Write(q); err != nil {
		fmt.Println("write:", err)
		return
	}
	buf := make([]byte, 4096)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		fmt.Println("read:", err)
		return
	}
	resp := buf[:n]

	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	fmt.Printf("%s → %d байт\n", addr, n)
	fmt.Printf("  ID=%d Response=%v RD=%v RA=%v RCode=%v Authoritative=%v Truncated=%v\n",
		h.ID, h.Response, h.RecursionDesired, h.RecursionAvailable, h.RCode, h.Authoritative, h.Truncated)

	qs, err := p.AllQuestions()
	if err != nil {
		fmt.Printf("  ВОПРОСЫ: ошибка разбора: %v\n", err)
	} else {
		fmt.Printf("  вопросов в ответе: %d %v\n", len(qs), qs)
	}
	as, err := p.AllAnswers()
	if err != nil {
		fmt.Printf("  ответы: %v\n", err)
	} else {
		fmt.Printf("  записей: %d\n", len(as))
		for _, a := range as {
			var val string
			switch b := a.Body.(type) {
			case *dnsmessage.AResource:
				val = net.IP(b.A[:]).String()
			case *dnsmessage.AAAAResource:
				val = net.IP(b.AAAA[:]).String()
			case *dnsmessage.CNAMEResource:
				val = b.CNAME.String()
			}
			fmt.Printf("    %v %v %s TTL=%d\n", a.Header.Name, a.Header.Type, val, a.Header.TTL)
		}
	}
	fmt.Printf("  hex: %s\n", hex.EncodeToString(resp))
}
