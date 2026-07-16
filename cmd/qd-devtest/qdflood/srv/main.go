// Command qdflood-srv — изолирующий сервер: чистый QUIC (без connect-ip, gVisor,
// TCP). Флудит клиента датаграммами на максимальной скорости и эхо-ит ping'и.
// Меряет ТОЛЬКО транспорт QUIC-datagram dev↔VM.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"math/big"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	markData = 0x02
	markPing = 0x01
)

func main() {
	addr := flag.String("addr", ":4443", "адрес прослушивания QUIC")
	size := flag.Int("size", 1200, "размер флуд-датаграммы")
	flag.Parse()

	ln, err := quic.ListenAddr(*addr, genTLS(), &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  30 * time.Second,
	})
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("qdflood-srv на %s (datagram size %d)", *addr, *size)

	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go serve(conn, *size)
	}
}

func serve(conn *quic.Conn, size int) {
	ctx := conn.Context()
	log.Printf("клиент %s", conn.RemoteAddr())

	// Флуд download на максимальной скорости. Каждая датаграмма нумеруется —
	// клиент по пропускам seq считает СЕТЕВЫЕ потери (датаграммы не ретрансмитятся).
	go func() {
		buf := make([]byte, size)
		buf[0] = markData
		var seq uint64
		for {
			if ctx.Err() != nil {
				return
			}
			binary.BigEndian.PutUint64(buf[1:], seq)
			err := conn.SendDatagram(buf)
			if err != nil {
				var tooLarge *quic.DatagramTooLargeError
				if errors.As(err, &tooLarge) {
					buf = make([]byte, tooLarge.MaxDatagramPayloadSize)
					buf[0] = markData
					continue
				}
				// очередь заполнена / нет разрешения — короткая уступка
				time.Sleep(50 * time.Microsecond)
				continue
			}
			seq++
		}
	}()

	// Эхо ping'ов.
	for {
		b, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(b) > 0 && b[0] == markPing {
			_ = conn.SendDatagram(b)
		}
	}
}

func genTLS() *tls.Config {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "qdflood"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		NextProtos:   []string{"qdflood"},
	}
}
