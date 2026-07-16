// Command udpflood-srv — сырой UDP-флуд БЕЗ QUIC и без congestion control.
// Отвечает на вопрос: упирается ли путь dev↔VM в сеть или в CC quic-go.
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"time"
)

func main() {
	addr := flag.String("addr", ":4444", "UDP-адрес")
	size := flag.Int("size", 1200, "размер датаграммы")
	dur := flag.Duration("d", 15*time.Second, "сколько флудить после запроса")
	flag.Parse()

	pc, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	// буферы побольше, чтобы не терять на всплесках
	if u, ok := pc.(*net.UDPConn); ok {
		_ = u.SetReadBuffer(8 << 20)
		_ = u.SetWriteBuffer(8 << 20)
	}
	log.Printf("udpflood-srv на %s (датаграмма %d байт)", *addr, *size)

	buf := make([]byte, 64)
	for {
		_, peer, err := pc.ReadFrom(buf)
		if err != nil {
			log.Fatalf("read: %v", err)
		}
		log.Printf("флужу %s в течение %v", peer, *dur)
		go flood(pc, peer, *size, *dur)
	}
}

// flood шлёт нумерованные датаграммы на максимальной скорости — без CC, без
// ретрансмита: чистая проверка того, что физически тянет путь.
func flood(pc net.PacketConn, peer net.Addr, size int, dur time.Duration) {
	data := make([]byte, size)
	deadline := time.Now().Add(dur)
	var seq uint64
	for time.Now().Before(deadline) {
		binary.BigEndian.PutUint64(data, seq)
		if _, err := pc.WriteTo(data, peer); err != nil {
			time.Sleep(50 * time.Microsecond)
			continue
		}
		seq++
	}
	log.Printf("готово: отправлено %d датаграмм", seq)
}
