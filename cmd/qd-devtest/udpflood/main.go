// Command udpflood — принимает сырой UDP-флуд с узла и считает, что реально
// тянет путь: throughput и потери (по пропускам seq). Без QUIC, без congestion.
//
// Если тут ~750 Мбит, а QUIC даёт 560 — виноват congestion control, и BRUTAL
// оправдан. Если и тут ~560 — упираемся в путь/UDP, и CC ни при чём.
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"math"
	"net"
	"time"
)

func main() {
	server := flag.String("server", "localhost:4444", "udpflood-srv")
	dur := flag.Duration("d", 15*time.Second, "длительность приёма")
	flag.Parse()

	conn, err := net.Dial("udp", *server)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if u, ok := conn.(*net.UDPConn); ok {
		_ = u.SetReadBuffer(8 << 20)
		_ = u.SetWriteBuffer(8 << 20)
	}

	if _, err := conn.Write([]byte("go")); err != nil {
		log.Fatalf("запрос: %v", err)
	}
	log.Printf("жду флуд с %s (%v)...", *server, *dur)

	buf := make([]byte, 65536)
	var total, packets int64
	var maxSeq uint64
	var samples []float64
	start := time.Now()
	deadline := start.Add(*dur)
	lastT, lastTotal := start, int64(0)

	_ = conn.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		total += int64(n)
		packets++
		if n >= 8 {
			if s := binary.BigEndian.Uint64(buf[:8]); s > maxSeq {
				maxSeq = s
			}
		}
		if now := time.Now(); now.Sub(lastT) >= time.Second {
			mbps := float64(total-lastTotal) * 8 / now.Sub(lastT).Seconds() / 1e6
			samples = append(samples, mbps)
			log.Printf("  %6.1f Mbps", mbps)
			lastTotal, lastT = total, now
		}
	}
	el := time.Since(start)

	avg := float64(total) * 8 / el.Seconds() / 1e6
	var loss float64
	if maxSeq > 0 {
		loss = float64(int64(maxSeq+1)-packets) * 100 / float64(maxSeq+1)
	}
	log.Printf("=== СЫРОЙ UDP (без QUIC, без congestion) ===")
	log.Printf("throughput: avg %.1f Mbps, stddev %.1f (%.0f%%), %d МБ",
		avg, stddev(samples), stddev(samples)*100/math.Max(avg, 1), total/1024/1024)
	log.Printf("потери: получено %d из %d (%.2f%%)", packets, maxSeq+1, loss)
	log.Printf("→ QUIC-datagram давал ~560, TCP по этому пути ~685-747")
}

func stddev(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	m := s / float64(len(xs))
	var v float64
	for _, x := range xs {
		v += (x - m) * (x - m)
	}
	return math.Sqrt(v / float64(len(xs)))
}
