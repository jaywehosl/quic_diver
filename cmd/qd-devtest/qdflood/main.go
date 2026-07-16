// Command qdflood — изолирующий измеритель ЧИСТОГО QUIC-datagram транспорта
// (без connect-ip, gVisor и TCP-over-tunnel). Сервер флудит датаграммами, клиент
// меряет throughput и его стабильность (stddev) плюс RTT ping'ов ПОД НАГРУЗКОЙ
// (рост RTT = bufferbloat).
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"log"
	"math"
	"sort"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	markData = 0x02
	markPing = 0x01
)

func main() {
	srv := flag.String("server", "localhost:4443", "qdflood-srv")
	dur := flag.Duration("d", 15*time.Second, "длительность")
	pingEvery := flag.Duration("ping", 100*time.Millisecond, "интервал ping")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *dur+10*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx,
		*srv,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"qdflood"}},
		&quic.Config{EnableDatagrams: true, MaxIdleTimeout: 30 * time.Second},
	)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")
	log.Printf("QUIC до %s установлен — чистый datagram-транспорт", *srv)

	var mu sync.Mutex
	var bytesRcvd int64
	var rtts []time.Duration
	// Учёт СЕТЕВЫХ потерь по пропускам seq (датаграммы не ретрансмитятся).
	var maxSeq, gotCount uint64
	var seenFirst bool

	// Ping под нагрузкой.
	go func() {
		t := time.NewTicker(*pingEvery)
		defer t.Stop()
		buf := make([]byte, 9)
		buf[0] = markPing
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				binary.BigEndian.PutUint64(buf[1:], uint64(time.Now().UnixNano()))
				_ = conn.SendDatagram(buf)
			}
		}
	}()

	// Приём: данные считаем, ping'и — измеряем RTT.
	go func() {
		for {
			b, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			if len(b) == 0 {
				continue
			}
			switch b[0] {
			case markData:
				mu.Lock()
				bytesRcvd += int64(len(b))
				if len(b) >= 9 {
					seq := binary.BigEndian.Uint64(b[1:])
					if !seenFirst || seq > maxSeq {
						maxSeq = seq
						seenFirst = true
					}
					gotCount++
				}
				mu.Unlock()
			case markPing:
				if len(b) >= 9 {
					sent := int64(binary.BigEndian.Uint64(b[1:]))
					mu.Lock()
					rtts = append(rtts, time.Duration(time.Now().UnixNano()-sent))
					mu.Unlock()
				}
			}
		}
	}()

	// Сэмплы throughput по секундам.
	var samples []float64
	var last int64
	start := time.Now()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	deadline := start.Add(*dur)
	for time.Now().Before(deadline) {
		select {
		case <-tick.C:
			mu.Lock()
			cur := bytesRcvd
			mu.Unlock()
			mbps := float64(cur-last) * 8 / 1e6
			samples = append(samples, mbps)
			log.Printf("  %5.1f Mbps", mbps)
			last = cur
		case <-ctx.Done():
			break
		}
	}

	mu.Lock()
	total := bytesRcvd
	r := append([]time.Duration(nil), rtts...)
	sentApprox := maxSeq + 1 // сервер нумерует с 0
	got := gotCount
	mu.Unlock()

	el := time.Since(start)
	avg := float64(total) * 8 / el.Seconds() / 1e6
	log.Printf("=== ЧИСТЫЙ QUIC-datagram ===")
	log.Printf("throughput: avg %.1f Mbps, stddev %.1f Mbps (%.0f%% от среднего), %d МБ за %v",
		avg, stddev(samples), stddev(samples)*100/math.Max(avg, 1), total/1024/1024, el.Round(time.Millisecond))
	if sentApprox > 0 && got > 0 {
		lost := int64(sentApprox) - int64(got)
		if lost < 0 {
			lost = 0
		}
		lossPct := float64(lost) * 100 / float64(sentApprox)
		log.Printf("СЕТЕВЫЕ потери датаграмм: отправлено≈%d, получено=%d, потеряно=%d (%.3f%%)",
			sentApprox, got, lost, lossPct)
		log.Printf("→ TCP через туннель по Mathis: BW ≈ MSS/(RTT×√p) — при %.3f%% и RTT 14мс это ≈ %.0f Mbps",
			lossPct, mathis(1200, 0.014, lossPct/100))
	}
	reportRTT(r)
}

// mathis — предел TCP при потерях: BW ≈ MSS/(RTT×√p), Мбит/с.
func mathis(mss float64, rtt float64, p float64) float64 {
	if p <= 0 {
		return math.Inf(1)
	}
	return mss * 8 / (rtt * math.Sqrt(p)) / 1e6
}

func stddev(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))
	var v float64
	for _, x := range xs {
		v += (x - mean) * (x - mean)
	}
	return math.Sqrt(v / float64(len(xs)))
}

func reportRTT(rtts []time.Duration) {
	if len(rtts) == 0 {
		log.Printf("RTT: нет ответов на ping (!)")
		return
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	var sum time.Duration
	for _, r := range rtts {
		sum += r
	}
	p := func(q float64) time.Duration { return rtts[int(float64(len(rtts)-1)*q)] }
	log.Printf("RTT под нагрузкой (n=%d): min %v, med %v, p95 %v, max %v, avg %v",
		len(rtts), rtts[0].Round(time.Millisecond), p(0.5).Round(time.Millisecond),
		p(0.95).Round(time.Millisecond), rtts[len(rtts)-1].Round(time.Millisecond),
		(sum / time.Duration(len(rtts))).Round(time.Millisecond))
	log.Printf("→ если min≈14мс, а med/p95 сильно выше — это bufferbloat (очередь под нагрузкой)")
}
