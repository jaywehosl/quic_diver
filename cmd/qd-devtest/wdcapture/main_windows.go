//go:build windows

// Command wdcapture — dev-smoke реального захвата WinDivert.
//
// Открывает WinDivert в режиме SNIFF (перехват КОПИЙ пакетов — оригинальный
// трафик идёт дальше, сеть не рвётся), печатает первые N пакетов и выходит.
// Проверяет на живом трафике: загрузку драйвера, filter-выражение, разбор батча
// и WINDIVERT_ADDRESS. Требует запуска ОТ ИМЕНИ АДМИНИСТРАТОРА.
//
// Пример (в elevated-консоли):
//
//	go run ./cmd/qd-devtest/wdcapture -filter "outbound and ip and tcp.DstPort == 443" -n 15
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"

	"quicdiver/internal/packet"
	"quicdiver/internal/packet/windivert"
)

func main() {
	dll := flag.String("dll", `C:\Users\jaywehosl\Downloads\WinDivert-2.2.2-A\x64\WinDivert.dll`, "путь к WinDivert.dll (рядом должен лежать WinDivert64.sys)")
	filter := flag.String("filter", "outbound and ip", "WinDivert filter-выражение")
	n := flag.Int("n", 10, "сколько пакетов показать")
	flag.Parse()

	src, err := windivert.Open(*dll, *filter, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		log.Fatalf("open: %v\n(запусти консоль ОТ ИМЕНИ АДМИНИСТРАТОРА)", err)
	}
	defer src.Close()

	fmt.Printf("WinDivert открыт. filter=%q\nловлю %d пакетов (SNIFF — трафик не трогается)...\n", *filter, *n)

	ctx := context.Background()
	shown := 0
	for shown < *n {
		pkts, err := src.Recv(ctx)
		if err != nil {
			log.Fatalf("recv: %v", err)
		}
		for i := range pkts {
			p := &pkts[i]
			fmt.Printf("  [%2d] dir=%-8s len=%-5d %s -> %s\n",
				shown, dirStr(p.Dir), len(p.Data), srcAddr(p.Data), dstAddr(p.Data))
			shown++
			if shown >= *n {
				break
			}
		}
	}
	fmt.Println("готово.")
}

func dirStr(d packet.Direction) string {
	if d == packet.Outbound {
		return "outbound"
	}
	return "inbound"
}

func srcAddr(b []byte) netip.Addr { return ipAt(b, false) }
func dstAddr(b []byte) netip.Addr { return ipAt(b, true) }

// ipAt извлекает src/dst адрес из IP-заголовка.
func ipAt(b []byte, dst bool) netip.Addr {
	if len(b) < 1 {
		return netip.Addr{}
	}
	switch b[0] >> 4 {
	case 4:
		off := 12 // src
		if dst {
			off = 16
		}
		if len(b) < off+4 {
			return netip.Addr{}
		}
		return netip.AddrFrom4([4]byte(b[off : off+4]))
	case 6:
		off := 8 // src
		if dst {
			off = 24
		}
		if len(b) < off+16 {
			return netip.Addr{}
		}
		return netip.AddrFrom16([16]byte(b[off : off+16]))
	default:
		return netip.Addr{}
	}
}
