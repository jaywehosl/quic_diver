//go:build windows

// Command wdfilter — проверка WinDivert filter-выражения без драйвера и без прав
// администратора (WinDivertHelperCompileFilter). Печатает валидность и позицию
// ошибки. Нужен для отладки генератора фильтров.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/netip"

	"quicdiver/internal/guard"
	"quicdiver/internal/packet/windivert"
)

func main() {
	dll := flag.String("dll", `C:\Users\jaywehosl\Downloads\WinDivert-2.2.2-A\x64\WinDivert.dll`, "путь к WinDivert.dll")
	custom := flag.String("filter", "", "проверить свой фильтр; пусто → построить клиентский")
	srv := flag.String("server-ip", "localhost", "IP узла (для bypass)")
	flag.Parse()

	if err := windivert.Load(*dll); err != nil {
		log.Fatalf("load: %v", err)
	}

	f := *custom
	if f == "" {
		srvIP := netip.MustParseAddr(*srv)
		g := guard.New([]netip.Addr{srvIP})
		bypass := append([]netip.Prefix(nil), g.Bypasses()...)
		bypass = append(bypass, netip.PrefixFrom(srvIP, srvIP.BitLen()))
		f = windivert.BuildFilter(windivert.CaptureConfig{TCP: true, UDP: true, Bypass: bypass})
	}
	fmt.Printf("filter (%d байт):\n%s\n\n", len(f), f)

	errText, pos, ok := windivert.CompileFilter(f, windivert.LayerNetwork)
	if ok {
		fmt.Println("OK — фильтр валиден")
		return
	}
	fmt.Printf("ОШИБКА в позиции %d: %s\n", pos, errText)
	lo := pos - 30
	if lo < 0 {
		lo = 0
	}
	hi := pos + 30
	if hi > len(f) {
		hi = len(f)
	}
	fmt.Printf("контекст: ...%s  >>>HERE>>>  %s...\n", f[lo:pos], f[pos:hi])
}
