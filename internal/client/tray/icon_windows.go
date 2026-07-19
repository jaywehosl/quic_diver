//go:build windows

package tray

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Иконки рисуются в коде, а не лежат файлами.
//
// Релизный клиент по ТЗ — один exe без внешних зависимостей. Четыре
// 16×16-кружка не стоят ни ресурсной секции с .ico, ни распаковки на диск:
// формы у них одинаковые, отличается только цвет, а именно цветом значок и
// говорит.
const iconSize = 16

// цвета кружков (BGR, как их ждёт Windows-битмап).
var lookColors = map[Look][3]byte{
	Grey:  {0x9E, 0x9E, 0x9E}, // выключено
	Green: {0x50, 0xAF, 0x4C}, // работает
	Red:   {0x36, 0x36, 0xF4}, // связи нет
	Blue:  {0xF4, 0x95, 0x21}, // есть уведомления
}

// icon отдаёт значок нужного цвета, создавая его при первом обращении.
func (t *Tray) icon(l Look) windows.Handle {
	t.mu.Lock()
	if h, ok := t.icons[l]; ok {
		t.mu.Unlock()
		return h
	}
	t.mu.Unlock()

	h := makeIcon(lookColors[l])

	t.mu.Lock()
	defer t.mu.Unlock()
	// Пока рисовали, значок мог создать и параллельный вызов — лишний убираем.
	if cur, ok := t.icons[l]; ok {
		procDestroyIcon.Call(uintptr(h))
		return cur
	}
	t.icons[l] = h
	return h
}

// makeIcon строит 16×16-кружок заданного цвета.
//
// CreateIcon хочет две маски: AND (прозрачность) и XOR (цвет). Единица в AND
// означает «оставить фон», поэтому кружок — это нули в AND и цвет в XOR.
func makeIcon(color [3]byte) windows.Handle {
	const bytesPerRow = iconSize / 8 // 1-битная маска: 16 пикселей = 2 байта

	and := make([]byte, bytesPerRow*iconSize)
	xor := make([]byte, iconSize*iconSize*4) // 32 бита на пиксель

	const r = iconSize / 2
	for y := 0; y < iconSize; y++ {
		for x := 0; x < iconSize; x++ {
			dx, dy := float64(x-r)+0.5, float64(y-r)+0.5
			inside := dx*dx+dy*dy <= float64(r-1)*float64(r-1)

			bit := uint(7 - x%8)
			if !inside {
				// Вне круга — прозрачно: единица в AND оставляет фон лотка.
				and[y*bytesPerRow+x/8] |= 1 << bit
				continue
			}
			p := (y*iconSize + x) * 4
			xor[p+0], xor[p+1], xor[p+2] = color[0], color[1], color[2]
			xor[p+3] = 0xFF
		}
	}

	inst, _, _ := procGetModuleHandle.Call(0)
	h, _, _ := procCreateIcon.Call(inst, iconSize, iconSize, 1, 32,
		uintptr(unsafe.Pointer(&and[0])), uintptr(unsafe.Pointer(&xor[0])))
	return windows.Handle(h)
}
