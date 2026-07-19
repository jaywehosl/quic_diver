//go:build windows

package windivert

import (
	"encoding/binary"
	"testing"
)

// Вшитые драйвер и библиотека обязаны быть целыми 64-битными PE-файлами.
//
// Проверка не теоретическая: при чистке истории репозитория sed прошёлся по ним
// как по тексту, и каждый потерял по последнему байту. Клиент после этого падал
// с «%1 is not a valid Win32 application» — сообщением, которое на повреждение
// файла не указывает вовсе, а наша обёртка вдобавок приписывала ему «нужны
// права администратора». Сутки поисков не там начинаются именно так.
func TestEmbeddedBinariesAreValidPE(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		// minSize — грубая нижняя граница: усечённый файл ловится и по ней.
		minSize int
	}{
		{"WinDivert.dll", mustAsset(t, "assets/WinDivert.dll"), 40000},
		{"WinDivert64.sys", mustAsset(t, "assets/WinDivert64.sys"), 80000},
	}

	for _, c := range cases {
		if len(c.data) < c.minSize {
			t.Fatalf("%s: %d байт — файл усечён", c.name, len(c.data))
		}
		if c.data[0] != 'M' || c.data[1] != 'Z' {
			t.Fatalf("%s: нет сигнатуры MZ — это не исполняемый файл", c.name)
		}

		// e_lfanew указывает на PE-заголовок.
		off := int(binary.LittleEndian.Uint32(c.data[0x3C:0x40]))
		if off <= 0 || off+6 > len(c.data) {
			t.Fatalf("%s: смещение PE-заголовка %d вне файла", c.name, off)
		}
		if string(c.data[off:off+4]) != "PE\x00\x00" {
			t.Fatalf("%s: нет сигнатуры PE по смещению %d", c.name, off)
		}

		// Машина обязана быть x86-64: 32-битная библиотека в 64-битном процессе
		// даёт ровно ту же ошибку загрузки, что и повреждённый файл.
		const machineAMD64 = 0x8664
		machine := binary.LittleEndian.Uint16(c.data[off+4 : off+6])
		if machine != machineAMD64 {
			t.Fatalf("%s: архитектура 0x%04x, ожидалась x86-64", c.name, machine)
		}
	}
}

func mustAsset(t *testing.T, name string) []byte {
	t.Helper()
	b, err := assets.ReadFile(name)
	if err != nil {
		t.Fatalf("вшитый %s не читается: %v", name, err)
	}
	return b
}
