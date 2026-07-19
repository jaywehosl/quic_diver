package main

import (
	"io"
	"log"
	"os"
	"path/filepath"

	"quicdiver/internal/client/config"
)

// maxLogSize — при каком размере журнал начинается заново.
//
// Журнал нужен, чтобы разобрать вчерашнюю поломку, а не чтобы копиться годами.
// Мегабайта хватает на несколько суток работы; при переполнении прежний файл
// сохраняется рядом как .old — одна предыдущая история остаётся.
const maxLogSize = 1 << 20

// setupLog направляет журнал в файл рядом с настройками.
//
// Релизная сборка собирается без консоли (-H windowsgui): выводить туда нечего,
// и без файла причина поломки просто исчезала бы. Возвращает функцию закрытия.
//
// Если файл открыть не удалось, журнал идёт в стандартный вывод как раньше:
// потеря журнала не повод не запускаться.
func setupLog(quiet bool) func() {
	dir, err := config.Dir()
	if err != nil {
		return func() {}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return func() {}
	}
	path := filepath.Join(dir, "qd-client.log")

	// Переполненный журнал начинаем заново, сохранив предыдущий.
	if st, err := os.Stat(path); err == nil && st.Size() > maxLogSize {
		os.Rename(path, path+".old")
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return func() {}
	}
	if quiet {
		// Консоли нет — пишем только в файл.
		log.SetOutput(f)
	} else {
		log.SetOutput(io.MultiWriter(os.Stderr, f))
	}
	log.Printf("--- журнал открыт (%s) ---", path)
	return func() { f.Close() }
}

// hasConsole — запущен ли процесс с консолью.
//
// У сборки без консоли стандартный вывод указывает в никуда, и писать туда
// бессмысленно; у запущенной из терминала — наоборот, вывод на месте и удобнее
// файла.
func hasConsole() bool {
	st, err := os.Stderr.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
