//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ensureElevated перезапускает процесс с правами администратора, если их нет.
//
// WinDivert грузит драйвер режима ядра — без elevation Open падает. Вместо того
// чтобы требовать «запуск от администратора» вручную, поднимаемся сами через UAC
// (ShellExecute с глаголом runas) и завершаем не-elevated экземпляр.
func ensureElevated() {
	if isElevated() {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return // не смогли — пусть падает дальше с понятной ошибкой WinDivert
	}
	// Аргументы не пробрасываем: боевая сборка все параметры несёт внутри (сервер,
	// токен), запускается двойным кликом без флагов.
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	// SW_SHOWNORMAL — открыть новое консольное окно elevated-процесса
	if err := windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL); err != nil {
		return // отказ UAC — выходим, ниже WinDivert всё равно не откроется
	}
	os.Exit(0)
}

// isElevated — запущены ли мы с повышенными правами.
func isElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	var elevation uint32
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &size)
	if err != nil {
		return false
	}
	return elevation != 0
}

// holdOnExit придерживает консольное окно, чтобы пользователь успел прочитать
// причину выхода (двойной клик закрыл бы окно мгновенно).
func holdOnExit() {
	fmt.Fprintln(os.Stderr, "\n[клиент остановлен — окно закроется через 15 c]")
	time.Sleep(15 * time.Second)
}
