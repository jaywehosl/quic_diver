//go:build !windows

package main

import "fmt"

func main() {
	fmt.Println("wdcapture: доступен только на Windows (WinDivert)")
}
