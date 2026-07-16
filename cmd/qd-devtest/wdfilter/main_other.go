//go:build !windows

package main

import "fmt"

func main() {
	fmt.Println("wdfilter: только Windows (WinDivert)")
}
