//go:build windows

package procwatch

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func listOSProcesses() ([]ProcessInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	err = windows.Process32First(snapshot, &procEntry)
	if err != nil {
		return nil, fmt.Errorf("Process32First: %w", err)
	}

	var procs []ProcessInfo
	for {
		name := windows.UTF16ToString(procEntry.ExeFile[:])
		procs = append(procs, ProcessInfo{
			PID:  procEntry.ProcessID,
			Name: name,
		})

		err = windows.Process32Next(snapshot, &procEntry)
		if err != nil {
			break
		}
	}

	return procs, nil
}
