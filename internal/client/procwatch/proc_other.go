//go:build !windows

package procwatch

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func listOSProcesses() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var procs []ProcessInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		commPath := filepath.Join("/proc", entry.Name(), "comm")
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(data))
		if name != "" {
			procs = append(procs, ProcessInfo{
				PID:  uint32(pid),
				Name: name,
			})
		}
	}
	return procs, nil
}
