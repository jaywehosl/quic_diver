package procwatch

import (
	"sort"
	"strings"
)

// ProcessInfo — информация о запущенном процессе.
type ProcessInfo struct {
	PID  uint32 `json:"pid"`
	Name string `json:"name"`
}

// ListUserProcesses возвращает список уникальных имен запущенных процессов пользователя.
func ListUserProcesses() ([]ProcessInfo, error) {
	raw, err := listOSProcesses()
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var result []ProcessInfo

	for _, p := range raw {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue
		}
		nameLower := strings.ToLower(name)
		if isSystemProcess(nameLower) {
			continue
		}
		if seen[nameLower] {
			continue
		}
		seen[nameLower] = true
		result = append(result, ProcessInfo{
			PID:  p.PID,
			Name: name,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})

	return result, nil
}

func isSystemProcess(name string) bool {
	systemProcs := []string{
		"system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe",
		"services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe",
		"memory compression", "spoolsv.exe", "sihost.exe", "taskhostw.exe",
		"explorer.exe", "ctfmon.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
		"searchhost.exe", "runtimebroker.exe", "applicationframehost.exe",
	}
	for _, sys := range systemProcs {
		if name == sys {
			return true
		}
	}
	return false
}
