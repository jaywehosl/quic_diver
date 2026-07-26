//go:build windows

package windivert

import (
	"fmt"
	"log"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"

	"quicdiver/internal/client/procwatch"
)

// WinDivertServiceNames — варианты имён системных служб WinDivert
var WinDivertServiceNames = []string{
	"WinDivert",
	"WinDivert14",
	"WinDivert2.2",
	"WinDivert64",
}

// ConflictingProcessNames — стороннее ПО, использующее WinDivert
var ConflictingProcessNames = []string{
	"winws.exe",
	"goodbyedpi.exe",
	"byedpi.exe",
	"zapret.exe",
}

// ConflictReport — статус проверки драйвера WinDivert и конфликтов
type ConflictReport struct {
	HasOrphanedService bool
	HasActiveConflict  bool
	ConflictingProcess string
	CleanedServices    []string
	Err                error
}

// InspectAndCleanupWinDivert проверяет наличие служб WinDivert в SCM,
// авто-удаляет «осиротевшие» службы от упавшего ПО и предупреждает об активных конфликтах.
func InspectAndCleanupWinDivert() ConflictReport {
	var report ConflictReport

	// 1. Проверяем запущенное стороннее ПО (Zapret, GoodbyeDPI и т.д.)
	processes, err := procwatch.ListUserProcesses()
	if err == nil {
		for _, proc := range processes {
			nameLower := strings.ToLower(proc.Name)
			for _, conflict := range ConflictingProcessNames {
				if nameLower == conflict {
					report.HasActiveConflict = true
					report.ConflictingProcess = proc.Name
					log.Printf("windivert: обнаружено активное конфликтующее ПО %s (PID: %d)", proc.Name, proc.PID)
					break
				}
			}
		}
	}

	// 2. Открываем SCM для проверки служб
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		report.Err = fmt.Errorf("ошибка открытия SCM: %w", err)
		return report
	}
	defer windows.CloseServiceHandle(scm)

	for _, svcName := range WinDivertServiceNames {
		pName, err := syscall.UTF16PtrFromString(svcName)
		if err != nil {
			continue
		}
		// Пробуем открыть службу
		svc, err := windows.OpenService(scm, pName, windows.SERVICE_QUERY_STATUS|windows.SERVICE_STOP|windows.DELETE)
		if err != nil {
			continue // служба не существует
		}

		// Если сторонний софт НЕ запущен — служба является «осиротевшей» (leftover)!
		if !report.HasActiveConflict {
			report.HasOrphanedService = true
			log.Printf("windivert: найдена осиротевшая служба %s, выполняем очистку...", svcName)

			var status windows.SERVICE_STATUS
			_ = windows.ControlService(svc, windows.SERVICE_CONTROL_STOP, &status)
			if err := windows.DeleteService(svc); err == nil || err == windows.ERROR_SERVICE_MARKED_FOR_DELETE {
				report.CleanedServices = append(report.CleanedServices, svcName)
				log.Printf("windivert: осиротевшая служба %s успешно удалена", svcName)
			} else {
				log.Printf("windivert: не удалось удалить службу %s: %v", svcName, err)
			}
		}
		windows.CloseServiceHandle(svc)
	}

	return report
}
