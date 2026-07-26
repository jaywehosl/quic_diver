//go:build windows

package windivert

import (
	"testing"
)

func TestInspectAndCleanupWinDivert(t *testing.T) {
	report := InspectAndCleanupWinDivert()
	if report.Err != nil {
		t.Logf("InspectAndCleanupWinDivert: %v", report.Err)
	} else {
		t.Logf("WinDivert inspection report: orphan=%v, conflict=%v (%s), cleaned=%v",
			report.HasOrphanedService, report.HasActiveConflict, report.ConflictingProcess, report.CleanedServices)
	}
}
