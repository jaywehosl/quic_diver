//go:build !windows

package windivert

type ConflictReport struct {
	HasOrphanedService bool
	HasActiveConflict  bool
	ConflictingProcess string
	CleanedServices    []string
	Err                error
}

func InspectAndCleanupWinDivert() ConflictReport {
	return ConflictReport{}
}
