package insight

import (
	"fmt"

	"cracknet/internal/db"
)

// ReuseReport summarises password reuse findings.
type ReuseReport struct {
	ExactReuseCount int
	Groups          []db.ReuseEntry
}

// RunReuse detects exact password reuse across accounts.
func RunReuse(potDB *db.DB) (*ReuseReport, error) {
	entries, err := potDB.DetectReuse()
	if err != nil {
		return nil, fmt.Errorf("detect reuse: %w", err)
	}
	return &ReuseReport{
		ExactReuseCount: len(entries),
		Groups:          entries,
	}, nil
}
