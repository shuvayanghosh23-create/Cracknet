package insight

import (
	"fmt"
	"time"

	"cracknet/internal/db"
)

// TemporalReport compares cracking activity across two time windows.
type TemporalReport struct {
	Period1      string
	Period2      string
	Period1Count int
	Period2Count int
}

// RunTemporal compares the number of hashes cracked in two date ranges.
func RunTemporal(potDB *db.DB, from1, to1, from2, to2 time.Time) (*TemporalReport, error) {
	all, err := potDB.GetAllCrackedWithPlaintext()
	if err != nil {
		return nil, fmt.Errorf("fetch hashes: %w", err)
	}

	count := func(from, to time.Time) int {
		n := 0
		for _, h := range all {
			if !h.CrackedAt.Before(from) && h.CrackedAt.Before(to) {
				n++
			}
		}
		return n
	}

	return &TemporalReport{
		Period1:      fmt.Sprintf("%s – %s", from1.Format("2006-01-02"), to1.Format("2006-01-02")),
		Period2:      fmt.Sprintf("%s – %s", from2.Format("2006-01-02"), to2.Format("2006-01-02")),
		Period1Count: count(from1, to1),
		Period2Count: count(from2, to2),
	}, nil
}
