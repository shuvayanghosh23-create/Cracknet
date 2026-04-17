package insight

import (
	"fmt"
	"sort"
	"strings"

	"cracknet/internal/db"
)

// OrgGroup aggregates stats for one email domain.
type OrgGroup struct {
	Domain       string
	Count        int
	CrackedCount int
	RiskScore    float64
}

// RunOrg groups metadata by email domain and calculates a simple risk score.
func RunOrg(potDB *db.DB) ([]OrgGroup, error) {
	hashes, err := potDB.GetAllCrackedWithPlaintext()
	if err != nil {
		return nil, fmt.Errorf("fetch hashes: %w", err)
	}

	domainCount := make(map[string]int)
	domainCracked := make(map[string]int)

	for _, h := range hashes {
		meta, err := potDB.GetHashMetadata(h.Hash)
		if err != nil || meta == nil {
			continue
		}
		email := meta.Email
		if email == "" {
			continue
		}
		parts := strings.SplitN(email, "@", 2)
		if len(parts) != 2 {
			continue
		}
		domain := strings.ToLower(parts[1])
		domainCount[domain]++
		if h.Plaintext != "" {
			domainCracked[domain]++
		}
	}

	var groups []OrgGroup
	for domain, count := range domainCount {
		cracked := domainCracked[domain]
		risk := 0.0
		if count > 0 {
			risk = float64(cracked) / float64(count) * 100.0
		}
		groups = append(groups, OrgGroup{
			Domain:       domain,
			Count:        count,
			CrackedCount: cracked,
			RiskScore:    risk,
		})
	}

	sort.Slice(groups, func(i, j int) bool {
		return groups[i].RiskScore > groups[j].RiskScore
	})
	return groups, nil
}
