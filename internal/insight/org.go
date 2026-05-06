package insight

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"cracknet/internal/db"
)

// OrgGroup aggregates stats for one email domain / department.
type OrgGroup struct {
	Domain       string  `json:"domain"`
	Department   string  `json:"department"`
	Count        int     `json:"count"`
	CrackedCount int     `json:"cracked_count"`
	CrackRate    float64 `json:"crack_rate"`
	AvgEntropy   float64 `json:"avg_entropy"`
	RiskScore    float64 `json:"risk_score"`
	RiskLabel    string  `json:"risk_label"`
}

// detectDepartment maps a subdomain/domain to a department label.
func detectDepartment(domain string) string {
	lower := strings.ToLower(domain)
	sub := lower
	if parts := strings.SplitN(lower, ".", 2); len(parts) > 1 {
		sub = parts[0]
	}
	switch {
	case contains(sub, "it", "dev", "infosec", "security"):
		return "IT"
	case contains(sub, "finance", "accounting", "payroll"):
		return "Finance"
	case contains(sub, "hr", "people", "talent"):
		return "HR"
	case contains(sub, "exec", "mgmt", "board", "leadership", "management"):
		return "Management"
	default:
		return sub
	}
}

func contains(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func riskLabel(score float64) string {
	switch {
	case score >= 70:
		return "CRITICAL"
	case score >= 50:
		return "HIGH"
	case score >= 30:
		return "MODERATE"
	default:
		return "LOW"
	}
}

// RunOrg groups metadata by email domain, computes risk scores, and prints a table.
func RunOrg(potDB *db.DB) ([]OrgGroup, error) {
	allHashes, err := potDB.GetAllCrackedWithPlaintext()
	if err != nil {
		return nil, fmt.Errorf("fetch hashes: %w", err)
	}

	allMeta, err := potDB.GetAllMetadata()
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}

	metaByHash := make(map[string]db.HashMetadata, len(allMeta))
	for _, m := range allMeta {
		metaByHash[m.Hash] = m
	}

	// Get entropy data.
	patterns, _ := potDB.GetPasswordPatterns()
	entropyByPlain := make(map[string]float64, len(patterns))
	for _, pp := range patterns {
		entropyByPlain[pp.Plaintext] = pp.EntropyBits
	}

	type domainData struct {
		count        int
		cracked      int
		entropySum   float64
		entropyCount int
	}
	domainMap := make(map[string]*domainData)

	for _, h := range allHashes {
		meta, ok := metaByHash[h.Hash]
		if !ok || meta.Email == "" {
			continue
		}
		parts := strings.SplitN(meta.Email, "@", 2)
		if len(parts) != 2 {
			continue
		}
		domain := strings.ToLower(parts[1])
		d, exists := domainMap[domain]
		if !exists {
			d = &domainData{}
			domainMap[domain] = d
		}
		d.count++
		if h.Plaintext != "" {
			d.cracked++
			if e, ok := entropyByPlain[h.Plaintext]; ok {
				d.entropySum += e
				d.entropyCount++
			}
		}
	}

	var groups []OrgGroup
	for domain, d := range domainMap {
		crackRate := 0.0
		if d.count > 0 {
			crackRate = float64(d.cracked) / float64(d.count)
		}
		avgEntropy := 0.0
		if d.entropyCount > 0 {
			avgEntropy = d.entropySum / float64(d.entropyCount)
		}
		normEntropy := math.Min(avgEntropy/50.0, 1.0)
		score := (crackRate*0.6 + (1-normEntropy)*0.4) * 100.0
		dept := detectDepartment(domain)
		groups = append(groups, OrgGroup{
			Domain:       domain,
			Department:   dept,
			Count:        d.count,
			CrackedCount: d.cracked,
			CrackRate:    crackRate,
			AvgEntropy:   avgEntropy,
			RiskScore:    score,
			RiskLabel:    riskLabel(score),
		})
	}

	sort.Slice(groups, func(i, j int) bool {
		return groups[i].RiskScore > groups[j].RiskScore
	})

	// Print table.
	fmt.Printf("\n  %-20s %-12s %6s %7s %9s %7s %5s\n",
		"Department", "Domain", "Users", "Cracked", "CrackRate", "AvgEnt", "Risk")
	fmt.Printf("  %s\n", strings.Repeat("─", 72))
	for _, g := range groups {
		fmt.Printf("  %-20s %-12s %6d %7d %8.1f%% %7.1f %-9s\n",
			g.Department, g.Domain, g.Count, g.CrackedCount,
			g.CrackRate*100, g.AvgEntropy, g.RiskLabel)
	}

	// Flag CRITICAL if Management crack rate > IT crack rate.
	mgmtRate, itRate := 0.0, 0.0
	mgmtSet, itSet := false, false
	for _, g := range groups {
		if g.Department == "Management" && (!mgmtSet || g.CrackRate > mgmtRate) {
			mgmtRate = g.CrackRate
			mgmtSet = true
		}
		if g.Department == "IT" && (!itSet || g.CrackRate > itRate) {
			itRate = g.CrackRate
			itSet = true
		}
	}
	if mgmtSet && itSet && mgmtRate > itRate {
		fmt.Printf("\n  [CRITICAL] Management accounts have a higher crack rate (%.1f%%) than IT (%.1f%%)\n",
			mgmtRate*100, itRate*100)
	}

	return groups, nil
}

