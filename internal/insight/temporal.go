package insight

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"cracknet/internal/db"
)

// TemporalReport compares cracking activity across two time windows and includes evolution analysis.
type TemporalReport struct {
	Period1      string                   `json:"period1"`
	Period2      string                   `json:"period2"`
	Period1Count int                      `json:"period1_count"`
	Period2Count int                      `json:"period2_count"`
	Evolution    map[string]float64       `json:"evolution,omitempty"`
	TrueChangePct float64                 `json:"true_change_pct"`
}

// classifyPasswordChange categorises how a password changed between two versions.
func classifyPasswordChange(old, new_ string) string {
	if old == new_ {
		return "no_change"
	}

	// case_change: only casing changed
	if strings.ToLower(old) == strings.ToLower(new_) {
		return "case_change"
	}

	// year_increment: same base word, year suffix changed by 1
	oldBase, oldYear := splitWordYear(old)
	newBase, newYear := splitWordYear(new_)
	if oldBase != "" && oldBase == newBase && oldYear > 0 && newYear > 0 && abs(newYear-oldYear) == 1 {
		return "year_increment"
	}

	// digit_increment: numeric suffix incremented
	oldWord, oldNum := splitWordNum(old)
	newWord, newNum := splitWordNum(new_)
	if oldWord != "" && strings.ToLower(oldWord) == strings.ToLower(newWord) && oldNum >= 0 && newNum > oldNum {
		return "digit_increment"
	}

	// special_append: same word with special char added at end
	if len(new_) > len(old) && strings.HasPrefix(new_, old) {
		tail := new_[len(old):]
		allSpecial := true
		for _, c := range tail {
			if unicode.IsLetter(c) || unicode.IsDigit(c) {
				allSpecial = false
				break
			}
		}
		if allSpecial {
			return "special_append"
		}
	}

	return "true_change"
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// splitWordYear splits a string like "Summer2024" into ("Summer", 2024).
func splitWordYear(s string) (string, int) {
	runes := []rune(s)
	n := len(runes)
	if n <= 4 {
		return "", 0
	}
	tail := string(runes[n-4:])
	head := string(runes[:n-4])
	allD := true
	for _, c := range tail {
		if !unicode.IsDigit(c) {
			allD = false
			break
		}
	}
	if !allD {
		return "", 0
	}
	allL := true
	for _, c := range head {
		if !unicode.IsLetter(c) {
			allL = false
			break
		}
	}
	if !allL {
		return "", 0
	}
	year := 0
	fmt.Sscanf(tail, "%d", &year)
	if year < 1900 || year > 2099 {
		return "", 0
	}
	return head, year
}

// splitWordNum splits a string like "dragon100" into ("dragon", 100).
func splitWordNum(s string) (string, int) {
	runes := []rune(s)
	n := len(runes)
	j := n
	for j > 0 && unicode.IsDigit(runes[j-1]) {
		j--
	}
	if j == 0 || j == n {
		return "", -1
	}
	word := string(runes[:j])
	numStr := string(runes[j:])
	num := 0
	fmt.Sscanf(numStr, "%d", &num)
	return word, num
}

// RunTemporal compares the number of hashes cracked in two date ranges and detects evolution.
func RunTemporal(potDB *db.DB, from1, to1, from2, to2 time.Time) (*TemporalReport, error) {
	all, err := potDB.GetAllCrackedWithPlaintext()
	if err != nil {
		return nil, fmt.Errorf("fetch hashes: %w", err)
	}

	countInRange := func(from, to time.Time) int {
		n := 0
		for _, h := range all {
			if !h.CrackedAt.Before(from) && h.CrackedAt.Before(to) {
				n++
			}
		}
		return n
	}

	// Evolution detection: look for usernames with multiple hashes from different source files.
	allMeta, _ := potDB.GetAllMetadata()
	// Group metadata by username.
	byUser := make(map[string][]db.HashMetadata)
	for _, m := range allMeta {
		if m.Username != "" {
			byUser[m.Username] = append(byUser[m.Username], m)
		}
	}

	// Build plaintext lookup.
	plaintextByHash := make(map[string]string, len(all))
	for _, h := range all {
		plaintextByHash[h.Hash] = h.Plaintext
	}

	evolutionCounts := make(map[string]int)
	totalEvolutions := 0
	for _, metas := range byUser {
		if len(metas) < 2 {
			continue
		}
		// Sort by import_date.
		sort.Slice(metas, func(i, j int) bool {
			return metas[i].ImportDate.Before(metas[j].ImportDate)
		})
		for i := 0; i+1 < len(metas); i++ {
			oldPT := plaintextByHash[metas[i].Hash]
			newPT := plaintextByHash[metas[i+1].Hash]
			if oldPT == "" || newPT == "" {
				continue
			}
			changeType := classifyPasswordChange(oldPT, newPT)
			evolutionCounts[changeType]++
			totalEvolutions++
		}
	}

	evolution := make(map[string]float64, len(evolutionCounts))
	trueChangePct := 0.0
	if totalEvolutions > 0 {
		for k, v := range evolutionCounts {
			evolution[k] = float64(v) * 100.0 / float64(totalEvolutions)
		}
		trueChangePct = evolution["true_change"]
	}

	if totalEvolutions > 0 {
		fmt.Printf("\n  Password evolution analysis (%d transitions):\n", totalEvolutions)
		keys := make([]string, 0, len(evolution))
		for k := range evolution {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return evolution[keys[i]] > evolution[keys[j]] })
		for _, k := range keys {
			fmt.Printf("    %-18s  %.1f%%\n", k, evolution[k])
		}
		fmt.Printf("  Only %.1f%% of users made a genuinely new password during the measured period.\n", trueChangePct)
	}

	return &TemporalReport{
		Period1:       fmt.Sprintf("%s – %s", from1.Format("2006-01-02"), to1.Format("2006-01-02")),
		Period2:       fmt.Sprintf("%s – %s", from2.Format("2006-01-02"), to2.Format("2006-01-02")),
		Period1Count:  countInRange(from1, to1),
		Period2Count:  countInRange(from2, to2),
		Evolution:     evolution,
		TrueChangePct: trueChangePct,
	}, nil
}

