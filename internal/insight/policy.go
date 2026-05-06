package insight

import (
	"fmt"
	"strings"
	"unicode"

	"cracknet/internal/db"
)

// PolicyReport holds detected policy assumptions and bypass pattern statistics.
type PolicyReport struct {
	DetectedPolicy  map[string]bool    `json:"detected_policy"`
	BypassPatterns  map[string]float64 `json:"bypass_patterns"`
	PolicyCompliant int                `json:"policy_compliant"`
	Total           int                `json:"total"`
}

// detectEnforcedPolicy infers the likely password policy from observed compositions.
func detectEnforcedPolicy(patterns []db.PasswordPattern) map[string]bool {
	total := len(patterns)
	if total == 0 {
		return map[string]bool{}
	}

	var minLen8, hasUpper, hasDigit, hasSpecial int
	for _, p := range patterns {
		if p.Length >= 8 {
			minLen8++
		}
		if p.HasUpper {
			hasUpper++
		}
		if p.HasDigit {
			hasDigit++
		}
		if p.HasSpecial {
			hasSpecial++
		}
	}

	policy := map[string]bool{
		"min_length_8": float64(minLen8)/float64(total) >= 0.9,
		"requires_upper": float64(hasUpper)/float64(total) >= 0.7,
		"requires_digit": float64(hasDigit)/float64(total) >= 0.8,
		"requires_special": float64(hasSpecial)/float64(total) >= 0.4,
	}
	return policy
}

// meetsPolicy checks if a pattern satisfies all detected policy rules.
func meetsPolicy(p db.PasswordPattern, policy map[string]bool) bool {
	if policy["min_length_8"] && p.Length < 8 {
		return false
	}
	if policy["requires_upper"] && !p.HasUpper {
		return false
	}
	if policy["requires_digit"] && !p.HasDigit {
		return false
	}
	if policy["requires_special"] && !p.HasSpecial {
		return false
	}
	return true
}

// detectBypassPattern checks which bypass pattern a plaintext matches.
func detectBypassPattern(plaintext string) string {
	runes := []rune(plaintext)
	n := len(runes)
	if n == 0 {
		return ""
	}

	// capitalise_only: only first char upper, rest all lowercase
	if n >= 2 && unicode.IsUpper(runes[0]) {
		rest := string(runes[1:])
		allLow := true
		for _, c := range rest {
			if !unicode.IsLower(c) && unicode.IsLetter(c) {
				allLow = false
				break
			}
		}
		if allLow {
			return "capitalise_only"
		}
	}

	// append_year: word + 4-digit year
	if n > 4 {
		tail := string(runes[n-4:])
		head := string(runes[:n-4])
		allD := true
		for _, c := range tail {
			if !unicode.IsDigit(c) {
				allD = false
				break
			}
		}
		allL := true
		for _, c := range head {
			if !unicode.IsLetter(c) {
				allL = false
				break
			}
		}
		if allD && allL {
			year := 0
			fmt.Sscanf(tail, "%d", &year)
			if year >= 1900 && year <= 2099 {
				return "append_year"
			}
		}
	}

	// append_digit_end: 1–3 digits at very end, nothing else special
	j := n
	for j > 0 && unicode.IsDigit(runes[j-1]) {
		j--
	}
	if j > 0 && n-j >= 1 && n-j <= 3 {
		head := string(runes[:j])
		hasSpec := false
		for _, c := range head {
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
				hasSpec = true
				break
			}
		}
		if !hasSpec {
			return "append_digit_end"
		}
	}

	// append_special_end: one special char at end after letters/digits
	if n >= 2 {
		last := runes[n-1]
		if !unicode.IsLetter(last) && !unicode.IsDigit(last) {
			rest := string(runes[:n-1])
			hasSpec := false
			for _, c := range rest {
				if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
					hasSpec = true
					break
				}
			}
			if !hasSpec {
				return "append_special_end"
			}
		}
	}

	// leet_substitution: a→@ e→3 i→1 o→0 only
	lower := strings.ToLower(plaintext)
	normalized := strings.NewReplacer("@", "a", "3", "e", "1", "i", "0", "o").Replace(lower)
	if normalized != lower && func() bool {
		for _, c := range normalized {
			if !unicode.IsLetter(c) {
				return false
			}
		}
		return true
	}() {
		return "leet_substitution"
	}

	// double_word: word repeated twice
	if n%2 == 0 {
		half := n / 2
		if string(runes[:half]) == string(runes[half:]) {
			return "double_word"
		}
	}

	return ""
}

// RunPolicy detects the likely enforced password policy and bypass patterns.
func RunPolicy(potDB *db.DB) (*PolicyReport, error) {
	patterns, err := potDB.GetPasswordPatterns()
	if err != nil {
		return nil, fmt.Errorf("fetch patterns: %w", err)
	}
	if len(patterns) == 0 {
		// Try running DNA first to populate patterns.
		_, _ = RunDNA(potDB)
		patterns, _ = potDB.GetPasswordPatterns()
	}

	total := len(patterns)
	if total == 0 {
		fmt.Println("  No password patterns available. Run 'cracknet insight --db --module dna' first.")
		return &PolicyReport{}, nil
	}

	policy := detectEnforcedPolicy(patterns)
	fmt.Printf("\n  Detected policy assumptions:\n")
	for rule, enforced := range policy {
		indicator := "✗"
		if enforced {
			indicator = "✓"
		}
		fmt.Printf("    %s  %s\n", indicator, rule)
	}

	// Count compliant passwords and their bypass patterns.
	bypasses := make(map[string]int)
	compliant := 0
	for _, p := range patterns {
		if !meetsPolicy(p, policy) {
			continue
		}
		compliant++
		bp := detectBypassPattern(p.Plaintext)
		if bp != "" {
			bypasses[bp]++
		}
	}

	bypassPcts := make(map[string]float64, len(bypasses))
	if compliant > 0 {
		for k, v := range bypasses {
			bypassPcts[k] = float64(v) * 100.0 / float64(compliant)
		}
	}

	fmt.Printf("\n  Policy-compliant passwords: %d / %d (%.1f%%)\n",
		compliant, total, float64(compliant)*100.0/float64(total))
	fmt.Printf("\n  Bypass patterns (as %% of compliant passwords):\n")
	for bp, pct := range bypassPcts {
		fmt.Printf("    %-22s  %.1f%%\n", bp, pct)
	}

	// Print key metric.
	fmt.Printf("\n  Benchmark metric: run `cracknet benchmark` for crackability estimate.\n")

	return &PolicyReport{
		DetectedPolicy:  policy,
		BypassPatterns:  bypassPcts,
		PolicyCompliant: compliant,
		Total:           total,
	}, nil
}
