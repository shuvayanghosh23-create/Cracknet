package insight

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"

	"cracknet/internal/db"
)

// DNAReportData summarises password pattern classification results.
type DNAReportData struct {
	Total       int                `json:"total"`
	Classes     map[string]int     `json:"classes"`
	Percentages map[string]float64 `json:"percentages"`
	KeyFindings []string           `json:"key_findings"`
}

// classifyDNA returns the pattern type, base word, prefix, and suffix for a plaintext.
func classifyDNA(p string) (patternType, baseWord, prefix, suffix string) {
	if p == "" {
		return "other", "", "", ""
	}

	// helpers
	allDigits := func(s string) bool {
		for _, c := range s {
			if !unicode.IsDigit(c) {
				return false
			}
		}
		return len(s) > 0
	}
	allLetters := func(s string) bool {
		for _, c := range s {
			if !unicode.IsLetter(c) {
				return false
			}
		}
		return len(s) > 0
	}
	isLeet := func(s string) bool {
		normalized := strings.NewReplacer("@", "a", "3", "e", "1", "i", "0", "o").Replace(strings.ToLower(s))
		if normalized == strings.ToLower(s) {
			return false
		}
		for _, c := range normalized {
			if !unicode.IsLetter(c) {
				return false
			}
		}
		return true
	}

	hasUpper := func(s string) bool {
		for _, c := range s {
			if unicode.IsUpper(c) {
				return true
			}
		}
		return false
	}
	hasLower := func(s string) bool {
		for _, c := range s {
			if unicode.IsLower(c) {
				return true
			}
		}
		return false
	}
	hasDigit := func(s string) bool {
		for _, c := range s {
			if unicode.IsDigit(c) {
				return true
			}
		}
		return false
	}
	hasSpecial := func(s string) bool {
		for _, c := range s {
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
				return true
			}
		}
		return false
	}

	runes := []rune(p)
	n := len(runes)

	if allDigits(p) {
		return "digits_only", "", "", p
	}
	if allLetters(p) {
		// check capitalised: first upper, rest lower
		if n >= 2 && unicode.IsUpper(runes[0]) {
			allLower := true
			for _, c := range runes[1:] {
				if !unicode.IsLower(c) {
					allLower = false
					break
				}
			}
			if allLower {
				return "capitalised", p, "", ""
			}
		}
		return "letters_only", p, "", ""
	}

	// leet speak: no special chars (other than leet substitutes), all letter-like after normalisation
	if isLeet(p) {
		return "leet_speak", p, "", ""
	}

	// name_plus_year: word + 4-digit year (19xx or 20xx)
	if n > 4 {
		tail := string(runes[n-4:])
		head := string(runes[:n-4])
		if allDigits(tail) && allLetters(head) {
			year := 0
			fmt.Sscanf(tail, "%d", &year)
			if year >= 1900 && year <= 2099 {
				return "name_plus_year", head, "", tail
			}
		}
	}

	// word_plus_digits: letters then digits at end
	// digits_plus_word: digits then letters
	i := 0
	for i < n && unicode.IsLetter(runes[i]) {
		i++
	}
	if i > 0 && i < n {
		letterPart := string(runes[:i])
		rest := string(runes[i:])
		if allDigits(rest) {
			return "word_plus_digits", letterPart, "", rest
		}
	}
	j := 0
	for j < n && unicode.IsDigit(runes[j]) {
		j++
	}
	if j > 0 && j < n {
		digitPart := string(runes[:j])
		rest := string(runes[j:])
		if allLetters(rest) {
			return "digits_plus_word", rest, digitPart, ""
		}
	}

	// word_plus_special: letters+digits followed by special chars at end
	k := n - 1
	for k >= 0 && hasSpecial(string(runes[k:k+1])) {
		k--
	}
	if k < n-1 && k >= 0 {
		head := string(runes[:k+1])
		tail := string(runes[k+1:])
		if !hasSpecial(head) {
			return "word_plus_special", head, "", tail
		}
	}

	// complex_mixed: uppercase + lowercase + digit + special
	if hasUpper(p) && hasLower(p) && hasDigit(p) && hasSpecial(p) {
		return "complex_mixed", p, "", ""
	}

	return "other", p, "", ""
}

// passwordEntropy computes Shannon entropy of the password in bits.
func passwordEntropy(p string) float64 {
	if p == "" {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range p {
		freq[c]++
	}
	n := float64(len([]rune(p)))
	var e float64
	for _, count := range freq {
		prob := float64(count) / n
		e -= prob * math.Log2(prob)
	}
	return e * n
}

// RunDNA classifies all cracked passwords, writes patterns to DB, prints a frequency table,
// and returns a DNAReportData suitable for serialization.
func RunDNA(potDB *db.DB) (*DNAReportData, error) {
	hashes, err := potDB.GetAllCrackedWithPlaintext()
	if err != nil {
		return nil, fmt.Errorf("fetch cracked hashes: %w", err)
	}

	classes := make(map[string]int)
	total := 0

	for _, h := range hashes {
		if h.Plaintext == "" {
			continue
		}
		total++
		pt := h.Plaintext
		ptype, baseWord, prefix, suffix := classifyDNA(pt)

		runes := []rune(pt)
		hasUpper := false
		hasLower := false
		hasDigit := false
		hasSpecial := false
		for _, c := range runes {
			if unicode.IsUpper(c) {
				hasUpper = true
			}
			if unicode.IsLower(c) {
				hasLower = true
			}
			if unicode.IsDigit(c) {
				hasDigit = true
			}
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
				hasSpecial = true
			}
		}

		classes[ptype]++

		pattern := db.PasswordPattern{
			Plaintext:   pt,
			PatternType: ptype,
			BaseWord:    baseWord,
			Prefix:      prefix,
			Suffix:      suffix,
			Length:      len(runes),
			HasUpper:    hasUpper,
			HasLower:    hasLower,
			HasDigit:    hasDigit,
			HasSpecial:  hasSpecial,
			EntropyBits: passwordEntropy(pt),
			AnalysedAt:  time.Now(),
		}
		_ = potDB.SavePasswordPattern(pattern)
	}

	percentages := make(map[string]float64, len(classes))
	for k, v := range classes {
		if total > 0 {
			percentages[k] = float64(v) * 100.0 / float64(total)
		}
	}

	// Build findings per spec thresholds.
	var findings []string
	check := func(key string, threshold float64, msg string) {
		if pct, ok := percentages[key]; ok && pct > threshold {
			findings = append(findings, fmt.Sprintf(msg, pct))
		}
	}
	check("word_plus_digits", 30, "%.1f%% of users satisfy digit requirements by appending digits.")
	check("name_plus_year", 10, "%.1f%% of passwords contain a year pattern.")
	check("digits_only", 5, "%.1f%% are numeric-only — likely PINs reused as passwords.")
	check("leet_speak", 5, "%.1f%% use predictable letter substitution (leet speak).")
	check("capitalised", 15, "%.1f%% capitalise only the first letter — easily guessed.")

	// Print frequency table.
	type row struct {
		name  string
		count int
		pct   float64
	}
	var rows []row
	for k, v := range classes {
		rows = append(rows, row{k, v, percentages[k]})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].count > rows[j].count })

	fmt.Printf("\n  %-20s %8s %8s\n", "Pattern Type", "Count", "Pct")
	fmt.Printf("  %s\n", strings.Repeat("─", 40))
	for _, r := range rows {
		fmt.Printf("  %-20s %8d %7.1f%%\n", r.name, r.count, r.pct)
	}
	if len(findings) > 0 {
		fmt.Printf("\n  Key findings:\n")
		for _, f := range findings {
			fmt.Printf("    ⚠ %s\n", f)
		}
	}

	return &DNAReportData{
		Total:       total,
		Classes:     classes,
		Percentages: percentages,
		KeyFindings: findings,
	}, nil
}

