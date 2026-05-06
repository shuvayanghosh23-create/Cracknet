package insight

import (
	"fmt"
	"sort"
	"strings"

	"cracknet/internal/db"
)

// privilegedUsernames are labels that trigger CRITICAL flagging.
var privilegedUsernames = []string{"admin", "root", "manager", "ceo", "cto", "cfo", "director"}

// ReuseReport summarises password reuse findings.
type ReuseReport struct {
	ExactReuseCount int            `json:"exact_reuse_count"`
	Top10           []ReuseGroup   `json:"top10,omitempty"`
	NearReuse       []NearReusePair `json:"near_reuse,omitempty"`
	CriticalCount   int            `json:"critical_count"`
	Groups          []db.ReuseEntry `json:"-"`
}

// ReuseGroup describes a plaintext shared by multiple users.
type ReuseGroup struct {
	Plaintext  string   `json:"plaintext"`
	UserCount  int      `json:"user_count"`
	Usernames  []string `json:"usernames"`
	IsCritical bool     `json:"is_critical"`
}

// NearReusePair describes two accounts sharing a base word but different passwords.
type NearReusePair struct {
	BaseWord   string  `json:"base_word"`
	PlaintextA string  `json:"plaintext_a"`
	PlaintextB string  `json:"plaintext_b"`
	UsernameA  string  `json:"username_a"`
	UsernameB  string  `json:"username_b"`
	Similarity float64 `json:"similarity"`
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	dp := make([][]int, la+1)
	for i := range dp {
		dp[i] = make([]int, lb+1)
		dp[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		dp[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			ins := dp[i][j-1] + 1
			del := dp[i-1][j] + 1
			rep := dp[i-1][j-1] + cost
			m := ins
			if del < m {
				m = del
			}
			if rep < m {
				m = rep
			}
			dp[i][j] = m
		}
	}
	return dp[la][lb]
}

// levSimilarity returns normalised Levenshtein similarity (0.0–1.0).
func levSimilarity(a, b string) float64 {
	ra, rb := []rune(a), []rune(b)
	maxLen := len(ra)
	if len(rb) > maxLen {
		maxLen = len(rb)
	}
	if maxLen == 0 {
		return 1.0
	}
	dist := levenshtein(a, b)
	return 1.0 - float64(dist)/float64(maxLen)
}

// isPrivileged checks if a username belongs to a privileged account.
func isPrivileged(username string) bool {
	lower := strings.ToLower(username)
	for _, priv := range privilegedUsernames {
		if strings.Contains(lower, priv) {
			return true
		}
	}
	return false
}

// RunReuse detects exact and near password reuse across accounts.
func RunReuse(potDB *db.DB) (*ReuseReport, error) {
	entries, err := potDB.DetectReuse()
	if err != nil {
		return nil, fmt.Errorf("detect reuse: %w", err)
	}

	// Save exact reuse pairs to DB.
	for _, e := range entries {
		_ = potDB.SaveReuseEntry(e)
	}

	// Group exact reuse by plaintext.
	type groupData struct {
		users   map[string]bool
		hashes  []string
	}
	groupMap := make(map[string]*groupData)
	for _, e := range entries {
		g, ok := groupMap[e.Plaintext]
		if !ok {
			g = &groupData{users: make(map[string]bool)}
			groupMap[e.Plaintext] = g
		}
		if e.Username1 != "" {
			g.users[e.Username1] = true
		}
		if e.Username2 != "" {
			g.users[e.Username2] = true
		}
		g.hashes = append(g.hashes, e.Hash1, e.Hash2)
	}

	// Build top-10 list sorted by user count.
	var groups []ReuseGroup
	criticalCount := 0
	for pt, gd := range groupMap {
		users := make([]string, 0, len(gd.users))
		for u := range gd.users {
			users = append(users, u)
		}
		sort.Strings(users)
		isCrit := false
		for _, u := range users {
			if isPrivileged(u) {
				isCrit = true
				break
			}
		}
		if isCrit {
			criticalCount++
		}
		groups = append(groups, ReuseGroup{
			Plaintext:  pt,
			UserCount:  len(users),
			Usernames:  users,
			IsCritical: isCrit,
		})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].UserCount > groups[j].UserCount })

	top10 := groups
	if len(top10) > 10 {
		top10 = top10[:10]
	}

	// Near-reuse: find plaintexts with same base word (from password_patterns).
	patterns, _ := potDB.GetPasswordPatterns()
	baseWordMap := make(map[string][]db.PasswordPattern)
	for _, pp := range patterns {
		if pp.BaseWord != "" {
			baseWordMap[pp.BaseWord] = append(baseWordMap[pp.BaseWord], pp)
		}
	}

	// For near-reuse, we need username info. Build a plaintext→usernames map.
	allHashes, _ := potDB.GetAllCrackedWithPlaintext()
	allMeta, _ := potDB.GetAllMetadata()
	metaByHash := make(map[string]db.HashMetadata, len(allMeta))
	for _, m := range allMeta {
		metaByHash[m.Hash] = m
	}
	plaintextUsers := make(map[string][]string)
	for _, h := range allHashes {
		m, ok := metaByHash[h.Hash]
		if ok && m.Username != "" {
			plaintextUsers[h.Plaintext] = append(plaintextUsers[h.Plaintext], m.Username)
		}
	}

	var nearPairs []NearReusePair
	clusterCount := 0
	for baseWord, pats := range baseWordMap {
		if len(pats) < 2 {
			continue
		}
		if clusterCount >= 5 {
			break
		}
		clusterCount++
		fmt.Printf("  Near-reuse cluster [base: %q]:\n", baseWord)
		for i := 0; i < len(pats) && i < 5; i++ {
			for j := i + 1; j < len(pats) && j < 5; j++ {
				sim := levSimilarity(pats[i].Plaintext, pats[j].Plaintext)
				if sim < 0.7 || sim >= 1.0 {
					continue
				}
				usersA := plaintextUsers[pats[i].Plaintext]
				usersB := plaintextUsers[pats[j].Plaintext]
				uA, uB := "", ""
				if len(usersA) > 0 {
					uA = usersA[0]
				}
				if len(usersB) > 0 {
					uB = usersB[0]
				}
				nearPairs = append(nearPairs, NearReusePair{
					BaseWord:   baseWord,
					PlaintextA: pats[i].Plaintext,
					PlaintextB: pats[j].Plaintext,
					UsernameA:  uA,
					UsernameB:  uB,
					Similarity: sim,
				})
				fmt.Printf("    %q ↔ %q  (sim=%.2f)\n", pats[i].Plaintext, pats[j].Plaintext, sim)
			}
		}
	}

	// Print exact reuse summary.
	fmt.Printf("\n  Exact password reuse: %d pair(s) found\n", len(entries))
	for i, g := range top10 {
		crit := ""
		if g.IsCritical {
			crit = " [CRITICAL]"
		}
		fmt.Printf("  %2d. %-24s  %d user(s)%s\n", i+1, fmt.Sprintf("%q", g.Plaintext), g.UserCount, crit)
	}

	return &ReuseReport{
		ExactReuseCount: len(entries),
		Top10:           top10,
		NearReuse:       nearPairs,
		CriticalCount:   criticalCount,
		Groups:          entries,
	}, nil
}

