package insight

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"cracknet/internal/db"
)

// PredictReport holds difficulty tier counts and the priority hash file path.
type PredictReport struct {
	Tiers            map[string]int `json:"tiers"`
	PriorityFile     string         `json:"priority_file"`
	PriorityCount    int            `json:"priority_count"`
	RecommendedCmd   string         `json:"recommended_cmd"`
}

// bcryptCost extracts the cost factor from a bcrypt hash string like "$2b$12$...".
func bcryptCost(hash string) int {
	// Format: $2b$NN$...
	if !strings.HasPrefix(hash, "$2") {
		return -1
	}
	parts := strings.SplitN(hash, "$", 4)
	if len(parts) < 3 {
		return -1
	}
	cost, err := strconv.Atoi(parts[2])
	if err != nil {
		return -1
	}
	return cost
}

// algoFromHash detects the algorithm of an uncracked hash for difficulty estimation.
func algoFromHash(hash string) string {
	switch {
	case strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2y$"):
		return "bcrypt"
	case strings.HasPrefix(hash, "$6$"):
		return "sha512crypt"
	case strings.HasPrefix(hash, "$5$"):
		return "sha256crypt"
	case strings.HasPrefix(hash, "$1$"):
		return "md5crypt"
	case len(hash) == 32:
		return "md5"
	case len(hash) == 40:
		return "sha1"
	case len(hash) == 64:
		return "sha256"
	case len(hash) == 128:
		return "sha512"
	default:
		return "unknown"
	}
}

// classifyDifficulty assigns a difficulty tier to a hash.
func classifyDifficulty(hash, algo string, sourceFileCrackRate float64) string {
	switch algo {
	case "md5", "ntlm":
		if sourceFileCrackRate > 0.7 {
			return "very_easy"
		}
		return "easy"
	case "sha1", "sha256":
		if sourceFileCrackRate > 0.5 {
			return "easy"
		}
		return "moderate"
	case "sha512", "md5crypt", "sha256crypt", "sha512crypt":
		return "moderate"
	case "bcrypt":
		cost := bcryptCost(hash)
		switch {
		case cost < 0:
			return "hard"
		case cost <= 10:
			return "moderate"
		case cost <= 12:
			return "hard"
		default:
			return "very_hard"
		}
	case "unknown":
		return "unknown"
	default:
		return "moderate"
	}
}

// RunPredict identifies uncracked hashes and assigns difficulty tiers.
func RunPredict(potDB *db.DB) (*PredictReport, error) {
	uncracked, err := potDB.GetUncracked()
	if err != nil {
		return nil, fmt.Errorf("fetch uncracked: %w", err)
	}

	// Compute per-source-file crack rates for each algorithm.
	type sfKey struct {
		sourceFile string
		algo       string
	}
	sfTotal := make(map[sfKey]int)
	sfCracked := make(map[sfKey]int)

	allHashes, _ := potDB.GetAllCrackedWithPlaintext()
	allMeta, _ := potDB.GetAllMetadata()
	metaByHash := make(map[string]db.HashMetadata, len(allMeta))
	for _, m := range allMeta {
		metaByHash[m.Hash] = m
	}
	for _, h := range allHashes {
		m, ok := metaByHash[h.Hash]
		if !ok {
			continue
		}
		algo := algoFromHash(h.Hash)
		key := sfKey{m.SourceFile, algo}
		sfTotal[key]++
		if h.Plaintext != "" {
			sfCracked[key]++
		}
	}
	// Include uncracked in totals.
	for _, m := range uncracked {
		algo := algoFromHash(m.Hash)
		key := sfKey{m.SourceFile, algo}
		sfTotal[key]++
	}
	crackRate := func(sf, algo string) float64 {
		key := sfKey{sf, algo}
		t := sfTotal[key]
		if t == 0 {
			return 0
		}
		return float64(sfCracked[key]) / float64(t)
	}

	tiers := make(map[string]int)
	var priorityHashes []string

	for _, m := range uncracked {
		algo := algoFromHash(m.Hash)
		rate := crackRate(m.SourceFile, algo)
		tier := classifyDifficulty(m.Hash, algo, rate)
		tiers[tier]++
		if tier == "very_easy" || tier == "easy" {
			priorityHashes = append(priorityHashes, m.Hash)
		}
	}

	// Print tier summary.
	fmt.Printf("\n  Uncracked hash difficulty tiers:\n")
	tierOrder := []string{"very_easy", "easy", "moderate", "hard", "very_hard", "unknown"}
	for _, t := range tierOrder {
		if n, ok := tiers[t]; ok {
			fmt.Printf("    %-12s  %d\n", t, n)
		}
	}

	priorityFile := ""
	if len(priorityHashes) > 0 {
		priorityFile = "priority_hashes.txt"
		f, err := os.Create(priorityFile)
		if err == nil {
			for _, h := range priorityHashes {
				fmt.Fprintln(f, h)
			}
			f.Close()
		}
		fmt.Printf("\n  Priority crack list → %s (%d hashes)\n", priorityFile, len(priorityHashes))
		fmt.Printf("  Recommended:\n")
		fmt.Printf("    cracknet crack --file %s --mode hybrid \\\n", priorityFile)
		fmt.Printf("      --wordlist rockyou.txt --mask '?d?d' --only md5,sha1\n")
	}

	recommendedCmd := ""
	if priorityFile != "" {
		recommendedCmd = fmt.Sprintf(
			"cracknet crack --file %s --mode hybrid --wordlist rockyou.txt --mask '?d?d' --only md5,sha1",
			priorityFile)
	}

	return &PredictReport{
		Tiers:          tiers,
		PriorityFile:   priorityFile,
		PriorityCount:  len(priorityHashes),
		RecommendedCmd: recommendedCmd,
	}, nil
}
