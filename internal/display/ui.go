package display

import (
	"fmt"
	"strings"
	"time"
)

// HashInfo holds the result of hash type detection.
type HashInfo struct {
	Hash       string
	Algorithm  string
	Confidence float32
	Difficulty string
}

// Result holds the result of a cracking attempt.
type Result struct {
	Hash      string
	Plaintext string
	Algorithm string
	ElapsedMs uint64
	Cracked   bool
}

// Progress holds current cracking progress.
type Progress struct {
	Tried     uint64
	Speed     float64
	ElapsedMs uint64
}

// PrintHashInfo prints detected hash type information.
func PrintHashInfo(info HashInfo) {
	fmt.Println(strings.Repeat("─", 50))
	fmt.Printf("  Hash       : %s\n", info.Hash)
	fmt.Printf("  Algorithm  : %s\n", info.Algorithm)
	fmt.Printf("  Confidence : %.0f%%\n", info.Confidence)
	fmt.Printf("  Difficulty : %s\n", info.Difficulty)
	fmt.Println(strings.Repeat("─", 50))
}

// PrintProgress prints a cracking progress update.
func PrintProgress(p Progress) {
	elapsed := time.Duration(p.ElapsedMs) * time.Millisecond
	speed := p.Speed
	unit := "H/s"
	switch {
	case speed >= 1_000_000_000:
		speed /= 1_000_000_000
		unit = "GH/s"
	case speed >= 1_000_000:
		speed /= 1_000_000
		unit = "MH/s"
	case speed >= 1_000:
		speed /= 1_000
		unit = "KH/s"
	}
	fmt.Printf("\r  Progress: %d tried | %.2f %s | elapsed: %s   ",
		p.Tried, speed, unit, elapsed.Round(time.Second))
}

// PrintResult prints the final cracking result.
func PrintResult(r Result) {
	fmt.Println()
	fmt.Println(strings.Repeat("─", 50))
	if r.Cracked {
		fmt.Printf("  ✓ CRACKED!\n")
		fmt.Printf("  Hash      : %s\n", r.Hash)
		fmt.Printf("  Plaintext : %s\n", r.Plaintext)
		fmt.Printf("  Algorithm : %s\n", r.Algorithm)
		fmt.Printf("  Time      : %dms\n", r.ElapsedMs)
	} else {
		fmt.Printf("  ✗ Not found in wordlist.\n")
		fmt.Printf("  Hash      : %s\n", r.Hash)
		fmt.Printf("  Algorithm : %s\n", r.Algorithm)
		fmt.Printf("  Time      : %dms\n", r.ElapsedMs)
	}
	fmt.Println(strings.Repeat("─", 50))
}

// PrintError prints a formatted error message.
func PrintError(msg string) {
	fmt.Printf("  error: %s\n", msg)
}

// PrintTable prints a table of cracked hashes.
func PrintTable(headers []string, rows [][]string) {
	if len(rows) == 0 {
		fmt.Println("  (no entries)")
		return
	}

	// Compute column widths
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Header
	printRow(headers, widths)
	sep := make([]string, len(headers))
	for i, w := range widths {
		sep[i] = strings.Repeat("─", w)
	}
	printRow(sep, widths)

	// Rows
	for _, row := range rows {
		printRow(row, widths)
	}
}

func printRow(cells []string, widths []int) {
	parts := make([]string, len(cells))
	for i, c := range cells {
		if i < len(widths) {
			parts[i] = fmt.Sprintf("%-*s", widths[i], c)
		} else {
			parts[i] = c
		}
	}
	fmt.Println("  " + strings.Join(parts, "  │  "))
}
