// Package batch provides parsing and grouping utilities for batch hash files.
package batch

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// HashEntry represents a single hash entry parsed from a batch file.
type HashEntry struct {
	// Hash is the hash string (required).
	Hash string
	// Algorithm is the detected or explicit algorithm (may be empty).
	Algorithm string
	// Username is the optional username/email prefix (e.g. from user:hash lines).
	Username string
}

// knownAlgorithms is the set of algorithm names that may appear as the
// second field in a `hash:algorithm` line.
var knownAlgorithms = map[string]bool{
	"md5":         true,
	"md5_or_ntlm": true,
	"sha1":        true,
	"sha256":      true,
	"sha512":      true,
	"ntlm":        true,
	"bcrypt":      true,
	"sha512crypt": true,
	"sha256crypt": true,
	"md5crypt":    true,
}

// looksLikeHash returns true if s looks like a raw hash value:
// all hex chars of a typical hash length, or a crypt-style string starting with '$'.
func looksLikeHash(s string) bool {
	if strings.HasPrefix(s, "$") {
		return true
	}
	switch len(s) {
	case 32, 40, 64, 128: // MD5/NTLM, SHA1, SHA256, SHA512
		for _, c := range s {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return true
	}
	return false
}

// parseLine parses one line of a batch hash file.
// Returns nil for blank lines and comments (lines starting with '#').
//
// Supported formats (per line):
//
//	hash                  → just the hash
//	hash:algorithm        → hash with an explicit algorithm hint
//	username:hash         → hash prefixed by a username or email
//	mixed in same file    → auto-detected
func parseLine(line string) *HashEntry {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	// Split on the FIRST colon only.
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		// No colon → the whole line is the hash.
		return &HashEntry{Hash: line}
	}

	left := line[:idx]
	right := line[idx+1:]

	// If the right-hand side is a known algorithm name → hash:algorithm.
	if knownAlgorithms[strings.ToLower(right)] && looksLikeHash(left) {
		return &HashEntry{Hash: left, Algorithm: strings.ToLower(right)}
	}

	// If the right-hand side starts with '$' it is a crypt hash → username:hash.
	if strings.HasPrefix(right, "$") {
		return &HashEntry{Hash: right, Username: left}
	}

	// If the left-hand side looks like a hash → hash (ignore right, e.g. trailing username).
	if looksLikeHash(left) {
		return &HashEntry{Hash: left}
	}

	// Otherwise assume username:hash.
	return &HashEntry{Hash: right, Username: left}
}

// ParseFile reads a batch hash file and returns a deduplicated slice of HashEntry.
// Lines starting with '#' and blank lines are skipped.
// Duplicate hashes (case-insensitive) are removed; the first occurrence wins.
func ParseFile(path string) ([]HashEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open batch file: %w", err)
	}
	defer f.Close()

	seen := make(map[string]bool)
	var entries []HashEntry

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		entry := parseLine(scanner.Text())
		if entry == nil {
			continue
		}

		key := strings.ToLower(entry.Hash)
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, *entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read batch file: %w", err)
	}

	return entries, nil
}

// GroupByAlgorithm groups hash entries by their algorithm.
// Entries without an explicit algorithm get the algorithm from the provided
// detector function (e.g. calling the Rust analyzer via bridge.RunAnalyze).
// The `md5_or_ntlm` ambiguous label is treated as "md5" by default.
func GroupByAlgorithm(
	entries []HashEntry,
	detect func(hash string) (string, error),
) (map[string][]HashEntry, error) {
	groups := make(map[string][]HashEntry)

	for _, e := range entries {
		algo := e.Algorithm
		if algo == "" {
			detected, err := detect(e.Hash)
			if err != nil {
				return nil, fmt.Errorf("detect algorithm for %q: %w", e.Hash, err)
			}
			algo = detected
		}

		// Treat the ambiguous "md5_or_ntlm" as "md5" by default.
		if algo == "md5_or_ntlm" {
			algo = "md5"
		}

		entry := e
		entry.Algorithm = algo
		groups[algo] = append(groups[algo], entry)
	}

	return groups, nil
}
