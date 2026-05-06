// Package batch provides parsing and grouping utilities for batch hash files.
package batch

import "strings"

// FilterGroups returns a filtered copy of groups applying --only or --skip.
// only and skip are comma-separated algo names (empty = no filter).
// Returns kept groups, skipped groups, and a slice of algo names from --only that were not found.
func FilterGroups(groups map[string][]HashEntry, only, skip string) (kept map[string][]HashEntry, skipped map[string][]HashEntry, warnings []string) {
	warnings = []string{}
	skipped = make(map[string][]HashEntry)
	if only == "" && skip == "" {
		return groups, skipped, warnings
	}
	kept = make(map[string][]HashEntry)
	if only != "" {
		onlySet := make(map[string]bool)
		for _, name := range SplitAlgoList(only) {
			onlySet[name] = true
		}
		for name, g := range groups {
			if onlySet[name] {
				kept[name] = g
			} else {
				skipped[name] = g
			}
		}
		// Warn about --only names that weren't present in the file.
		for _, name := range SplitAlgoList(only) {
			if _, ok := groups[name]; !ok {
				warnings = append(warnings, name)
			}
		}
		return kept, skipped, warnings
	}
	// skip mode
	skipSet := make(map[string]bool)
	for _, name := range SplitAlgoList(skip) {
		skipSet[name] = true
	}
	for name, g := range groups {
		if skipSet[name] {
			skipped[name] = g
		} else {
			kept[name] = g
		}
	}
	return kept, skipped, warnings
}

// SplitAlgoList splits a comma-separated algo list into lowercase trimmed names.
func SplitAlgoList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
