// Package batch provides parsing and grouping utilities for batch hash files.
package batch

import "strings"

// FilterGroups returns a filtered copy of groups applying --only or --skip.
// only and skip are comma-separated algo names (empty = no filter).
// Returns the filtered map and a slice of algo names from --only that were not found.
func FilterGroups(groups map[string][]HashEntry, only, skip string) (map[string][]HashEntry, []string) {
	warnings := []string{}
	if only == "" && skip == "" {
		return groups, warnings
	}
	result := make(map[string][]HashEntry)
	if only != "" {
		for _, name := range SplitAlgoList(only) {
			if g, ok := groups[name]; ok {
				result[name] = g
			} else {
				warnings = append(warnings, name)
			}
		}
		return result, warnings
	}
	// skip mode
	skipSet := make(map[string]bool)
	for _, name := range SplitAlgoList(skip) {
		skipSet[name] = true
	}
	for name, g := range groups {
		if !skipSet[name] {
			result[name] = g
		}
	}
	return result, warnings
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
