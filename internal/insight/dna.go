package insight

import (
	"encoding/json"
	"fmt"

	"cracknet/internal/bridge"
	"cracknet/internal/db"
)

// DNAReportData mirrors the Rust DnaReport struct fields.
type DNAReportData struct {
	Total       int                `json:"total"`
	Classes     map[string]int     `json:"classes"`
	Percentages map[string]float64 `json:"percentages"`
	KeyFindings []string           `json:"key_findings"`
}

// RunDNA fetches cracked plaintexts from the pot DB and calls the Rust DNA analyser.
// Returns a *DNAReportData that can be serialized into reports.
func RunDNA(potDB *db.DB) (*DNAReportData, error) {
	hashes, err := potDB.GetAllCrackedWithPlaintext()
	if err != nil {
		return nil, fmt.Errorf("fetch cracked hashes: %w", err)
	}

	plaintexts := make([]string, 0, len(hashes))
	for _, h := range hashes {
		if h.Plaintext != "" {
			plaintexts = append(plaintexts, h.Plaintext)
		}
	}

	if len(plaintexts) == 0 {
		return &DNAReportData{Total: 0}, nil
	}

	msg, err := bridge.RunDNAAnalyze(plaintexts)
	if err != nil {
		return nil, fmt.Errorf("dna analyze: %w", err)
	}
	if msg.Type == "error" {
		return nil, fmt.Errorf("rust engine error: %s", msg.Msg)
	}

	var report DNAReportData
	if len(msg.Report) > 0 {
		if err := json.Unmarshal(msg.Report, &report); err != nil {
			return nil, fmt.Errorf("parse dna report: %w", err)
		}
	}
	return &report, nil
}
