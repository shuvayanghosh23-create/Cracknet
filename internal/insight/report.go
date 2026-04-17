package insight

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// FullReport bundles all insight module outputs.
type FullReport struct {
	GeneratedAt string      `json:"generated_at"`
	DNA         interface{} `json:"dna,omitempty"`
	Reuse       interface{} `json:"reuse,omitempty"`
	Temporal    interface{} `json:"temporal,omitempty"`
	Org         interface{} `json:"org,omitempty"`
	Predictor   interface{} `json:"predictor,omitempty"`
}

// GenerateReport formats a FullReport as text, json, or html.
func GenerateReport(report FullReport, format string) (string, error) {
	if report.GeneratedAt == "" {
		report.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	switch format {
	case "json":
		b, err := json.MarshalIndent(report, "", "  ")
		return string(b), err
	case "html":
		return generateHTML(report)
	default: // text
		return generateText(report)
	}
}

func generateText(report FullReport) (string, error) {
	var sb strings.Builder
	sb.WriteString("╔══════════════════════════════════════╗\n")
	sb.WriteString("║      CrackNet Insight Report         ║\n")
	sb.WriteString("╚══════════════════════════════════════╝\n")
	sb.WriteString(fmt.Sprintf("  Generated: %s\n\n", report.GeneratedAt))

	if report.DNA != nil {
		sb.WriteString("── DNA Analysis ──────────────────────\n")
		if dna, ok := report.DNA.(*DNAReportData); ok {
			sb.WriteString(fmt.Sprintf("  Total passwords analysed: %d\n", dna.Total))
			for class, count := range dna.Classes {
				pct := dna.Percentages[class]
				sb.WriteString(fmt.Sprintf("    %-20s %d (%.1f%%)\n", class+":", count, pct))
			}
			if len(dna.KeyFindings) > 0 {
				sb.WriteString("  Key findings:\n")
				for _, f := range dna.KeyFindings {
					sb.WriteString(fmt.Sprintf("    ⚠ %s\n", f))
				}
			}
		} else {
			sb.WriteString(fmt.Sprintf("  %v\n", report.DNA))
		}
		sb.WriteString("\n")
	}

	if report.Reuse != nil {
		sb.WriteString("── Password Reuse ────────────────────\n")
		if r, ok := report.Reuse.(*ReuseReport); ok {
			sb.WriteString(fmt.Sprintf("  Exact reuse cases: %d\n", r.ExactReuseCount))
			for i, e := range r.Groups {
				if i >= 5 {
					sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(r.Groups)-5))
					break
				}
				sb.WriteString(fmt.Sprintf("    %q shared by %s and %s\n",
					e.Plaintext, e.Username1, e.Username2))
			}
		}
		sb.WriteString("\n")
	}

	if report.Temporal != nil {
		sb.WriteString("── Temporal Comparison ───────────────\n")
		if t, ok := report.Temporal.(*TemporalReport); ok {
			sb.WriteString(fmt.Sprintf("  Period 1 [%s]: %d cracked\n", t.Period1, t.Period1Count))
			sb.WriteString(fmt.Sprintf("  Period 2 [%s]: %d cracked\n", t.Period2, t.Period2Count))
		}
		sb.WriteString("\n")
	}

	if report.Org != nil {
		sb.WriteString("── Org Risk ──────────────────────────\n")
		if groups, ok := report.Org.([]OrgGroup); ok {
			for _, g := range groups {
				sb.WriteString(fmt.Sprintf("  %-30s cracked %d/%d (%.1f%% risk)\n",
					g.Domain, g.CrackedCount, g.Count, g.RiskScore))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

func generateHTML(report FullReport) (string, error) {
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>CrackNet Insight Report</title>
<style>body{font-family:monospace;background:#111;color:#eee;padding:2em}
pre{background:#222;padding:1em;border-radius:4px;overflow:auto}</style>
</head>
<body>
<h1>CrackNet Insight Report</h1>
<p>Generated: %s</p>
<pre>%s</pre>
</body></html>`, report.GeneratedAt, string(b))
	return html, nil
}
