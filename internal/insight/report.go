package insight

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cracknet/internal/db"
)

// FullReport bundles all insight module outputs.
type FullReport struct {
	GeneratedAt string      `json:"generated_at"`
	Score       int         `json:"score,omitempty"`
	Grade       string      `json:"grade,omitempty"`
	DNA         interface{} `json:"dna,omitempty"`
	Reuse       interface{} `json:"reuse,omitempty"`
	Temporal    interface{} `json:"temporal,omitempty"`
	Org         interface{} `json:"org,omitempty"`
	Policy      interface{} `json:"policy,omitempty"`
	Predictor   interface{} `json:"predictor,omitempty"`
}

// grade converts a score to a grade string.
func grade(score int) string {
	switch {
	case score >= 80:
		return "GOOD"
	case score >= 60:
		return "MODERATE"
	case score >= 40:
		return "POOR"
	default:
		return "CRITICAL"
	}
}

// computeScore calculates the overall posture score (0–100).
func computeScore(report FullReport) int {
	score := 100.0

	// crack_rate × 40
	if report.DNA != nil {
		if dna, ok := report.DNA.(*DNAReportData); ok && dna.Total > 0 {
			// Use a heuristic: if word_plus_digits is high, assume ~80% crack rate
			_ = dna
		}
	}
	if report.Org != nil {
		if groups, ok := report.Org.([]OrgGroup); ok && len(groups) > 0 {
			totalUsers, totalCracked := 0, 0
			for _, g := range groups {
				totalUsers += g.Count
				totalCracked += g.CrackedCount
			}
			if totalUsers > 0 {
				crackRate := float64(totalCracked) / float64(totalUsers)
				score -= crackRate * 40
			}
		}
	}

	// reuse_rate × 20
	if report.Reuse != nil {
		if r, ok := report.Reuse.(*ReuseReport); ok {
			total := 0
			if report.DNA != nil {
				if dna, ok2 := report.DNA.(*DNAReportData); ok2 {
					total = dna.Total
				}
			}
			if total > 0 {
				reuseRate := float64(r.ExactReuseCount*2) / float64(total)
				if reuseRate > 1 {
					reuseRate = 1
				}
				score -= reuseRate * 20
			}
		}
	}

	// policy_bypass_rate × 20
	if report.Policy != nil {
		if p, ok := report.Policy.(*PolicyReport); ok && p.PolicyCompliant > 0 {
			totalBypass := 0.0
			for _, pct := range p.BypassPatterns {
				totalBypass += pct
			}
			bypassRate := totalBypass / 100.0
			if bypassRate > 1 {
				bypassRate = 1
			}
			score -= bypassRate * 20
		}
	}

	// management_crack_rate × 20
	if report.Org != nil {
		if groups, ok := report.Org.([]OrgGroup); ok {
			for _, g := range groups {
				if g.Department == "Management" {
					score -= g.CrackRate * 20
					break
				}
			}
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return int(score)
}

// GenerateReport formats a FullReport as text, json, or html.
// If potDB is non-nil, saves the report to the insight_reports table.
func GenerateReport(report FullReport, format string) (string, error) {
	if report.GeneratedAt == "" {
		report.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if report.Score == 0 && report.Grade == "" {
		report.Score = computeScore(report)
		report.Grade = grade(report.Score)
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

// SaveReport saves the rendered report to the pot DB.
func SaveReport(potDB *db.DB, report FullReport, modulesRun []string) {
	if potDB == nil {
		return
	}
	textOut, _ := generateText(report)
	jsonOut, _ := json.Marshal(report)
	_, _ = potDB.SaveInsightReport(string(jsonOut), textOut, strings.Join(modulesRun, ","), report.Score)
}

func generateText(report FullReport) (string, error) {
	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════════════════\n")
	sb.WriteString(" ORGANISATION SECURITY POSTURE REPORT\n")
	sb.WriteString(fmt.Sprintf(" CrackNet  |  Generated: %s\n", report.GeneratedAt))
	sb.WriteString("═══════════════════════════════════════════════════════\n\n")

	sb.WriteString(fmt.Sprintf("Overall score:  %d / 100  [%s]\n\n", report.Score, report.Grade))

	// Summary section
	totalHashes, totalCracked := 0, 0
	if report.DNA != nil {
		if dna, ok := report.DNA.(*DNAReportData); ok {
			totalHashes = dna.Total
		}
	}
	if report.Org != nil {
		if groups, ok := report.Org.([]OrgGroup); ok {
			for _, g := range groups {
				totalCracked += g.CrackedCount
			}
		}
	}
	crackPct := 0.0
	if totalHashes > 0 {
		crackPct = float64(totalCracked) * 100.0 / float64(totalHashes)
	}
	reuseRate := 0
	if report.Reuse != nil {
		if r, ok := report.Reuse.(*ReuseReport); ok {
			if totalHashes > 0 {
				reuseRate = r.ExactReuseCount * 2 * 100 / totalHashes
			}
		}
	}
	policyBypassRate := 0.0
	if report.Policy != nil {
		if p, ok := report.Policy.(*PolicyReport); ok {
			for _, pct := range p.BypassPatterns {
				policyBypassRate += pct
			}
		}
	}

	sb.WriteString("Summary\n")
	sb.WriteString(fmt.Sprintf("  Hashes analysed      : %d\n", totalHashes))
	sb.WriteString(fmt.Sprintf("  Successfully cracked : %d  (%.1f%%)\n", totalCracked, crackPct))
	if report.Reuse != nil {
		sb.WriteString(fmt.Sprintf("  Password reuse rate  : %d%%\n", reuseRate))
	}
	if report.Policy != nil {
		sb.WriteString(fmt.Sprintf("  Policy bypass rate   : %.0f%%\n", policyBypassRate))
	}
	sb.WriteString("\n")

	// Key findings
	sb.WriteString("Key findings\n")
	if report.Org != nil {
		if groups, ok := report.Org.([]OrgGroup); ok {
			for _, g := range groups {
				if g.Department == "Management" && g.CrackRate >= 0.8 {
					sb.WriteString(fmt.Sprintf("  [CRITICAL]  Management accounts: %.0f%% crack rate\n", g.CrackRate*100))
				}
			}
		}
	}
	if report.Policy != nil {
		if _, ok := report.Policy.(*PolicyReport); ok && policyBypassRate > 50 {
			sb.WriteString(fmt.Sprintf("  [HIGH]      %.0f%% of policy-compliant passwords use bypass patterns\n", policyBypassRate))
		}
	}
	if report.DNA != nil {
		if dna, ok := report.DNA.(*DNAReportData); ok {
			for _, f := range dna.KeyFindings {
				sb.WriteString(fmt.Sprintf("  [HIGH]      %s\n", f))
			}
		}
	}
	if report.Reuse != nil {
		if r, ok := report.Reuse.(*ReuseReport); ok && r.ExactReuseCount > 0 {
			sb.WriteString(fmt.Sprintf("  [HIGH]      %d exact password reuse pairs found\n", r.ExactReuseCount))
		}
	}
	sb.WriteString("\n")

	// Module results
	sb.WriteString("Module results\n")
	if report.DNA != nil {
		if dna, ok := report.DNA.(*DNAReportData); ok {
			topClass, topCount := "", 0
			for k, v := range dna.Classes {
				if v > topCount {
					topClass, topCount = k, v
				}
			}
			pct := 0.0
			if dna.Total > 0 {
				pct = float64(topCount) * 100.0 / float64(dna.Total)
			}
			sb.WriteString(fmt.Sprintf("  dna       → top pattern: %s %.0f%%\n", topClass, pct))
		}
	}
	if report.Reuse != nil {
		if r, ok := report.Reuse.(*ReuseReport); ok {
			sb.WriteString(fmt.Sprintf("  reuse     → %d exact reuse pairs found\n", r.ExactReuseCount))
		}
	}
	if report.Policy != nil {
		if p, ok := report.Policy.(*PolicyReport); ok {
			topBP, topBPPct := "", 0.0
			for k, v := range p.BypassPatterns {
				if v > topBPPct {
					topBP, topBPPct = k, v
				}
			}
			if topBP != "" {
				sb.WriteString(fmt.Sprintf("  policy    → %s bypass: %.0f%%\n", topBP, topBPPct))
			} else {
				sb.WriteString("  policy    → no bypasses detected\n")
			}
		}
	}
	if report.Org != nil {
		if groups, ok := report.Org.([]OrgGroup); ok && len(groups) > 0 {
			top := groups[0]
			sb.WriteString(fmt.Sprintf("  org       → %s dept: %s (%.0f%% cracked)\n",
				top.Department, top.RiskLabel, top.CrackRate*100))
		}
	}
	if report.Temporal != nil {
		if t, ok := report.Temporal.(*TemporalReport); ok {
			sb.WriteString(fmt.Sprintf("  temporal  → only %.1f%% made a true password change\n", t.TrueChangePct))
		}
	}
	if report.Predictor != nil {
		if p, ok := report.Predictor.(*PredictReport); ok {
			ve := p.Tiers["very_easy"]
			e := p.Tiers["easy"]
			sb.WriteString(fmt.Sprintf("  predict   → %d hashes rated very_easy/easy", ve+e))
			if p.PriorityFile != "" {
				sb.WriteString(fmt.Sprintf(", written to %s", p.PriorityFile))
			}
			sb.WriteString("\n")
		}
	}
	sb.WriteString("\n")

	// Recommendations
	sb.WriteString("Recommendations\n")
	recs := []string{
		"Enforce minimum password length of 12 characters",
		"Block passwords containing organisation name or current year",
		"Require privileged accounts to use a password manager",
		"Implement breach password checking at account creation",
		"Re-educate Finance and HR departments on password hygiene",
	}
	for i, r := range recs {
		sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, r))
	}

	sb.WriteString("\n═══════════════════════════════════════════════════════\n")
	return sb.String(), nil
}

func generateHTML(report FullReport) (string, error) {
	textOut, _ := generateText(report)
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	// Build org table HTML if available.
	orgTable := ""
	if report.Org != nil {
		if groups, ok := report.Org.([]OrgGroup); ok && len(groups) > 0 {
			var t strings.Builder
			t.WriteString(`<table><thead><tr>
<th>Department</th><th>Domain</th><th>Users</th><th>Cracked</th><th>Crack Rate</th><th>Risk</th>
</tr></thead><tbody>`)
			for _, g := range groups {
				cls := strings.ToLower(g.RiskLabel)
				t.WriteString(fmt.Sprintf(`<tr class="%s"><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%.1f%%</td><td>%s</td></tr>`,
					cls, g.Department, g.Domain, g.Count, g.CrackedCount, g.CrackRate*100, g.RiskLabel))
			}
			t.WriteString("</tbody></table>")
			orgTable = t.String()
		}
	}

	gradeCls := strings.ToLower(report.Grade)
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>CrackNet Security Posture Report</title>
<style>
body{font-family:monospace;background:#111;color:#eee;padding:2em;max-width:1200px;margin:0 auto}
h1{color:#0af}
.score-badge{display:inline-block;padding:.4em 1.2em;border-radius:6px;font-size:2em;font-weight:bold;margin-bottom:1em}
.good{background:#1a3;color:#fff}.moderate{background:#a80;color:#fff}
.poor{background:#a40;color:#fff}.critical{background:#a00;color:#fff}
table{width:100%%;border-collapse:collapse;margin:1em 0}
th,td{text-align:left;padding:.4em .8em;border-bottom:1px solid #333}
th{background:#222}
.critical td:last-child{color:#f44}.high td:last-child{color:#fa4}
.moderate td:last-child{color:#aa4}.low td:last-child{color:#4a4}
pre{background:#1a1a1a;padding:1em;border-radius:4px;overflow:auto;font-size:.85em}
section{margin:2em 0}
</style></head>
<body>
<h1>CrackNet — Organisation Security Posture Report</h1>
<p>Generated: %s</p>
<div class="score-badge %s">Score: %d / 100 [%s]</div>
<section>
<h2>Summary</h2>
<pre>%s</pre>
</section>
%s
<section>
<h2>Raw JSON</h2>
<pre>%s</pre>
</section>
</body></html>`,
		report.GeneratedAt, gradeCls, report.Score, report.Grade,
		textOut,
		func() string {
			if orgTable != "" {
				return "<section><h2>Organisation Risk by Department</h2>" + orgTable + "</section>"
			}
			return ""
		}(),
		string(b))
	return html, nil
}

