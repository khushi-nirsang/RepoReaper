package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/khushi/reporeaper/internal/model"
)

type sarif map[string]any

type sarifRuleMetadata struct {
	name     string
	category string
	severity model.Severity
}

func Write(path, format string, r model.Report) error {
	var b []byte
	var err error
	switch format {
	case "json":
		b, err = JSON(r)
	case "html":
		b, err = HTML(r)
	case "sarif":
		b, err = SARIF(r)
	case "table", "":
		b = []byte(Table(r))
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		return err
	}
	if path == "" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return WriteBytes(path, b)
}

func WriteBytes(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".reporeaper-report-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return replaceReportFile(tmpName, path)
}

func JSON(r model.Report) ([]byte, error) {
	if r.Findings == nil {
		r.Findings = []model.Finding{}
	}
	return json.MarshalIndent(r, "", "  ")
}

func Table(r model.Report) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Finding  Severity  Confidence  Detector  Redacted  Location  First seen  Status  Remote  Risk\n")
	for _, f := range r.Findings {
		loc := ""
		if f.FirstSeen != nil {
			loc = f.FirstSeen.Path
			if f.FirstSeen.Line > 0 {
				loc += fmt.Sprintf(":%d", f.FirstSeen.Line)
			}
		}
		first := ""
		if f.FirstSeen != nil {
			first = f.FirstSeen.Time.Format("2006-01-02")
		}
		fmt.Fprintf(&sb, "%s  %s  %s  %s  %s  %s  %s  %s  %s  %d\n", plainText(f.ID), f.Severity, f.Confidence, plainText(f.DetectorID), plainText(f.Redacted), plainText(loc), first, plainText(f.CurrentStatus), plainText(f.RemoteStatus), f.RiskScore)
	}
	fmt.Fprintf(&sb, "\nSummary\nRepository: %s\nScan duration: %dms\nObjects scanned: %d\nObjects skipped: %d\nPayloads scanned: %d\nBytes inspected: %d\nArchives opened: %d\nEncoded payloads scanned: %d\nTrees read: %d\nTree cache hits: %d\nPersistent blob cache hits: %d\nPersistent blob cache misses: %d\nBlobs deduplicated: %d\nCommits analyzed: %d\nCurrent secrets: %d\nHistorical secrets: %d\nUnreachable-object secrets: %d\nSuppressed findings: %d\nAllowlist suppressed: %d\nBaseline suppressed: %d\n", plainText(r.Repository.Path), r.Stats.DurationMillis, r.Stats.ObjectsScanned, r.Stats.ObjectsSkipped, r.Stats.PayloadsScanned, r.Stats.BytesInspected, r.Stats.ArchivesOpened, r.Stats.EncodedPayloads, r.Stats.TreesRead, r.Stats.TreeCacheHits, r.Stats.BlobCacheHits, r.Stats.BlobCacheMisses, r.Stats.BlobsDeduplicated, r.Stats.CommitsAnalyzed, r.Summary.CurrentSecrets, r.Summary.HistoricalSecrets, r.Summary.UnreachableSecrets, r.Summary.SuppressedFindings, r.Summary.AllowlistSuppressed, r.Summary.BaselineSuppressed)
	for _, severity := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		fmt.Fprintf(&sb, "%s findings: %d\n", severity, r.Summary.FindingsBySeverity[severity])
	}
	if len(r.Warnings) > 0 {
		safeWarnings := make([]string, 0, len(r.Warnings))
		for _, warning := range r.Warnings {
			safeWarnings = append(safeWarnings, plainText(warning))
		}
		fmt.Fprintf(&sb, "Warnings: %s\n", strings.Join(safeWarnings, "; "))
	}
	if len(r.Notices) > 0 {
		safeNotices := make([]string, 0, len(r.Notices))
		for _, notice := range r.Notices {
			safeNotices = append(safeNotices, plainText(notice))
		}
		fmt.Fprintf(&sb, "Notices: %s\n", strings.Join(safeNotices, "; "))
	}
	return sb.String()
}

func HTML(r model.Report) ([]byte, error) {
	var sb strings.Builder
	sb.WriteString(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RepoReaper Report</title><style>body{font-family:system-ui,Segoe UI,sans-serif;margin:0;color:#172026;background:#f7f8fa}header,main{max-width:1100px;margin:auto;padding:24px}header{background:#fff;border-bottom:1px solid #d8dee4}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.card,.finding{background:#fff;border:1px solid #d8dee4;border-radius:8px;padding:14px}.finding{margin:12px 0}.filters{display:grid;grid-template-columns:2fr 1fr;gap:8px;margin:16px 0}code{background:#eef1f4;padding:2px 4px;border-radius:4px}input,select{padding:8px;width:100%;box-sizing:border-box}summary{cursor:pointer;font-weight:700}.critical{border-left:5px solid #9b1c1c}.high{border-left:5px solid #d14900}.medium{border-left:5px solid #ad7800}.low,.info{border-left:5px solid #3973ac}@media(max-width:600px){.filters{grid-template-columns:1fr}}@media print{.filters{display:none}body{background:white}.card,.finding{break-inside:avoid}}</style><script>function filterFindings(){let q=document.getElementById('q').value.toLowerCase(),s=document.getElementById('severity').value;document.querySelectorAll('.finding').forEach(e=>e.style.display=(e.innerText.toLowerCase().includes(q)&&(!s||e.dataset.severity===s))?'block':'none')}</script></head><body>`)
	fmt.Fprintf(&sb, "<header><h1>RepoReaper Report</h1><p>%s</p></header><main>", html.EscapeString(r.Repository.Path))
	fmt.Fprintf(&sb, `<section class="cards"><div class="card"><b>Total</b><br>%d</div><div class="card"><b>Current</b><br>%d</div><div class="card"><b>Historical</b><br>%d</div><div class="card"><b>Unreachable</b><br>%d</div><div class="card"><b>Skipped</b><br>%d</div><div class="card"><b>Archives</b><br>%d</div><div class="card"><b>Decoded</b><br>%d</div><div class="card"><b>Blob cache</b><br>%d hit / %d miss</div></section>`, len(r.Findings), r.Summary.CurrentSecrets, r.Summary.HistoricalSecrets, r.Summary.UnreachableSecrets, r.Stats.ObjectsSkipped, r.Stats.ArchivesOpened, r.Stats.EncodedPayloads, r.Stats.BlobCacheHits, r.Stats.BlobCacheMisses)
	if len(r.Warnings) > 0 {
		sb.WriteString(`<section class="card"><b>Coverage warnings</b><ul>`)
		for _, warning := range r.Warnings {
			fmt.Fprintf(&sb, "<li>%s</li>", html.EscapeString(warning))
		}
		sb.WriteString(`</ul></section>`)
	}
	if len(r.Notices) > 0 {
		sb.WriteString(`<section class="card"><b>Operational notices</b><ul>`)
		for _, notice := range r.Notices {
			fmt.Fprintf(&sb, "<li>%s</li>", html.EscapeString(notice))
		}
		sb.WriteString(`</ul></section>`)
	}
	sb.WriteString(`<div class="filters"><input id="q" oninput="filterFindings()" aria-label="Search findings" placeholder="Search findings"><select id="severity" onchange="filterFindings()" aria-label="Filter severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select></div>`)
	for _, f := range r.Findings {
		fmt.Fprintf(&sb, `<article class="finding %s" data-severity="%s"><details open><summary>%s %s %s risk %d</summary><p><code>%s</code> fingerprint %s</p><p>Status: %s. Remote: %s.</p><p>%s</p><p><b>Risk:</b> %s</p>`, html.EscapeString(string(f.Severity)), html.EscapeString(string(f.Severity)), html.EscapeString(f.ID), html.EscapeString(string(f.Severity)), html.EscapeString(f.DetectorID), f.RiskScore, html.EscapeString(f.Redacted), html.EscapeString(f.ShortFingerprint), html.EscapeString(f.CurrentStatus), html.EscapeString(f.RemoteStatus), html.EscapeString(f.RemoteReason), html.EscapeString(f.RiskExplanation))
		sb.WriteString("<h3>Exposure timeline</h3><ul>")
		for _, interval := range f.ExposureIntervals {
			end := "open or historically ambiguous"
			if !interval.EndedAt.IsZero() {
				end = interval.EndedAt.Format(time.RFC3339) + " removed by " + short(interval.RemovedBy)
			}
			fmt.Fprintf(&sb, "<li>%s from %s (%s) to %s</li>", html.EscapeString(interval.Status), html.EscapeString(interval.StartedAt.Format(time.RFC3339)), html.EscapeString(short(interval.StartCommit)), html.EscapeString(end))
		}
		sb.WriteString("</ul><h3>Evidence</h3><ul>")
		for _, e := range f.Evidence {
			decoder := ""
			if e.Decoder != "" {
				decoder = " decoded via " + e.Decoder
			}
			fmt.Fprintf(&sb, "<li>%s %s %s:%d%s</li>", html.EscapeString(e.Source), html.EscapeString(short(e.Commit)), html.EscapeString(e.Path), e.Line, html.EscapeString(decoder))
		}
		sb.WriteString("</ul><h3>Remediation</h3><ol>")
		for _, step := range f.Remediation {
			fmt.Fprintf(&sb, "<li>%s</li>", html.EscapeString(step))
		}
		sb.WriteString("</ol></details></article>")
	}
	sb.WriteString("</main></body></html>")
	return []byte(sb.String()), nil
}

func SARIF(r model.Report) ([]byte, error) {
	ruleMetadata := map[string]sarifRuleMetadata{}
	results := make([]sarif, 0)
	for _, f := range r.Findings {
		metadata, exists := ruleMetadata[f.DetectorID]
		if !exists || (f.DetectorName != "" && (metadata.name == "" || f.DetectorName < metadata.name)) {
			metadata.name = f.DetectorName
		}
		if !exists || (f.Category != "" && (metadata.category == "" || f.Category < metadata.category)) {
			metadata.category = f.Category
		}
		if !exists || sarifSeverityRank(f.Severity) > sarifSeverityRank(metadata.severity) {
			metadata.severity = f.Severity
		}
		ruleMetadata[f.DetectorID] = metadata
		for _, e := range f.Evidence {
			res := sarif{"ruleId": f.DetectorID, "level": sarifLevel(f.Severity), "message": sarif{"text": fmt.Sprintf("%s detected as %s (%s)", f.Redacted, f.ID, f.ShortFingerprint)}, "partialFingerprints": sarif{"reporeaperFingerprint": f.ShortFingerprint}, "properties": sarif{"commit": e.Commit, "source": e.Source, "remoteStatus": f.RemoteStatus, "decoder": e.Decoder, "riskScore": f.RiskScore}}
			if e.Path != "" {
				res["locations"] = []sarif{{"physicalLocation": sarif{"artifactLocation": sarif{"uri": e.Path}, "region": sarif{"startLine": max(1, e.Line)}}}}
			}
			results = append(results, res)
		}
	}
	rules := make(map[string]sarif, len(ruleMetadata))
	for detectorID, metadata := range ruleMetadata {
		rules[detectorID] = sarif{
			"id": detectorID, "name": metadata.name,
			"shortDescription": sarif{"text": metadata.name},
			"fullDescription":  sarif{"text": metadata.category},
			"properties":       sarif{"security-severity": sarifSecuritySeverity(metadata.severity)},
		}
	}
	ruleList := make([]sarif, 0, len(rules))
	for _, k := range sortedRuleKeys(rules) {
		ruleList = append(ruleList, rules[k])
	}
	var notifications []sarif
	for _, warning := range r.Warnings {
		notifications = append(notifications, sarif{"level": "warning", "message": sarif{"text": warning}})
	}
	for _, notice := range r.Notices {
		notifications = append(notifications, sarif{"level": "note", "message": sarif{"text": notice}})
	}
	run := sarif{
		"tool":    sarif{"driver": sarif{"name": "RepoReaper", "semanticVersion": r.ToolVersion, "rules": ruleList}},
		"results": results,
		"properties": sarif{
			"objectsScanned":  r.Stats.ObjectsScanned,
			"objectsSkipped":  r.Stats.ObjectsSkipped,
			"blobCacheHits":   r.Stats.BlobCacheHits,
			"blobCacheMisses": r.Stats.BlobCacheMisses,
		},
	}
	if len(notifications) > 0 {
		run["invocations"] = []sarif{{"executionSuccessful": true, "toolExecutionNotifications": notifications}}
	}
	doc := sarif{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []sarif{run}}
	return json.MarshalIndent(doc, "", "  ")
}
func sarifLevel(s model.Severity) string {
	if s == model.SeverityCritical || s == model.SeverityHigh {
		return "error"
	}
	if s == model.SeverityMedium {
		return "warning"
	}
	return "note"
}

func sarifSecuritySeverity(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return "9.5"
	case model.SeverityHigh:
		return "8.0"
	case model.SeverityMedium:
		return "5.5"
	case model.SeverityLow:
		return "3.0"
	default:
		return "1.0"
	}
}

func sarifSeverityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func sortedRuleKeys(m map[string]sarif) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func plainText(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) ||
			character == '\u061c' ||
			character == '\u200e' ||
			character == '\u200f' ||
			character == '\u2028' ||
			character == '\u2029' ||
			(character >= '\u202a' && character <= '\u202e') ||
			(character >= '\u2066' && character <= '\u2069') {
			return '\uFFFD'
		}
		return character
	}, value)
}
