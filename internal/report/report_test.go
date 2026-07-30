package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/khushi/reporeaper/internal/model"
)

func TestReportsDoNotLeakRawSecretAndSARIFShape(t *testing.T) {
	raw := "ghp_" + strings.Repeat("A1b2C3d4E5f6G7h8I9j0K1l2M3n4", 2)
	r := model.Report{SchemaVersion: model.SchemaVersion, ToolVersion: "test", Repository: model.Repository{Path: "/repo"}, Findings: []model.Finding{{ID: "RR-0001", DetectorID: "github-token", DetectorName: "GitHub token", Severity: model.SeverityCritical, Redacted: "ghp_1A************************3456", ShortFingerprint: "abc123abc123", RiskScore: 95, CurrentStatus: "history-only", RemoteStatus: "possible", Evidence: []model.Evidence{{Path: "config.env", Line: 1}}}}}
	for name, fn := range map[string]func(model.Report) ([]byte, error){
		"json":  JSON,
		"html":  HTML,
		"sarif": SARIF,
		"table": func(report model.Report) ([]byte, error) { return []byte(Table(report)), nil },
	} {
		b, err := fn(r)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Contains(b, []byte(raw)) {
			t.Fatalf("%s leaked raw secret", name)
		}
		if name == "sarif" {
			var doc map[string]any
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatalf("sarif json: %v", err)
			}
			if doc["version"] != "2.1.0" {
				t.Fatalf("bad sarif version: %v", doc["version"])
			}
		}
	}
}

func TestTableNeutralizesTerminalControlCharacters(t *testing.T) {
	r := model.Report{
		Repository: model.Repository{Path: "repo\x1b[31m\nname\u009b\u202e"},
		Warnings:   []string{"warning\x07text"},
		Findings: []model.Finding{{
			ID:            "RR-0001",
			DetectorID:    "synthetic-detector",
			Severity:      model.SeverityHigh,
			Confidence:    model.ConfidenceHigh,
			Redacted:      "safe\x1b[2Jpreview",
			CurrentStatus: "history-only",
			RemoteStatus:  "unknown",
			FirstSeen:     &model.Evidence{Path: "folder\nfixture.env", Line: 1},
		}},
	}
	output := Table(r)
	for _, unsafe := range []string{"\x1b", "\x07", "\u009b", "\u202e", "folder\nfixture.env", "repo\x1b[31m"} {
		if strings.Contains(output, unsafe) {
			t.Fatalf("table output retained terminal control sequence %q", unsafe)
		}
	}
}

func TestWriteBytesCreatesAndReplacesReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := WriteBytes(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := WriteBytes(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "second" {
		t.Fatalf("report content = %q", b)
	}
}

func TestHTMLEscapesFieldsAndHasNoExternalDependencies(t *testing.T) {
	r := model.Report{
		SchemaVersion: model.SchemaVersion,
		Repository:    model.Repository{Path: `<repo onmouseover="alert(1)">`},
		Warnings:      []string{`coverage <script>alert("warning")</script>`},
		Notices:       []string{`cache <script>alert("notice")</script>`},
		Stats:         model.ScanStats{ObjectsSkipped: 2, BlobCacheHits: 3, BlobCacheMisses: 1},
		Findings: []model.Finding{{
			ID: "RR-0001", DetectorID: `<script>alert(1)</script>`, Severity: model.SeverityHigh,
			Redacted: "safe********view", ShortFingerprint: "abcdef123456", CurrentStatus: "history-only",
			Evidence: []model.Evidence{{Path: `<img src=x onerror=alert(1)>`, Line: 1}},
		}},
	}
	b, err := HTML(r)
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	if strings.Contains(html, `<script>alert(1)</script>`) || strings.Contains(html, `<script>alert("warning")</script>`) || strings.Contains(html, `<script>alert("notice")</script>`) || strings.Contains(html, `<img src=x`) {
		t.Fatal("unescaped report data appeared in HTML")
	}
	if !strings.Contains(html, "Coverage warnings") || !strings.Contains(html, "Operational notices") || !strings.Contains(html, "<b>Skipped</b><br>2") || !strings.Contains(html, "<b>Blob cache</b><br>3 hit / 1 miss") {
		t.Fatal("HTML omitted coverage diagnostics")
	}
	for _, external := range []string{"<link ", "src=\"http", "href=\"http", "cdn."} {
		if strings.Contains(strings.ToLower(html), external) {
			t.Fatalf("external dependency marker %q found", external)
		}
	}
}

func TestSARIFRulesAreDeterministicallyOrdered(t *testing.T) {
	r := model.Report{ToolVersion: "test", Warnings: []string{"synthetic coverage warning"}, Notices: []string{"synthetic operational notice"}, Stats: model.ScanStats{ObjectsSkipped: 1, BlobCacheHits: 2}, Findings: []model.Finding{
		{ID: "RR-0002", DetectorID: "z-rule", DetectorName: "Z", Severity: model.SeverityHigh, Evidence: []model.Evidence{{Path: "z"}}},
		{ID: "RR-0001", DetectorID: "a-rule", DetectorName: "A", Severity: model.SeverityLow, Evidence: []model.Evidence{{Path: "a"}}},
	}}
	b, err := SARIF(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(string(b), `"id": "a-rule"`) > strings.Index(string(b), `"id": "z-rule"`) {
		t.Fatal("SARIF rules were not sorted")
	}
	if !strings.Contains(string(b), `"toolExecutionNotifications"`) || !strings.Contains(string(b), `"objectsSkipped": 1`) || !strings.Contains(string(b), `"blobCacheHits": 2`) || !strings.Contains(string(b), `"level": "note"`) {
		t.Fatal("SARIF omitted coverage diagnostics")
	}
}

func TestSARIFSecuritySeverityIsStableAndWithinGitHubRange(t *testing.T) {
	findings := []model.Finding{
		{DetectorID: "same-rule", DetectorName: "Rule", Severity: model.SeverityLow, RiskScore: 12},
		{DetectorID: "same-rule", DetectorName: "Rule", Severity: model.SeverityCritical, RiskScore: 99},
	}
	securitySeverity := func(findings []model.Finding) string {
		t.Helper()
		body, err := SARIF(model.Report{ToolVersion: "test", Findings: findings})
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Runs []struct {
				Tool struct {
					Driver struct {
						Rules []struct {
							ID         string            `json:"id"`
							Properties map[string]string `json:"properties"`
						} `json:"rules"`
					} `json:"driver"`
				} `json:"tool"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(body, &document); err != nil {
			t.Fatal(err)
		}
		if len(document.Runs) != 1 || len(document.Runs[0].Tool.Driver.Rules) != 1 {
			t.Fatalf("unexpected SARIF rule shape: %s", body)
		}
		return document.Runs[0].Tool.Driver.Rules[0].Properties["security-severity"]
	}

	forward := securitySeverity(findings)
	reversed := securitySeverity([]model.Finding{findings[1], findings[0]})
	if forward != reversed {
		t.Fatalf("security severity depends on finding order: forward=%q reversed=%q", forward, reversed)
	}
	value, err := strconv.ParseFloat(forward, 64)
	if err != nil || value <= 0 || value > 10 {
		t.Fatalf("security severity %q is outside GitHub's 0.1-10.0 range", forward)
	}
	if forward != "9.5" {
		t.Fatalf("critical security severity = %q, want 9.5", forward)
	}
}
