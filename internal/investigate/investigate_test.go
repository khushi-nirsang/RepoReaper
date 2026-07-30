package investigate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/khushi/reporeaper/internal/model"
)

func TestRunValidatesSchemaAndSelectsFinding(t *testing.T) {
	report := model.Report{
		SchemaVersion: model.SchemaVersion,
		Repository:    model.Repository{Path: "/repo"},
		Findings:      []model.Finding{{ID: "RR-0001", DetectorID: "github-token", Redacted: "ghp_Ab************9Z", Severity: model.SeverityCritical, Remediation: []string{"Rotate it."}}},
	}
	path := writeReport(t, report)
	out, err := Run(path, "RR-0001")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "RR-0001") || strings.Contains(out, "raw-secret") {
		t.Fatalf("unexpected investigation output: %s", out)
	}
	if _, err := Run(path, "RR-9999"); err == nil {
		t.Fatal("unknown finding was accepted")
	}
	report.SchemaVersion = "0.1"
	if _, err := Run(writeReport(t, report), ""); err == nil {
		t.Fatal("unsupported schema was accepted")
	}
	report.SchemaVersion = model.LegacySchemaVersion
	if _, err := Run(writeReport(t, report), "RR-0001"); err != nil {
		t.Fatalf("legacy additive schema was rejected: %v", err)
	}
}

func TestRunNeutralizesTerminalControlCharacters(t *testing.T) {
	report := model.Report{
		SchemaVersion: model.SchemaVersion,
		Repository:    model.Repository{Path: "repo\x1b[31m\nname\u009b\u202e"},
		Findings: []model.Finding{{
			ID: "RR-0001", DetectorID: "synthetic", Severity: model.SeverityHigh,
			Redacted: "safe\x1b[2Jpreview", CurrentStatus: "history-only",
			Paths: []string{"folder\nfixture.env"},
		}},
	}
	output, err := Run(writeReport(t, report), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"\x1b", "\u009b", "\u202e", "repo\x1b[31m", "folder\nfixture.env"} {
		if strings.Contains(output, unsafe) {
			t.Fatalf("investigation output retained terminal control sequence %q", unsafe)
		}
	}
}

func TestRunAcceptsCleanReportAndRequiresExactFindingID(t *testing.T) {
	clean := model.Report{
		SchemaVersion: model.SchemaVersion,
		Repository:    model.Repository{Path: "/repo/RR-9999"},
		Findings:      []model.Finding{},
	}
	output, err := Run(writeReport(t, clean), "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "Findings: 0") {
		t.Fatalf("clean investigation output = %q", output)
	}

	clean.Findings = []model.Finding{{ID: "RR-0001", DetectorID: "synthetic"}}
	if _, err := Run(writeReport(t, clean), "RR-9999"); err == nil {
		t.Fatal("repository-path text was mistaken for an exact finding ID")
	}
}

func writeReport(t *testing.T, report model.Report) string {
	t.Helper()
	report.DocumentType = model.ScanReportDocumentType
	if report.ToolVersion == "" {
		report.ToolVersion = "test"
	}
	if report.GeneratedAt.IsZero() {
		report.GeneratedAt = time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	}
	if report.Config.Workers == 0 {
		report.Config.Workers = 1
	}
	if report.Config.MaxFileSize == 0 {
		report.Config.MaxFileSize = 1024
	}
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
