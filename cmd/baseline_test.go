package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/khushi/reporeaper/internal/model"
)

func TestBaselineSuppressionRequiresDetectorFingerprintAndKnownPaths(t *testing.T) {
	fingerprint := strings.Repeat("a", 64)
	baseline := model.Report{Findings: []model.Finding{{
		DetectorID:  "github-token",
		Fingerprint: fingerprint,
		Paths:       []string{"./config//secret.env", `archives\bundle.zip!.\nested\key.txt`},
	}}}

	existing := model.Finding{
		DetectorID:  "github-token",
		Fingerprint: fingerprint,
		Paths:       []string{`config\secret.env`},
	}
	kept, suppressed := suppressBaselineFindings([]model.Finding{existing}, baseline)
	if suppressed != 1 || len(kept) != 0 {
		t.Fatalf("existing path: kept=%d suppressed=%d", len(kept), suppressed)
	}

	copied := existing
	copied.Paths = []string{"config/secret.env", "deploy/production.env"}
	kept, suppressed = suppressBaselineFindings([]model.Finding{copied}, baseline)
	if suppressed != 0 || len(kept) != 1 {
		t.Fatalf("new path was suppressed: kept=%d suppressed=%d", len(kept), suppressed)
	}

	differentDetector := existing
	differentDetector.DetectorID = "generic-api-key"
	shortFingerprint := existing
	shortFingerprint.Fingerprint = fingerprint[:12]
	kept, suppressed = suppressBaselineFindings([]model.Finding{differentDetector, shortFingerprint}, baseline)
	if suppressed != 0 || len(kept) != 2 {
		t.Fatalf("detector or short-fingerprint collision suppressed findings: kept=%d suppressed=%d", len(kept), suppressed)
	}
}

func TestBaselineSuppressionTreatsRemovedPathsAsKnownAndUnpathableEvidenceAsASet(t *testing.T) {
	fingerprint := strings.Repeat("b", 64)
	baseline := model.Report{Findings: []model.Finding{
		{DetectorID: "github-token", Fingerprint: fingerprint, Paths: []string{"a.env", "b.env"}},
		{DetectorID: "jwt", Fingerprint: strings.Repeat("c", 64)},
	}}
	findings := []model.Finding{
		{DetectorID: "github-token", Fingerprint: fingerprint, Paths: []string{"a.env"}},
		{DetectorID: "jwt", Fingerprint: strings.Repeat("c", 64)},
	}
	kept, suppressed := suppressBaselineFindings(findings, baseline)
	if suppressed != 2 || len(kept) != 0 {
		t.Fatalf("subset semantics: kept=%d suppressed=%d", len(kept), suppressed)
	}
}

func TestBaselineSuppressionDoesNotHideNewScopeOrPathlessResidualEvidence(t *testing.T) {
	fingerprint := strings.Repeat("d", 64)
	baseline := model.Report{Findings: []model.Finding{{
		DetectorID:  "github-token",
		Fingerprint: fingerprint,
		Paths:       []string{"config.env"},
	}}}
	for name, finding := range map[string]model.Finding{
		"reintroduced to head": {
			DetectorID: "github-token", Fingerprint: fingerprint, Paths: []string{"config.env"}, InHead: true,
		},
		"new index copy": {
			DetectorID: "github-token", Fingerprint: fingerprint, Paths: []string{"config.env"}, InIndex: true,
		},
		"new unreachable copy": {
			DetectorID: "github-token", Fingerprint: fingerprint, InUnreachable: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			kept, suppressed := suppressBaselineFindings([]model.Finding{finding}, baseline)
			if suppressed != 0 || len(kept) != 1 {
				t.Fatalf("new evidence scope was suppressed: kept=%d suppressed=%d", len(kept), suppressed)
			}
		})
	}

	baseline.Findings[0].InHead = true
	baseline.Findings[0].InIndex = true
	current := baseline.Findings[0]
	kept, suppressed := suppressBaselineFindings([]model.Finding{current}, baseline)
	if suppressed != 1 || len(kept) != 0 {
		t.Fatalf("unchanged covered scope was not suppressed: kept=%d suppressed=%d", len(kept), suppressed)
	}
}

func TestLoadScanBaselineRejectsWrongSchemaAndNonFullFingerprint(t *testing.T) {
	for name, document := range map[string]string{
		"schema":      `{"schema_version":"0.9","findings":[]}`,
		"fingerprint": fmt.Sprintf(`{"schema_version":%q,"findings":[{"detector_id":"github-token","fingerprint":"abc123"}]}`, model.SchemaVersion),
		"detector":    fmt.Sprintf(`{"schema_version":%q,"findings":[{"detector_id":"","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`, model.SchemaVersion),
	} {
		t.Run(name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "baseline.json")
			if err := os.WriteFile(filename, []byte(document), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadScanBaseline(filename); err == nil {
				t.Fatal("invalid baseline was accepted")
			}
		})
	}
}

func TestBaselineRepositoryIdentityIgnoresCheckoutPathsAndNormalizesNetworkRemotes(t *testing.T) {
	baseline := model.Repository{
		Path:   `C:\build\checkout-one`,
		GitDir: `C:\build\checkout-one\.git`,
		Remotes: []model.Remote{{
			Name: "origin",
			URL:  "https://github.example/team/project.git",
		}},
	}
	current := model.Repository{
		Path:   "/runner/work/checkout-two",
		GitDir: "/runner/work/checkout-two/.git",
		Remotes: []model.Remote{{
			Name: "upstream",
			URL:  "git@github.example:team/project.git",
		}},
	}
	if err := validateBaselineRepository(baseline, current); err != nil {
		t.Fatalf("equivalent remote identity rejected: %v", err)
	}

	current.Remotes[0].URL = "https://github.example/another/project.git"
	if err := validateBaselineRepository(baseline, current); err == nil {
		t.Fatal("obviously different network remotes were accepted")
	}

	baseline.Remotes[0].URL = `C:\repositories\one.git`
	current.Remotes[0].URL = `D:\repositories\two.git`
	if err := validateBaselineRepository(baseline, current); err != nil {
		t.Fatalf("machine-local remote paths must not be compared: %v", err)
	}
}

func TestScanBaselineSuppressesKnownFindingButFailsWhenCopiedToNewPath(t *testing.T) {
	repository := t.TempDir()
	initTestRepository(t, repository)
	// Deliberately fake fixture that satisfies the GitHub-token detector.
	fakeToken := "ghp_" + strings.Repeat("A1b2C3d4E5f6G7h8I9j0K1l2M3n4", 1)
	writeTestFile(t, repository, "known.env", fakeToken+"\n")
	runTestGit(t, repository, "add", "known.env")
	runTestGit(t, repository, "commit", "-m", "add fake fixture")

	baselinePath := filepath.Join(t.TempDir(), "baseline.json")
	runScanToJSON(t, repository, baselinePath)

	knownOnlyPath := filepath.Join(t.TempDir(), "known-only.json")
	command := scanCmd()
	command.SetArgs([]string{repository, "--format", "json", "--output", knownOnlyPath, "--baseline", baselinePath, "--fail-on", "critical"})
	if err := command.Execute(); err != nil {
		t.Fatalf("known-only scan unexpectedly failed policy: %v", err)
	}
	knownOnly := readTestReport(t, knownOnlyPath)
	if len(knownOnly.Findings) != 0 || knownOnly.Summary.SuppressedFindings != 1 || knownOnly.Summary.BaselineSuppressed != 1 || knownOnly.Summary.AllowlistSuppressed != 0 {
		t.Fatalf("known-only report: findings=%d summary=%+v", len(knownOnly.Findings), knownOnly.Summary)
	}

	writeTestFile(t, repository, filepath.Join("copied", "secret.env"), fakeToken+"\n")
	runTestGit(t, repository, "add", "copied/secret.env")
	runTestGit(t, repository, "commit", "-m", "copy fake fixture")

	copiedPath := filepath.Join(t.TempDir(), "copied.json")
	command = scanCmd()
	command.SilenceErrors = true
	command.SilenceUsage = true
	command.SetArgs([]string{repository, "--format", "json", "--output", copiedPath, "--baseline", baselinePath, "--fail-on", "critical"})
	err := command.Execute()
	var coded *exitError
	if !errors.As(err, &coded) || coded.code != 1 {
		t.Fatalf("new-path scan error = %v, want policy exit 1", err)
	}
	copied := readTestReport(t, copiedPath)
	if len(copied.Findings) != 1 || !containsString(copied.Findings[0].Paths, "copied/secret.env") {
		t.Fatalf("new path was not reported: %#v", copied.Findings)
	}
	if strings.Contains(string(mustReadFile(t, copiedPath)), fakeToken) {
		t.Fatal("JSON report leaked the fake raw credential")
	}
}

func TestScanSummaryCombinesAllowlistAndBaselineSuppression(t *testing.T) {
	repository := t.TempDir()
	initTestRepository(t, repository)
	fakeKnownToken := "ghp_" + strings.Repeat("Z9y8X7w6V5u4T3s2R1q0P9o8N7m6", 1)
	fakeAllowlistedToken := "ghp_" + strings.Repeat("M1n2B3v4C5x6Z7a8S9d0F1g2H3j4", 1)
	writeTestFile(t, repository, "known.env", fakeKnownToken+"\n")
	runTestGit(t, repository, "add", "known.env")
	runTestGit(t, repository, "commit", "-m", "add known fake fixture")

	baselinePath := filepath.Join(t.TempDir(), "baseline.json")
	runScanToJSON(t, repository, baselinePath)

	writeTestFile(t, repository, "allowed.env", fakeAllowlistedToken+"\n")
	runTestGit(t, repository, "add", "allowed.env")
	runTestGit(t, repository, "commit", "-m", "add allowlisted fake fixture")

	allowlistedFingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(fakeAllowlistedToken)))
	configPath := filepath.Join(t.TempDir(), ".reporeaper.yaml")
	configDocument := fmt.Sprintf("version: 1\nreport:\n  default_format: json\n  redact: true\nallowlist:\n  fingerprints:\n    - %s\n", allowlistedFingerprint)
	if err := os.WriteFile(configPath, []byte(configDocument), 0600); err != nil {
		t.Fatal(err)
	}
	previousConfig := cfgFile
	cfgFile = configPath
	t.Cleanup(func() { cfgFile = previousConfig })

	outputPath := filepath.Join(t.TempDir(), "combined.json")
	command := scanCmd()
	command.SetArgs([]string{repository, "--format", "json", "--output", outputPath, "--baseline", baselinePath})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	got := readTestReport(t, outputPath)
	if len(got.Findings) != 0 || got.Summary.SuppressedFindings != 2 || got.Summary.AllowlistSuppressed != 1 || got.Summary.BaselineSuppressed != 1 {
		t.Fatalf("combined suppression summary: findings=%d summary=%+v", len(got.Findings), got.Summary)
	}
}

func initTestRepository(t *testing.T, repository string) {
	t.Helper()
	runTestGit(t, repository, "init")
	runTestGit(t, repository, "config", "user.name", "RepoReaper Test")
	runTestGit(t, repository, "config", "user.email", "test@example.invalid")
}

func writeTestFile(t *testing.T, repository, relativePath, value string) {
	t.Helper()
	filename := filepath.Join(repository, relativePath)
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

func runScanToJSON(t *testing.T, repository, outputPath string) {
	t.Helper()
	command := scanCmd()
	command.SetArgs([]string{repository, "--format", "json", "--output", outputPath})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
}

func readTestReport(t *testing.T, filename string) model.Report {
	t.Helper()
	data := mustReadFile(t, filename)
	var parsed model.Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed
}

func mustReadFile(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
