package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/khushi/reporeaper/internal/model"
)

func TestCompareSeparatesVerificationDimensions(t *testing.T) {
	fingerprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	baseline := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Findings:      []model.Finding{{ID: "RR-0001", DetectorID: "test-detector", Fingerprint: fingerprint, ShortFingerprint: fingerprint[:12]}},
	}
	path := writeBaseline(t, baseline)
	current := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Repository:    model.Repository{Path: "/repo", WorktreeOK: true},
		Findings: []model.Finding{{
			Fingerprint: fingerprint, ShortFingerprint: fingerprint[:12], CommitCount: 2,
			Tags: []string{"release"}, Branches: []string{"refs/remotes/origin/main"},
			Evidence: []model.Evidence{{Reflog: true}, {Unreachable: true}},
		}},
	}
	result, code, err := Compare(path, current)
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 || result.Passed || len(result.Items) != 1 {
		t.Fatalf("code=%d result=%#v", code, result)
	}
	item := result.Items[0]
	if item.SourceRemoval != "remediated-from-current-source" || item.ReachableHistory != "still-in-reachable-history" || item.RemoteCopy != "local-remote-tracking-evidence-remains" || item.LocalResidualObjects != "still-in-reflog-and-unreachable-objects" {
		t.Fatalf("unexpected dimensions: %#v", item)
	}
}

func TestAbsentFindingInShallowScanIsUnableToVerify(t *testing.T) {
	fingerprint := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	path := writeBaseline(t, model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Findings:      []model.Finding{{ID: "RR-0001", DetectorID: "test-detector", Fingerprint: fingerprint, ShortFingerprint: fingerprint[:12]}},
	})
	current := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Repository:    model.Repository{Path: "/repo", Shallow: true, WorktreeOK: true},
		Warnings:      []string{"repository is shallow"},
	}
	result, code, err := Compare(path, current)
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 || !result.Incomplete || result.Items[0].Status != "unable-to-verify" {
		t.Fatalf("code=%d result=%#v", code, result)
	}
}

func TestReproductionConfigUsesDeepScopeSuperset(t *testing.T) {
	baseline := model.Report{Config: model.ScanConfig{
		MaxFileSize: 128, Since: "2025-01-01", Until: "2025-12-31",
		DetectorSignatures: map[string]string{"test-detector": "signature-v1"},
	}}
	got := ReproductionConfig(baseline, 3, 256)
	if !got.IncludeUntracked || !got.Branches || !got.Tags || !got.AllRefs || !got.Unreachable || !got.Reflogs {
		t.Fatalf("verification scope is not deep: %#v", got)
	}
	if got.Since != "" || got.Until != "" || got.MaxFileSize != 256 || got.Workers != 3 {
		t.Fatalf("verification execution config = %#v", got)
	}
	if got.DetectorSignatures != nil {
		t.Fatal("baseline signatures leaked into the current scan metadata")
	}
}

func TestUntrackedBaselineCannotPassWithNarrowCurrentScope(t *testing.T) {
	fingerprint := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	baseline := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Findings:      []model.Finding{{ID: "RR-0001", DetectorID: "test-detector", Fingerprint: fingerprint, ShortFingerprint: fingerprint[:12]}},
	}
	baseline.Config.IncludeUntracked = true
	current := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Repository:    model.Repository{Path: "/repo", WorktreeOK: true},
	}
	result, code, err := CompareReports(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 || result.Items[0].Status != "unable-to-verify" {
		t.Fatalf("code=%d result=%#v", code, result)
	}
}

func TestObservedUntrackedFindingIsClassifiedPrecisely(t *testing.T) {
	fingerprint := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	config := verificationTestConfig("signature-v1")
	config.IncludeUntracked = true
	baseline := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        config,
		Findings:      []model.Finding{{ID: "RR-0001", DetectorID: "test-detector", Fingerprint: fingerprint, ShortFingerprint: fingerprint[:12]}},
	}
	current := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        config,
		Repository:    model.Repository{Path: "/repo", WorktreeOK: true},
		Findings: []model.Finding{{
			DetectorID: "test-detector", Fingerprint: fingerprint,
			InWorkingTree: true, InUntracked: true, CurrentStatus: "present-in-untracked-file",
		}},
	}
	result, code, err := CompareReports(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 || result.Items[0].Status != "still-in-untracked-file" {
		t.Fatalf("code=%d result=%#v", code, result)
	}
}

func TestObservedIndexFindingIsClassifiedPrecisely(t *testing.T) {
	fingerprint := "dededededededededededededededededededededededededededededededede"
	config := verificationTestConfig("signature-v1")
	baseline := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        config,
		Findings:      []model.Finding{{ID: "RR-0001", DetectorID: "test-detector", Fingerprint: fingerprint, ShortFingerprint: fingerprint[:12]}},
	}
	current := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        config,
		Repository:    model.Repository{Path: "/repo", WorktreeOK: true, IndexOK: true},
		Findings: []model.Finding{{
			DetectorID: "test-detector", Fingerprint: fingerprint,
			InIndex: true, CurrentStatus: "present-in-index",
		}},
	}
	result, code, err := CompareReports(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 || result.Items[0].Status != "still-in-index" || result.Items[0].SourceRemoval != "still-in-index" {
		t.Fatalf("code=%d result=%#v", code, result)
	}
}

func TestDetectorRuleDriftIsUnableToVerifyAbsence(t *testing.T) {
	fingerprint := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	baseline := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Findings:      []model.Finding{{ID: "RR-0001", DetectorID: "test-detector", Fingerprint: fingerprint, ShortFingerprint: fingerprint[:12]}},
	}
	current := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v2"),
		Repository:    model.Repository{Path: "/repo", WorktreeOK: true},
	}
	result, code, err := CompareReports(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 || result.Items[0].Status != "unable-to-verify" {
		t.Fatalf("code=%d result=%#v", code, result)
	}
}

func TestOperationalCacheNoticeDoesNotInvalidateCompleteVerification(t *testing.T) {
	fingerprint := "abababababababababababababababababababababababababababababababab"
	baseline := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Repository:    model.Repository{Path: "/repo", WorktreeOK: true},
		Findings:      []model.Finding{{ID: "RR-0001", DetectorID: "test-detector", Fingerprint: fingerprint}},
	}
	current := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Repository:    model.Repository{Path: "/repo", WorktreeOK: true},
		Notices:       []string{"persistent blob scan cache was busy; results were rescanned"},
	}
	result, code, err := CompareReports(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || !result.Passed || result.Incomplete {
		t.Fatalf("operational notice invalidated verification: code=%d result=%#v", code, result)
	}
}

func TestBareBaselineDoesNotRequireWorkingTreeCoverage(t *testing.T) {
	fingerprint := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	baseline := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Repository:    model.Repository{Path: "/repo.git", Bare: true, WorktreeOK: false},
		Findings:      []model.Finding{{ID: "RR-0001", DetectorID: "test-detector", Fingerprint: fingerprint, ShortFingerprint: fingerprint[:12]}},
	}
	current := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Repository:    model.Repository{Path: "/repo.git", Bare: true, WorktreeOK: false},
	}
	result, code, err := CompareReports(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || !result.Passed || result.Incomplete {
		t.Fatalf("code=%d result=%#v", code, result)
	}
}

func TestNonBareBaselineRequiresWorkingTreeCoverage(t *testing.T) {
	fingerprint := "9999999999999999999999999999999999999999999999999999999999999999"
	baseline := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Repository:    model.Repository{Path: "/repo", WorktreeOK: true},
		Findings:      []model.Finding{{ID: "RR-0001", DetectorID: "test-detector", Fingerprint: fingerprint, ShortFingerprint: fingerprint[:12]}},
	}
	current := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Repository:    model.Repository{Path: "/repo.git", Bare: true, WorktreeOK: false},
	}
	result, code, err := CompareReports(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 || !result.Incomplete || result.Items[0].Status != "unable-to-verify" {
		t.Fatalf("code=%d result=%#v", code, result)
	}
}

func TestCompareRejectsWrongSchema(t *testing.T) {
	path := writeBaseline(t, model.Report{SchemaVersion: "0.1", Findings: []model.Finding{{ID: "RR-0001", Fingerprint: "abc"}}})
	if _, code, err := Compare(path, model.Report{}); err == nil || code != 2 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestCompareRejectsMalformedFingerprintAndCurrentSchema(t *testing.T) {
	baseline := model.Report{
		SchemaVersion: model.SchemaVersion,
		Findings:      []model.Finding{{DetectorID: "test-detector", Fingerprint: "abc123"}},
	}
	current := model.Report{SchemaVersion: model.SchemaVersion}
	if _, code, err := CompareReports(baseline, current); err == nil || code != 2 {
		t.Fatalf("malformed baseline fingerprint: code=%d err=%v", code, err)
	}

	baseline.Findings[0].Fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	current.SchemaVersion = "0.1"
	if _, code, err := CompareReports(baseline, current); err == nil || code != 2 {
		t.Fatalf("unsupported current schema: code=%d err=%v", code, err)
	}
}

func TestCompareRejectsUnambiguousRepositoryMismatch(t *testing.T) {
	fingerprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	baseline := model.Report{
		SchemaVersion: model.SchemaVersion,
		Repository:    model.Repository{Remotes: []model.Remote{{Name: "origin", URL: "https://example.invalid/owner/first.git"}}},
		Findings:      []model.Finding{{DetectorID: "test-detector", Fingerprint: fingerprint}},
	}
	current := model.Report{
		SchemaVersion: model.SchemaVersion,
		Repository:    model.Repository{Remotes: []model.Remote{{Name: "origin", URL: "https://example.invalid/owner/second.git"}}},
	}
	if _, code, err := CompareReports(baseline, current); err == nil || code != 2 {
		t.Fatalf("repository mismatch: code=%d err=%v", code, err)
	}
}

func TestCompareAcceptsLegacySchema(t *testing.T) {
	baseline := model.Report{
		SchemaVersion: model.LegacySchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Repository:    model.Repository{Path: "/repo", WorktreeOK: true},
	}
	current := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Repository:    model.Repository{Path: "/repo", WorktreeOK: true},
	}
	result, code, err := CompareReports(baseline, current)
	if err != nil {
		t.Fatalf("legacy additive schema was rejected: %v", err)
	}
	if code != 0 || !result.Passed {
		t.Fatalf("legacy empty baseline result = %#v, code %d", result, code)
	}
}

func TestLoadBaselineRejectsSchemaOnlyAndWrongDocumentType(t *testing.T) {
	for name, document := range map[string]string{
		"schema-only":    `{"schema_version":"1.1"}`,
		"wrong-document": `{"document_type":"verification-result","schema_version":"1.1","tool_version":"test","generated_at":"2026-07-28T00:00:00Z","scan_config":{"workers":1,"max_file_size":1024},"repository":{"path":"/repo"},"findings":[],"summary":{},"stats":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "baseline.json")
			if err := os.WriteFile(path, []byte(document), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadBaseline(path); err == nil {
				t.Fatal("non-scan baseline was accepted")
			}
		})
	}
}

func TestEmptyBaselineWithCoverageGapIsIncomplete(t *testing.T) {
	baseline := model.Report{
		SchemaVersion: model.SchemaVersion,
		Config:        verificationTestConfig("signature-v1"),
		Repository:    model.Repository{Path: "/repo", WorktreeOK: true},
	}
	current := baseline
	current.Warnings = []string{"synthetic coverage warning"}
	result, code, err := CompareReports(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 || !result.Incomplete || result.Passed {
		t.Fatalf("coverage gap passed an empty baseline: code=%d result=%#v", code, result)
	}
}

func writeBaseline(t *testing.T, report model.Report) string {
	t.Helper()
	if report.DocumentType == "" {
		report.DocumentType = model.ScanReportDocumentType
	}
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
	if report.Repository.Path == "" {
		report.Repository.Path = "/repo"
	}
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func verificationTestConfig(signature string) model.ScanConfig {
	return model.ScanConfig{
		Workers: 1, MaxFileSize: 1024,
		DetectorSignatures: map[string]string{"test-detector": signature},
	}
}
