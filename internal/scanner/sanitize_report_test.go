package scanner

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/khushi/reporeaper/internal/detector"
	"github.com/khushi/reporeaper/internal/fingerprint"
	"github.com/khushi/reporeaper/internal/model"
)

func TestScrubScanReportCoversRepositoryAndNestedFindingMetadata(t *testing.T) {
	captured := "ghp_" + strings.Repeat("Synth3ticReportMetadataValue123456", 1)
	full, short := fingerprint.SHA256(captured)
	scrubber, valid := detector.NewCaptureScrubber([]detector.Match{{
		Fingerprint: full, Short: short, ValueLength: len(captured),
	}})
	if !valid {
		t.Fatal("cached capture proof was invalid")
	}
	report := model.Report{
		ToolVersion: captured,
		Config: model.ScanConfig{
			Detectors:          []string{"detector-" + captured},
			DetectorSignatures: map[string]string{"detector-" + captured: full},
			Since:              captured,
		},
		Repository: model.Repository{
			Path: captured, GitDir: "git-" + captured, Head: captured, Branch: "branch-" + captured,
			Remotes: []model.Remote{{Name: captured, URL: "https://example.invalid/" + captured}},
		},
		Findings: []model.Finding{{
			ID: "RR-0001", DetectorID: "detector-" + captured, DetectorName: captured,
			Fingerprint: full, ShortFingerprint: short, Redacted: "preview-" + captured,
			Removed: &model.Evidence{AuthorName: captured, AuthorEmail: captured + "@example.invalid"},
			Evidence: []model.Evidence{{
				Source: "commit-" + captured, Commit: captured, Blob: captured,
				Path: "path/" + captured, Ref: "refs/" + captured, Decoder: "decoder-" + captured,
			}},
			ExposureIntervals: []model.ExposureInterval{{
				StartCommit: captured, EndCommit: captured, RemovedBy: captured, Status: "status-" + captured,
			}},
			Paths: []string{captured}, Branches: []string{captured}, Tags: []string{captured},
			Remediation: []string{"replace " + captured},
		}},
		Warnings: []string{"warning " + captured},
		Notices:  []string{"notice " + captured},
	}

	scrubScanReport(&report, scrubber)
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(captured)) {
		t.Fatalf("captured value remained in serialized report: %s", encoded)
	}
	if report.Findings[0].Fingerprint != full || report.Config.DetectorSignatures["detector-[REDACTED-CAPTURE]"] != full {
		t.Fatal("derived fingerprints or signatures were altered")
	}
}
