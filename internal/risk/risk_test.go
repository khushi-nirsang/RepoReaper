package risk

import (
	"strings"
	"testing"
	"time"

	"github.com/khushi/reporeaper/internal/model"
)

func TestScoreIsDeterministicAndAccountsForRiskFactors(t *testing.T) {
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	finding := model.Finding{
		Severity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Category: "private-key",
		InHead: true, CommitCount: 6, Paths: []string{"a", "b"}, Tags: []string{"release"},
		Branches: []string{"refs/remotes/origin/main"}, InReflog: true, InUnreachable: true,
		ExposureIntervals: []model.ExposureInterval{{StartedAt: start, EndedAt: start.Add(60 * 24 * time.Hour)}},
	}
	firstScore, firstExplanation := Score(finding)
	secondScore, secondExplanation := Score(finding)
	if firstScore != secondScore || firstExplanation != secondExplanation {
		t.Fatal("risk score is not deterministic")
	}
	if firstScore != 100 {
		t.Fatalf("score = %d", firstScore)
	}
	for _, factor := range []string{"private-key", "remote-tracking", "unreachable", "30 days"} {
		if !strings.Contains(firstExplanation, factor) {
			t.Fatalf("explanation missing %q: %s", factor, firstExplanation)
		}
	}
}

func TestScoreUsesUnionedExposureDuration(t *testing.T) {
	finding := model.Finding{
		Severity: model.SeverityMedium, Confidence: model.ConfidenceHigh,
		ExposureDurationSeconds: int64((31 * 24 * time.Hour) / time.Second),
	}
	_, explanation := Score(finding)
	if !strings.Contains(explanation, "30 days") {
		t.Fatalf("unioned exposure duration was ignored: %s", explanation)
	}
}

func TestScoreTreatsIndexPresenceAsCurrentExposure(t *testing.T) {
	finding := model.Finding{
		Severity: model.SeverityMedium, Confidence: model.ConfidenceHigh, InIndex: true,
	}
	_, explanation := Score(finding)
	if !strings.Contains(explanation, "current source presence") {
		t.Fatalf("index presence was not treated as current exposure: %s", explanation)
	}
}
