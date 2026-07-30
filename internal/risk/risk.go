package risk

import (
	"fmt"
	"strings"
	"time"

	"github.com/khushi/reporeaper/internal/model"
)

func Score(f model.Finding) (int, string) {
	base := map[model.Severity]int{
		model.SeverityInfo: 8, model.SeverityLow: 20, model.SeverityMedium: 40,
		model.SeverityHigh: 62, model.SeverityCritical: 78,
	}[f.Severity]
	confidence := map[model.Confidence]int{
		model.ConfidenceUncertain: -12, model.ConfidenceLow: -8, model.ConfidenceMedium: -3,
		model.ConfidenceHigh: 4, model.ConfidenceConfirmed: 8,
	}[f.Confidence]
	score := base + confidence
	var factors []string
	factors = append(factors, fmt.Sprintf("severity %s (%d)", f.Severity, base), fmt.Sprintf("confidence %s (%+d)", f.Confidence, confidence))

	if f.InWorkingTree || f.InHead || f.InIndex || f.CurrentStatus == "present-in-head" ||
		f.CurrentStatus == "present-in-index" || f.CurrentStatus == "present-in-working-tree" {
		score += 10
		factors = append(factors, "current source presence (+10)")
	} else if f.InDirectRef || f.CommitCount > 0 {
		score += 4
		factors = append(factors, "reachable history (+4)")
	}
	if len(f.Tags) > 0 {
		score += 5
		factors = append(factors, "tag reachability (+5)")
	}
	for _, branch := range f.Branches {
		if strings.HasPrefix(branch, "refs/remotes/") || strings.HasPrefix(branch, "remotes/") {
			score += 8
			factors = append(factors, "remote-tracking evidence (+8)")
			break
		}
	}
	if f.Category == "private-key" {
		score += 7
		factors = append(factors, "private-key material (+7)")
	}
	if f.CommitCount >= 5 {
		score += 4
		factors = append(factors, "five or more commits (+4)")
	} else if f.CommitCount >= 2 {
		score += 2
		factors = append(factors, "multiple commits (+2)")
	}
	if len(f.Paths) >= 2 {
		score += 3
		factors = append(factors, "multiple paths (+3)")
	}
	if exposureDuration(f) >= 30*24*time.Hour {
		score += 3
		factors = append(factors, "exposure interval at least 30 days (+3)")
	}
	if f.InReflog {
		score += 2
		factors = append(factors, "reflog residual (+2)")
	}
	if f.InUnreachable {
		score += 2
		factors = append(factors, "unreachable residual (+2)")
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score, "Deterministic factors: " + strings.Join(factors, "; ") + "."
}

func exposureDuration(f model.Finding) time.Duration {
	if f.ExposureDurationSeconds > 0 {
		return time.Duration(f.ExposureDurationSeconds) * time.Second
	}
	var longest time.Duration
	for _, interval := range f.ExposureIntervals {
		if interval.EndedAt.IsZero() {
			continue
		}
		if d := interval.EndedAt.Sub(interval.StartedAt); d > longest {
			longest = d
		}
	}
	return longest
}
