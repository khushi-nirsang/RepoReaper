package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"

	"github.com/khushi/reporeaper/internal/model"
	"github.com/khushi/reporeaper/internal/repoidentity"
	"github.com/khushi/reporeaper/internal/verify"
)

type baselineFindingKey struct {
	detectorID  string
	fingerprint string
}

type baselineFindingState struct {
	paths                map[string]struct{}
	inHead               bool
	inWorkingTree        bool
	inTrackedWorkingTree bool
	inUntracked          bool
	inIndex              bool
	inDirectRef          bool
	inReflog             bool
	inUnreachable        bool
}

// loadScanBaseline loads the same redacted JSON artifact accepted by verify,
// then validates the fields used to decide whether a finding is already known.
// Short fingerprints are deliberately not accepted for this decision.
func loadScanBaseline(filename string) (model.Report, error) {
	baseline, err := verify.LoadBaseline(filename)
	if err != nil {
		return model.Report{}, err
	}
	for index, finding := range baseline.Findings {
		if strings.TrimSpace(finding.DetectorID) == "" {
			return model.Report{}, fmt.Errorf("baseline finding %d has no detector ID", index+1)
		}
		if !isFullFingerprint(finding.Fingerprint) {
			return model.Report{}, fmt.Errorf("baseline finding %d has an invalid full fingerprint", index+1)
		}
	}
	return baseline, nil
}

func isFullFingerprint(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// suppressBaselineFindings removes a current finding only when its detector and
// full fingerprint were in the baseline, every currently observed path was
// already associated with that credential, and no current-source or residual
// scope has expanded. If the credential has appeared at a new path or has been
// reintroduced into a scope that was previously clean, the complete current
// finding remains visible.
func suppressBaselineFindings(findings []model.Finding, baseline model.Report) ([]model.Finding, int) {
	known := make(map[baselineFindingKey]*baselineFindingState, len(baseline.Findings))
	for _, finding := range baseline.Findings {
		key := baselineFindingKey{detectorID: finding.DetectorID, fingerprint: finding.Fingerprint}
		state := known[key]
		if state == nil {
			state = &baselineFindingState{paths: map[string]struct{}{}}
			known[key] = state
		}
		for normalized := range normalizedFindingPaths(finding.Paths) {
			state.paths[normalized] = struct{}{}
		}
		state.inHead = state.inHead || finding.InHead
		state.inWorkingTree = state.inWorkingTree || finding.InWorkingTree
		state.inTrackedWorkingTree = state.inTrackedWorkingTree || finding.InTrackedWorkingTree
		state.inUntracked = state.inUntracked || finding.InUntracked
		state.inIndex = state.inIndex || finding.InIndex
		state.inDirectRef = state.inDirectRef || finding.InDirectRef
		state.inReflog = state.inReflog || finding.InReflog
		state.inUnreachable = state.inUnreachable || finding.InUnreachable
	}

	kept := make([]model.Finding, 0, len(findings))
	suppressed := 0
	for _, finding := range findings {
		key := baselineFindingKey{detectorID: finding.DetectorID, fingerprint: finding.Fingerprint}
		state, found := known[key]
		if found && pathSetContained(normalizedFindingPaths(finding.Paths), state.paths) && baselineScopeCovers(*state, finding) {
			suppressed++
			continue
		}
		kept = append(kept, finding)
	}
	return kept, suppressed
}

func normalizedFindingPaths(paths []string) map[string]struct{} {
	normalized := make(map[string]struct{}, len(paths))
	for _, value := range paths {
		value = strings.ReplaceAll(value, `\`, "/")
		parts := strings.Split(value, "!")
		for index, part := range parts {
			parts[index] = path.Clean(part)
		}
		normalized[strings.Join(parts, "!")] = struct{}{}
	}
	return normalized
}

func pathSetContained(current, baseline map[string]struct{}) bool {
	if len(current) == 0 && len(baseline) != 0 {
		return false
	}
	for value := range current {
		if _, found := baseline[value]; !found {
			return false
		}
	}
	return true
}

func baselineScopeCovers(baseline baselineFindingState, current model.Finding) bool {
	return (!current.InHead || baseline.inHead) &&
		(!current.InWorkingTree || baseline.inWorkingTree) &&
		(!current.InTrackedWorkingTree || baseline.inTrackedWorkingTree) &&
		(!current.InUntracked || baseline.inUntracked) &&
		(!current.InIndex || baseline.inIndex) &&
		(!current.InDirectRef || baseline.inDirectRef) &&
		(!current.InReflog || baseline.inReflog) &&
		(!current.InUnreachable || baseline.inUnreachable)
}

// validateBaselineRepository rejects only an unambiguous remote mismatch. A
// checkout directory, Git directory, branch, or HEAD is never used as identity:
// those values legitimately change across machines and runs.
func validateBaselineRepository(baseline, current model.Repository) error {
	return repoidentity.Validate(baseline, current)
}
