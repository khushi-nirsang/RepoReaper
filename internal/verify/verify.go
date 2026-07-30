package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/khushi/reporeaper/internal/model"
	"github.com/khushi/reporeaper/internal/repoidentity"
)

const maxVerificationFileSize = int64(1024 * 1024 * 1024)

type Result struct {
	DocumentType  string   `json:"document_type"`
	SchemaVersion string   `json:"schema_version"`
	Repository    string   `json:"repository"`
	Items         []Item   `json:"items"`
	Passed        bool     `json:"passed"`
	Incomplete    bool     `json:"incomplete"`
	Notes         []string `json:"notes"`
}

type Item struct {
	FindingID              string   `json:"finding_id,omitempty"`
	Fingerprint            string   `json:"fingerprint,omitempty"`
	Status                 string   `json:"status"`
	ScopeStatus            string   `json:"scope_status"`
	ScopeGaps              []string `json:"scope_gaps,omitempty"`
	CredentialRotation     string   `json:"credential_rotation_status"`
	SourceRemoval          string   `json:"source_removal_status"`
	ReachableHistory       string   `json:"reachable_history_status"`
	RemoteCopy             string   `json:"remote_copy_status"`
	LocalResidualObjects   string   `json:"local_residual_object_status"`
	SupportingObservations []string `json:"supporting_observations,omitempty"`
}

func LoadBaseline(path string) (model.Report, error) {
	b, err := readBaselineFile(path)
	if err != nil {
		return model.Report{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return model.Report{}, fmt.Errorf("parse baseline report: %w", err)
	}
	for _, required := range []string{
		"schema_version", "tool_version", "generated_at", "scan_config",
		"repository", "findings", "summary", "stats",
	} {
		if _, ok := fields[required]; !ok {
			return model.Report{}, fmt.Errorf("baseline is not a complete RepoReaper scan report: missing %q", required)
		}
	}
	var baseline model.Report
	if err := json.Unmarshal(b, &baseline); err != nil {
		return model.Report{}, fmt.Errorf("parse baseline report: %w", err)
	}
	if !model.IsSupportedSchema(baseline.SchemaVersion) {
		return model.Report{}, fmt.Errorf("unsupported baseline schema %q", baseline.SchemaVersion)
	}
	if baseline.DocumentType != "" && baseline.DocumentType != model.ScanReportDocumentType {
		return model.Report{}, fmt.Errorf("baseline document type %q is not a scan report", baseline.DocumentType)
	}
	if strings.TrimSpace(baseline.ToolVersion) == "" || baseline.GeneratedAt.IsZero() ||
		strings.TrimSpace(baseline.Repository.Path) == "" {
		return model.Report{}, fmt.Errorf("baseline is not a complete RepoReaper scan report")
	}
	if baseline.Config.Workers < 1 || baseline.Config.Workers > 64 ||
		baseline.Config.MaxFileSize < 1 || baseline.Config.MaxFileSize > maxVerificationFileSize {
		return model.Report{}, fmt.Errorf("baseline contains invalid scan execution metadata")
	}
	return baseline, nil
}

func readBaselineFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("baseline report is not a regular file")
	}
	if info.Size() > maxVerificationFileSize {
		return nil, fmt.Errorf("baseline report exceeds the %d-byte size limit", maxVerificationFileSize)
	}
	body, err := io.ReadAll(io.LimitReader(file, maxVerificationFileSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxVerificationFileSize {
		return nil, fmt.Errorf("baseline report exceeds the %d-byte size limit", maxVerificationFileSize)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("baseline report is empty")
	}
	return body, nil
}

// ReproductionConfig returns a conservative superset of the semantic scan
// scope recorded in the baseline. Verification intentionally removes date
// restrictions and enables every local Git evidence source so newly exposed or
// residual copies cannot be hidden by a narrower current scan.
func ReproductionConfig(baseline model.Report, workers int, safeMaxFileSize int64) model.ScanConfig {
	config := baseline.Config
	if workers < 1 || workers > 64 {
		workers = 1
	}
	config.Workers = workers
	if safeMaxFileSize < 1 || safeMaxFileSize > maxVerificationFileSize {
		safeMaxFileSize = 5 * 1024 * 1024
	}
	if config.MaxFileSize < 1 || config.MaxFileSize > maxVerificationFileSize {
		config.MaxFileSize = safeMaxFileSize
	} else if safeMaxFileSize > config.MaxFileSize && safeMaxFileSize <= maxVerificationFileSize {
		config.MaxFileSize = safeMaxFileSize
	}
	config.IncludeUntracked = true
	config.Branches = true
	config.Tags = true
	config.AllRefs = true
	config.Unreachable = true
	config.Reflogs = true
	config.Severity = nil
	config.Detectors = nil
	config.Since = ""
	config.Until = ""
	config.DetectorSignatures = nil
	return config
}

func Compare(baselinePath string, current model.Report) (Result, int, error) {
	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		return Result{}, 2, err
	}
	return CompareReports(baseline, current)
}

func CompareReports(baseline, current model.Report) (Result, int, error) {
	if !model.IsSupportedSchema(baseline.SchemaVersion) {
		return Result{}, 2, fmt.Errorf("unsupported baseline schema %q", baseline.SchemaVersion)
	}
	if !model.IsSupportedSchema(current.SchemaVersion) {
		return Result{}, 2, fmt.Errorf("unsupported current report schema %q", current.SchemaVersion)
	}
	if baseline.DocumentType != "" && baseline.DocumentType != model.ScanReportDocumentType {
		return Result{}, 2, fmt.Errorf("baseline document type %q is not a scan report", baseline.DocumentType)
	}
	if current.DocumentType != "" && current.DocumentType != model.ScanReportDocumentType {
		return Result{}, 2, fmt.Errorf("current document type %q is not a scan report", current.DocumentType)
	}
	if err := repoidentity.Validate(baseline.Repository, current.Repository); err != nil {
		return Result{}, 2, err
	}
	currentByFingerprint := map[string]model.Finding{}
	for index, finding := range current.Findings {
		if !isFullFingerprint(finding.Fingerprint) {
			return Result{}, 2, fmt.Errorf("current finding %d has an invalid full fingerprint", index+1)
		}
		currentByFingerprint[strings.ToLower(finding.Fingerprint)] = finding
	}
	result := Result{
		DocumentType:  model.VerificationResultDocumentType,
		SchemaVersion: model.SchemaVersion,
		Repository:    current.Repository.Path,
		Passed:        true,
		Notes: []string{
			"Credential rotation or revocation cannot be confirmed because RepoReaper never contacts credential providers.",
			"Remote-copy status is inferred only from local refs; absence of local evidence does not prove remote deletion.",
		},
	}
	globalGaps := globalScopeGaps(baseline, current)
	allGaps := append([]string{}, globalGaps...)
	if len(globalGaps) > 0 {
		result.Incomplete = true
		result.Passed = false
	}
	for index, baselineFinding := range baseline.Findings {
		if strings.TrimSpace(baselineFinding.DetectorID) == "" {
			return Result{}, 2, fmt.Errorf("baseline finding %d has no detector identity", index+1)
		}
		if !isFullFingerprint(baselineFinding.Fingerprint) {
			return Result{}, 2, fmt.Errorf("baseline finding %d has an invalid full fingerprint", index+1)
		}
		itemGaps := append([]string{}, globalGaps...)
		itemGaps = append(itemGaps, detectorScopeGaps(baselineFinding, baseline, current)...)
		itemGaps = sortedUnique(itemGaps)
		allGaps = append(allGaps, itemGaps...)
		displayFingerprint := baselineFinding.ShortFingerprint
		if len(displayFingerprint) != 12 {
			displayFingerprint = strings.ToLower(baselineFinding.Fingerprint[:12])
		}
		item := Item{
			FindingID: baselineFinding.ID, Fingerprint: displayFingerprint,
			ScopeStatus: "complete", CredentialRotation: "cannot-be-confirmed",
			SourceRemoval: "removed-from-current-source", ReachableHistory: "not-observed",
			RemoteCopy: "no-local-evidence-remote-deletion-unproven", LocalResidualObjects: "not-observed",
		}
		if len(itemGaps) > 0 {
			item.ScopeStatus = "incomplete"
			item.ScopeGaps = itemGaps
			result.Incomplete = true
			result.Passed = false
		}

		finding, observed := currentByFingerprint[strings.ToLower(baselineFinding.Fingerprint)]
		if !observed {
			if len(itemGaps) > 0 {
				item.Status = "unable-to-verify"
				item.SourceRemoval = "unable-to-verify"
				item.ReachableHistory = "unable-to-verify"
				item.LocalResidualObjects = "unable-to-verify"
			} else {
				item.Status = "not-observed"
			}
			result.Items = append(result.Items, item)
			continue
		}

		result.Passed = false
		setCurrentSourceStatus(&item, finding)
		if finding.CommitCount > 0 {
			item.ReachableHistory = "still-in-reachable-history"
			item.SupportingObservations = append(item.SupportingObservations, "still-in-reachable-history")
			if item.Status == "remediated-from-current-source" {
				item.Status = "still-in-reachable-history"
			}
		}
		if len(finding.Tags) > 0 {
			item.SupportingObservations = append(item.SupportingObservations, "still-in-tags")
			if item.Status == "remediated-from-current-source" || item.Status == "still-in-reachable-history" {
				item.Status = "still-in-tags"
			}
		}
		if hasRemote(finding) {
			item.RemoteCopy = "local-remote-tracking-evidence-remains"
			item.SupportingObservations = append(item.SupportingObservations, "still-in-remote-tracking-refs")
			if !isCurrentSourceStatus(item.Status) {
				item.Status = "still-in-remote-tracking-refs"
			}
		}
		if finding.InReflog || hasReflog(finding) {
			item.LocalResidualObjects = "still-in-reflog"
			item.SupportingObservations = append(item.SupportingObservations, "still-in-reflog")
			if item.Status == "remediated-from-current-source" {
				item.Status = "still-in-reflog"
			}
		}
		if finding.InUnreachable || hasUnreachable(finding) {
			if item.LocalResidualObjects == "still-in-reflog" {
				item.LocalResidualObjects = "still-in-reflog-and-unreachable-objects"
			} else {
				item.LocalResidualObjects = "still-in-unreachable-objects"
			}
			item.SupportingObservations = append(item.SupportingObservations, "still-in-unreachable-objects")
			if item.Status == "remediated-from-current-source" {
				item.Status = "still-in-unreachable-objects"
			}
		}
		item.SupportingObservations = sortedUnique(item.SupportingObservations)
		result.Items = append(result.Items, item)
	}
	sort.Slice(result.Items, func(i, j int) bool { return result.Items[i].FindingID < result.Items[j].FindingID })
	if result.Incomplete {
		result.Notes = append(result.Notes, "Verification scope is incomplete: "+strings.Join(sortedUnique(allGaps), "; "))
		return result, 3, nil
	}
	if result.Passed {
		return result, 0, nil
	}
	return result, 1, nil
}

func isFullFingerprint(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func globalScopeGaps(baseline, current model.Report) []string {
	var gaps []string
	base, now := baseline.Config, current.Config
	if current.Repository.Shallow {
		gaps = append(gaps, "current repository is shallow")
	}
	if !baseline.Repository.Bare && !current.Repository.WorktreeOK {
		gaps = append(gaps, "current working tree was unavailable")
	}
	for _, warning := range current.Warnings {
		if strings.TrimSpace(warning) != "" {
			gaps = append(gaps, "current scan warning: "+strings.TrimSpace(warning))
		}
	}
	if !baseline.Repository.Bare && base.IncludeUntracked && !now.IncludeUntracked {
		gaps = append(gaps, "baseline untracked-file coverage was not reproduced")
	}
	if base.AllRefs && !now.AllRefs {
		gaps = append(gaps, "baseline all-refs coverage was not reproduced")
	}
	if base.Branches && !(now.Branches || now.AllRefs) {
		gaps = append(gaps, "baseline branch coverage was not reproduced")
	}
	if base.Tags && !(now.Tags || now.AllRefs) {
		gaps = append(gaps, "baseline tag coverage was not reproduced")
	}
	if base.Reflogs && !now.Reflogs {
		gaps = append(gaps, "baseline reflog coverage was not reproduced")
	}
	if base.Unreachable && !now.Unreachable {
		gaps = append(gaps, "baseline unreachable-object coverage was not reproduced")
	}
	if !dateScopeCovered(base.Since, now.Since, false) || !dateScopeCovered(base.Until, now.Until, true) {
		gaps = append(gaps, "baseline date-filter scope was not reproduced")
	}
	if base.MaxFileSize < 1 || base.MaxFileSize > maxVerificationFileSize {
		gaps = append(gaps, "baseline max-file-size metadata is invalid")
	} else if now.MaxFileSize < base.MaxFileSize {
		gaps = append(gaps, "current max-file-size is smaller than the baseline")
	}
	return sortedUnique(gaps)
}

func dateScopeCovered(baseline, current string, upperBound bool) bool {
	if baseline == "" {
		return current == ""
	}
	if current == "" || current == baseline {
		return true
	}
	baseTime, baseOK := parseScopeTime(baseline, upperBound)
	currentTime, currentOK := parseScopeTime(current, upperBound)
	if !baseOK || !currentOK {
		return false
	}
	if upperBound {
		return !currentTime.Before(baseTime)
	}
	return !currentTime.After(baseTime)
}

func parseScopeTime(value string, endOfDay bool) (time.Time, bool) {
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed, true
	}
	parsed, err := time.ParseInLocation("2006-01-02", value, time.Local)
	if err != nil {
		return time.Time{}, false
	}
	if endOfDay {
		parsed = parsed.Add(24*time.Hour - time.Nanosecond)
	}
	return parsed, true
}

func detectorScopeGaps(finding model.Finding, baseline, current model.Report) []string {
	if finding.DetectorID == "" {
		return []string{"baseline finding has no detector identity"}
	}
	want, recorded := baseline.Config.DetectorSignatures[finding.DetectorID]
	if !recorded || want == "" {
		return []string{"baseline has no rule signature for detector " + finding.DetectorID}
	}
	got, available := current.Config.DetectorSignatures[finding.DetectorID]
	if !available || got == "" {
		return []string{"detector " + finding.DetectorID + " was unavailable for the current scan"}
	}
	if got != want {
		return []string{"detector " + finding.DetectorID + " rule differs from the baseline"}
	}
	return nil
}

func setCurrentSourceStatus(item *Item, finding model.Finding) {
	switch {
	case finding.InHead || finding.CurrentStatus == "present-in-head":
		item.SourceRemoval = "still-in-head"
		item.Status = "still-in-head"
		item.SupportingObservations = append(item.SupportingObservations, "still-in-head")
	case finding.InIndex || finding.CurrentStatus == "present-in-index":
		item.SourceRemoval = "still-in-index"
		item.Status = "still-in-index"
		item.SupportingObservations = append(item.SupportingObservations, "still-in-index")
	case finding.InDirectRef || finding.CurrentStatus == "present-in-ref-object":
		item.SourceRemoval = "still-in-ref-object"
		item.Status = "still-in-ref-object"
		item.SupportingObservations = append(item.SupportingObservations, "still-in-ref-object")
	case finding.InTrackedWorkingTree || finding.CurrentStatus == "present-in-tracked-working-tree":
		item.SourceRemoval = "still-in-tracked-working-tree"
		item.Status = "still-in-tracked-working-tree"
		item.SupportingObservations = append(item.SupportingObservations, "still-in-tracked-working-tree")
	case finding.InUntracked || finding.CurrentStatus == "present-in-untracked-file":
		item.SourceRemoval = "still-in-untracked-file"
		item.Status = "still-in-untracked-file"
		item.SupportingObservations = append(item.SupportingObservations, "still-in-untracked-file")
	case finding.InWorkingTree || finding.CurrentStatus == "present-in-working-tree":
		item.SourceRemoval = "still-in-working-tree-origin-unknown"
		item.Status = "still-in-working-tree-origin-unknown"
		item.SupportingObservations = append(item.SupportingObservations, "still-in-working-tree-origin-unknown")
	default:
		item.SourceRemoval = "remediated-from-current-source"
		item.Status = "remediated-from-current-source"
	}
	if finding.InHead {
		item.SupportingObservations = append(item.SupportingObservations, "still-in-head")
	}
	if finding.InIndex {
		item.SupportingObservations = append(item.SupportingObservations, "still-in-index")
	}
	if finding.InDirectRef {
		item.SupportingObservations = append(item.SupportingObservations, "still-in-ref-object")
	}
	if finding.InTrackedWorkingTree {
		item.SupportingObservations = append(item.SupportingObservations, "still-in-tracked-working-tree")
	}
	if finding.InUntracked {
		item.SupportingObservations = append(item.SupportingObservations, "still-in-untracked-file")
	}
}

func isCurrentSourceStatus(status string) bool {
	return status == "still-in-head" || status == "still-in-index" || status == "still-in-ref-object" || status == "still-in-tracked-working-tree" || status == "still-in-untracked-file" || status == "still-in-working-tree-origin-unknown"
}

func hasRemote(f model.Finding) bool {
	for _, branch := range f.Branches {
		if strings.HasPrefix(branch, "refs/remotes/") || strings.HasPrefix(branch, "remotes/") {
			return true
		}
	}
	return false
}

func hasUnreachable(f model.Finding) bool {
	for _, evidence := range f.Evidence {
		if evidence.Unreachable {
			return true
		}
	}
	return false
}

func hasReflog(f model.Finding) bool {
	for _, evidence := range f.Evidence {
		if evidence.Reflog {
			return true
		}
	}
	return false
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
