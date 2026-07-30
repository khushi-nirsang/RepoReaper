package scanner

import (
	"github.com/khushi/reporeaper/internal/detector"
	"github.com/khushi/reporeaper/internal/model"
)

// scrubScanReport is the final no-raw-capture boundary for serialized scan
// reports. Fingerprints and detector signatures are derived proof values and
// intentionally remain unchanged.
func scrubScanReport(report *model.Report, scrubber detector.CaptureScrubber) {
	report.ToolVersion = scrubber.Scrub(report.ToolVersion)
	report.Config.Since = scrubber.Scrub(report.Config.Since)
	report.Config.Until = scrubber.Scrub(report.Config.Until)
	scrubStringSlice(report.Config.Severity, scrubber)
	scrubStringSlice(report.Config.Detectors, scrubber)
	if len(report.Config.DetectorSignatures) > 0 {
		signatures := make(map[string]string, len(report.Config.DetectorSignatures))
		for id, signature := range report.Config.DetectorSignatures {
			signatures[scrubber.Scrub(id)] = signature
		}
		report.Config.DetectorSignatures = signatures
	}

	report.Repository.Path = scrubber.Scrub(report.Repository.Path)
	report.Repository.GitDir = scrubber.Scrub(report.Repository.GitDir)
	report.Repository.Head = scrubber.Scrub(report.Repository.Head)
	report.Repository.Branch = scrubber.Scrub(report.Repository.Branch)
	for index := range report.Repository.Remotes {
		report.Repository.Remotes[index].Name = scrubber.Scrub(report.Repository.Remotes[index].Name)
		report.Repository.Remotes[index].URL = scrubber.Scrub(report.Repository.Remotes[index].URL)
	}

	for index := range report.Findings {
		scrubFinding(&report.Findings[index], scrubber)
	}
	scrubStringSlice(report.Warnings, scrubber)
	scrubStringSlice(report.Notices, scrubber)
}

func scrubFinding(finding *model.Finding, scrubber detector.CaptureScrubber) {
	finding.ID = scrubber.Scrub(finding.ID)
	finding.DetectorID = scrubber.Scrub(finding.DetectorID)
	finding.DetectorName = scrubber.Scrub(finding.DetectorName)
	finding.Category = scrubber.Scrub(finding.Category)
	finding.ConfidenceReason = scrubber.Scrub(finding.ConfidenceReason)
	finding.RiskExplanation = scrubber.Scrub(finding.RiskExplanation)
	finding.Redacted = scrubber.Scrub(finding.Redacted)
	finding.CurrentStatus = scrubber.Scrub(finding.CurrentStatus)
	finding.RemoteStatus = scrubber.Scrub(finding.RemoteStatus)
	finding.RemoteReason = scrubber.Scrub(finding.RemoteReason)
	scrubEvidence(finding.FirstSeen, scrubber)
	scrubEvidence(finding.LastSeen, scrubber)
	scrubEvidence(finding.Introduced, scrubber)
	scrubEvidence(finding.Removed, scrubber)
	for index := range finding.ExposureIntervals {
		finding.ExposureIntervals[index].StartCommit = scrubber.Scrub(finding.ExposureIntervals[index].StartCommit)
		finding.ExposureIntervals[index].EndCommit = scrubber.Scrub(finding.ExposureIntervals[index].EndCommit)
		finding.ExposureIntervals[index].RemovedBy = scrubber.Scrub(finding.ExposureIntervals[index].RemovedBy)
		finding.ExposureIntervals[index].Status = scrubber.Scrub(finding.ExposureIntervals[index].Status)
	}
	for index := range finding.Evidence {
		scrubEvidence(&finding.Evidence[index], scrubber)
	}
	scrubStringSlice(finding.Paths, scrubber)
	scrubStringSlice(finding.Branches, scrubber)
	scrubStringSlice(finding.Tags, scrubber)
	scrubStringSlice(finding.Remediation, scrubber)
}

func scrubEvidence(evidence *model.Evidence, scrubber detector.CaptureScrubber) {
	if evidence == nil {
		return
	}
	evidence.Source = scrubber.Scrub(evidence.Source)
	evidence.Commit = scrubber.Scrub(evidence.Commit)
	evidence.Blob = scrubber.Scrub(evidence.Blob)
	evidence.Path = scrubber.Scrub(evidence.Path)
	evidence.Ref = scrubber.Scrub(evidence.Ref)
	evidence.AuthorName = scrubber.Scrub(evidence.AuthorName)
	evidence.AuthorEmail = scrubber.Scrub(evidence.AuthorEmail)
	evidence.Decoder = scrubber.Scrub(evidence.Decoder)
}

func scrubStringSlice(values []string, scrubber detector.CaptureScrubber) {
	for index := range values {
		values[index] = scrubber.Scrub(values[index])
	}
}
