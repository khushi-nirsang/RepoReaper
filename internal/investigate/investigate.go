package investigate

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/khushi/reporeaper/internal/verify"
)

func Run(path, finding string) (string, error) {
	r, err := verify.LoadBaseline(path)
	if err != nil {
		return "", fmt.Errorf("load scan report: %w", err)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Repository: %s\nFindings: %d\n\n", plainText(r.Repository.Path), len(r.Findings))
	matched := finding == ""
	for _, f := range r.Findings {
		if finding != "" && f.ID != finding {
			continue
		}
		matched = true
		fmt.Fprintf(&sb, "%s %s %s risk %d\nRedacted: %s\nStatus: %s\nRemote: %s - %s\nRisk: %s\n", plainText(f.ID), f.Severity, plainText(f.DetectorID), f.RiskScore, plainText(f.Redacted), plainText(f.CurrentStatus), plainText(f.RemoteStatus), plainText(f.RemoteReason), plainText(f.RiskExplanation))
		if f.FirstSeen != nil {
			fmt.Fprintf(&sb, "Introduced: %s %s %s:%d\n", plainText(f.FirstSeen.Commit), f.FirstSeen.Time.Format("2006-01-02"), plainText(f.FirstSeen.Path), f.FirstSeen.Line)
		}
		if f.Removed != nil {
			fmt.Fprintf(&sb, "Removed from later snapshots by: %s %s\n", plainText(f.Removed.Commit), f.Removed.Time.Format("2006-01-02"))
		}
		fmt.Fprintln(&sb, "Exposure intervals:")
		for _, interval := range f.ExposureIntervals {
			end := "open or ambiguous"
			if !interval.EndedAt.IsZero() {
				end = interval.EndedAt.Format("2006-01-02") + " removed by " + plainText(interval.RemovedBy)
			}
			fmt.Fprintf(&sb, "- %s: %s (%s) to %s\n", plainText(interval.Status), interval.StartedAt.Format("2006-01-02"), plainText(interval.StartCommit), end)
		}
		fmt.Fprintf(&sb, "Branches: %s\nTags: %s\nPaths: %s\nRemediation:\n", plainJoin(f.Branches), plainJoin(f.Tags), plainJoin(f.Paths))
		for i, step := range f.Remediation {
			fmt.Fprintf(&sb, "%d. %s\n", i+1, plainText(step))
		}
		sb.WriteString("\n")
	}
	if !matched {
		return "", fmt.Errorf("finding %s not found", plainText(finding))
	}
	return sb.String(), nil
}

func plainJoin(values []string) string {
	safe := make([]string, 0, len(values))
	for _, value := range values {
		safe = append(safe, plainText(value))
	}
	return strings.Join(safe, ", ")
}

func plainText(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) ||
			character == '\u061c' ||
			character == '\u200e' ||
			character == '\u200f' ||
			character == '\u2028' ||
			character == '\u2029' ||
			(character >= '\u202a' && character <= '\u202e') ||
			(character >= '\u2066' && character <= '\u2069') {
			return '\uFFFD'
		}
		return character
	}, value)
}
