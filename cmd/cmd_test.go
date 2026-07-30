package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/khushi/reporeaper/internal/config"
	"github.com/khushi/reporeaper/internal/model"
)

func TestRequiredTopLevelCommandsAndHelp(t *testing.T) {
	want := map[string]bool{"scan": false, "investigate": false, "verify": false, "detectors": false, "config": false, "protect": false, "doctor": false, "completion": false, "version": false}
	for _, command := range rootCmd.Commands() {
		if _, ok := want[command.Name()]; ok {
			want[command.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("command %s missing", name)
		}
	}
	command := scanCmd()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"--help"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--all-refs", "--unreachable", "--reflogs", "--format", "--severity", "--detector", "--workers", "--max-file-size", "--fail-on", "--fail-scope", "--baseline", "--cache", "--cache-path", "--cache-max-entries", "--cache-max-size"} {
		if !strings.Contains(output.String(), flag) {
			t.Fatalf("scan help missing %s", flag)
		}
	}
}

func TestScanPolicySeverityAndScope(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityHigh, InHead: true},
		{Severity: model.SeverityCritical, InUnreachable: true},
		{Severity: model.SeverityMedium, CommitCount: 1},
		{Severity: model.SeverityCritical, InIndex: true},
	}
	if got := scanPolicyMatches(findings, "high", "current"); got != 2 {
		t.Fatalf("current high matches = %d", got)
	}
	if got := scanPolicyMatches(findings, "critical", "current"); got != 1 {
		t.Fatalf("current critical matches = %d", got)
	}
	if got := scanPolicyMatches(findings, "critical", "residual"); got != 1 {
		t.Fatalf("residual critical matches = %d", got)
	}
	if got := scanPolicyMatches(findings, "", "any"); got != 0 {
		t.Fatalf("disabled policy matches = %d", got)
	}
	for _, invalid := range []struct{ severity, scope string }{{"urgent", "any"}, {"high", "remote"}} {
		if err := validateScanPolicy(invalid.severity, invalid.scope); err == nil {
			t.Fatalf("invalid policy %#v was accepted", invalid)
		}
	}
}

func TestScanFlagValidation(t *testing.T) {
	for name, args := range map[string]struct {
		format, severity, since, until string
		workers                        int
		max                            int64
	}{
		"format":   {format: "xml", workers: 1, max: 1},
		"severity": {format: "json", severity: "urgent", workers: 1, max: 1},
		"date":     {format: "json", since: "yesterday", workers: 1, max: 1},
		"workers":  {format: "json", workers: 0, max: 1},
		"size":     {format: "json", workers: 1, max: 0},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateScanFlags(args.format, args.severity, args.since, args.until, args.workers, args.max); err == nil {
				t.Fatal("invalid flags were accepted")
			}
		})
	}
	for name, args := range map[string]struct {
		entries int
		size    int64
	}{
		"cache entries": {entries: 0, size: 1024},
		"cache size":    {entries: 1, size: 1023},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateScanFlagsWithCache("json", "", "", "", 1, 1, args.entries, args.size); err == nil {
				t.Fatal("invalid cache limits were accepted")
			}
		})
	}
}

func TestNormalizeScanDatesUsesInclusiveLocalDayBoundaries(t *testing.T) {
	local := time.FixedZone("test-local", 5*60*60+30*60)
	since, until, err := normalizeScanDates("2026-07-20", "2026-07-20", local)
	if err != nil {
		t.Fatal(err)
	}
	if since != "2026-07-20T00:00:00+05:30" {
		t.Fatalf("since = %q", since)
	}
	if until != "2026-07-20T23:59:59+05:30" {
		t.Fatalf("until = %q", until)
	}
}

func TestNormalizeScanDatesRejectsReversedRange(t *testing.T) {
	if _, _, err := normalizeScanDates("2026-07-29", "2020-01-01", time.UTC); err == nil {
		t.Fatal("reversed scan date range was accepted")
	}
}

func TestScanDateFlagsIncludeCommitsFromTheWholeLocalDay(t *testing.T) {
	repo := t.TempDir()
	runTestGit(t, repo, "init")
	runTestGit(t, repo, "config", "user.name", "RepoReaper Test")
	runTestGit(t, repo, "config", "user.email", "test@example.invalid")
	if err := os.WriteFile(filepath.Join(repo, "note.txt"), []byte("safe fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, repo, "add", "note.txt")
	commitDate := time.Date(2026, 7, 20, 12, 0, 0, 0, time.Local).Format(time.RFC3339)
	runTestGitAt(t, repo, commitDate, "commit", "-m", "same-day commit")

	output := filepath.Join(t.TempDir(), "report.json")
	command := scanCmd()
	command.SetArgs([]string{repo, "--since", "2026-07-20", "--until", "2026-07-20", "--format", "json", "--output", output})
	if err := command.Execute(); err != nil {
		t.Fatalf("scan command: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var report model.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Stats.CommitsAnalyzed != 1 {
		t.Fatalf("commits analyzed = %d, want 1", report.Stats.CommitsAnalyzed)
	}
	if report.Config.Since == "2026-07-20" || report.Config.Until == "2026-07-20" {
		t.Fatalf("date boundaries were not made timezone-explicit: since=%q until=%q", report.Config.Since, report.Config.Until)
	}
}

func TestScanPolicyIsIndependentFromOutputSeverityFilter(t *testing.T) {
	repo := t.TempDir()
	runTestGit(t, repo, "init")
	runTestGit(t, repo, "config", "user.name", "RepoReaper Test")
	runTestGit(t, repo, "config", "user.email", "test@example.invalid")
	const fakeToken = "github_pat_11AA22bb33CC44dd55EE66ff77GG88hh99"
	if err := os.WriteFile(filepath.Join(repo, "fixture.env"), []byte("TOKEN="+fakeToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, repo, "add", "fixture.env")
	runTestGit(t, repo, "commit", "-m", "add synthetic credential")

	output := filepath.Join(t.TempDir(), "report.json")
	command := scanCmd()
	command.SetArgs([]string{repo, "--severity", "low", "--fail-on", "high", "--fail-scope", "current", "--format", "json", "--output", output})
	err := command.Execute()
	var policyErr *exitError
	if !errors.As(err, &policyErr) || policyErr.code != 1 {
		t.Fatalf("policy error = %v, want exit code 1", err)
	}
	data, readErr := os.ReadFile(output)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if bytes.Contains(data, []byte(fakeToken)) {
		t.Fatal("raw synthetic token leaked into report")
	}
	var result model.Report
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("output severity filter retained %d finding(s)", len(result.Findings))
	}
	if result.Findings == nil {
		t.Fatal("empty filtered findings serialized as null instead of an array")
	}
}

func runTestGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	runTestGitAt(t, dir, "", args...)
}

func runTestGitAt(t *testing.T, dir, date string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	command.Env = os.Environ()
	if date != "" {
		command.Env = append(command.Env, "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}

func TestDetectorSelectionRejectsUnknownID(t *testing.T) {
	if _, err := detectorSet(config.Default(), "does-not-exist"); err == nil {
		t.Fatal("unknown detector was silently accepted")
	}
}

func TestPrivateKeyDetectorGroupAlias(t *testing.T) {
	detectors, err := detectorSet(config.Default(), "private-key")
	if err != nil {
		t.Fatal(err)
	}
	if len(detectors) != 3 {
		t.Fatalf("private-key detector group size = %d", len(detectors))
	}
}

func TestDoubleStarPathAllowlist(t *testing.T) {
	finding := model.Finding{Paths: []string{"testdata/repositories/nested/config.env"}}
	if !allowPath(finding, []string{"testdata/**"}) {
		t.Fatal("double-star allowlist did not match nested path")
	}
}

func TestDoubleStarSlashPathAllowlistAlsoMatchesRepositoryRoot(t *testing.T) {
	finding := model.Finding{Paths: []string{"config.env"}}
	if !allowPath(finding, []string{"**/*.env"}) {
		t.Fatal("double-star slash allowlist did not match a root-level path")
	}
}

func TestPathAllowlistDoesNotHideFindingInAnotherPath(t *testing.T) {
	finding := model.Finding{Paths: []string{"testdata/fixture.env", "deploy/production.env"}}
	if allowPath(finding, []string{"testdata/**"}) {
		t.Fatal("partial path allowlist hid a finding with non-allowlisted evidence")
	}
}
