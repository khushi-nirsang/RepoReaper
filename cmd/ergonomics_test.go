package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/khushi/reporeaper/internal/verify"
	"github.com/spf13/cobra"
)

func TestCompletionCommandGeneratesSupportedShells(t *testing.T) {
	tests := map[string]string{
		"bash":       "__start_reporeaper",
		"zsh":        "#compdef reporeaper",
		"fish":       "complete -c reporeaper",
		"powershell": "Register-ArgumentCompleter",
	}
	for shell, marker := range tests {
		t.Run(shell, func(t *testing.T) {
			root := &cobra.Command{Use: "reporeaper"}
			root.AddCommand(&cobra.Command{Use: "scan"})
			root.AddCommand(completionCmd(root))
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(&output)
			root.SetArgs([]string{"completion", shell})
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), marker) {
				t.Fatalf("%s completion missing %q", shell, marker)
			}
		})
	}
}

func TestCompletionCommandRejectsUnsupportedShell(t *testing.T) {
	root := &cobra.Command{Use: "reporeaper"}
	root.AddCommand(completionCmd(root))
	root.SetArgs([]string{"completion", "cmd"})
	if err := root.Execute(); err == nil {
		t.Fatal("unsupported completion shell was accepted")
	}
}

func TestDoctorDiagnosesUnbornRepositoryWithoutReadingContents(t *testing.T) {
	repository := t.TempDir()
	runTestGit(t, repository, "init")
	const fakeFixture = "FAKE_DOCTOR_SENTINEL_NOT_A_SECRET"
	if err := os.WriteFile(filepath.Join(repository, "fixture.txt"), []byte(fakeFixture), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "reporeaper.yaml")
	const validConfig = `version: 1
scan:
  max_file_size: 5242880
  include_untracked: false
  branches: true
  tags: true
  unreachable: false
  reflogs: false
  workers: 4
report:
  default_format: table
  redact: true
policy:
  scope: any
allowlist: {}
detectors: {}
`
	if err := os.WriteFile(configPath, []byte(validConfig), 0600); err != nil {
		t.Fatal(err)
	}

	report := diagnose(context.Background(), repository, configPath)
	if !report.Healthy || report.Errors != 0 {
		t.Fatalf("doctor report = %#v", report)
	}
	if report.Warnings != 1 {
		t.Fatalf("warnings = %d, want unborn-history warning", report.Warnings)
	}
	statuses := map[string]string{}
	for _, check := range report.Checks {
		statuses[check.Name] = check.Status
	}
	for _, name := range []string{"runtime", "configuration", "git", "repository", "coverage"} {
		if statuses[name] != "ok" {
			t.Fatalf("%s status = %q", name, statuses[name])
		}
	}
	if statuses["history"] != "warning" {
		t.Fatalf("history status = %q", statuses["history"])
	}

	var output bytes.Buffer
	if err := writeDoctorReport(&output, "json", report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), fakeFixture) {
		t.Fatal("doctor output included repository file contents")
	}
	var decoded doctorReport
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Healthy || len(decoded.Checks) != len(report.Checks) {
		t.Fatalf("decoded doctor report = %#v", decoded)
	}
}

func TestDoctorReportsConfigurationAndRepositoryErrors(t *testing.T) {
	report := diagnose(context.Background(), filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "missing.yaml"))
	if report.Healthy || report.Errors != 2 {
		t.Fatalf("doctor report = %#v", report)
	}
	var output bytes.Buffer
	if err := writeDoctorReport(&output, "text", report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Summary: unhealthy") {
		t.Fatalf("doctor text output = %q", output.String())
	}
}

func TestFlagOnlyCommandsRejectPositionalArguments(t *testing.T) {
	tests := map[string]struct {
		command *cobra.Command
		args    []string
	}{
		"version":           {command: versionCmd(), args: []string{"unexpected"}},
		"investigate":       {command: investigateCmd(), args: []string{"unexpected", "--report", "unused.json"}},
		"config validate":   {command: configCmd(), args: []string{"validate", "unexpected"}},
		"detectors list":    {command: detectorsCmd(), args: []string{"list", "unexpected"}},
		"protect install":   {command: protectCmd(), args: []string{"install", "unexpected"}},
		"protect uninstall": {command: protectCmd(), args: []string{"uninstall", "unexpected"}},
		"protect status":    {command: protectCmd(), args: []string{"status", "unexpected"}},
		"protect staged":    {command: protectCmd(), args: []string{"staged", "unexpected"}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			test.command.SetOut(&output)
			test.command.SetErr(&output)
			test.command.SetArgs(test.args)
			test.command.SilenceErrors = true
			test.command.SilenceUsage = true
			if err := test.command.Execute(); err == nil {
				t.Fatal("unexpected positional argument was accepted")
			}
		})
	}
}

func TestVerificationTableIncludesOverallStateAndDiagnostics(t *testing.T) {
	clean := verificationTable(verify.Result{
		Repository: "repo",
		Passed:     true,
		Notes:      []string{"local evidence only"},
	})
	for _, expected := range []string{"Verification: passed", "Baseline findings: 0", "No baseline findings to verify.", "local evidence only"} {
		if !strings.Contains(clean, expected) {
			t.Fatalf("clean verification table omitted %q:\n%s", expected, clean)
		}
	}

	incomplete := verificationTable(verify.Result{
		Repository: "repo",
		Incomplete: true,
		Items: []verify.Item{{
			FindingID: "RR-0001", Status: "unable-to-verify", ScopeStatus: "incomplete",
			ScopeGaps:              []string{"current repository is shallow"},
			SupportingObservations: []string{"still-in-head"},
		}},
	})
	for _, expected := range []string{"Verification: incomplete", "scope=incomplete", "Scope gaps: current repository is shallow", "Supporting observations: still-in-head"} {
		if !strings.Contains(incomplete, expected) {
			t.Fatalf("incomplete verification table omitted %q:\n%s", expected, incomplete)
		}
	}
}

func TestTerminalTextNeutralizesC1AndBidiControls(t *testing.T) {
	input := "safe\n\u009b\u061c\u200e\u202e\u2066text"
	output := safeTerminalText(input)
	for _, unsafe := range []string{"\n", "\u009b", "\u061c", "\u200e", "\u202e", "\u2066"} {
		if strings.Contains(output, unsafe) {
			t.Fatalf("terminal text retained unsafe character %q", unsafe)
		}
	}

	var doctorOutput bytes.Buffer
	report := doctorReport{
		Healthy: true,
		Checks:  []doctorCheck{{Name: "repository", Status: "ok", Detail: input}},
	}
	if err := writeDoctorReport(&doctorOutput, "text", report); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"\u009b", "\u202e", "\u2066"} {
		if strings.Contains(doctorOutput.String(), unsafe) {
			t.Fatalf("doctor output retained unsafe character %q", unsafe)
		}
	}
}
