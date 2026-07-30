package cmd

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/khushi/reporeaper/internal/config"
	"github.com/khushi/reporeaper/internal/model"
)

var (
	stagedGitHubFixture  = "ghp_" + strings.Repeat("Q7m2Wv9Rk4Np8Xs3Ld6Tf1Hy5Jc0BaZe", 1)
	stagedGenericFixture = strings.Repeat("Q7m2Wv9Rk4Np8Xs3Ld6Tf1Hy5Jc0BaZe", 1)
)

func TestStagedProtectionAppliesConfiguredAllowlists(t *testing.T) {
	repo := initProtectRepo(t)
	stageProtectFile(t, repo, "config.env", "GITHUB_TOKEN="+stagedGitHubFixture+"\napi_key="+stagedGenericFixture+"\n")
	ctx := context.Background()

	baseline := config.Default()
	findings, err := stagedFindings(ctx, repo, baseline)
	if err != nil {
		t.Fatal(err)
	}
	github := findingByDetector(findings, "github-token")
	if github == nil || github.Fingerprint == "" || github.ShortFingerprint == "" {
		t.Fatal("default staged protection did not return fingerprinted GitHub evidence")
	}

	t.Run("full fingerprint", func(t *testing.T) {
		cfg := baseline
		cfg.Allowlist.Fingerprints = []string{github.Fingerprint}
		assertNoDetector(t, stagedFindingsForTest(t, ctx, repo, cfg), "github-token")
	})

	t.Run("short fingerprint", func(t *testing.T) {
		cfg := baseline
		cfg.Allowlist.Fingerprints = []string{github.ShortFingerprint}
		assertNoDetector(t, stagedFindingsForTest(t, ctx, repo, cfg), "github-token")
	})

	t.Run("path", func(t *testing.T) {
		cfg := baseline
		cfg.Allowlist.Paths = []string{"**/*.env"}
		if got := stagedFindingsForTest(t, ctx, repo, cfg); len(got) != 0 {
			t.Fatalf("path allowlist left %d staged findings", len(got))
		}
	})

	t.Run("regex is selective", func(t *testing.T) {
		cfg := baseline
		cfg.Allowlist.Regexes = []string{`^github-token `}
		got := stagedFindingsForTest(t, ctx, repo, cfg)
		assertNoDetector(t, got, "github-token")
		if findingByDetector(got, "generic-api-key") == nil {
			t.Fatal("detector-specific regex unexpectedly suppressed unrelated staged evidence")
		}
	})

	t.Run("commit is not applicable", func(t *testing.T) {
		cfg := baseline
		cfg.Allowlist.Commits = []string{"not-a-staged-commit"}
		if findingByDetector(stagedFindingsForTest(t, ctx, repo, cfg), "github-token") == nil {
			t.Fatal("commit allowlist suppressed uncommitted index evidence")
		}
	})
}

func TestStagedProtectionHonorsDetectorConfiguration(t *testing.T) {
	repo := initProtectRepo(t)
	stageProtectFile(t, repo, "config.env", "GITHUB_TOKEN="+stagedGitHubFixture+"\napi_key="+stagedGenericFixture+"\n")
	ctx := context.Background()

	disabled := config.Default()
	disabled.Detectors.Disabled = []string{"github-token"}
	got := stagedFindingsForTest(t, ctx, repo, disabled)
	assertNoDetector(t, got, "github-token")
	if findingByDetector(got, "generic-api-key") == nil {
		t.Fatal("disabling one detector weakened unrelated default detection")
	}

	stageProtectFile(t, repo, "custom.txt", "WIDGET_7Qm2Wv9Rk4Np8Xs3Ld6Tf1Hy\n")
	custom := config.Default()
	custom.Detectors.Custom = []config.CustomDetector{{
		ID:          "widget-token",
		Name:        "Widget token",
		Description: "Synthetic token used to test configured staged detection.",
		Regex:       `\b(WIDGET_[A-Za-z0-9]{24})\b`,
		Severity:    string(model.SeverityHigh),
		Remediation: "Rotate the synthetic widget credential.",
		Keywords:    []string{"WIDGET_"},
	}}
	if findingByDetector(stagedFindingsForTest(t, ctx, repo, custom), "widget-token") == nil {
		t.Fatal("custom configured detector was not used for staged protection")
	}
}

func TestStagedProtectionOutputIsRedactedAndDefaultBlocks(t *testing.T) {
	repo := initProtectRepo(t)
	stageProtectFile(t, repo, "config.env", "GITHUB_TOKEN="+stagedGitHubFixture+"\n")
	var output bytes.Buffer
	if err := runStagedProtection(context.Background(), repo, config.Default(), &output); err == nil {
		t.Fatal("default protection did not block staged critical evidence")
	}
	if strings.Contains(output.String(), stagedGitHubFixture) {
		t.Fatal("staged protection output leaked a raw secret fixture")
	}

	allowed := config.Default()
	allowed.Allowlist.Paths = []string{"config.env"}
	output.Reset()
	if err := runStagedProtection(context.Background(), repo, allowed, &output); err != nil {
		t.Fatalf("allowlisted staged evidence was blocked: %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("allowlisted evidence was printed: %q", output.String())
	}
}

func TestStagedProtectionFailsClosedWhenContentExceedsLimit(t *testing.T) {
	repo := initProtectRepo(t)
	stageProtectFile(t, repo, "large.bin", strings.Repeat("A", 128))
	cfg := config.Default()
	cfg.Scan.MaxFileSize = 32
	var output bytes.Buffer
	err := runStagedProtection(context.Background(), repo, cfg, &output)
	if err == nil || !strings.Contains(err.Error(), "could not be completely inspected") {
		t.Fatalf("incomplete staged scan error = %v", err)
	}
	if !strings.Contains(output.String(), "configured size limit") {
		t.Fatalf("coverage warning not shown: %q", output.String())
	}
}

func initProtectRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	command := exec.Command("git", "init", "--quiet")
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	return dir
}

func stageProtectFile(t *testing.T, repo, name, content string) {
	t.Helper()
	path := filepath.Join(repo, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("git", "add", "--", name)
	command.Dir = repo
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, output)
	}
}

func stagedFindingsForTest(t *testing.T, ctx context.Context, repo string, cfg config.File) []model.Finding {
	t.Helper()
	findings, err := stagedFindings(ctx, repo, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func findingByDetector(findings []model.Finding, detectorID string) *model.Finding {
	for i := range findings {
		if findings[i].DetectorID == detectorID {
			return &findings[i]
		}
	}
	return nil
}

func assertNoDetector(t *testing.T, findings []model.Finding, detectorID string) {
	t.Helper()
	if findingByDetector(findings, detectorID) != nil {
		t.Fatalf("detector %s was not suppressed", detectorID)
	}
}
