package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/khushi/reporeaper/internal/detector"
	"github.com/khushi/reporeaper/internal/model"
	"github.com/khushi/reporeaper/internal/verify"
)

var testToken = "ghp_" + strings.Repeat("A1b2C3d4E5f6G7h8I9j0K1l2M3n4", 2)
var unreachableSecret = "sk_test_" + strings.Repeat("aB3dE5fG7hJ9kL2mN4pQ6rS8t", 2)

func TestAcceptanceHistoryTimelineAndVerify(t *testing.T) {
	repo := makeRepo(t)
	write(t, repo, "config.env", "GITHUB_TOKEN="+testToken+"\n")
	git(t, repo, "add", ".")
	c1 := commit(t, repo, "add token")
	write(t, repo, "note.txt", "hello\n")
	git(t, repo, "add", ".")
	commit(t, repo, "unrelated")
	write(t, repo, "config.env", "# removed\n")
	git(t, repo, "add", ".")
	c3 := commit(t, repo, "remove token")
	write(t, repo, "config.env", "GITHUB_TOKEN=${GITHUB_TOKEN}\n")
	git(t, repo, "add", ".")
	commit(t, repo, "env reference")
	git(t, repo, "tag", "contains-token", c1)
	git(t, repo, "branch", "token-branch", c1)
	git(t, repo, "update-ref", "refs/remotes/origin/token-branch", c1)
	tmp := filepath.Join(repo, "unreachable.txt")
	write(t, repo, "unreachable.txt", "STRIPE="+unreachableSecret+"\n")
	blob := git(t, repo, "hash-object", "-w", tmp)
	if strings.TrimSpace(blob) == "" {
		t.Fatal("no unreachable blob")
	}
	os.Remove(tmp)

	r, err := Scan(context.Background(), repo, Options{Version: "test", Detectors: detector.Registry(nil, nil), Config: model.ScanConfig{Branches: true, Tags: true, AllRefs: true, Workers: 2, MaxFileSize: 1024 * 1024}})
	if err != nil {
		t.Fatal(err)
	}
	var gh model.Finding
	for _, f := range r.Findings {
		if f.DetectorID == "github-token" {
			gh = f
		}
		if f.DetectorID == "stripe-key" {
			t.Fatal("unreachable secret appeared without --unreachable")
		}
	}
	if gh.ID == "" {
		t.Fatal("github token not found")
	}
	if gh.CurrentStatus != "history-only" {
		t.Fatalf("status = %s", gh.CurrentStatus)
	}
	if gh.Introduced == nil || gh.Introduced.Commit != c1 {
		t.Fatalf("introduced = %+v want %s", gh.Introduced, c1)
	}
	if gh.Removed == nil || gh.Removed.Commit != c3 {
		t.Fatalf("removed = %+v want %s", gh.Removed, c3)
	}
	if !has(gh.Tags, "contains-token") || !hasRef(gh.Branches, "token-branch") {
		t.Fatalf("missing refs branches=%v tags=%v", gh.Branches, gh.Tags)
	}
	if gh.RemoteStatus != "confirmed-from-local-refs" {
		t.Fatalf("remote = %s", gh.RemoteStatus)
	}
	b, _ := json.Marshal(r)
	if bytes.Contains(b, []byte(testToken)) {
		t.Fatal("raw token leaked into JSON")
	}

	r2, err := Scan(context.Background(), repo, Options{Version: "test", Detectors: detector.Registry(nil, nil), Config: model.ScanConfig{Branches: true, Tags: true, AllRefs: true, Unreachable: true, Workers: 2, MaxFileSize: 1024 * 1024}})
	if err != nil {
		t.Fatal(err)
	}
	if !containsDetector(r2, "stripe-key") {
		t.Fatal("unreachable secret missing with --unreachable")
	}

	clean := makeRepo(t)
	write(t, clean, "config.env", "GITHUB_TOKEN=${GITHUB_TOKEN}\n")
	git(t, clean, "add", ".")
	commit(t, clean, "clean")
	cleanReport, err := Scan(context.Background(), clean, Options{Version: "test", Detectors: detector.Registry(nil, nil), Config: model.ScanConfig{Branches: true, Tags: true, AllRefs: true, Unreachable: true, Workers: 2, MaxFileSize: 1024 * 1024}})
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "baseline.json")
	data, _ := json.Marshal(r)
	os.WriteFile(base, data, 0600)
	res, code, err := verify.Compare(base, cleanReport)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || !res.Passed || len(res.Items) == 0 || res.Items[0].Status != "not-observed" {
		t.Fatalf("verify = code %d %+v", code, res)
	}
}

func TestRenameReintroductionAndBlobDeduplication(t *testing.T) {
	repo := makeRepo(t)
	write(t, repo, "old.env", "GITHUB_TOKEN="+testToken+"\n")
	git(t, repo, "add", ".")
	commit(t, repo, "introduce")
	if err := os.Rename(filepath.Join(repo, "old.env"), filepath.Join(repo, "renamed.env")); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", "-A")
	commit(t, repo, "rename")
	write(t, repo, "renamed.env", "GITHUB_TOKEN=${GITHUB_TOKEN}\n")
	git(t, repo, "add", ".")
	commit(t, repo, "remove")
	write(t, repo, "second.env", "GITHUB_TOKEN="+testToken+"\n")
	git(t, repo, "add", ".")
	commit(t, repo, "reintroduce")
	write(t, repo, "second.env", "GITHUB_TOKEN=${GITHUB_TOKEN}\n")
	git(t, repo, "add", ".")
	commit(t, repo, "remove again")

	report, err := Scan(context.Background(), repo, Options{Version: "test", Detectors: detector.Registry(nil, nil), Config: model.ScanConfig{Branches: true, Tags: true, Workers: 3, MaxFileSize: 1024 * 1024}})
	if err != nil {
		t.Fatal(err)
	}
	var finding model.Finding
	for _, candidate := range report.Findings {
		if candidate.DetectorID == "github-token" {
			finding = candidate
			break
		}
	}
	if finding.ID == "" {
		t.Fatal("renamed and reintroduced finding missing")
	}
	if len(finding.ExposureIntervals) != 2 {
		t.Fatalf("intervals = %#v", finding.ExposureIntervals)
	}
	for _, want := range []string{"old.env", "renamed.env", "second.env"} {
		if !has(finding.Paths, want) {
			t.Fatalf("path %s missing from %v", want, finding.Paths)
		}
	}
	if report.Stats.BlobsDeduplicated == 0 {
		t.Fatal("duplicate blobs were not accounted for")
	}
}

func TestReflogAndUnreachableCommitCoverage(t *testing.T) {
	repo := makeRepo(t)
	write(t, repo, "config.env", "GITHUB_TOKEN=${GITHUB_TOKEN}\n")
	git(t, repo, "add", ".")
	clean := commit(t, repo, "clean")
	write(t, repo, "config.env", "GITHUB_TOKEN="+testToken+"\n")
	git(t, repo, "add", ".")
	commit(t, repo, "secret")
	git(t, repo, "reset", "--hard", clean)

	baseOptions := Options{Version: "test", Detectors: detector.Registry(nil, nil), Config: model.ScanConfig{Branches: true, Tags: true, Workers: 2, MaxFileSize: 1024 * 1024}}
	without, err := Scan(context.Background(), repo, baseOptions)
	if err != nil {
		t.Fatal(err)
	}
	if containsDetector(without, "github-token") {
		t.Fatal("reflog-only finding appeared without explicit residual scanning")
	}
	baseOptions.Config.Reflogs = true
	withReflog, err := Scan(context.Background(), repo, baseOptions)
	if err != nil {
		t.Fatal(err)
	}
	reflogFinding := detectorFinding(withReflog, "github-token")
	if !reflogFinding.InReflog || reflogFinding.CurrentStatus != "reflog-only" {
		t.Fatalf("reflog finding = %#v", reflogFinding)
	}
	baseOptions.Config.Reflogs = false
	baseOptions.Config.Unreachable = true
	withUnreachable, err := Scan(context.Background(), repo, baseOptions)
	if err != nil {
		t.Fatal(err)
	}
	unreachableFinding := detectorFinding(withUnreachable, "github-token")
	if !unreachableFinding.InUnreachable || unreachableFinding.CurrentStatus != "unreachable-only" {
		t.Fatalf("unreachable finding = %#v", unreachableFinding)
	}
}

func TestMergeHistoryLowersTimelineConfidence(t *testing.T) {
	repo := makeRepo(t)
	write(t, repo, "config.env", "GITHUB_TOKEN=${GITHUB_TOKEN}\n")
	git(t, repo, "add", ".")
	commit(t, repo, "root")
	mainBranch := strings.TrimSpace(git(t, repo, "branch", "--show-current"))
	git(t, repo, "checkout", "-b", "secret-side")
	write(t, repo, "config.env", "GITHUB_TOKEN="+testToken+"\n")
	git(t, repo, "add", ".")
	commit(t, repo, "side introduces secret")
	git(t, repo, "checkout", mainBranch)
	write(t, repo, "note.txt", "unrelated\n")
	git(t, repo, "add", ".")
	commit(t, repo, "main change")
	git(t, repo, "merge", "--no-ff", "secret-side", "-m", "merge side")
	write(t, repo, "config.env", "GITHUB_TOKEN=${GITHUB_TOKEN}\n")
	git(t, repo, "add", ".")
	commit(t, repo, "remove after merge")

	report, err := Scan(context.Background(), repo, Options{Version: "test", Detectors: detector.Registry(nil, nil), Config: model.ScanConfig{Branches: true, Tags: true, Workers: 2, MaxFileSize: 1024 * 1024}})
	if err != nil {
		t.Fatal(err)
	}
	finding := detectorFinding(report, "github-token")
	if finding.ID == "" {
		t.Fatal("merge finding missing")
	}
	if finding.Confidence != model.ConfidenceMedium || !strings.Contains(finding.ConfidenceReason, "merge") {
		t.Fatalf("confidence = %s reason = %s", finding.Confidence, finding.ConfidenceReason)
	}
}

func TestShallowRepositoryWarning(t *testing.T) {
	origin := makeRepo(t)
	write(t, origin, "first.txt", "first\n")
	git(t, origin, "add", ".")
	commit(t, origin, "first")
	write(t, origin, "second.txt", "second\n")
	git(t, origin, "add", ".")
	commit(t, origin, "second")

	fileURL := (&url.URL{Scheme: "file", Path: "/" + strings.TrimPrefix(filepath.ToSlash(origin), "/")}).String()
	parent := t.TempDir()
	clone := filepath.Join(parent, "shallow")
	git(t, parent, "clone", "--depth", "1", fileURL, clone)
	report, err := Scan(context.Background(), clone, Options{Version: "test", Detectors: detector.Registry(nil, nil), Config: model.ScanConfig{Branches: true, Tags: true, Workers: 1, MaxFileSize: 1024 * 1024}})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Repository.Shallow || len(report.Warnings) == 0 {
		t.Fatalf("shallow metadata missing: %#v", report.Repository)
	}
}

func TestArchiveAndBase64PayloadCoverage(t *testing.T) {
	repo := makeRepo(t)
	var archive bytes.Buffer
	zipWriter := zip.NewWriter(&archive)
	entry, err := zipWriter.Create("nested/config.env")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte("GITHUB_TOKEN=" + testToken + "\n"))
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	writeBytes(t, repo, "bundle.zip", archive.Bytes())
	encoded := base64.StdEncoding.EncodeToString([]byte("GITHUB_TOKEN=" + testToken))
	write(t, repo, "encoded.txt", "payload="+encoded+"\n")
	git(t, repo, "add", ".")
	commit(t, repo, "add encoded fixtures")

	result, err := Scan(context.Background(), repo, Options{
		Version: "test", Detectors: detector.Registry(nil, nil),
		Config: model.ScanConfig{Branches: true, Tags: true, Workers: 2, MaxFileSize: 1024 * 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	finding := detectorFinding(result, "github-token")
	if finding.ID == "" {
		t.Fatal("encoded GitHub token was not detected")
	}
	var archiveEvidence, base64Evidence bool
	for _, evidence := range finding.Evidence {
		if strings.Contains(evidence.Path, "bundle.zip!nested/config.env") && strings.Contains(evidence.Decoder, "zip") {
			archiveEvidence = true
		}
		if strings.Contains(evidence.Path, "encoded.txt") && strings.Contains(evidence.Decoder, "base64") {
			base64Evidence = true
		}
	}
	if !archiveEvidence || !base64Evidence {
		t.Fatalf("missing decoded provenance: %#v", finding.Evidence)
	}
	if result.Stats.ArchivesOpened == 0 || result.Stats.EncodedPayloads == 0 || result.Stats.PayloadsScanned == 0 {
		t.Fatalf("decoded-content stats missing: %#v", result.Stats)
	}
	encodedReport, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encodedReport, []byte(testToken)) {
		t.Fatal("raw decoded token leaked into report")
	}
}

func TestExposureDurationUsesUnionOfConcurrentIntervals(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	intervals := []model.ExposureInterval{
		{StartedAt: base, EndedAt: base.Add(2 * time.Hour)},
		{StartedAt: base.Add(time.Hour), EndedAt: base.Add(3 * time.Hour)},
	}
	if got := exposureDuration(intervals, nil, nil); got != int64((3*time.Hour)/time.Second) {
		t.Fatalf("duration = %d", got)
	}
}

func TestUnbornRepositoryReturnsEmptyReport(t *testing.T) {
	repo := makeRepo(t)
	report, err := Scan(context.Background(), repo, Options{
		Version:   "test",
		Detectors: detector.Registry(nil, nil),
		Config:    model.ScanConfig{Branches: true, Tags: true, Workers: 1, MaxFileSize: 1024 * 1024},
	})
	if err != nil {
		t.Fatalf("scan unborn repository: %v", err)
	}
	if report.Repository.Head != "" {
		t.Fatalf("HEAD = %q, want empty", report.Repository.Head)
	}
	if report.Stats.CommitsAnalyzed != 0 || len(report.Findings) != 0 {
		t.Fatalf("unborn report contains history: commits=%d findings=%d", report.Stats.CommitsAnalyzed, len(report.Findings))
	}
	if report.Findings == nil {
		t.Fatal("empty report findings must serialize as an array, not null")
	}
}

func TestDetachedHEADIsAlwaysIncludedInHistoryScope(t *testing.T) {
	repo := makeRepo(t)
	write(t, repo, "config.env", "GITHUB_TOKEN=${GITHUB_TOKEN}\n")
	git(t, repo, "add", ".")
	commit(t, repo, "safe branch tip")
	git(t, repo, "checkout", "--detach")
	write(t, repo, "config.env", "GITHUB_TOKEN="+testToken+"\n")
	git(t, repo, "add", ".")
	detachedCommit := commit(t, repo, "synthetic detached exposure")

	report, err := Scan(context.Background(), repo, Options{
		Version:   "test",
		Detectors: detector.Registry(nil, nil),
		Config:    model.ScanConfig{Branches: true, Tags: true, Workers: 1, MaxFileSize: 1024 * 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	finding := detectorFinding(report, "github-token")
	if finding.ID == "" || !finding.InHead || finding.CurrentStatus != "present-in-head" {
		t.Fatalf("detached HEAD finding scope = %#v", finding)
	}
	foundCommit := false
	for _, evidence := range finding.Evidence {
		if evidence.Commit == detachedCommit {
			foundCommit = true
			break
		}
	}
	if !foundCommit {
		t.Fatalf("detached HEAD commit %s missing from evidence", detachedCommit)
	}
}

func TestIndexOnlyBlobIsScannedAsCurrentWithoutReadingWorktreeContent(t *testing.T) {
	repo := makeRepo(t)
	write(t, repo, "config.env", "GITHUB_TOKEN=${GITHUB_TOKEN}\n")
	git(t, repo, "add", "config.env")
	commit(t, repo, "safe fixture")

	secret := "ghp_" + strings.Repeat("IndexOnlyFake7Qm2Wv9Rk4Np8Xs3Ld6Tf", 1)
	hashObject := exec.Command("git", "hash-object", "-w", "--stdin")
	hashObject.Dir = repo
	hashObject.Stdin = strings.NewReader("GITHUB_TOKEN=" + secret + "\n")
	output, err := hashObject.Output()
	if err != nil {
		t.Fatalf("write synthetic index blob: %v", err)
	}
	oid := strings.TrimSpace(string(output))
	git(t, repo, "update-index", "--cacheinfo", "100644,"+oid+",config.env")

	report, err := Scan(context.Background(), repo, Options{
		Version:   "test",
		Detectors: detector.Registry(nil, nil),
		Config:    model.ScanConfig{Branches: true, Tags: true, Workers: 1, MaxFileSize: 1024 * 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Repository.IndexOK {
		t.Fatalf("index coverage unexpectedly incomplete: %v", report.Warnings)
	}
	finding := detectorFinding(report, "github-token")
	if finding.ID == "" {
		t.Fatal("fake token present only in the Git index was not found")
	}
	if !finding.InIndex || finding.InHead || finding.InWorkingTree || finding.CurrentStatus != "present-in-index" {
		t.Fatalf("index-only finding scope = %#v", finding)
	}
	foundIndexEvidence := false
	for _, evidence := range finding.Evidence {
		if evidence.Source == "index" && evidence.Blob == oid && evidence.Path == "config.env" {
			foundIndexEvidence = true
		}
	}
	if !foundIndexEvidence {
		t.Fatalf("index evidence missing from %#v", finding.Evidence)
	}
	if report.Summary.CurrentSecrets != 1 || report.Summary.HistoricalSecrets != 0 {
		t.Fatalf("index-only summary = %#v", report.Summary)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(secret)) {
		t.Fatal("raw fake index token leaked into the report")
	}
}

func TestDirectBlobRefIsScannedEvenThoughItIsNotCommitHistory(t *testing.T) {
	repo := makeRepo(t)
	write(t, repo, "safe.env", "ordinary fixture\n")
	git(t, repo, "add", "safe.env")
	commit(t, repo, "safe fixture")
	secret := "ghp_" + strings.Repeat("DirectRefFake7Qm2Wv9Rk4Np8Xs3Ld6Tf", 1)
	hashObject := exec.Command("git", "hash-object", "-w", "--stdin")
	hashObject.Dir = repo
	hashObject.Stdin = strings.NewReader("GITHUB_TOKEN=" + secret + "\n")
	output, err := hashObject.Output()
	if err != nil {
		t.Fatal(err)
	}
	oid := strings.TrimSpace(string(output))
	git(t, repo, "update-ref", "refs/objects/direct-fixture", oid)

	report, err := Scan(context.Background(), repo, Options{
		Version:   "test",
		Detectors: detector.Registry(nil, nil),
		Config:    model.ScanConfig{AllRefs: true, Workers: 1, MaxFileSize: 1024 * 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	finding := detectorFinding(report, "github-token")
	if finding.ID == "" || !finding.InDirectRef || finding.InHead || finding.CurrentStatus != "present-in-ref-object" {
		t.Fatalf("direct-ref finding scope = %#v", finding)
	}
	found := false
	for _, evidence := range finding.Evidence {
		if evidence.Source == "ref-object" && evidence.Ref == "refs/objects/direct-fixture" && evidence.Blob == oid {
			found = true
		}
	}
	if !found {
		t.Fatalf("direct-ref evidence missing: %#v", finding.Evidence)
	}
}

func TestDateFiltersNeverExcludeTheCurrentHeadSnapshot(t *testing.T) {
	repo := makeRepo(t)
	write(t, repo, "config.env", "GITHUB_TOKEN="+testToken+"\n")
	git(t, repo, "add", "config.env")
	commit(t, repo, "current fake token")
	report, err := Scan(context.Background(), repo, Options{
		Version:   "test",
		Detectors: detector.Registry(nil, nil),
		Config:    model.ScanConfig{Since: "2099-01-01", Workers: 1, MaxFileSize: 1024 * 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	finding := detectorFinding(report, "github-token")
	if finding.ID == "" || !finding.InHead || finding.CurrentStatus != "present-in-head" {
		t.Fatalf("date-filtered HEAD finding = %#v", finding)
	}
}

func TestBareRepositoryScansHistoryWithoutWorktree(t *testing.T) {
	source := makeRepo(t)
	write(t, source, "config.env", "GITHUB_TOKEN="+testToken+"\n")
	git(t, source, "add", ".")
	commit(t, source, "add fake token")

	parent := t.TempDir()
	barePath := filepath.Join(parent, "fixture.git")
	git(t, parent, "clone", "--bare", source, barePath)
	report, err := Scan(context.Background(), barePath, Options{
		Version:   "test",
		Detectors: detector.Registry(nil, nil),
		Config:    model.ScanConfig{IncludeUntracked: true, Branches: true, Tags: true, Workers: 1, MaxFileSize: 1024 * 1024},
	})
	if err != nil {
		t.Fatalf("scan bare repository: %v", err)
	}
	if !report.Repository.Bare || report.Repository.WorktreeOK {
		t.Fatalf("bare repository capabilities = %#v", report.Repository)
	}
	finding := detectorFinding(report, "github-token")
	if finding.ID == "" {
		t.Fatal("fake token in bare repository history was not found")
	}
	if !finding.InHead || finding.InWorkingTree || finding.InTrackedWorkingTree || finding.InUntracked {
		t.Fatalf("bare finding scope = %#v", finding)
	}
	for _, evidence := range finding.Evidence {
		if evidence.Source == "working-tree" {
			t.Fatalf("bare finding contains working-tree evidence: %#v", evidence)
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(testToken)) {
		t.Fatal("raw fake token leaked into bare repository report")
	}
}

func TestOversizedInputsAreReportedAsCoverageGaps(t *testing.T) {
	repo := makeRepo(t)
	write(t, repo, "large.txt", strings.Repeat("A", 128))
	git(t, repo, "add", ".")
	commit(t, repo, "add oversized fixture")

	report, err := Scan(context.Background(), repo, Options{
		Version:   "test",
		Detectors: detector.Registry(nil, nil),
		Config:    model.ScanConfig{Branches: true, Tags: true, Workers: 1, MaxFileSize: 32},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.ObjectsSkipped < 2 {
		t.Fatalf("objects skipped = %d, want working tree and Git object", report.Stats.ObjectsSkipped)
	}
	for _, fragment := range []string{"working-tree files exceeded", "Git objects exceeded"} {
		if !warningContains(report.Warnings, fragment) {
			t.Fatalf("coverage warning %q missing from %v", fragment, report.Warnings)
		}
	}
}

func TestUnbornBareRepositoryReturnsEmptyReport(t *testing.T) {
	parent := t.TempDir()
	barePath := filepath.Join(parent, "empty.git")
	git(t, parent, "init", "--bare", barePath)
	report, err := Scan(context.Background(), barePath, Options{
		Version:   "test",
		Detectors: detector.Registry(nil, nil),
		Config:    model.ScanConfig{Branches: true, Tags: true, Workers: 1, MaxFileSize: 1024 * 1024},
	})
	if err != nil {
		t.Fatalf("scan unborn bare repository: %v", err)
	}
	if !report.Repository.Bare || report.Repository.WorktreeOK || report.Repository.Head != "" {
		t.Fatalf("unborn bare repository metadata = %#v", report.Repository)
	}
	if report.Stats.CommitsAnalyzed != 0 || len(report.Findings) != 0 {
		t.Fatalf("unborn bare report contains history: commits=%d findings=%d", report.Stats.CommitsAnalyzed, len(report.Findings))
	}
	if report.Findings == nil {
		t.Fatal("empty bare report findings must serialize as an array, not null")
	}
}

func makeRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init")
	git(t, dir, "config", "user.name", "RepoReaper Test")
	git(t, dir, "config", "user.email", "test@example.invalid")
	return dir
}
func write(t *testing.T, repo, name, body string) {
	t.Helper()
	writeBytes(t, repo, name, []byte(body))
}
func writeBytes(t *testing.T, repo, name string, body []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, filepath.FromSlash(name)), body, 0600); err != nil {
		t.Fatal(err)
	}
}
func commit(t *testing.T, repo, msg string) string {
	t.Helper()
	git(t, repo, "commit", "-m", msg)
	return strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))
}
func git(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	if runtime.GOOS != "windows" {
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE=2025-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2025-01-01T00:00:00Z")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}
func has(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
func hasRef(xs []string, want string) bool {
	for _, x := range xs {
		if strings.Contains(x, want) {
			return true
		}
	}
	return false
}
func containsDetector(r model.Report, id string) bool {
	for _, f := range r.Findings {
		if f.DetectorID == id {
			return true
		}
	}
	return false
}

func detectorFinding(r model.Report, id string) model.Finding {
	for _, finding := range r.Findings {
		if finding.DetectorID == id {
			return finding
		}
	}
	return model.Finding{}
}

func warningContains(warnings []string, fragment string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, fragment) {
			return true
		}
	}
	return false
}
