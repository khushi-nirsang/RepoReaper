package gitrepo

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestBatchBlobReaderReadsSequentialObjects(t *testing.T) {
	repo := initBatchRepo(t)
	first := []byte("ordinary fixture content\n")
	second := []byte("another synthetic fixture\n")
	firstOID := writeBatchBlob(t, repo, first)
	secondOID := writeBatchBlob(t, repo, second)

	reader, err := (&Repo{Path: repo}).NewBatchBlobReader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for _, item := range []struct {
		oid  string
		want []byte
	}{{firstOID, first}, {secondOID, second}, {firstOID, first}} {
		got, err := reader.ReadBlob(item.oid, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, item.want) {
			t.Fatalf("blob %s content mismatch", item.oid)
		}
	}
}

func TestBatchBlobReaderStaysAlignedAfterOversizedObject(t *testing.T) {
	repo := initBatchRepo(t)
	largeOID := writeBatchBlob(t, repo, bytes.Repeat([]byte("x"), 4096))
	small := []byte("small fixture")
	smallOID := writeBatchBlob(t, repo, small)

	reader, err := (&Repo{Path: repo}).NewBatchBlobReader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.ReadBlob(largeOID, 128); !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("oversized read error = %v", err)
	}
	got, err := reader.ReadBlob(smallOID, 128)
	if err != nil {
		t.Fatalf("reader lost protocol alignment: %v", err)
	}
	if !bytes.Equal(got, small) {
		t.Fatal("small blob content mismatch")
	}
}

func TestBatchBlobReaderRejectsMissingAndInjectedObjectIDs(t *testing.T) {
	repo := initBatchRepo(t)
	reader, err := (&Repo{Path: repo}).NewBatchBlobReader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.ReadBlob(strings.Repeat("0", 40), 128); !errors.Is(err, ErrObjectMissing) {
		t.Fatalf("missing object error = %v", err)
	}
	if _, err := reader.ReadBlob(strings.Repeat("a", 40)+"\nHEAD", 128); err == nil {
		t.Fatal("protocol injection object ID was accepted")
	}
}

func TestTreeWalkerEnumeratesAndCachesSharedTrees(t *testing.T) {
	repo, commit := committedBatchRepo(t)
	walker, err := repo.NewTreeWalker(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer walker.Close()
	blobs, err := walker.BlobsAtCommit(commit)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, blob := range blobs {
		paths = append(paths, blob.Path)
		if blob.Size != -1 {
			t.Fatalf("batch tree blob size = %d", blob.Size)
		}
	}
	sort.Strings(paths)
	if strings.Join(paths, ",") != "nested/one.txt,two.txt" {
		t.Fatalf("tree paths = %v", paths)
	}
	firstStats := walker.Stats()
	if firstStats.TreesRead < 2 {
		t.Fatalf("tree stats = %#v", firstStats)
	}
	if _, err := walker.BlobsAtCommit(commit); err != nil {
		t.Fatal(err)
	}
	secondStats := walker.Stats()
	if secondStats.TreesRead != firstStats.TreesRead || secondStats.CacheHits <= firstStats.CacheHits {
		t.Fatalf("tree cache was not reused: first=%#v second=%#v", firstStats, secondStats)
	}
}

func TestContainingRefsUsesOneCachedLookup(t *testing.T) {
	repo, commit := committedBatchRepo(t)
	runBatchGit(t, repo.Path, nil, "tag", "fixture-tag", commit.Hash)
	runBatchGit(t, repo.Path, nil, "branch", "fixture-branch", commit.Hash)
	runBatchGit(t, repo.Path, nil, "update-ref", "refs/remotes/origin/fixture", commit.Hash)
	branches, tags, err := repo.ContainingRefs(context.Background(), commit.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if !sliceContains(branches, "refs/heads/fixture-branch") || !sliceContains(branches, "refs/remotes/origin/fixture") || !sliceContains(tags, "fixture-tag") {
		t.Fatalf("branches=%v tags=%v", branches, tags)
	}
	if _, _, err := repo.ContainingRefs(context.Background(), commit.Hash); err != nil {
		t.Fatal(err)
	}
	repo.containmentMu.Lock()
	cacheSize := len(repo.containment)
	repo.containmentMu.Unlock()
	if cacheSize != 1 {
		t.Fatalf("containment cache size = %d", cacheSize)
	}
}

func BenchmarkBatchBlobReader(b *testing.B) {
	repo := initBatchRepo(b)
	oid := writeBatchBlob(b, repo, bytes.Repeat([]byte("benchmark fixture data\n"), 1024))
	reader, err := (&Repo{Path: repo}).NewBatchBlobReader(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = reader.Close() })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := reader.ReadBlob(oid, 1<<20); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOneProcessPerBlob(b *testing.B) {
	repo := initBatchRepo(b)
	oid := writeBatchBlob(b, repo, bytes.Repeat([]byte("benchmark fixture data\n"), 1024))
	gitRepo := &Repo{Path: repo}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := gitRepo.CatBlob(context.Background(), oid); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTreeWalker(b *testing.B) {
	repo, commit := committedBatchRepo(b)
	walker, err := repo.NewTreeWalker(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = walker.Close() })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := walker.BlobsAtCommit(commit); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLsTreeProcess(b *testing.B) {
	repo, commit := committedBatchRepo(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := repo.BlobsAtCommit(context.Background(), commit.Hash); err != nil {
			b.Fatal(err)
		}
	}
}

func initBatchRepo(tb testing.TB) string {
	tb.Helper()
	repo := tb.TempDir()
	runBatchGit(tb, repo, nil, "init", "-q")
	return repo
}

func committedBatchRepo(tb testing.TB) (*Repo, Commit) {
	tb.Helper()
	path := initBatchRepo(tb)
	runBatchGit(tb, path, nil, "config", "user.name", "RepoReaper Test")
	runBatchGit(tb, path, nil, "config", "user.email", "test@example.invalid")
	if err := os.MkdirAll(filepath.Join(path, "nested"), 0700); err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "nested", "one.txt"), []byte("one\n"), 0600); err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "two.txt"), []byte("two\n"), 0600); err != nil {
		tb.Fatal(err)
	}
	runBatchGit(tb, path, nil, "add", ".")
	runBatchGit(tb, path, nil, "commit", "-q", "-m", "fixture")
	repo := &Repo{Path: path}
	commits, err := repo.Commits(context.Background(), nil, "", "")
	if err != nil || len(commits) != 1 {
		tb.Fatalf("commits = %#v err=%v", commits, err)
	}
	return repo, commits[0]
}

func writeBatchBlob(tb testing.TB, repo string, content []byte) string {
	tb.Helper()
	return strings.TrimSpace(runBatchGit(tb, repo, content, "hash-object", "-w", "--stdin"))
}

func runBatchGit(tb testing.TB, repo string, stdin []byte, args ...string) string {
	tb.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		tb.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func sliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
