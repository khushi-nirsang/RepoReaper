package gitrepo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeRemoteURLRemovesCredentialsAndQuery(t *testing.T) {
	raw := "https://user:V7r9Q2m4L8x6N3p5@example.invalid/repo.git?access_token=Ab3dE5fG7hJ9"
	got := sanitizeRemoteURL(raw)
	for _, sensitive := range []string{"V7r9Q2m4L8x6N3p5", "Ab3dE5fG7hJ9", "user"} {
		if strings.Contains(got, sensitive) {
			t.Fatalf("sanitized URL leaked %q: %s", sensitive, got)
		}
	}
	if !strings.Contains(got, "example.invalid/repo.git") {
		t.Fatalf("sanitized URL lost repository identity: %s", got)
	}
}

func TestSafeJoinRejectsRepositoryEscape(t *testing.T) {
	root := t.TempDir()
	if _, err := safeJoin(root, filepath.Join("..", "outside")); err == nil {
		t.Fatal("path escape was accepted")
	}
	if _, err := safeJoin(root, filepath.Join("nested", "file")); err != nil {
		t.Fatalf("safe nested path rejected: %v", err)
	}
}

func TestGitObjectAndHookInputsRejectOptionOrPathInjection(t *testing.T) {
	repo := &Repo{Path: t.TempDir()}
	ctx := context.Background()
	if _, err := repo.CatBlob(ctx, "--help"); err == nil {
		t.Fatal("option-like blob object ID was accepted")
	}
	if _, err := repo.BlobsAtCommit(ctx, "HEAD^{tree}"); err == nil {
		t.Fatal("revision expression was accepted as a commit object ID")
	}
	if _, err := repo.CommitInfo(ctx, "--all"); err == nil {
		t.Fatal("option-like commit object ID was accepted")
	}
	if _, err := repo.HookPath(ctx, "../pre-commit"); err == nil {
		t.Fatal("hook path traversal was accepted")
	}
}

func TestFileBytesReadsRegularFilesAndEnforcesLimit(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fixture.txt")
	if err := os.WriteFile(path, []byte("safe synthetic fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	repo := &Repo{Path: root}
	content, err := repo.FileBytes("fixture.txt", 1024)
	if err != nil {
		t.Fatalf("read regular fixture: %v", err)
	}
	if string(content) != "safe synthetic fixture" {
		t.Fatalf("content = %q", content)
	}
	if _, err := repo.FileBytes("fixture.txt", 4); !errors.Is(err, ErrWorktreeFileTooLarge) {
		t.Fatalf("oversized read error = %v", err)
	}
}

func TestFileBytesRejectsSymlinkComponents(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "fixture.txt"), []byte("synthetic fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	repo := &Repo{Path: root}
	if _, err := repo.FileBytes(filepath.Join("link", "fixture.txt"), 1024); !errors.Is(err, ErrWorktreeSymlink) {
		t.Fatalf("symlinked path error = %v", err)
	}
}

func TestWorktreeFilesClassifiesTrackedAndUntracked(t *testing.T) {
	root := t.TempDir()
	runBatchGit(t, root, nil, "init")
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("tracked fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	runBatchGit(t, root, nil, "add", "tracked.txt")
	if err := os.WriteFile(filepath.Join(root, "untracked.txt"), []byte("untracked fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	repo, err := Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := repo.WorktreeFiles(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, file := range files {
		got[filepath.ToSlash(file.Path)] = file.Untracked
	}
	if got["tracked.txt"] || !got["untracked.txt"] {
		t.Fatalf("worktree classification = %#v", got)
	}
}

func TestIndexBlobsReturnsTheExactStagedObject(t *testing.T) {
	root := t.TempDir()
	runBatchGit(t, root, nil, "init")
	if err := os.WriteFile(filepath.Join(root, "config.env"), []byte("safe fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runBatchGit(t, root, nil, "add", "config.env")

	blobContent := []byte("GITHUB_TOKEN=ghp_" + strings.Repeat("I7nD3xOnlyFakeQm2Wv9Rk4Np8Xs3Ld6Tf", 1) + "\n")
	oid := writeBatchBlob(t, root, blobContent)
	runBatchGit(t, root, nil, "update-index", "--cacheinfo", "100644,"+oid+",config.env")

	repo, err := Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := repo.IndexBlobs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 1 {
		t.Fatalf("index blobs = %#v", blobs)
	}
	got := blobs[0]
	if got.OID != oid || filepath.ToSlash(got.Path) != "config.env" || got.Mode != "100644" || got.Stage != 0 {
		t.Fatalf("index blob = %#v, want oid=%s path=config.env mode=100644 stage=0", got, oid)
	}
}

func TestIndexBlobsReturnsEveryUnmergedStage(t *testing.T) {
	root := t.TempDir()
	runBatchGit(t, root, nil, "init")
	oids := []string{
		writeBatchBlob(t, root, []byte("safe base fixture\n")),
		writeBatchBlob(t, root, []byte("safe ours fixture\n")),
		writeBatchBlob(t, root, []byte("safe theirs fixture\n")),
	}
	var indexInfo strings.Builder
	for index, oid := range oids {
		fmt.Fprintf(&indexInfo, "100644 %s %d\tconfig.env\n", oid, index+1)
	}
	runBatchGit(t, root, []byte(indexInfo.String()), "update-index", "--index-info")

	repo, err := Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := repo.IndexBlobs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 3 {
		t.Fatalf("unmerged index blobs = %#v", blobs)
	}
	for index, blob := range blobs {
		if blob.Stage != index+1 || blob.OID != oids[index] || filepath.ToSlash(blob.Path) != "config.env" {
			t.Fatalf("unmerged index blob %d = %#v", index, blob)
		}
	}
}

func TestGitEnumerationDoesNotSwallowCancellation(t *testing.T) {
	root := t.TempDir()
	runBatchGit(t, root, nil, "init")
	repo, err := Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checks := []struct {
		name string
		run  func() error
	}{
		{"head", func() error { _, err := repo.Head(ctx); return err }},
		{"branch", func() error { _, err := repo.Branch(ctx); return err }},
		{"shallow", func() error { _, err := repo.IsShallow(ctx); return err }},
		{"remotes", func() error { _, err := repo.Remotes(ctx); return err }},
		{"refs", func() error { _, err := repo.Refs(ctx, true, true, true); return err }},
		{"worktree", func() error { _, err := repo.WorktreeFiles(ctx, true); return err }},
		{"index", func() error { _, err := repo.IndexBlobs(ctx); return err }},
		{"reflogs", func() error { _, err := repo.ReflogCommits(ctx); return err }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); err == nil {
				t.Fatal("canceled Git operation unexpectedly succeeded")
			}
		})
	}
}

func TestOpenUnbornBareRepository(t *testing.T) {
	parent := t.TempDir()
	barePath := filepath.Join(parent, "fixture.git")
	runBatchGit(t, parent, nil, "init", "--bare", barePath)

	repo, err := Open(context.Background(), barePath)
	if err != nil {
		t.Fatalf("open bare repository: %v", err)
	}
	wantPath, err := filepath.Abs(barePath)
	if err != nil {
		t.Fatal(err)
	}
	wantPath = filepath.Clean(wantPath)
	if !repo.Bare || repo.Path != wantPath || repo.GitDir(context.Background()) != wantPath {
		t.Fatalf("bare repository metadata = %#v, git dir %q, want path %q", repo, repo.GitDir(context.Background()), wantPath)
	}
	if head, err := repo.Head(context.Background()); err != nil || head != "" {
		t.Fatalf("unborn bare HEAD = %q, want empty", head)
	}
	commits, err := repo.Commits(context.Background(), nil, "", "")
	if err != nil {
		t.Fatalf("enumerate unborn bare repository: %v", err)
	}
	if len(commits) != 0 {
		t.Fatalf("unborn bare repository has %d commits", len(commits))
	}
	if files, err := repo.WorktreeFiles(context.Background(), true); err != nil || len(files) != 0 {
		t.Fatalf("bare repository exposed worktree files: %v", files)
	}
	if _, err := repo.FileBytes("config.env", 1024); err == nil {
		t.Fatal("bare repository filesystem read unexpectedly succeeded")
	}
}
