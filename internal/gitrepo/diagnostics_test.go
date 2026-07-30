package gitrepo

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestGitVersion(t *testing.T) {
	got, err := GitVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "git version ") {
		t.Fatalf("GitVersion() = %q", got)
	}
}

func TestRepositoryDiagnosticsForUnbornRepository(t *testing.T) {
	path := t.TempDir()
	command := exec.Command("git", "init", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, output)
	}
	repo, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo.Diagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.GitDir == "" {
		t.Fatal("Git directory is empty")
	}
	if got.Head != "" {
		t.Fatalf("unborn repository HEAD = %q", got.Head)
	}
	if got.Shallow {
		t.Fatal("new local repository reported as shallow")
	}
}
