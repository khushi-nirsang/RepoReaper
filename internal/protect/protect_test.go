package protect

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/khushi/reporeaper/internal/detector"
)

func TestHookLifecycleAndConflictRefusal(t *testing.T) {
	repo := initRepo(t)
	ctx := context.Background()
	if err := Install(ctx, repo, false); err != nil {
		t.Fatal(err)
	}
	status, err := Status(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if status != "installed" {
		t.Fatalf("status = %q", status)
	}
	if err := Uninstall(ctx, repo); err != nil {
		t.Fatal(err)
	}
	path, err := HookPath(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	foreign := []byte("#!/bin/sh\necho existing\n")
	if err := os.WriteFile(path, foreign, 0700); err != nil {
		t.Fatal(err)
	}
	if err := Install(ctx, repo, true); err == nil {
		t.Fatal("--force overwrote or accepted a foreign hook")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(foreign) {
		t.Fatal("foreign hook content changed")
	}
}

func TestStatusReturnsRepositoryErrors(t *testing.T) {
	if _, err := Status(context.Background(), filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("status hid a repository error")
	}
}

func TestStagedReturnsOnlyRedactedEvidence(t *testing.T) {
	repo := initRepo(t)
	secret := "ghp_" + strings.Repeat("7Qm2Wv9Rk4Np8Xs3Ld6Tf1Hy5Jc0BaZe", 1)
	path := filepath.Join(repo, "config.env")
	if err := os.WriteFile(path, []byte("GITHUB_TOKEN="+secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "add", "config.env")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	findings, err := Staged(context.Background(), repo, detector.Registry(nil, nil), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("staged secret was not detected")
	}
	for _, finding := range findings {
		if finding.Fingerprint == "" || finding.ShortFingerprint == "" {
			t.Fatal("staged result omitted its allowlist fingerprints")
		}
		if strings.Contains(finding.Redacted, secret) {
			t.Fatal("staged result leaked the raw secret")
		}
		for _, evidence := range finding.Evidence {
			if evidence.Source != "index" || evidence.Path != "config.env" || evidence.Line != 1 {
				t.Fatalf("unexpected staged evidence: %+v", evidence)
			}
		}
	}
}

func TestStagedFinalScrubCoversCapturesFromOtherBlobs(t *testing.T) {
	repo := initRepo(t)
	firstSecret := "ghp_" + strings.Repeat("Aud1tCrossBlobToken7Qm2Wv9Rk4Np8Xs3", 1)
	secondSecret := "ghp_" + strings.Repeat("Aud1tSecondBlob9Rm3Xw0Sk5Pq8Yt4Me", 1)
	files := map[string]string{
		"first.env":          "GITHUB_TOKEN=" + firstSecret + "\n",
		firstSecret + ".env": "GITHUB_TOKEN=" + secondSecret + "\n",
	}
	for name, body := range files {
		path := filepath.Join(repo, name)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("git", "add", "--", name)
		command.Dir = repo
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git add %s: %v: %s", name, err, output)
		}
	}

	result, err := ScanStaged(context.Background(), repo, detector.Registry(nil, nil), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{firstSecret, secondSecret} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("staged result leaked a raw capture from another blob: %s", secret)
		}
	}
}

func TestStagedScansArchivesAndBase64WithProvenance(t *testing.T) {
	repo := initRepo(t)
	secret := "ghp_" + strings.Repeat("8Rm3Xw0Sk5Pq9Yt4Me7Ug2Iz6Kd1CbAf", 1)
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	member, err := writer.Create("nested/config.env")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write([]byte("GITHUB_TOKEN=" + secret + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"bundle.zip": archive.Bytes(),
		"encoded.txt": []byte("payload=" + base64.StdEncoding.EncodeToString(
			[]byte("GITHUB_TOKEN="+secret+"\n"),
		) + "\n"),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(repo, name), body, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("git", "add", "--", name)
		command.Dir = repo
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git add %s: %v: %s", name, err, output)
		}
	}

	findings, err := Staged(context.Background(), repo, detector.Registry(nil, nil), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	var archiveFound, encodedFound bool
	for _, finding := range findings {
		if finding.DetectorID != "github-token" {
			continue
		}
		if strings.Contains(finding.Redacted, secret) {
			t.Fatal("staged embedded finding leaked the raw secret")
		}
		for _, evidence := range finding.Evidence {
			switch {
			case evidence.Path == "bundle.zip!nested/config.env" && evidence.Decoder == "zip":
				archiveFound = true
			case evidence.Path == "encoded.txt" && evidence.Decoder == "base64" && evidence.Line == 1:
				encodedFound = true
			}
		}
	}
	if !archiveFound || !encodedFound {
		t.Fatalf("embedded findings missing: archive=%v base64=%v findings=%+v", archiveFound, encodedFound, findings)
	}
}

func TestStagedScansUTF16TextWithProvenance(t *testing.T) {
	repo := initRepo(t)
	secret := "ghp_" + strings.Repeat("Utf16StagedFake7Qm2Wv9Rk4Np8Xs3Ld6Tf", 1)
	text := utf16.Encode([]rune("GITHUB_TOKEN=" + secret + "\n"))
	body := []byte{0xff, 0xfe}
	for _, value := range text {
		var encoded [2]byte
		binary.LittleEndian.PutUint16(encoded[:], value)
		body = append(body, encoded[:]...)
	}
	if err := os.WriteFile(filepath.Join(repo, "windows.env"), body, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("git", "add", "windows.env")
	command.Dir = repo
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git add UTF-16 fixture: %v: %s", err, output)
	}
	result, err := ScanStaged(context.Background(), repo, detector.Registry(nil, nil), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range result.Findings {
		if finding.DetectorID != "github-token" {
			continue
		}
		for _, evidence := range finding.Evidence {
			if evidence.Decoder == "utf-16le" && evidence.Path == "windows.env" {
				return
			}
		}
	}
	t.Fatalf("UTF-16 staged finding missing: findings=%+v warnings=%v", result.Findings, result.Warnings)
}

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".git", "hooks"), 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
