package gitrepo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Repo struct {
	Path string
	Bare bool

	gitDir string

	containmentMu sync.Mutex
	containment   map[string]containmentResult
}

var (
	ErrWorktreeFileTooLarge = errors.New("working-tree file exceeds the configured size limit")
	ErrWorktreeSymlink      = errors.New("working-tree path is a symbolic link")
	ErrWorktreeNotRegular   = errors.New("working-tree path is not a regular file")
)

type containmentResult struct {
	branches []string
	tags     []string
}

var ErrNotRepository = errors.New("not a Git repository")

type Commit struct {
	Hash, AuthorName, AuthorEmail string
	Tree                          string
	Time                          time.Time
	Parents                       []string
}
type Ref struct {
	Name, Hash string
	Type       string
	Target     string
}
type Blob struct {
	Commit, OID, Path string
	Size              int64
	Mode              string
	Stage             int
}

type WorktreeFile struct {
	Path      string
	Untracked bool
}

func Open(ctx context.Context, path string) (*Repo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	topLevel, topLevelErr := run(ctx, abs, "rev-parse", "--show-toplevel")
	if topLevelErr == nil {
		root := filepath.Clean(strings.TrimSpace(topLevel))
		gitDir, err := absoluteGitDir(ctx, root)
		if err != nil {
			return nil, fmt.Errorf("resolve Git directory: %w", err)
		}
		return &Repo{Path: root, gitDir: gitDir}, nil
	}

	bare, bareErr := run(ctx, abs, "rev-parse", "--is-bare-repository")
	if bareErr != nil || strings.TrimSpace(bare) != "true" {
		return nil, fmt.Errorf("%w: %v", ErrNotRepository, topLevelErr)
	}
	gitDir, err := absoluteGitDir(ctx, abs)
	if err != nil {
		return nil, fmt.Errorf("resolve bare Git directory: %w", err)
	}
	return &Repo{Path: gitDir, Bare: true, gitDir: gitDir}, nil
}

func (r *Repo) GitDir(ctx context.Context) string {
	if r.gitDir != "" {
		return r.gitDir
	}
	gitDir, _ := absoluteGitDir(ctx, r.Path)
	return gitDir
}
func (r *Repo) Head(ctx context.Context) (string, error) {
	return r.resolveHead(ctx)
}
func (r *Repo) Branch(ctx context.Context) (string, error) {
	s, err := run(ctx, r.Path, "branch", "--show-current")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(s), nil
}
func (r *Repo) IsShallow(ctx context.Context) (bool, error) {
	s, err := run(ctx, r.Path, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(s) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("Git returned an invalid shallow-repository status")
	}
}

func (r *Repo) Remotes(ctx context.Context) ([]struct{ Name, URL string }, error) {
	out, err := run(ctx, r.Path, "remote", "-v")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var rem []struct{ Name, URL string }
	for _, ln := range strings.Split(out, "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 2 {
			return nil, fmt.Errorf("parse Git remote metadata")
		}
		if !seen[f[0]] {
			seen[f[0]] = true
			rem = append(rem, struct{ Name, URL string }{f[0], sanitizeRemoteURL(f[1])})
		}
	}
	return rem, nil
}

func (r *Repo) Refs(ctx context.Context, branches, tags, all bool) ([]Ref, error) {
	if !all && !branches && !tags {
		return nil, nil
	}
	args := []string{"for-each-ref", "--format=%(refname)%00%(objectname)%00%(objecttype)"}
	if !all {
		if branches {
			args = append(args, "refs/heads", "refs/remotes")
		}
		if tags {
			args = append(args, "refs/tags")
		}
	}
	out, err := run(ctx, r.Path, args...)
	if err != nil {
		return nil, err
	}
	var refs []Ref
	for _, rec := range strings.Split(out, "\n") {
		if strings.TrimSpace(rec) == "" {
			continue
		}
		p := strings.Split(rec, "\x00")
		if len(p) != 3 || p[0] == "" || !validObjectID(p[1]) || p[2] == "" {
			return nil, fmt.Errorf("parse Git reference metadata")
		}
		ref := Ref{Name: p[0], Hash: p[1], Type: p[2], Target: p[1]}
		if p[2] == "tag" {
			peeled, peelErr := run(ctx, r.Path, "rev-parse", "--verify", "--quiet", p[0]+"^{}")
			if peelErr != nil {
				return nil, fmt.Errorf("peel Git reference %s: %w", p[0], peelErr)
			}
			ref.Target = strings.TrimSpace(peeled)
			if !validObjectID(ref.Target) {
				return nil, fmt.Errorf("parse peeled Git reference metadata")
			}
			targetType, typeErr := run(ctx, r.Path, "cat-file", "-t", ref.Target)
			if typeErr != nil {
				return nil, fmt.Errorf("classify peeled Git reference %s: %w", p[0], typeErr)
			}
			ref.Type = strings.TrimSpace(targetType)
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func sanitizeRemoteURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		if at := strings.LastIndex(raw, "@"); at > 0 {
			return "[REDACTED]@" + raw[at+1:]
		}
		return raw
	}
	if parsed.User != nil {
		parsed.User = url.User("[REDACTED]")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func (r *Repo) Commits(ctx context.Context, refs []Ref, since, until string) ([]Commit, error) {
	args := []string{"rev-list", "--reverse", "--date-order", "--parents", "--format=%H%x00%an%x00%ae%x00%aI%x00%P%x00%T"}
	if since != "" {
		args = append(args, "--since="+since)
	}
	if until != "" {
		args = append(args, "--until="+until)
	}
	commitRefs := 0
	for _, ref := range refs {
		target := ref.Target
		if target == "" {
			target = ref.Hash
		}
		if ref.Type != "" && ref.Type != "commit" {
			continue
		}
		args = append(args, target)
		commitRefs++
	}
	if len(refs) == 0 {
		head, err := r.resolveHead(ctx)
		if err != nil {
			return nil, fmt.Errorf("resolve HEAD: %w", err)
		}
		if head == "" {
			return nil, nil
		}
		args = append(args, head)
	}
	if len(refs) > 0 && commitRefs == 0 {
		return nil, nil
	}
	out, err := run(ctx, r.Path, args...)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var commits []Commit
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "commit ") || strings.TrimSpace(ln) == "" {
			continue
		}
		p := strings.Split(ln, "\x00")
		if len(p) != 6 || !validObjectID(p[0]) || !validObjectID(p[5]) {
			return nil, fmt.Errorf("parse Git commit metadata")
		}
		if seen[p[0]] {
			continue
		}
		t, err := time.Parse(time.RFC3339, p[3])
		if err != nil {
			return nil, fmt.Errorf("parse Git commit timestamp: %w", err)
		}
		var parents []string
		if len(p) > 4 && strings.TrimSpace(p[4]) != "" {
			parents = strings.Fields(p[4])
			for _, parent := range parents {
				if !validObjectID(parent) {
					return nil, fmt.Errorf("parse Git commit parent")
				}
			}
		}
		commits = append(commits, Commit{Hash: p[0], AuthorName: p[1], AuthorEmail: p[2], Tree: p[5], Time: t, Parents: parents})
		seen[p[0]] = true
	}
	return commits, nil
}

func (r *Repo) resolveHead(ctx context.Context) (string, error) {
	out, err := run(ctx, r.Path, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
	if err == nil {
		return strings.TrimSpace(out), nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return "", nil
	}
	return "", err
}

func (r *Repo) BlobsAtCommit(ctx context.Context, commit string) ([]Blob, error) {
	if !validObjectID(commit) {
		return nil, fmt.Errorf("invalid commit object ID")
	}
	return r.blobsAtTreeObject(ctx, commit, commit)
}

// BlobsAtTree returns all blob entries reachable from a tree object. It is
// used for direct refs that point at trees rather than commits.
func (r *Repo) BlobsAtTree(ctx context.Context, tree string) ([]Blob, error) {
	if !validObjectID(tree) {
		return nil, fmt.Errorf("invalid tree object ID")
	}
	return r.blobsAtTreeObject(ctx, tree, "")
}

func (r *Repo) blobsAtTreeObject(ctx context.Context, tree, commit string) ([]Blob, error) {
	out, err := run(ctx, r.Path, "ls-tree", "-r", "-l", "-z", "--full-tree", tree)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(out, "\x00")
	var blobs []Blob
	for _, part := range parts {
		if part == "" {
			continue
		}
		tab := strings.IndexByte(part, '\t')
		if tab < 0 {
			return nil, fmt.Errorf("parse Git tree listing")
		}
		meta, path := part[:tab], part[tab+1:]
		f := strings.Fields(meta)
		if len(f) < 4 {
			return nil, fmt.Errorf("parse Git tree entry")
		}
		if f[1] != "blob" {
			continue
		}
		if !validObjectID(f[2]) {
			return nil, fmt.Errorf("parse Git blob object ID")
		}
		var size int64
		if _, err := fmt.Sscanf(f[3], "%d", &size); err != nil || size < 0 {
			return nil, fmt.Errorf("parse Git blob size")
		}
		blobs = append(blobs, Blob{Commit: commit, OID: f[2], Path: path, Size: size, Mode: f[0]})
	}
	return blobs, nil
}

func (r *Repo) CatBlob(ctx context.Context, oid string) ([]byte, error) {
	if !validObjectID(oid) {
		return nil, fmt.Errorf("invalid blob object ID")
	}
	return runBytes(ctx, r.Path, "cat-file", "blob", oid)
}

func (r *Repo) ContainingRefs(ctx context.Context, commit string) ([]string, []string, error) {
	if !validObjectID(commit) {
		return nil, nil, fmt.Errorf("invalid commit object ID")
	}
	r.containmentMu.Lock()
	if cached, ok := r.containment[commit]; ok {
		branches := append([]string{}, cached.branches...)
		tags := append([]string{}, cached.tags...)
		r.containmentMu.Unlock()
		return branches, tags, nil
	}
	r.containmentMu.Unlock()

	out, err := run(ctx, r.Path, "for-each-ref", "--contains="+commit, "--format=%(refname)", "refs/heads", "refs/remotes", "refs/tags")
	if err != nil {
		return nil, nil, err
	}
	var result containmentResult
	for _, ref := range cleanLines(out) {
		switch {
		case strings.HasPrefix(ref, "refs/tags/"):
			result.tags = append(result.tags, strings.TrimPrefix(ref, "refs/tags/"))
		case strings.HasPrefix(ref, "refs/heads/"), strings.HasPrefix(ref, "refs/remotes/"):
			result.branches = append(result.branches, ref)
		}
	}
	r.containmentMu.Lock()
	if r.containment == nil {
		r.containment = map[string]containmentResult{}
	}
	r.containment[commit] = result
	r.containmentMu.Unlock()
	return append([]string{}, result.branches...), append([]string{}, result.tags...), nil
}
func (r *Repo) WorktreeFiles(ctx context.Context, includeUntracked bool) ([]WorktreeFile, error) {
	if r.Bare {
		return nil, nil
	}
	out, err := run(ctx, r.Path, "ls-files", "-z")
	if err != nil {
		return nil, err
	}
	var files []WorktreeFile
	seen := map[string]bool{}
	for _, path := range splitNul(out) {
		files = append(files, WorktreeFile{Path: path})
		seen[path] = true
	}
	if includeUntracked {
		u, err := run(ctx, r.Path, "ls-files", "-z", "--others", "--exclude-standard")
		if err != nil {
			return files, err
		}
		for _, path := range splitNul(u) {
			if seen[path] {
				continue
			}
			files = append(files, WorktreeFile{Path: path, Untracked: true})
		}
	}
	return files, nil
}

// IndexBlobs returns every index entry, including unresolved merge stages.
// Callers that need a clean stage-zero view can reject entries with Stage != 0.
func (r *Repo) IndexBlobs(ctx context.Context) ([]Blob, error) {
	if r.Bare {
		return nil, nil
	}
	out, err := run(ctx, r.Path, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, err
	}
	var blobs []Blob
	for _, record := range splitNul(out) {
		tab := strings.IndexByte(record, '\t')
		if tab < 0 {
			return nil, fmt.Errorf("parse Git index entry")
		}
		meta, file := record[:tab], record[tab+1:]
		fields := strings.Fields(meta)
		if len(fields) != 3 || !validObjectID(fields[1]) {
			return nil, fmt.Errorf("parse Git index metadata")
		}
		stage, err := strconv.Atoi(fields[2])
		if err != nil || stage < 0 || stage > 3 {
			return nil, fmt.Errorf("parse Git index stage")
		}
		switch fields[0] {
		case "100644", "100755", "120000", "160000":
		default:
			return nil, fmt.Errorf("parse Git index mode")
		}
		blobs = append(blobs, Blob{OID: fields[1], Path: file, Size: -1, Mode: fields[0], Stage: stage})
	}
	sort.Slice(blobs, func(i, j int) bool {
		if blobs[i].Path != blobs[j].Path {
			return blobs[i].Path < blobs[j].Path
		}
		return blobs[i].Stage < blobs[j].Stage
	})
	return blobs, nil
}

// StagedBlobs returns changed, non-deleted stage-zero index entries. It
// resolves all object IDs in one Git invocation so callers can stream their
// contents through BatchBlobReader without loading an unbounded `git show`
// response into memory.
func (r *Repo) StagedBlobs(ctx context.Context) ([]Blob, error) {
	if r.Bare {
		return nil, nil
	}
	changedOutput, err := run(ctx, r.Path, "diff", "--cached", "--name-only", "-z")
	if err != nil {
		return nil, err
	}
	changed := make(map[string]bool)
	for _, file := range splitNul(changedOutput) {
		changed[file] = true
	}
	if len(changed) == 0 {
		return nil, nil
	}
	indexBlobs, err := r.IndexBlobs(ctx)
	if err != nil {
		return nil, err
	}
	var blobs []Blob
	for _, blob := range indexBlobs {
		if !changed[blob.Path] {
			continue
		}
		if blob.Stage != 0 {
			return nil, fmt.Errorf("one or more staged paths have unresolved index stages")
		}
		if blob.Mode == "160000" {
			continue
		}
		blobs = append(blobs, blob)
	}
	return blobs, nil
}

type UnreachableObject struct {
	Type string
	OID  string
}

func (r *Repo) UnreachableObjects(ctx context.Context) ([]UnreachableObject, error) {
	out, err := run(ctx, r.Path, "fsck", "--unreachable", "--no-reflogs", "--no-progress")
	if err != nil {
		return nil, err
	}
	var objects []UnreachableObject
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) == 3 && (f[1] == "blob" || f[1] == "commit") {
			objects = append(objects, UnreachableObject{Type: f[1], OID: f[2]})
		}
	}
	return objects, nil
}

func (r *Repo) ReflogCommits(ctx context.Context) ([]Ref, error) {
	out, err := run(ctx, r.Path, "reflog", "--all", "--format=%H%x00%gD")
	if err != nil {
		return nil, err
	}
	var refs []Ref
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "\x00", 2)
		if len(parts) != 2 || !validObjectID(parts[0]) || parts[1] == "" {
			return nil, fmt.Errorf("parse Git reflog metadata")
		}
		if seen[parts[0]] {
			continue
		}
		seen[parts[0]] = true
		refs = append(refs, Ref{Name: parts[1], Hash: parts[0]})
	}
	return refs, nil
}

func (r *Repo) CommitInfo(ctx context.Context, hash string) (Commit, error) {
	if !validObjectID(hash) {
		return Commit{}, fmt.Errorf("invalid commit object ID")
	}
	out, err := run(ctx, r.Path, "show", "-s", "--format=%H%x00%an%x00%ae%x00%aI%x00%P%x00%T", hash)
	if err != nil {
		return Commit{}, err
	}
	p := strings.Split(strings.TrimSpace(out), "\x00")
	if len(p) < 6 {
		return Commit{}, fmt.Errorf("unexpected metadata for commit %s", hash)
	}
	t, err := time.Parse(time.RFC3339, p[3])
	if err != nil {
		return Commit{}, fmt.Errorf("parse commit time: %w", err)
	}
	return Commit{Hash: p[0], AuthorName: p[1], AuthorEmail: p[2], Tree: p[5], Time: t, Parents: strings.Fields(p[4])}, nil
}

func (r *Repo) HookPath(ctx context.Context, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, `/\`+"\x00") {
		return "", fmt.Errorf("invalid hook name")
	}
	out, err := run(ctx, r.Path, "rev-parse", "--path-format=absolute", "--git-path", "hooks/"+name)
	if err != nil {
		return "", err
	}
	return filepath.Clean(strings.TrimSpace(out)), nil
}
func (r *Repo) FileBytes(path string, max int64) ([]byte, error) {
	if r.Bare {
		return nil, fmt.Errorf("bare repository has no working tree")
	}
	if max < 1 {
		return nil, fmt.Errorf("maximum file size must be positive")
	}
	full, err := safeJoin(r.Path, path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrWorktreeSymlink
	}
	if err := rejectSymlinkComponents(r.Path, path); err != nil {
		return nil, err
	}
	if info.Size() > max {
		return nil, ErrWorktreeFileTooLarge
	}
	file, err := os.Open(full)
	if err != nil {
		return nil, fmt.Errorf("open working-tree file: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, ErrWorktreeNotRegular
	}
	if openedInfo.Size() > max {
		return nil, ErrWorktreeFileTooLarge
	}
	content, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > max {
		return nil, ErrWorktreeFileTooLarge
	}
	return content, nil
}

func absoluteGitDir(ctx context.Context, dir string) (string, error) {
	out, err := run(ctx, dir, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return "", err
	}
	gitDir := strings.TrimSpace(out)
	if gitDir == "" {
		return "", fmt.Errorf("Git returned an empty Git directory")
	}
	return filepath.Clean(gitDir), nil
}

func safeJoin(root, rel string) (string, error) {
	full := filepath.Clean(filepath.Join(root, rel))
	rr, _ := filepath.Abs(root)
	ff, _ := filepath.Abs(full)
	relative, err := filepath.Rel(rr, ff)
	if err != nil || relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repository")
	}
	return ff, nil
}

func rejectSymlinkComponents(root, relative string) error {
	current := filepath.Clean(root)
	relative = filepath.Clean(filepath.FromSlash(relative))
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			return fmt.Errorf("path escapes repository")
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrWorktreeSymlink
		}
	}
	return nil
}

func run(ctx context.Context, dir string, args ...string) (string, error) {
	b, err := runBytes(ctx, dir, args...)
	return string(b), err
}
func runBytes(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, "git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
func cleanLines(out string) []string {
	seen := map[string]bool{}
	var lines []string
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(strings.TrimPrefix(ln, "*"))
		if ln != "" && !seen[ln] {
			seen[ln] = true
			lines = append(lines, ln)
		}
	}
	return lines
}
func splitNul(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
