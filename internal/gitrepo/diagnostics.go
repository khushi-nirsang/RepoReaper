package gitrepo

import (
	"context"
	"fmt"
	"strings"
)

// Diagnostics contains read-only repository metadata used by health checks.
type Diagnostics struct {
	GitDir  string
	Head    string
	Branch  string
	Shallow bool
}

// GitVersion reports the installed Git version without invoking a shell.
func GitVersion(ctx context.Context) (string, error) {
	out, err := run(ctx, "", "--version")
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(out)
	if version == "" {
		return "", fmt.Errorf("git --version returned no output")
	}
	return version, nil
}

// Diagnostics returns metadata needed to assess scan coverage. It does not
// inspect repository file or object contents.
func (r *Repo) Diagnostics(ctx context.Context) (Diagnostics, error) {
	gitDir, err := run(ctx, r.Path, "rev-parse", "--path-format=absolute", "--git-dir")
	if err != nil {
		return Diagnostics{}, fmt.Errorf("resolve Git directory: %w", err)
	}
	head, err := r.resolveHead(ctx)
	if err != nil {
		return Diagnostics{}, fmt.Errorf("resolve HEAD: %w", err)
	}
	branch, err := run(ctx, r.Path, "branch", "--show-current")
	if err != nil {
		return Diagnostics{}, fmt.Errorf("resolve branch: %w", err)
	}
	shallowText, err := run(ctx, r.Path, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return Diagnostics{}, fmt.Errorf("inspect shallow state: %w", err)
	}
	var shallow bool
	switch strings.TrimSpace(shallowText) {
	case "true":
		shallow = true
	case "false":
	default:
		return Diagnostics{}, fmt.Errorf("unexpected shallow repository state %q", strings.TrimSpace(shallowText))
	}
	return Diagnostics{
		GitDir:  strings.TrimSpace(gitDir),
		Head:    head,
		Branch:  strings.TrimSpace(branch),
		Shallow: shallow,
	}, nil
}
