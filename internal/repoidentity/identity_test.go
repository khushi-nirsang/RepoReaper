package repoidentity

import (
	"testing"

	"github.com/khushi/reporeaper/internal/model"
)

func TestValidateUsesOnlyCanonicalNetworkRemotes(t *testing.T) {
	baseline := model.Repository{Path: "/old/checkout", Remotes: []model.Remote{{Name: "origin", URL: "https://user@example.invalid/Owner/Repo.git"}}}
	current := model.Repository{Path: "/new/checkout", Remotes: []model.Remote{{Name: "upstream", URL: "ssh://git@example.invalid/Owner/Repo"}}}
	if err := Validate(baseline, current); err != nil {
		t.Fatalf("equivalent repository identities rejected: %v", err)
	}

	current.Remotes[0].URL = "git@example.invalid:Other/Repo.git"
	if err := Validate(baseline, current); err == nil {
		t.Fatal("unambiguous repository mismatch was accepted")
	}

	local := model.Repository{Path: "C:\\checkout", Remotes: []model.Remote{{Name: "origin", URL: "C:\\local\\repo.git"}}}
	if err := Validate(local, current); err != nil {
		t.Fatalf("local path was treated as a stable network identity: %v", err)
	}
}

func TestCanonicalNetworkRemoteNormalizesSafeVariants(t *testing.T) {
	for _, raw := range []string{
		"https://example.invalid/owner/repo.git",
		"ssh://git@example.invalid/owner/repo",
		"git@example.invalid:owner/repo.git",
	} {
		got, ok := canonicalNetworkRemote(raw)
		if !ok || got != "example.invalid/owner/repo" {
			t.Fatalf("canonical remote %q = %q, %v", raw, got, ok)
		}
	}
	for _, local := range []string{"C:\\checkout\\repo.git", "../repo.git", "file:///repo.git"} {
		if identity, ok := canonicalNetworkRemote(local); ok {
			t.Fatalf("local remote %q became identity %q", local, identity)
		}
	}
}
