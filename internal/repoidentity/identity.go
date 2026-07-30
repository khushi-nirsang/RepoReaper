package repoidentity

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/khushi/reporeaper/internal/model"
)

// Validate rejects only an unambiguous network-remote mismatch. Checkout
// paths, Git directories, branches, and HEADs legitimately change during
// remediation and across machines, so they are not treated as identity.
func Validate(baseline, current model.Repository) error {
	want := safeRemoteIdentities(baseline.Remotes)
	got := safeRemoteIdentities(current.Remotes)
	if len(want) == 0 || len(got) == 0 {
		return nil
	}
	for identity := range want {
		if _, found := got[identity]; found {
			return nil
		}
	}
	return fmt.Errorf("report appears to describe a different repository: no network remote identity matches")
}

func safeRemoteIdentities(remotes []model.Remote) map[[sha256.Size]byte]struct{} {
	identities := map[[sha256.Size]byte]struct{}{}
	for _, remote := range remotes {
		if canonical, ok := canonicalNetworkRemote(remote.URL); ok {
			// Repository identities stay hashed so they cannot appear in
			// comparison diagnostics or be accidentally serialized.
			identities[sha256.Sum256([]byte(canonical))] = struct{}{}
		}
	}
	return identities
}

func canonicalNetworkRemote(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Scheme != "" {
		switch strings.ToLower(parsed.Scheme) {
		case "http", "https", "ssh", "git":
		default:
			return "", false
		}
		host := strings.ToLower(parsed.Hostname())
		repositoryPath := normalizeRemotePath(parsed.Path)
		if host == "" || repositoryPath == "" {
			return "", false
		}
		if port := parsed.Port(); port != "" && !isDefaultRemotePort(parsed.Scheme, port) {
			host += ":" + port
		}
		return host + "/" + repositoryPath, true
	}

	// Git's SCP-like syntax: [user@]host:owner/repository.git. Exclude
	// Windows drive paths so local checkout locations never become identities.
	colon := strings.IndexByte(raw, ':')
	if colon <= 0 || (colon == 1 && isASCIILetter(raw[0])) {
		return "", false
	}
	hostPart, repositoryPart := raw[:colon], raw[colon+1:]
	if at := strings.LastIndexByte(hostPart, '@'); at >= 0 {
		hostPart = hostPart[at+1:]
	}
	hostPart = strings.ToLower(strings.TrimSpace(hostPart))
	repositoryPart = normalizeRemotePath(repositoryPart)
	if hostPart == "" || strings.ContainsAny(hostPart, `/\`) || repositoryPart == "" {
		return "", false
	}
	return hostPart + "/" + repositoryPart, true
}

func normalizeRemotePath(value string) string {
	value = strings.Trim(strings.ReplaceAll(value, `\`, "/"), "/")
	value = strings.TrimSuffix(value, ".git")
	if value == "" || value == "." || strings.HasPrefix(value, "../") {
		return ""
	}
	return path.Clean(value)
}

func isDefaultRemotePort(scheme, port string) bool {
	switch strings.ToLower(scheme) {
	case "http":
		return port == "80"
	case "https":
		return port == "443"
	case "ssh":
		return port == "22"
	case "git":
		return port == "9418"
	default:
		return false
	}
}

func isASCIILetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}
