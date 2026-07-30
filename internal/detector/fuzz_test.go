package detector

import (
	"strings"
	"testing"
)

// FuzzBuiltInDetectors exercises every parser and redactor with hostile input.
// The invariant is deliberately stronger than "does not panic": no match may
// return its complete value through the user-visible redacted representation.
func FuzzBuiltInDetectors(f *testing.F) {
	for _, seed := range []string{
		"plain text",
		"GITHUB_TOKEN=ghp_" + strings.Repeat("A1b2C3d4E5f6G7h8I9j0K1l2M3n4", 2),
		"DATABASE_URL=postgres://app:V7r9Q2m4L8x6N3p5@db.invalid/app",
		"-----BEGIN PRIVATE KEY-----\nZmFrZS10ZXN0LWtleQ==\n-----END PRIVATE KEY-----",
		"\x00\xff\x00",
	} {
		f.Add([]byte(seed))
	}

	detectors := Registry(nil, nil)
	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 1<<20 {
			t.Skip()
		}
		for _, d := range detectors {
			for _, match := range d.Find(content) {
				if match.Fingerprint == "" || match.Short == "" {
					t.Fatalf("detector %s returned a match without a fingerprint", d.ID())
				}
				if match.Line < 1 {
					t.Fatalf("detector %s returned invalid line %d", d.ID(), match.Line)
				}
				if len(match.Value) >= 4 && strings.Contains(match.Redacted, match.Value) {
					t.Fatalf("detector %s exposed its complete match in redacted output", d.ID())
				}
			}
		}
	})
}
