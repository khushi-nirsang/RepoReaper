package detector

import (
	"bytes"
	"strings"
	"testing"
)

func BenchmarkRegistryFindPrepared(b *testing.B) {
	content := bytes.Repeat([]byte("ordinary source code and configuration without credentials\n"), 2048)
	content = append(content, []byte("GITHUB_TOKEN=ghp_"+strings.Repeat("A1b2C3d4E5f6G7h8I9j0K1l2M3n4", 2)+"\n")...)
	detectors := Registry(nil, nil)
	b.ReportAllocs()
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prepared := PrepareText(content)
		for _, d := range detectors {
			_ = FindPrepared(d, prepared)
		}
	}
}
