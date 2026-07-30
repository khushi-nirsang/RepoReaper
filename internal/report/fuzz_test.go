package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/khushi/reporeaper/internal/model"
)

func FuzzReportEncodersNeverExposeAbsentRawValues(f *testing.F) {
	f.Add("path/to/file.env", "detector", "<script>alert(1)</script>")
	f.Add("line\nbreak", "github-token", "ordinary text")
	f.Fuzz(func(t *testing.T, path, detectorID, arbitrary string) {
		if len(path)+len(detectorID)+len(arbitrary) > 1<<16 {
			t.Skip()
		}
		sum := sha256.Sum256([]byte(path + "\x00" + detectorID + "\x00" + arbitrary))
		raw := "rr-fuzz-secret-" + hex.EncodeToString(sum[:])
		r := model.Report{
			SchemaVersion: model.SchemaVersion,
			ToolVersion:   "fuzz",
			Repository:    model.Repository{Path: arbitrary},
			Findings: []model.Finding{{
				ID: "RR-0001", DetectorID: detectorID, DetectorName: arbitrary,
				Severity: model.SeverityHigh, Redacted: "rr-fuzz-********",
				Fingerprint: hex.EncodeToString(sum[:]), ShortFingerprint: hex.EncodeToString(sum[:6]),
				Evidence: []model.Evidence{{Path: path, Line: 1}},
			}},
		}
		outputs := map[string][]byte{"table": []byte(Table(r))}
		for name, encode := range map[string]func(model.Report) ([]byte, error){
			"json": JSON, "html": HTML, "sarif": SARIF,
		} {
			encoded, err := encode(r)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			outputs[name] = encoded
		}
		for name, output := range outputs {
			if bytes.Contains(output, []byte(raw)) {
				t.Fatalf("%s emitted a value that was never supplied to the report model", name)
			}
		}
	})
}
