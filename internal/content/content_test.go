package content

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestExpandPlainAndBase64Text(t *testing.T) {
	decoded := "GITHUB_TOKEN=ghp_" + strings.Repeat("A1b2C3d4E5f6G7h8I9j0K1l2M3n4", 2)
	encoded := base64.StdEncoding.EncodeToString([]byte(decoded))
	result := Expand([]byte("first line\npayload="+encoded+"\n"), Limits{MaxUnitSize: 1 << 20})
	if len(result.Units) != 2 {
		t.Fatalf("units = %d warnings=%v", len(result.Units), result.Warnings)
	}
	var found bool
	for _, unit := range result.Units {
		if unit.Decoder == "base64" {
			found = true
			if string(unit.Data) != decoded || unit.SourceLine != 2 {
				t.Fatalf("decoded unit = %#v", unit)
			}
		}
	}
	if !found || result.EncodedPayloads != 1 {
		t.Fatalf("base64 expansion missing: %#v", result)
	}
}

func TestExpandUTF16TextWithAndWithoutBOM(t *testing.T) {
	fixture := "GITHUB_TOKEN=ghp_" + strings.Repeat("U7tF6aK3eQ2mWv9Rk4Np8Xs3Ld6Tf", 1)
	for _, test := range []struct {
		name  string
		order binary.ByteOrder
		bom   []byte
		want  string
	}{
		{name: "little-endian-bom", order: binary.LittleEndian, bom: []byte{0xff, 0xfe}, want: "utf-16le"},
		{name: "big-endian-bom", order: binary.BigEndian, bom: []byte{0xfe, 0xff}, want: "utf-16be"},
		{name: "little-endian-no-bom", order: binary.LittleEndian, want: "utf-16le"},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := append([]byte{}, test.bom...)
			for _, value := range utf16.Encode([]rune(fixture)) {
				var encoded [2]byte
				test.order.PutUint16(encoded[:], value)
				data = append(data, encoded[:]...)
			}
			result := Expand(data, Limits{MaxUnitSize: 1 << 20})
			if len(result.Units) != 1 || result.Units[0].Decoder != test.want || string(result.Units[0].Data) != fixture {
				t.Fatalf("UTF-16 result = %#v warnings=%v", result.Units, result.Warnings)
			}
		})
	}
}

func TestExpandZIPAndRejectUnsafeMember(t *testing.T) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	safe, err := writer.Create("nested/config.env")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = safe.Write([]byte("TOKEN=synthetic-value-for-testing-only"))
	unsafe, err := writer.Create("../outside.env")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = unsafe.Write([]byte("ordinary"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	result := Expand(buffer.Bytes(), Limits{MaxUnitSize: 1 << 20})
	if len(result.Units) != 1 || result.Units[0].Location != "nested/config.env" || result.Units[0].Decoder != "zip" {
		t.Fatalf("zip units = %#v", result.Units)
	}
	if !containsWarning(result.Warnings, "unsafe archive member") {
		t.Fatalf("unsafe member warning missing: %v", result.Warnings)
	}
}

func TestExpandTarInsideGzip(t *testing.T) {
	var tarBuffer bytes.Buffer
	tarWriter := tar.NewWriter(&tarBuffer)
	body := []byte("ordinary nested fixture")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "config.txt", Mode: 0600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	_, _ = tarWriter.Write(body)
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var gzipBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&gzipBuffer)
	gzipWriter.Name = "bundle.tar"
	_, _ = gzipWriter.Write(tarBuffer.Bytes())
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}

	result := Expand(gzipBuffer.Bytes(), Limits{MaxUnitSize: 1 << 20})
	if len(result.Units) != 1 {
		t.Fatalf("units = %#v warnings=%v", result.Units, result.Warnings)
	}
	unit := result.Units[0]
	if string(unit.Data) != string(body) || unit.Location != "bundle.tar!config.txt" || unit.Decoder != "gzip+tar" {
		t.Fatalf("nested unit = %#v", unit)
	}
}

func TestExpansionLimitsHighCompressionRatio(t *testing.T) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.Create("repetitive.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write(bytes.Repeat([]byte("A"), 64*1024))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	result := Expand(buffer.Bytes(), Limits{MaxUnitSize: 1 << 20, MaxCompression: 2})
	if len(result.Units) != 0 || !containsWarning(result.Warnings, "compression-ratio") {
		t.Fatalf("compression guard result = %#v", result)
	}
}

func TestExpansionLimitsHighCompressionRatioGzip(t *testing.T) {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(bytes.Repeat([]byte("A"), 64*1024)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	result := Expand(buffer.Bytes(), Limits{MaxUnitSize: 1 << 20, MaxCompression: 2})
	if len(result.Units) != 0 || !containsWarning(result.Warnings, "gzip stream") {
		t.Fatalf("gzip compression guard result = %#v", result)
	}
}

func TestExpandBase64ChecksRemainingBudgetBeforeDecode(t *testing.T) {
	limits := normalizedLimits(Limits{MaxUnitSize: 64, MaxExpandedBytes: 512})
	expander := &expander{
		limits:   limits,
		expanded: limits.MaxExpandedBytes - 8,
		warnings: map[string]bool{},
	}

	expander.expandBase64([]byte(strings.Repeat("QUJD", 12)), "", "", 0)

	if expander.result.EncodedPayloads != 0 || len(expander.result.Units) != 0 {
		t.Fatalf("over-budget Base64 payload was expanded: %#v", expander.result)
	}
	if !expander.warnings["a Base64 payload exceeded the decoded-content size limit"] {
		t.Fatalf("decoded-size warning missing: %#v", expander.warnings)
	}
}

func containsWarning(warnings []string, fragment string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, fragment) {
			return true
		}
	}
	return false
}
