package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsUnknownFieldsAndUnsafeRedaction(t *testing.T) {
	for name, body := range map[string]string{
		"unknown": "version: 1\nunknown: true\n",
		"redact":  "version: 1\nreport:\n  redact: false\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("unsafe configuration was accepted")
			}
		})
	}
}

func TestValidateRejectsBuiltInCollisionAndBadAllowlistRegex(t *testing.T) {
	cfg := Default()
	cfg.Detectors.Custom = []CustomDetector{{ID: "github-token", Name: "Collision", Description: "collision", Regex: "x+", Severity: "high", Remediation: "rotate"}}
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("collision error = %v", err)
	}
	cfg = Default()
	cfg.Allowlist.Regexes = []string{"["}
	if err := Validate(cfg); err == nil {
		t.Fatal("invalid allowlist regex was accepted")
	}
}

func TestExplicitMissingConfigIsError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("explicit missing configuration was accepted")
	}
}

func TestValidateRejectsInvalidPolicy(t *testing.T) {
	cfg := Default()
	cfg.Policy.FailOn = "urgent"
	if err := Validate(cfg); err == nil {
		t.Fatal("invalid policy severity was accepted")
	}
	cfg = Default()
	cfg.Policy.Scope = "remote-only"
	if err := Validate(cfg); err == nil {
		t.Fatal("invalid policy scope was accepted")
	}
}

func TestValidateRejectsEmptyReportFormat(t *testing.T) {
	cfg := Default()
	cfg.Report.DefaultFormat = ""
	if err := Validate(cfg); err == nil {
		t.Fatal("empty default report format was accepted")
	}
}

func TestCacheDefaultsAreOptInAndPartialConfigPreservesBounds(t *testing.T) {
	defaults := Default()
	if defaults.Scan.Cache.Enabled {
		t.Fatal("persistent cache must be opt-in")
	}
	if defaults.Scan.Cache.MaxEntries != 50_000 || defaults.Scan.Cache.MaxSize != 64*1024*1024 {
		t.Fatalf("cache defaults = %#v", defaults.Scan.Cache)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "version: 1\nscan:\n  cache:\n    enabled: true\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Scan.Cache.Enabled || loaded.Scan.Cache.MaxEntries != 50_000 || loaded.Scan.Cache.MaxSize != 64*1024*1024 {
		t.Fatalf("loaded cache config = %#v", loaded.Scan.Cache)
	}
}

func TestValidateRejectsUnsafeCacheBounds(t *testing.T) {
	cfg := Default()
	cfg.Scan.Cache.MaxEntries = 0
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "max_entries") {
		t.Fatalf("max entries error = %v", err)
	}
	cfg = Default()
	cfg.Scan.Cache.MaxSize = 1023
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "max_size") {
		t.Fatalf("max size error = %v", err)
	}
	cfg = Default()
	cfg.Scan.Cache.Path = "bad\x00path"
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("cache path error = %v", err)
	}
}
