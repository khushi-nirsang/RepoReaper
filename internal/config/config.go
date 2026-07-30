package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/khushi/reporeaper/internal/model"
	"gopkg.in/yaml.v3"
)

type File struct {
	Version   int       `yaml:"version"`
	Scan      Scan      `yaml:"scan"`
	Report    Report    `yaml:"report"`
	Policy    Policy    `yaml:"policy"`
	Allowlist Allowlist `yaml:"allowlist"`
	Detectors Detectors `yaml:"detectors"`
}
type Scan struct {
	MaxFileSize      int64 `yaml:"max_file_size"`
	IncludeUntracked bool  `yaml:"include_untracked"`
	Branches         bool  `yaml:"branches"`
	Tags             bool  `yaml:"tags"`
	Unreachable      bool  `yaml:"unreachable"`
	Reflogs          bool  `yaml:"reflogs"`
	Workers          int   `yaml:"workers"`
	Cache            Cache `yaml:"cache"`
}
type Cache struct {
	Enabled    bool   `yaml:"enabled"`
	Path       string `yaml:"path"`
	MaxEntries int    `yaml:"max_entries"`
	MaxSize    int64  `yaml:"max_size"`
}
type Report struct {
	DefaultFormat string `yaml:"default_format"`
	Redact        bool   `yaml:"redact"`
}
type Policy struct {
	FailOn string `yaml:"fail_on"`
	Scope  string `yaml:"scope"`
}
type Allowlist struct {
	Fingerprints []string `yaml:"fingerprints"`
	Paths        []string `yaml:"paths"`
	Commits      []string `yaml:"commits"`
	Regexes      []string `yaml:"regexes"`
}
type Detectors struct {
	Disabled []string         `yaml:"disabled"`
	Custom   []CustomDetector `yaml:"custom"`
}
type CustomDetector struct {
	ID             string   `yaml:"id"`
	Name           string   `yaml:"name"`
	Description    string   `yaml:"description"`
	Regex          string   `yaml:"regex"`
	Severity       string   `yaml:"severity"`
	Remediation    string   `yaml:"remediation"`
	Keywords       []string `yaml:"keywords"`
	MinimumEntropy float64  `yaml:"minimum_entropy"`
}

func Default() File {
	return File{
		Version: 1,
		Scan: Scan{
			MaxFileSize: 5 * 1024 * 1024, Branches: true, Tags: true, Workers: 4,
			Cache: Cache{MaxEntries: 50_000, MaxSize: 64 * 1024 * 1024},
		},
		Report: Report{DefaultFormat: "table", Redact: true},
		Policy: Policy{Scope: "any"},
	}
}

func Load(path string) (File, error) {
	cfg := Default()
	explicit := path != ""
	if path == "" {
		path = ".reporeaper.yaml"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if explicit {
				return cfg, fmt.Errorf("configuration file %s does not exist", path)
			}
			return cfg, nil
		}
		return cfg, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, Validate(cfg)
}

func Validate(cfg File) error {
	if cfg.Version != 1 {
		return fmt.Errorf("unsupported config version %d", cfg.Version)
	}
	if cfg.Scan.MaxFileSize <= 0 || cfg.Scan.MaxFileSize > 1024*1024*1024 {
		return fmt.Errorf("max_file_size must be between 1 and 1073741824")
	}
	if cfg.Scan.Workers <= 0 || cfg.Scan.Workers > 64 {
		return fmt.Errorf("workers must be between 1 and 64")
	}
	if cfg.Scan.Cache.MaxEntries <= 0 || cfg.Scan.Cache.MaxEntries > 1_000_000 {
		return fmt.Errorf("scan.cache.max_entries must be between 1 and 1000000")
	}
	if cfg.Scan.Cache.MaxSize < 1024 || cfg.Scan.Cache.MaxSize > 1024*1024*1024 {
		return fmt.Errorf("scan.cache.max_size must be between 1024 and 1073741824")
	}
	if strings.ContainsRune(cfg.Scan.Cache.Path, '\x00') {
		return fmt.Errorf("scan.cache.path contains an invalid NUL byte")
	}
	if !cfg.Report.Redact {
		return fmt.Errorf("report.redact must be true; raw-secret output is not supported")
	}
	switch cfg.Report.DefaultFormat {
	case "table", "json", "html", "sarif":
	default:
		return fmt.Errorf("unsupported report format %q", cfg.Report.DefaultFormat)
	}
	if cfg.Policy.FailOn != "" && !validSeverity(cfg.Policy.FailOn) {
		return fmt.Errorf("policy.fail_on has invalid severity %q", cfg.Policy.FailOn)
	}
	switch cfg.Policy.Scope {
	case "", "any", "current", "reachable", "residual":
	default:
		return fmt.Errorf("policy.scope must be any, current, reachable, or residual")
	}
	seen := map[string]bool{}
	for _, id := range BuiltInDetectorIDs() {
		seen[id] = true
	}
	for _, d := range cfg.Detectors.Custom {
		if d.ID == "" || seen[d.ID] {
			return fmt.Errorf("custom detector ID %q must be non-empty and must not duplicate another detector", d.ID)
		}
		seen[d.ID] = true
		if d.Name == "" || d.Description == "" || d.Regex == "" || d.Remediation == "" {
			return fmt.Errorf("custom detector %s requires name, description, regex, and remediation", d.ID)
		}
		if _, err := regexp.Compile(d.Regex); err != nil {
			return fmt.Errorf("custom detector %s regex: %w", d.ID, err)
		}
		if !validSeverity(d.Severity) {
			return fmt.Errorf("custom detector %s has invalid severity %q", d.ID, d.Severity)
		}
		if d.MinimumEntropy < 0 || d.MinimumEntropy > 8 {
			return fmt.Errorf("custom detector %s minimum_entropy must be between 0 and 8", d.ID)
		}
	}
	for _, rx := range cfg.Allowlist.Regexes {
		if _, err := regexp.Compile(rx); err != nil {
			return fmt.Errorf("allowlist regex: %w", err)
		}
	}
	known := map[string]bool{}
	for _, id := range BuiltInDetectorIDs() {
		known[id] = true
	}
	for _, custom := range cfg.Detectors.Custom {
		known[custom.ID] = true
	}
	disabled := map[string]bool{}
	for _, id := range cfg.Detectors.Disabled {
		if disabled[id] {
			return fmt.Errorf("detector %s is disabled more than once", id)
		}
		if !known[id] {
			return fmt.Errorf("disabled detector %s is unknown", id)
		}
		disabled[id] = true
	}
	return nil
}

func BuiltInDetectorIDs() []string {
	return []string{
		"aws-access-key-id", "aws-secret-access-key", "github-token", "gitlab-token", "slack-token", "google-api-key", "stripe-key",
		"twilio-credential", "twilio-auth-token", "sendgrid-api-key", "npm-token", "pypi-token", "jwt", "generic-bearer-token",
		"generic-api-key", "postgres-connection-string", "mysql-connection-string", "mongodb-connection-string",
		"redis-credential-url", "basic-auth-url", "pem-private-key", "openssh-private-key", "pgp-private-key",
		"kubernetes-secret", "docker-registry-credential", "env-password", "service-account-json", "high-entropy-secret",
		"openai-api-key", "anthropic-api-key", "digitalocean-token", "huggingface-token", "hcp-terraform-token",
		"hashicorp-vault-token", "azure-storage-account-key", "supabase-secret-key",
	}
}

func validSeverity(s string) bool {
	switch model.Severity(s) {
	case model.SeverityInfo, model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical:
		return true
	default:
		return false
	}
}
