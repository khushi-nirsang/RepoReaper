package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestWorkflowGuardrails(t *testing.T) {
	paths, err := filepath.Glob(filepath.FromSlash(".github/workflows/*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no GitHub Actions workflows found")
	}

	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			var workflow map[string]any
			if err := yaml.Unmarshal(data, &workflow); err != nil {
				t.Fatalf("invalid YAML: %v", err)
			}
			for _, key := range []string{"name", "on", "jobs", "permissions"} {
				if _, ok := workflow[key]; !ok {
					t.Errorf("missing top-level %q", key)
				}
			}

			jobs, ok := stringMap(workflow["jobs"])
			if !ok || len(jobs) == 0 {
				t.Fatal("jobs must be a non-empty mapping")
			}
			for jobName, rawJob := range jobs {
				job, ok := stringMap(rawJob)
				if !ok {
					t.Errorf("job %q must be a mapping", jobName)
					continue
				}
				if _, ok := job["runs-on"]; !ok {
					t.Errorf("job %q has no runs-on", jobName)
				}
				if _, ok := job["timeout-minutes"]; !ok {
					t.Errorf("job %q has no timeout-minutes", jobName)
				}

				steps, ok := rawSlice(job["steps"])
				if !ok || len(steps) == 0 {
					t.Errorf("job %q must have steps", jobName)
					continue
				}
				checkWorkflowSteps(t, jobName, steps)
			}
		})
	}
}

func TestDependabotConfigurationIsWellFormed(t *testing.T) {
	data, err := os.ReadFile(filepath.FromSlash(".github/dependabot.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Version int `yaml:"version"`
		Updates []struct {
			Ecosystem string `yaml:"package-ecosystem"`
			Directory string `yaml:"directory"`
			Schedule  struct {
				Interval string `yaml:"interval"`
			} `yaml:"schedule"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("invalid YAML: %v", err)
	}
	if config.Version != 2 {
		t.Errorf("Dependabot schema version = %d, want 2", config.Version)
	}
	if len(config.Updates) == 0 {
		t.Fatal("Dependabot has no update ecosystems")
	}
	for _, update := range config.Updates {
		if update.Ecosystem == "" || update.Directory == "" || update.Schedule.Interval == "" {
			t.Errorf("incomplete Dependabot update entry: %+v", update)
		}
	}
}

func TestReleaseWorkflowPrivilegeBoundary(t *testing.T) {
	data, err := os.ReadFile(filepath.FromSlash(".github/workflows/release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow map[string]any
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("invalid YAML: %v", err)
	}

	permissions, ok := stringMap(workflow["permissions"])
	if !ok || fmt.Sprint(permissions["contents"]) != "read" {
		t.Fatal("release workflow must default to contents: read")
	}
	jobs, _ := stringMap(workflow["jobs"])
	verify, ok := stringMap(jobs["verify"])
	if !ok {
		t.Fatal("release workflow has no read-only verification job")
	}
	publish, ok := stringMap(jobs["goreleaser"])
	if !ok {
		t.Fatal("release workflow has no publishing job")
	}
	for _, dependency := range []string{"verify", "platform-test"} {
		if !jobNeeds(publish, dependency) {
			t.Errorf("publishing job must depend on successful %s", dependency)
		}
	}

	publishPermissions, ok := stringMap(publish["permissions"])
	if !ok {
		t.Fatal("publishing job must declare explicit permissions")
	}
	if got := fmt.Sprint(publishPermissions["contents"]); got != "write" {
		t.Errorf("publishing contents permission = %q, want %q", got, "write")
	}
	for _, permission := range []string{"attestations", "id-token"} {
		if _, ok := publishPermissions[permission]; ok {
			t.Errorf("publishing job must not have %q permission", permission)
		}
	}

	attest, ok := stringMap(jobs["attest"])
	if !ok {
		t.Fatal("release workflow has no isolated attestation job")
	}
	if fmt.Sprint(attest["needs"]) != "goreleaser" {
		t.Error("attestation job must depend on successful publication")
	}
	attestPermissions, ok := stringMap(attest["permissions"])
	if !ok {
		t.Fatal("attestation job must declare explicit permissions")
	}
	for permission, want := range map[string]string{
		"contents":          "read",
		"attestations":      "write",
		"artifact-metadata": "write",
		"id-token":          "write",
	} {
		if got := fmt.Sprint(attestPermissions[permission]); got != want {
			t.Errorf("attestation permission %q = %q, want %q", permission, got, want)
		}
	}

	assertHasCommand(t, verify, "go vet ./...")
	assertHasCommand(t, verify, "go test -count=1 ./...")
	assertHasCommand(t, verify, "go test -race -count=1 ./...")
	assertHasCommand(t, verify, "govulncheck@v1.6.0")
	assertHasCommand(t, verify, "goreleaser/v2@v2.17.1 check")
	assertLacksCommand(t, publish, "go vet")
	assertLacksCommand(t, publish, "go test")
	assertLacksAction(t, attest, "actions/checkout@")
}

func TestGoReleaserConfiguration(t *testing.T) {
	data, err := os.ReadFile(".goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}

	var config struct {
		Version int `yaml:"version"`
		Before  struct {
			Hooks []string `yaml:"hooks"`
		} `yaml:"before"`
		Builds []struct {
			Flags   []string `yaml:"flags"`
			LDFlags []string `yaml:"ldflags"`
		} `yaml:"builds"`
		Archives []struct {
			BuildsInfo struct {
				Mtime string `yaml:"mtime"`
			} `yaml:"builds_info"`
			Files []struct {
				Source string `yaml:"src"`
				Info   struct {
					Mtime string `yaml:"mtime"`
				} `yaml:"info"`
			} `yaml:"files"`
		} `yaml:"archives"`
		Checksum struct {
			Algorithm string `yaml:"algorithm"`
		} `yaml:"checksum"`
		SBOMs []struct {
			Artifacts string   `yaml:"artifacts"`
			Documents []string `yaml:"documents"`
		} `yaml:"sboms"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("invalid YAML: %v", err)
	}
	if config.Version != 2 {
		t.Errorf("GoReleaser schema version = %d, want 2", config.Version)
	}
	for _, hook := range config.Before.Hooks {
		if hook != "go mod verify" {
			t.Errorf("release hook is not allowed in the privileged publishing job: %q", hook)
		}
	}
	if len(config.Builds) == 0 {
		t.Fatal("no release builds configured")
	}
	if !contains(config.Builds[0].Flags, "-trimpath") {
		t.Error("release build does not use -trimpath")
	}
	ldflags := strings.Join(config.Builds[0].LDFlags, " ")
	for _, variable := range []string{"cmd.version", "cmd.commit", "cmd.buildDate"} {
		if !strings.Contains(ldflags, variable) {
			t.Errorf("release ldflags do not set %s", variable)
		}
	}
	if !strings.EqualFold(config.Checksum.Algorithm, "sha256") {
		t.Errorf("checksum algorithm = %q, want sha256", config.Checksum.Algorithm)
	}
	if len(config.Archives) == 0 || config.Archives[0].BuildsInfo.Mtime != "{{ .CommitDate }}" {
		t.Error("archive binary timestamps are not normalized to the commit date")
	} else {
		if len(config.Archives[0].Files) == 0 {
			t.Error("release archive has no supplemental files")
		}
		for _, file := range config.Archives[0].Files {
			if file.Source == "" || file.Info.Mtime != "{{ .CommitDate }}" {
				t.Errorf("archive file metadata is not reproducible: %+v", file)
			}
		}
	}
	if len(config.SBOMs) == 0 || config.SBOMs[0].Artifacts != "archive" {
		t.Error("archive SBOM generation is not configured")
	}
	if len(config.SBOMs) > 0 && !contains(config.SBOMs[0].Documents, "${artifact}.spdx.json") {
		t.Error("archive SBOMs are not configured as SPDX JSON")
	}
}

var immutableActionReference = regexp.MustCompile(`@[0-9a-fA-F]{40}$`)

func checkWorkflowSteps(t *testing.T, jobName string, steps []any) {
	t.Helper()
	for i, rawStep := range steps {
		step, ok := stringMap(rawStep)
		if !ok {
			t.Errorf("job %q step %d must be a mapping", jobName, i+1)
			continue
		}
		uses, _ := step["uses"].(string)
		if uses == "" {
			continue
		}
		if !immutableActionReference.MatchString(uses) {
			t.Errorf("job %q step %d does not pin an immutable action commit: %q", jobName, i+1, uses)
		}
		if !strings.HasPrefix(uses, "actions/checkout@") {
			continue
		}
		with, ok := stringMap(step["with"])
		if !ok {
			t.Errorf("job %q checkout step does not disable credential persistence", jobName)
			continue
		}
		value, ok := with["persist-credentials"]
		if !ok || fmt.Sprint(value) != "false" {
			t.Errorf("job %q checkout step must set persist-credentials: false", jobName)
		}
	}
}

func stringMap(value any) (map[string]any, bool) {
	result, ok := value.(map[string]any)
	return result, ok
}

func rawSlice(value any) ([]any, bool) {
	result, ok := value.([]any)
	return result, ok
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func jobNeeds(job map[string]any, target string) bool {
	switch needs := job["needs"].(type) {
	case string:
		return needs == target
	case []any:
		for _, dependency := range needs {
			if fmt.Sprint(dependency) == target {
				return true
			}
		}
	}
	return false
}

func assertHasCommand(t *testing.T, job map[string]any, command string) {
	t.Helper()
	for _, rawStep := range mustSteps(t, job) {
		step, _ := stringMap(rawStep)
		if strings.Contains(fmt.Sprint(step["run"]), command) {
			return
		}
	}
	t.Errorf("job does not run %q", command)
}

func assertLacksCommand(t *testing.T, job map[string]any, command string) {
	t.Helper()
	for _, rawStep := range mustSteps(t, job) {
		step, _ := stringMap(rawStep)
		if strings.Contains(fmt.Sprint(step["run"]), command) {
			t.Errorf("privileged publishing job runs %q", command)
		}
	}
}

func assertLacksAction(t *testing.T, job map[string]any, action string) {
	t.Helper()
	for _, rawStep := range mustSteps(t, job) {
		step, _ := stringMap(rawStep)
		if strings.HasPrefix(fmt.Sprint(step["uses"]), action) {
			t.Errorf("isolated job must not use %q", action)
		}
	}
}

func mustSteps(t *testing.T, job map[string]any) []any {
	t.Helper()
	steps, ok := rawSlice(job["steps"])
	if !ok {
		t.Fatal("job has no steps")
	}
	return steps
}
