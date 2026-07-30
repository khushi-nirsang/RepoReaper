package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/khushi/reporeaper/internal/model"
	"github.com/khushi/reporeaper/internal/report"
	"github.com/khushi/reporeaper/internal/scanner"
	"github.com/spf13/cobra"
)

func scanCmd() *cobra.Command {
	var format, output, severity, detectorIDs, since, until, failOn, failScope, baselinePath string
	var includeUntracked, branches, tags, allRefs, unreachable, reflogs, progress, cacheEnabled bool
	var workers, cacheMaxEntries int
	var maxFileSize, cacheMaxSize int64
	var cachePath string
	c := &cobra.Command{
		Use:     "scan [repository]",
		Short:   "Scan a repository for current and historical secret exposure",
		Example: "reporeaper scan .\nreporeaper scan . --all-refs --unreachable --format json --output report.json\nreporeaper scan . --severity high,critical --detector github-token,private-key --since 2025-01-01",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("format") {
				format = cfg.Report.DefaultFormat
			}
			if !cmd.Flags().Changed("include-untracked") {
				includeUntracked = cfg.Scan.IncludeUntracked
			}
			if !cmd.Flags().Changed("branches") {
				branches = cfg.Scan.Branches
			}
			if !cmd.Flags().Changed("tags") {
				tags = cfg.Scan.Tags
			}
			if !cmd.Flags().Changed("unreachable") {
				unreachable = cfg.Scan.Unreachable
			}
			if !cmd.Flags().Changed("reflogs") {
				reflogs = cfg.Scan.Reflogs
			}
			if !cmd.Flags().Changed("workers") {
				workers = cfg.Scan.Workers
			}
			if !cmd.Flags().Changed("max-file-size") {
				maxFileSize = cfg.Scan.MaxFileSize
			}
			if !cmd.Flags().Changed("cache") {
				cacheEnabled = cfg.Scan.Cache.Enabled
			}
			if !cmd.Flags().Changed("cache-path") {
				cachePath = cfg.Scan.Cache.Path
			}
			if !cmd.Flags().Changed("cache-max-entries") {
				cacheMaxEntries = cfg.Scan.Cache.MaxEntries
			}
			if !cmd.Flags().Changed("cache-max-size") {
				cacheMaxSize = cfg.Scan.Cache.MaxSize
			}
			if !cmd.Flags().Changed("fail-on") {
				failOn = cfg.Policy.FailOn
			}
			if !cmd.Flags().Changed("fail-scope") {
				failScope = cfg.Policy.Scope
			}
			if failScope == "" {
				failScope = "any"
			}
			dets, err := detectorSet(cfg, detectorIDs)
			if err != nil {
				return err
			}
			if err := validateScanFlagsWithCache(format, severity, since, until, workers, maxFileSize, cacheMaxEntries, cacheMaxSize); err != nil {
				return err
			}
			if err := validateScanPolicy(failOn, failScope); err != nil {
				return err
			}
			normalizedSince, normalizedUntil, err := normalizeScanDates(since, until, time.Local)
			if err != nil {
				return err
			}
			var baseline *model.Report
			if baselinePath != "" {
				loaded, err := loadScanBaseline(baselinePath)
				if err != nil {
					return fmt.Errorf("load scan baseline: %w", err)
				}
				baseline = &loaded
			}
			showProgress := progress || isTerminal(os.Stderr)
			if showProgress {
				fmt.Fprintln(os.Stderr, "RepoReaper: scanning repository metadata and Git objects...")
			}
			r, err := scanner.Scan(ctx(), args[0], scanner.Options{
				Version: version, Detectors: dets,
				Config: model.ScanConfig{IncludeUntracked: includeUntracked, Branches: branches, Tags: tags, AllRefs: allRefs, Unreachable: unreachable, Reflogs: reflogs, Workers: workers, MaxFileSize: maxFileSize, Severity: severities(severity), Detectors: severities(detectorIDs), Since: normalizedSince, Until: normalizedUntil},
				Cache:  scanner.CacheOptions{Enabled: cacheEnabled, Path: cachePath, MaxEntries: cacheMaxEntries, MaxBytes: cacheMaxSize},
			})
			if err != nil {
				return scanExecutionError(err)
			}
			beforeAllowlist := len(r.Findings)
			r.Findings = applyAllowlist(r.Findings, cfg)
			allowlistSuppressed := beforeAllowlist - len(r.Findings)
			baselineSuppressed := 0
			if baseline != nil {
				if err := validateBaselineRepository(baseline.Repository, r.Repository); err != nil {
					return err
				}
				r.Findings, baselineSuppressed = suppressBaselineFindings(r.Findings, *baseline)
			}
			policyFindings := r.Findings
			if severity != "" {
				r.Findings = filterSeverity(r.Findings, severities(severity))
			}
			scanner.Recalculate(&r, allowlistSuppressed, baselineSuppressed)
			if showProgress {
				fmt.Fprintf(os.Stderr, "RepoReaper: analyzed %d commits and %d unique objects.\n", r.Stats.CommitsAnalyzed, r.Stats.ObjectsScanned)
			}
			triggered := scanPolicyMatches(policyFindings, failOn, failScope)
			if err := report.Write(output, format, r); err != nil {
				return err
			}
			if triggered > 0 {
				return &exitError{code: 1, err: fmt.Errorf("scan policy failed: %d finding(s) at or above %s in %s scope", triggered, failOn, failScope)}
			}
			return nil
		},
	}
	c.Flags().StringVar(&format, "format", "table", "report format: table, json, html, sarif")
	c.Flags().StringVar(&output, "output", "", "write report to file")
	c.Flags().StringVar(&severity, "severity", "", "comma-separated severities")
	c.Flags().StringVar(&detectorIDs, "detector", "", "comma-separated detector IDs")
	c.Flags().StringVar(&since, "since", "", "only analyze commits since date")
	c.Flags().StringVar(&until, "until", "", "only analyze commits until date")
	c.Flags().BoolVar(&includeUntracked, "include-untracked", false, "include non-ignored untracked working-tree files")
	c.Flags().BoolVar(&branches, "branches", true, "scan local and remote-tracking branches")
	c.Flags().BoolVar(&tags, "tags", true, "scan tags")
	c.Flags().BoolVar(&allRefs, "all-refs", false, "scan all refs")
	c.Flags().BoolVar(&unreachable, "unreachable", false, "scan dangling and unreachable objects")
	c.Flags().BoolVar(&reflogs, "reflogs", false, "scan commits referenced by reflogs")
	c.Flags().IntVar(&workers, "workers", 4, "bounded worker count")
	c.Flags().Int64Var(&maxFileSize, "max-file-size", 5*1024*1024, "maximum blob/file size")
	c.Flags().BoolVar(&cacheEnabled, "cache", false, "enable the bounded persistent Git blob result cache")
	c.Flags().StringVar(&cachePath, "cache-path", "", "cache file path inside the repository's dedicated RepoReaper Git directory")
	c.Flags().IntVar(&cacheMaxEntries, "cache-max-entries", 50_000, "maximum cached Git blob results")
	c.Flags().Int64Var(&cacheMaxSize, "cache-max-size", 64*1024*1024, "maximum cache file size in bytes")
	c.Flags().BoolVar(&progress, "progress", false, "show progress diagnostics on stderr")
	c.Flags().StringVar(&failOn, "fail-on", "", "exit 1 for findings at or above severity: info, low, medium, high, critical")
	c.Flags().StringVar(&failScope, "fail-scope", "any", "evidence scope for --fail-on: any, current, reachable, residual")
	c.Flags().StringVar(&baselinePath, "baseline", "", "suppress findings already known at the same repository paths in a RepoReaper JSON report")
	return c
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func validateScanFlags(format, severity, since, until string, workers int, maxFileSize int64) error {
	return validateScanFlagsWithCache(format, severity, since, until, workers, maxFileSize, 50_000, 64*1024*1024)
}

func validateScanFlagsWithCache(format, severity, since, until string, workers int, maxFileSize int64, cacheMaxEntries int, cacheMaxSize int64) error {
	switch format {
	case "table", "json", "html", "sarif":
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
	validSeverity := map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	for _, value := range severities(severity) {
		if !validSeverity[value] {
			return fmt.Errorf("unsupported severity %q", value)
		}
	}
	for name, value := range map[string]string{"since": since, "until": until} {
		if value != "" {
			if _, err := time.Parse("2006-01-02", value); err != nil {
				return fmt.Errorf("--%s must use YYYY-MM-DD", name)
			}
		}
	}
	if workers < 1 || workers > 64 {
		return fmt.Errorf("workers must be between 1 and 64")
	}
	if maxFileSize < 1 || maxFileSize > 1024*1024*1024 {
		return fmt.Errorf("max-file-size must be between 1 and 1073741824")
	}
	if cacheMaxEntries < 1 || cacheMaxEntries > 1_000_000 {
		return fmt.Errorf("cache-max-entries must be between 1 and 1000000")
	}
	if cacheMaxSize < 1024 || cacheMaxSize > 1024*1024*1024 {
		return fmt.Errorf("cache-max-size must be between 1024 and 1073741824")
	}
	return nil
}

func normalizeScanDates(since, until string, location *time.Location) (string, string, error) {
	if location == nil {
		location = time.Local
	}
	normalize := func(name, value string, endOfDay bool) (string, error) {
		if value == "" {
			return "", nil
		}
		day, err := time.ParseInLocation("2006-01-02", value, location)
		if err != nil {
			return "", fmt.Errorf("--%s must use YYYY-MM-DD", name)
		}
		if endOfDay {
			day = day.AddDate(0, 0, 1).Add(-time.Second)
		}
		return day.Format(time.RFC3339), nil
	}
	normalizedSince, err := normalize("since", since, false)
	if err != nil {
		return "", "", err
	}
	normalizedUntil, err := normalize("until", until, true)
	if err != nil {
		return "", "", err
	}
	if normalizedSince != "" && normalizedUntil != "" {
		sinceTime, _ := time.Parse(time.RFC3339, normalizedSince)
		untilTime, _ := time.Parse(time.RFC3339, normalizedUntil)
		if sinceTime.After(untilTime) {
			return "", "", fmt.Errorf("--since must be on or before --until")
		}
	}
	return normalizedSince, normalizedUntil, nil
}

func filterSeverity(in []model.Finding, allowed []string) []model.Finding {
	m := map[string]bool{}
	for _, s := range allowed {
		m[s] = true
	}
	out := make([]model.Finding, 0, len(in))
	for _, f := range in {
		if m[string(f.Severity)] {
			out = append(out, f)
		}
	}
	return out
}

func validateScanPolicy(failOn, scope string) error {
	if failOn != "" {
		switch model.Severity(failOn) {
		case model.SeverityInfo, model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical:
		default:
			return fmt.Errorf("--fail-on must be info, low, medium, high, or critical")
		}
	}
	switch scope {
	case "any", "current", "reachable", "residual":
		return nil
	default:
		return fmt.Errorf("--fail-scope must be any, current, reachable, or residual")
	}
}

func scanPolicyMatches(findings []model.Finding, failOn, scope string) int {
	if failOn == "" {
		return 0
	}
	threshold := scanSeverityRank(model.Severity(failOn))
	matches := 0
	for _, finding := range findings {
		if scanSeverityRank(finding.Severity) < threshold || !findingInPolicyScope(finding, scope) {
			continue
		}
		matches++
	}
	return matches
}

func findingInPolicyScope(finding model.Finding, scope string) bool {
	switch scope {
	case "current":
		return finding.InHead || finding.InIndex || finding.InWorkingTree || finding.InTrackedWorkingTree || finding.InUntracked
	case "reachable":
		return finding.InHead || finding.InDirectRef || finding.CommitCount > 0 || len(finding.Branches) > 0 || len(finding.Tags) > 0
	case "residual":
		return finding.InReflog || finding.InUnreachable
	default:
		return true
	}
}

func scanSeverityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}
