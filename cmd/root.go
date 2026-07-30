package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"

	"github.com/khushi/reporeaper/internal/config"
	"github.com/khushi/reporeaper/internal/detector"
	"github.com/khushi/reporeaper/internal/gitrepo"
	"github.com/khushi/reporeaper/internal/model"
	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
	cfgFile   string
	rootCmd   = &cobra.Command{
		Use:           "reporeaper",
		Short:         "Defensive Git secret-exposure investigation tool",
		Long:          "RepoReaper finds redacted secret evidence in working trees, Git history, refs, reflogs, and unreachable objects without uploading repository contents.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
)

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func Execute() {
	commandContext, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := rootCmd.ExecuteContext(commandContext); err != nil {
		fmt.Fprintln(os.Stderr, safeTerminalText(err.Error()))
		var coded *exitError
		if errors.As(err, &coded) {
			os.Exit(coded.code)
		}
		os.Exit(2)
	}
}

func scanExecutionError(err error) error {
	if errors.Is(err, gitrepo.ErrNotRepository) {
		return &exitError{code: 2, err: err}
	}
	return &exitError{code: 4, err: err}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "configuration file (default .reporeaper.yaml)")
	rootCmd.AddCommand(scanCmd(), investigateCmd(), verifyCmd(), detectorsCmd(), configCmd(), protectCmd(), doctorCmd(), completionCmd(rootCmd), versionCmd())
}

func ctx() context.Context {
	if rootCmd.Context() != nil {
		return rootCmd.Context()
	}
	return context.Background()
}

func load() (config.File, error) { return config.Load(cfgFile) }

func detectorSet(cfg config.File, onlyCSV string) ([]detector.Detector, error) {
	disabled := map[string]bool{}
	for _, id := range cfg.Detectors.Disabled {
		disabled[id] = true
	}
	var custom []detector.Detector
	for _, c := range cfg.Detectors.Custom {
		remediation := detector.GenericRemediation()
		remediation = append([]string{c.Remediation}, remediation...)
		d, err := detector.NewRegex(c.ID, c.Name, c.Description, "custom", model.Severity(c.Severity), c.Keywords, c.Regex, c.MinimumEntropy, nil, remediation)
		if err != nil {
			return nil, err
		}
		custom = append(custom, d)
	}
	all := detector.Registry(custom, disabled)
	if onlyCSV == "" {
		return all, nil
	}
	allow := map[string]bool{}
	for _, id := range strings.Split(onlyCSV, ",") {
		id = strings.TrimSpace(id)
		if id != "" {
			if id == "private-key" {
				allow["pem-private-key"] = true
				allow["openssh-private-key"] = true
				allow["pgp-private-key"] = true
			} else {
				allow[id] = true
			}
		}
	}
	var out []detector.Detector
	for _, d := range all {
		if allow[d.ID()] {
			out = append(out, d)
			delete(allow, d.ID())
		}
	}
	if len(allow) > 0 {
		var unknown []string
		for id := range allow {
			unknown = append(unknown, id)
		}
		sort.Strings(unknown)
		return nil, fmt.Errorf("unknown or disabled detector(s): %s", strings.Join(unknown, ", "))
	}
	return out, nil
}

func severities(csv string) []string {
	if csv == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(csv, ",") {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func applyAllowlist(in []model.Finding, cfg config.File) []model.Finding {
	fp := map[string]bool{}
	commits := map[string]bool{}
	for _, v := range cfg.Allowlist.Fingerprints {
		fp[v] = true
	}
	for _, v := range cfg.Allowlist.Commits {
		commits[v] = true
	}
	var regexes []*regexp.Regexp
	for _, rx := range cfg.Allowlist.Regexes {
		if re, err := regexp.Compile(rx); err == nil {
			regexes = append(regexes, re)
		}
	}
	out := make([]model.Finding, 0, len(in))
	for _, f := range in {
		if fp[f.Fingerprint] || fp[f.ShortFingerprint] || allowPath(f, cfg.Allowlist.Paths) || allowCommit(f, commits) || allowRegex(f, regexes) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func allowPath(f model.Finding, patterns []string) bool {
	if len(f.Paths) == 0 || len(patterns) == 0 {
		return false
	}
	for _, filePath := range f.Paths {
		matched := false
		for _, pat := range patterns {
			if re, err := allowlistGlobRegexp(pat); err == nil && re.MatchString(strings.ReplaceAll(filePath, "\\", "/")) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func allowlistGlobRegexp(pattern string) (*regexp.Regexp, error) {
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	var expression strings.Builder
	expression.WriteByte('^')
	for i := 0; i < len(pattern); {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i += 2
				if i < len(pattern) && pattern[i] == '/' {
					expression.WriteString(`(?:.*/)?`)
					i++
				} else {
					expression.WriteString(`.*`)
				}
			} else {
				expression.WriteString(`[^/]*`)
				i++
			}
		case '?':
			expression.WriteString(`[^/]`)
			i++
		default:
			expression.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
			i++
		}
	}
	expression.WriteByte('$')
	return regexp.Compile(expression.String())
}

func allowCommit(f model.Finding, commits map[string]bool) bool {
	matched := false
	for _, e := range f.Evidence {
		if e.Commit == "" || !commits[e.Commit] {
			return false
		}
		matched = true
	}
	return matched
}

func allowRegex(f model.Finding, regexes []*regexp.Regexp) bool {
	text := f.DetectorID + " " + f.Redacted + " " + strings.Join(f.Paths, " ")
	for _, re := range regexes {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}
