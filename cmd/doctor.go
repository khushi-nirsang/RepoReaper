package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/khushi/reporeaper/internal/config"
	"github.com/khushi/reporeaper/internal/gitrepo"
	"github.com/spf13/cobra"
)

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type doctorReport struct {
	Healthy  bool          `json:"healthy"`
	OK       int           `json:"ok"`
	Warnings int           `json:"warnings"`
	Errors   int           `json:"errors"`
	Checks   []doctorCheck `json:"checks"`
}

func doctorCmd() *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "doctor [repository]",
		Short: "Check whether RepoReaper is ready to scan",
		Long:  "Run read-only checks for configuration validity, Git availability, repository access, and history coverage.",
		Args:  cobra.MaximumNArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
			return nil, cobra.ShellCompDirectiveFilterDirs
		},
		Example: "reporeaper doctor\nreporeaper doctor /path/to/repository\nreporeaper doctor . --format json",
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" {
				return fmt.Errorf("--format must be text or json")
			}
			repository := "."
			if len(args) == 1 {
				repository = args[0]
			}
			report := diagnose(cmd.Context(), repository, cfgFile)
			if err := writeDoctorReport(cmd.OutOrStdout(), format, report); err != nil {
				return err
			}
			if !report.Healthy {
				return &exitError{code: 2, err: fmt.Errorf("doctor found %d error(s)", report.Errors)}
			}
			return nil
		},
	}
	command.Flags().StringVar(&format, "format", "text", "output format: text or json")
	if err := command.RegisterFlagCompletionFunc("format", cobra.FixedCompletions(
		[]string{"text", "json"},
		cobra.ShellCompDirectiveNoFileComp,
	)); err != nil {
		panic(err)
	}
	return command
}

func diagnose(ctx context.Context, repository, configPath string) doctorReport {
	report := doctorReport{Healthy: true}
	add := func(name, status, detail string) {
		report.Checks = append(report.Checks, doctorCheck{Name: name, Status: status, Detail: detail})
		switch status {
		case "ok":
			report.OK++
		case "warning":
			report.Warnings++
		case "error":
			report.Errors++
			report.Healthy = false
		}
	}

	add("runtime", "ok", fmt.Sprintf("reporeaper %s; %s; %s/%s", version, runtime.Version(), runtime.GOOS, runtime.GOARCH))

	cfg, err := config.Load(configPath)
	if err != nil {
		add("configuration", "error", err.Error())
	} else {
		detectors, detectorErr := detectorSet(cfg, "")
		if detectorErr != nil {
			add("configuration", "error", detectorErr.Error())
		} else {
			add("configuration", "ok", fmt.Sprintf("version %d; %d active detectors; redacted reports enforced", cfg.Version, len(detectors)))
		}
	}

	gitVersion, err := gitrepo.GitVersion(ctx)
	if err != nil {
		add("git", "error", err.Error())
		return report
	}
	add("git", "ok", gitVersion)

	repo, err := gitrepo.Open(ctx, repository)
	if err != nil {
		add("repository", "error", err.Error())
		return report
	}
	add("repository", "ok", repo.Path)

	metadata, err := repo.Diagnostics(ctx)
	if err != nil {
		add("history", "error", err.Error())
		return report
	}
	if metadata.Head == "" {
		add("history", "warning", "repository has no commits yet")
	} else {
		detail := "HEAD " + shortObjectID(metadata.Head)
		if metadata.Branch != "" {
			detail += " on " + metadata.Branch
		}
		add("history", "ok", detail)
	}
	if metadata.Shallow {
		add("coverage", "warning", "shallow repository; fetch complete history before a definitive scan")
	} else {
		add("coverage", "ok", "repository is not shallow")
	}
	batchReader, err := repo.NewBatchBlobReader(ctx)
	if err != nil {
		add("object-reader", "error", err.Error())
		return report
	}
	if err := batchReader.Close(); err != nil {
		add("object-reader", "error", err.Error())
		return report
	}
	add("object-reader", "ok", "Git batch object reader is available")
	return report
}

func shortObjectID(oid string) string {
	if len(oid) > 12 {
		return oid[:12]
	}
	return oid
}

func writeDoctorReport(output io.Writer, format string, report doctorReport) error {
	if format == "json" {
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	if _, err := fmt.Fprintln(output, "RepoReaper doctor"); err != nil {
		return err
	}
	for _, check := range report.Checks {
		label := safeTerminalText(strings.ToUpper(check.Status))
		if _, err := fmt.Fprintf(output, "  [%-7s] %-13s %s\n", label, safeTerminalText(check.Name), safeTerminalText(check.Detail)); err != nil {
			return err
		}
	}
	state := "healthy"
	if !report.Healthy {
		state = "unhealthy"
	} else if report.Warnings > 0 {
		state = "healthy with warnings"
	}
	_, err := fmt.Fprintf(output, "Summary: %s (%d ok, %d warning(s), %d error(s))\n", state, report.OK, report.Warnings, report.Errors)
	return err
}
