package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/khushi/reporeaper/internal/config"
	"github.com/khushi/reporeaper/internal/model"
	"github.com/khushi/reporeaper/internal/protect"
	"github.com/spf13/cobra"
)

func protectCmd() *cobra.Command {
	c := &cobra.Command{Use: "protect", Short: "Install or run pre-commit protection"}
	var force bool
	install := &cobra.Command{Use: "install", Short: "Install a local pre-commit hook", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { return protect.Install(ctx(), ".", force) }}
	install.Flags().BoolVar(&force, "force", false, "replace an existing RepoReaper-managed hook")
	c.AddCommand(install)
	c.AddCommand(&cobra.Command{Use: "uninstall", Short: "Remove a RepoReaper-managed hook", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { return protect.Uninstall(ctx(), ".") }})
	c.AddCommand(&cobra.Command{Use: "status", Short: "Show hook status", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		status, err := protect.Status(ctx(), ".")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), safeTerminalText(status))
		return err
	}})
	c.AddCommand(&cobra.Command{Use: "staged", Short: "Scan staged content", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		return runStagedProtection(ctx(), ".", cfg, cmd.ErrOrStderr())
	}})
	return c
}

func stagedFindings(ctx context.Context, repoPath string, cfg config.File) ([]model.Finding, error) {
	result, err := stagedScan(ctx, repoPath, cfg)
	return result.Findings, err
}

func stagedScan(ctx context.Context, repoPath string, cfg config.File) (protect.StagedResult, error) {
	ds, err := detectorSet(cfg, "")
	if err != nil {
		return protect.StagedResult{}, err
	}
	result, err := protect.ScanStaged(ctx, repoPath, ds, cfg.Scan.MaxFileSize)
	if err != nil {
		return protect.StagedResult{}, err
	}
	result.Findings = applyAllowlist(result.Findings, cfg)
	return result, nil
}

func runStagedProtection(ctx context.Context, repoPath string, cfg config.File, output io.Writer) error {
	result, err := stagedScan(ctx, repoPath, cfg)
	if err != nil {
		return err
	}
	for _, warning := range result.Warnings {
		if _, err := fmt.Fprintf(output, "warning: %s\n", safeTerminalText(warning)); err != nil {
			return err
		}
	}
	block := false
	for _, finding := range result.Findings {
		paths := make([]string, 0, len(finding.Paths))
		for _, path := range finding.Paths {
			paths = append(paths, safeTerminalText(path))
		}
		if _, err := fmt.Fprintf(output, "%s %s %s [%s]\n", finding.Severity, safeTerminalText(finding.DetectorID), safeTerminalText(finding.Redacted), strings.Join(paths, ", ")); err != nil {
			return err
		}
		severe := finding.Severity == model.SeverityHigh || finding.Severity == model.SeverityCritical
		confident := finding.Confidence == model.ConfidenceHigh || finding.Confidence == model.ConfidenceConfirmed
		if severe && confident {
			block = true
		}
	}
	if block {
		return fmt.Errorf("staged high or critical secret evidence detected")
	}
	if len(result.Warnings) > 0 {
		return fmt.Errorf("staged content could not be completely inspected")
	}
	return nil
}
