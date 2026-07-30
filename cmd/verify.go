package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/khushi/reporeaper/internal/report"
	"github.com/khushi/reporeaper/internal/scanner"
	"github.com/khushi/reporeaper/internal/verify"
	"github.com/spf13/cobra"
)

func verifyCmd() *cobra.Command {
	var baseline, format, output string
	c := &cobra.Command{Use: "verify [repository]", Short: "Compare a new scan with a previous baseline", Example: "reporeaper verify . --baseline report.json\nreporeaper verify . --baseline report.json --format json --output verification.json", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if format != "table" && format != "json" {
			return fmt.Errorf("--format must be table or json")
		}
		cfg, err := load()
		if err != nil {
			return err
		}
		baselineReport, err := verify.LoadBaseline(baseline)
		if err != nil {
			return err
		}
		verificationDetectorConfig := cfg
		verificationDetectorConfig.Detectors.Disabled = nil
		dets, err := detectorSet(verificationDetectorConfig, "")
		if err != nil {
			return err
		}
		scanConfig := verify.ReproductionConfig(baselineReport, cfg.Scan.Workers, cfg.Scan.MaxFileSize)
		r, err := scanner.Scan(ctx(), args[0], scanner.Options{
			Version: version, Detectors: dets, Config: scanConfig,
			// Absence verification always reads current Git objects directly.
			// It must never depend on a mutable trusted-local scan cache.
			Cache: scanner.CacheOptions{},
		})
		if err != nil {
			return scanExecutionError(err)
		}
		res, code, err := verify.CompareReports(baselineReport, r)
		if err != nil {
			return err
		}
		var body []byte
		if format == "json" {
			body, err = json.MarshalIndent(res, "", "  ")
			if err == nil {
				body = append(body, '\n')
			}
		} else {
			body = []byte(verificationTable(res))
		}
		if err != nil {
			return err
		}
		if output != "" {
			err = report.WriteBytes(output, body)
		} else {
			_, err = cmd.OutOrStdout().Write(body)
		}
		if err != nil {
			return err
		}
		if code != 0 {
			return &exitError{code: code, err: fmt.Errorf("verification did not pass (exit code %d)", code)}
		}
		return nil
	}}
	c.Flags().StringVar(&baseline, "baseline", "", "baseline RepoReaper JSON report")
	c.Flags().StringVar(&format, "format", "table", "format: table or json")
	c.Flags().StringVar(&output, "output", "", "write verification output to file")
	_ = c.MarkFlagRequired("baseline")
	return c
}

func verificationTable(result verify.Result) string {
	var body strings.Builder
	status := "evidence-remains"
	if result.Incomplete {
		status = "incomplete"
	} else if result.Passed {
		status = "passed"
	}
	fmt.Fprintf(&body, "Verification: %s\nRepository: %s\nBaseline findings: %d\n",
		status, safeTerminalText(result.Repository), len(result.Items))
	if len(result.Items) == 0 {
		body.WriteString("No baseline findings to verify.\n")
	}
	for _, item := range result.Items {
		fmt.Fprintf(&body, "%s %s %s | scope=%s source=%s history=%s remote=%s residual=%s rotation=%s\n",
			safeTerminalText(item.FindingID), safeTerminalText(item.Fingerprint), safeTerminalText(item.Status),
			safeTerminalText(item.ScopeStatus),
			safeTerminalText(item.SourceRemoval), safeTerminalText(item.ReachableHistory), safeTerminalText(item.RemoteCopy),
			safeTerminalText(item.LocalResidualObjects), safeTerminalText(item.CredentialRotation))
		if len(item.ScopeGaps) > 0 {
			fmt.Fprintf(&body, "  Scope gaps: %s\n", safeTerminalJoin(item.ScopeGaps))
		}
		if len(item.SupportingObservations) > 0 {
			fmt.Fprintf(&body, "  Supporting observations: %s\n", safeTerminalJoin(item.SupportingObservations))
		}
	}
	if len(result.Notes) > 0 {
		body.WriteString("Notes:\n")
		for _, note := range result.Notes {
			fmt.Fprintf(&body, "- %s\n", safeTerminalText(note))
		}
	}
	return body.String()
}

func safeTerminalJoin(values []string) string {
	safe := make([]string, 0, len(values))
	for _, value := range values {
		safe = append(safe, safeTerminalText(value))
	}
	return strings.Join(safe, "; ")
}

func safeTerminalText(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) ||
			character == '\u061c' ||
			character == '\u200e' ||
			character == '\u200f' ||
			character == '\u2028' ||
			character == '\u2029' ||
			(character >= '\u202a' && character <= '\u202e') ||
			(character >= '\u2066' && character <= '\u2069') {
			return '\uFFFD'
		}
		return character
	}, value)
}
