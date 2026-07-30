package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func detectorsCmd() *cobra.Command {
	c := &cobra.Command{Use: "detectors", Short: "List and describe detectors"}
	c.AddCommand(&cobra.Command{Use: "list", Short: "List detectors", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := load()
		if err != nil {
			return err
		}
		ds, err := detectorSet(cfg, "")
		if err != nil {
			return err
		}
		for _, d := range ds {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", safeTerminalText(d.ID()), d.Severity(), safeTerminalText(d.Name())); err != nil {
				return err
			}
		}
		return nil
	}})
	c.AddCommand(&cobra.Command{Use: "describe [detector-id]", Short: "Describe one detector", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := load()
		if err != nil {
			return err
		}
		ds, err := detectorSet(cfg, "")
		if err != nil {
			return err
		}
		for _, d := range ds {
			if d.ID() == args[0] {
				keywords := make([]string, 0, len(d.Keywords()))
				for _, keyword := range d.Keywords() {
					keywords = append(keywords, safeTerminalText(keyword))
				}
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n%s\nSeverity: %s\nKeywords: %s\n", safeTerminalText(d.Name()), safeTerminalText(d.Description()), d.Severity(), strings.Join(keywords, ", "))
				return err
			}
		}
		return fmt.Errorf("detector %s not found", safeTerminalText(args[0]))
	}})
	return c
}
