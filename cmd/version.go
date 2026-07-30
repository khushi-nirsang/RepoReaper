package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "version",
		Short:   "Show version information",
		Example: "reporeaper version",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "reporeaper %s\ncommit: %s\nbuilt: %s\n", safeTerminalText(version), safeTerminalText(commit), safeTerminalText(buildDate))
			return err
		},
	}
}
