package cmd

import (
	"github.com/khushi/reporeaper/internal/investigate"
	"github.com/spf13/cobra"
)

func investigateCmd() *cobra.Command {
	var reportPath, finding string
	c := &cobra.Command{Use: "investigate", Short: "Investigate a RepoReaper JSON report", Example: "reporeaper investigate --report report.json\nreporeaper investigate --report report.json --finding RR-0001", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		out, err := investigate.Run(reportPath, finding)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write([]byte(out))
		return err
	}}
	c.Flags().StringVar(&reportPath, "report", "", "RepoReaper JSON report")
	c.Flags().StringVar(&finding, "finding", "", "finding ID to inspect")
	_ = c.MarkFlagRequired("report")
	return c
}
