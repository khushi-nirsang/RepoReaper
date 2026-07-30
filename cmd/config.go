package cmd

import (
	"github.com/khushi/reporeaper/internal/config"
	"github.com/spf13/cobra"
)

func configCmd() *cobra.Command {
	c := &cobra.Command{Use: "config", Short: "Configuration helpers"}
	c.AddCommand(&cobra.Command{Use: "validate", Short: "Validate .reporeaper.yaml", Example: "reporeaper config validate\nreporeaper config validate --config .reporeaper.yaml", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		if err := config.Validate(cfg); err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write([]byte("configuration valid\n"))
		return err
	}})
	return c
}
