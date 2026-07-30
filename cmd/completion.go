package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func completionCmd(root *cobra.Command) *cobra.Command {
	command := &cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     "Generate shell completion scripts",
		Long:      "Generate a completion script for the selected shell. Write the output to a file sourced by your shell or its completion system.",
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		Example:   "reporeaper completion bash > reporeaper.bash\nreporeaper completion zsh > _reporeaper\nreporeaper completion fish > reporeaper.fish\nreporeaper completion powershell > reporeaper.ps1",
		RunE: func(cmd *cobra.Command, args []string) error {
			return writeCompletion(root, cmd.OutOrStdout(), args[0])
		},
	}
	return command
}

func writeCompletion(root *cobra.Command, output io.Writer, shell string) error {
	switch shell {
	case "bash":
		return root.GenBashCompletion(output)
	case "zsh":
		return root.GenZshCompletion(output)
	case "fish":
		return root.GenFishCompletion(output, true)
	case "powershell":
		return root.GenPowerShellCompletion(output)
	default:
		return fmt.Errorf("unsupported shell %q", shell)
	}
}
