package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "undertaker",
	Short: "Static malware analysis and triage tool",
	Long: `Undertaker is a static malware analysis tool that triages a sample
and produces a structured report for use with Claude and Ghidra MCP.

Run 'undertaker analyze <file>' to perform a full static analysis.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(configCmd)
}
