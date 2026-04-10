package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/urb4n3/undertaker/internal/analysis"
	"github.com/spf13/cobra"
)

var (
	flagJSON  bool
	flagQuiet bool
	flagFull  bool
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze <file>",
	Short: "Run static analysis on a file",
	Long:  `Analyze a file with all applicable static analyzers and produce a structured report.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runAnalyze,
}

func init() {
	analyzeCmd.Flags().BoolVar(&flagJSON, "json", false, "Output JSON to stdout instead of TUI")
	analyzeCmd.Flags().BoolVar(&flagQuiet, "quiet", false, "No TUI, just save report to case directory")
	analyzeCmd.Flags().BoolVar(&flagFull, "full", false, "No caps on strings/IOCs — include everything")
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	// Verify the file exists before starting analysis.
	if _, err := os.Stat(filePath); err != nil {
		return fmt.Errorf("cannot access file: %w", err)
	}

	opts := analysis.AnalysisOptions{
		Full:  flagFull,
		JSON:  flagJSON,
		Quiet: flagQuiet,
	}

	report, err := analysis.RunPipeline(filePath, opts)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// For Stage 1, output JSON to stdout as temporary output.
	// Markdown reporting and TUI come in later stages.
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encoding report: %w", err)
	}

	return nil
}
