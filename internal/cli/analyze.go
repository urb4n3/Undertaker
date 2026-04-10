package cli

import (
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/urb4n3/undertaker/internal/analysis"
	"github.com/urb4n3/undertaker/internal/config"
	"github.com/urb4n3/undertaker/internal/models"
	"github.com/urb4n3/undertaker/internal/reporting"
	"github.com/urb4n3/undertaker/internal/tui"
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
	analyzeCmd.Flags().BoolVar(&flagJSON, "json", false, "Output JSON to stdout instead of saving report")
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

	// --json: run pipeline, output JSON to stdout.
	if flagJSON {
		report, err := analysis.RunPipeline(filePath, opts)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}
		jsonData, err := reporting.GenerateJSON(report)
		if err != nil {
			return fmt.Errorf("generating JSON: %w", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	// --quiet: run pipeline, save reports silently.
	if flagQuiet {
		report, err := analysis.RunPipeline(filePath, opts)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}
		return saveReports(report, true)
	}

	// Default: run with TUI.
	return runWithTUI(filePath, opts)
}

func runWithTUI(filePath string, opts analysis.AnalysisOptions) error {
	m := tui.NewModel(filePath)
	p := tea.NewProgram(m, tea.WithAltScreen())

	// Set up progress callback that sends messages to the TUI.
	opts.OnProgress = func(msg string) {
		p.Send(tui.ProgressMsg{Text: msg})
	}

	// Run analysis in background goroutine.
	go func() {
		report, err := analysis.RunPipeline(filePath, opts)
		if err != nil {
			p.Send(tui.AnalysisCompleteMsg{Err: err})
			return
		}

		// Save reports.
		markdown := reporting.GenerateMarkdown(report)
		caseDir, saveErr := createCaseDir(report.Sample.SHA256)
		if saveErr == nil {
			mdPath := filepath.Join(caseDir, "report.md")
			_ = os.WriteFile(mdPath, []byte(markdown), 0o640)
			jsonData, _ := reporting.GenerateJSON(report)
			jsonPath := filepath.Join(caseDir, "report.json")
			_ = os.WriteFile(jsonPath, jsonData, 0o640)
		}

		// Send complete message with results attached to model.
		p.Send(tui.AnalysisCompleteMsg{
			Report: report,
		})
		// Set markdown and caseDir on model via special message.
		p.Send(tui.ReportReadyMsg{
			Markdown: markdown,
			CaseDir:  caseDir,
		})
	}()

	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	// If user quit before completion, print partial info.
	_ = finalModel
	return nil
}

func saveReports(report *models.AnalysisReport, quiet bool) error {
	markdown := reporting.GenerateMarkdown(report)
	caseDir, err := createCaseDir(report.Sample.SHA256)
	if err != nil {
		return fmt.Errorf("creating case directory: %w", err)
	}

	mdPath := filepath.Join(caseDir, "report.md")
	if err := os.WriteFile(mdPath, []byte(markdown), 0o640); err != nil {
		return fmt.Errorf("writing markdown report: %w", err)
	}

	jsonData, err := reporting.GenerateJSON(report)
	if err != nil {
		return fmt.Errorf("generating JSON: %w", err)
	}
	jsonPath := filepath.Join(caseDir, "report.json")
	if err := os.WriteFile(jsonPath, jsonData, 0o640); err != nil {
		return fmt.Errorf("writing JSON report: %w", err)
	}

	if quiet {
		fmt.Printf("Report saved to %s\n", mdPath)
	}
	return nil
}

func createCaseDir(sha256 string) (string, error) {
	cfg, _ := config.Load()
	baseDir := cfg.Output.CaseDir
	if baseDir == "" {
		baseDir = "./cases"
	}

	prefix := sha256
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}

	caseDir := filepath.Join(baseDir, prefix)
	if err := os.MkdirAll(caseDir, 0o750); err != nil {
		return "", fmt.Errorf("creating directory %s: %w", caseDir, err)
	}

	return caseDir, nil
}
