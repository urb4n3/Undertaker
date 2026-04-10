package analysis

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/urb4n3/undertaker/internal/models"
)

// AnalysisOptions controls pipeline behaviour from CLI flags.
type AnalysisOptions struct {
	Full  bool // Override string/IOC caps
	JSON  bool // Output JSON to stdout
	Quiet bool // No TUI, save report silently
}

// RunPipeline executes the analysis pipeline on the given file and returns a report.
func RunPipeline(path string, opts AnalysisOptions) (*models.AnalysisReport, error) {
	// Resolve absolute path.
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}

	// Verify file exists and is readable.
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("accessing file: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory, not a file", absPath)
	}

	report := &models.AnalysisReport{}
	report.Sample.Path = absPath
	report.Sample.FileSize = info.Size()

	// Step 1: File identification.
	fileID, err := IdentifyFile(absPath)
	if err != nil {
		report.Errors = append(report.Errors, models.AnalyzerError{
			Analyzer: "fileid",
			Error:    err.Error(),
		})
		// File ID failure is partially recoverable — continue with hashing.
		report.Sample.FileType = FileTypeUnknown
	} else {
		report.Sample.FileType = fileID.FileType
		report.Sample.Architecture = fileID.Architecture
	}

	// Step 2: Hashing (always runs regardless of file type).
	hashes, err := HashFile(absPath)
	if err != nil {
		report.Errors = append(report.Errors, models.AnalyzerError{
			Analyzer: "hashing",
			Error:    err.Error(),
		})
	} else {
		report.Sample.MD5 = hashes.MD5
		report.Sample.SHA1 = hashes.SHA1
		report.Sample.SHA256 = hashes.SHA256
		report.Sample.SSDeep = hashes.SSDeep
	}

	// Imphash stub — completed in Stage 4.
	report.Sample.ImpHash = ComputeImpHash()

	// File type guard: PE-specific analyzers only run on PE files.
	// Non-PE routing is completed in Stage 7. For now, non-PE files
	// get hashing + file ID only.
	if fileID != nil && !IsPEType(fileID.FileType) {
		// Non-PE: only hashing + file ID for now.
		// Stages 3+ will add strings/IOC extraction for non-PE types.
		return report, nil
	}

	// PE-specific analysis will be added in Stage 2+.
	// For now, return the report with hashing + file ID.

	return report, nil
}
