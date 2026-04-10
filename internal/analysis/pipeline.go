package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

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

	// Step 3: PE-specific analysis — parse PE and run analyzers concurrently.
	runPEAnalyzers(absPath, report)

	return report, nil
}

// runPEAnalyzers parses the PE and runs metadata, entropy, packing, and overlay
// analyzers concurrently via goroutines. Errors are captured in the report.
func runPEAnalyzers(path string, report *models.AnalysisReport) {
	pefile, err := ParsePE(path)
	if err != nil {
		report.Errors = append(report.Errors, models.AnalyzerError{
			Analyzer: "pe_parser",
			Error:    err.Error(),
		})
		return
	}
	defer pefile.Close()

	// Extract metadata first — other analyzers depend on section info.
	meta, err := ExtractMetadata(pefile)
	if err != nil {
		report.Errors = append(report.Errors, models.AnalyzerError{
			Analyzer: "metadata",
			Error:    err.Error(),
		})
		return
	}
	report.Metadata = *meta

	// Run independent analyzers concurrently.
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Entropy: per-section + overall file.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer catchAnalyzerPanic("entropy", report, &mu)

		ComputeSectionEntropies(pefile, &report.Metadata)

		fileEntropy, err := ComputeFileEntropy(path)
		if err != nil {
			mu.Lock()
			report.Errors = append(report.Errors, models.AnalyzerError{
				Analyzer: "entropy",
				Error:    err.Error(),
			})
			mu.Unlock()
			return
		}

		// Packing detection uses file entropy + metadata.
		packInfo := DetectPacking(pefile, &report.Metadata, fileEntropy)
		mu.Lock()
		report.Packing = *packInfo
		mu.Unlock()
	}()

	// Overlay detection.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer catchAnalyzerPanic("overlay", report, &mu)

		overlay, err := DetectOverlay(pefile, path)
		if err != nil {
			mu.Lock()
			report.Errors = append(report.Errors, models.AnalyzerError{
				Analyzer: "overlay",
				Error:    err.Error(),
			})
			mu.Unlock()
			return
		}

		mu.Lock()
		report.Overlay = overlay
		mu.Unlock()
	}()

	wg.Wait()
}

// catchAnalyzerPanic recovers from panics in analyzer goroutines and records
// the error in the report. Must be called via defer.
func catchAnalyzerPanic(name string, report *models.AnalysisReport, mu *sync.Mutex) {
	if r := recover(); r != nil {
		mu.Lock()
		report.Errors = append(report.Errors, models.AnalyzerError{
			Analyzer: name,
			Error:    fmt.Sprintf("panic: %v", r),
		})
		mu.Unlock()
	}
}
