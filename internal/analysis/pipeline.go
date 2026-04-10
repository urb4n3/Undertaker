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
		return report, nil
	}

	// Step 3: Run PE-specific and string/IOC analyzers concurrently.
	// Strings + IOCs run sequentially (IOCs depend on strings) but in
	// parallel with PE structural analyzers.
	var outerWg sync.WaitGroup
	var mu sync.Mutex

	outerWg.Add(1)
	go func() {
		defer outerWg.Done()
		runPEAnalyzers(absPath, report, &mu)
	}()

	outerWg.Add(1)
	go func() {
		defer outerWg.Done()
		runStringIOCAnalyzers(absPath, report, opts, &mu)
	}()

	outerWg.Wait()

	return report, nil
}

// runStringIOCAnalyzers extracts strings then IOCs (sequentially, since IOCs
// depend on strings). Thread-safe via mutex.
func runStringIOCAnalyzers(path string, report *models.AnalysisReport, opts AnalysisOptions, mu *sync.Mutex) {
	defer func() {
		if r := recover(); r != nil {
			mu.Lock()
			report.Errors = append(report.Errors, models.AnalyzerError{
				Analyzer: "strings",
				Error:    fmt.Sprintf("panic: %v", r),
			})
			mu.Unlock()
		}
	}()

	strings, err := ExtractStrings(path, opts.Full)
	if err != nil {
		mu.Lock()
		report.Errors = append(report.Errors, models.AnalyzerError{
			Analyzer: "strings",
			Error:    err.Error(),
		})
		mu.Unlock()
		return
	}

	mu.Lock()
	report.Strings = strings
	mu.Unlock()

	iocs, err := ExtractIOCs(strings, opts.Full)
	if err != nil {
		mu.Lock()
		report.Errors = append(report.Errors, models.AnalyzerError{
			Analyzer: "iocs",
			Error:    err.Error(),
		})
		mu.Unlock()
		return
	}

	mu.Lock()
	report.IOCs = iocs
	mu.Unlock()
}

// runPEAnalyzers parses the PE and runs metadata, entropy, packing, and overlay
// analyzers concurrently via goroutines. Errors are captured in the report.
func runPEAnalyzers(path string, report *models.AnalysisReport, outerMu *sync.Mutex) {
	pefile, err := ParsePE(path)
	if err != nil {
		outerMu.Lock()
		report.Errors = append(report.Errors, models.AnalyzerError{
			Analyzer: "pe_parser",
			Error:    err.Error(),
		})
		outerMu.Unlock()
		return
	}
	defer pefile.Close()

	// Extract metadata first — other analyzers depend on section info.
	meta, err := ExtractMetadata(pefile)
	if err != nil {
		outerMu.Lock()
		report.Errors = append(report.Errors, models.AnalyzerError{
			Analyzer: "metadata",
			Error:    err.Error(),
		})
		outerMu.Unlock()
		return
	}
	outerMu.Lock()
	report.Metadata = *meta
	outerMu.Unlock()

	// Run independent analyzers concurrently.
	var wg sync.WaitGroup

	// Entropy: per-section + overall file.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer catchAnalyzerPanic("entropy", report, outerMu)

		ComputeSectionEntropies(pefile, &report.Metadata)

		fileEntropy, err := ComputeFileEntropy(path)
		if err != nil {
			outerMu.Lock()
			report.Errors = append(report.Errors, models.AnalyzerError{
				Analyzer: "entropy",
				Error:    err.Error(),
			})
			outerMu.Unlock()
			return
		}

		// Packing detection uses file entropy + metadata.
		packInfo := DetectPacking(pefile, &report.Metadata, fileEntropy)
		outerMu.Lock()
		report.Packing = *packInfo
		outerMu.Unlock()
	}()

	// Overlay detection.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer catchAnalyzerPanic("overlay", report, outerMu)

		overlay, err := DetectOverlay(pefile, path)
		if err != nil {
			outerMu.Lock()
			report.Errors = append(report.Errors, models.AnalyzerError{
				Analyzer: "overlay",
				Error:    err.Error(),
			})
			outerMu.Unlock()
			return
		}

		outerMu.Lock()
		report.Overlay = overlay
		outerMu.Unlock()
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
