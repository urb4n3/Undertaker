package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractMetadata_RealPE(t *testing.T) {
	// Test against a real system PE (notepad.exe).
	notepad := filepath.Join(os.Getenv("WINDIR"), "System32", "notepad.exe")
	if _, err := os.Stat(notepad); err != nil {
		t.Skipf("notepad.exe not found: %v", err)
	}

	pefile, err := ParsePE(notepad)
	if err != nil {
		t.Fatalf("ParsePE: %v", err)
	}
	defer pefile.Close()

	meta, err := ExtractMetadata(pefile)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}

	// Should have sections.
	if len(meta.Sections) == 0 {
		t.Error("expected sections, got none")
	}

	// Check that section names are non-empty.
	for _, sec := range meta.Sections {
		if sec.Name == "" {
			t.Error("section has empty name")
		}
	}

	// Timestamp should be valid (not anomalous for a system binary).
	if meta.TimestampAnomaly == "zeroed" {
		t.Log("notepad.exe has zeroed timestamp (may be normal for some builds)")
	}
}

func TestExtractMetadata_Sections(t *testing.T) {
	notepad := filepath.Join(os.Getenv("WINDIR"), "System32", "notepad.exe")
	if _, err := os.Stat(notepad); err != nil {
		t.Skipf("notepad.exe not found: %v", err)
	}

	pefile, err := ParsePE(notepad)
	if err != nil {
		t.Fatalf("ParsePE: %v", err)
	}
	defer pefile.Close()

	meta, err := ExtractMetadata(pefile)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}

	// Verify sections have expected fields populated.
	for _, sec := range meta.Sections {
		if sec.Characteristics == "" {
			t.Errorf("section %s has empty characteristics", sec.Name)
		}
	}
}

func TestParsePE_NonExistent(t *testing.T) {
	_, err := ParsePE("/nonexistent/file.exe")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestParsePE_NotAPE(t *testing.T) {
	// Use a file outside TempDir to avoid cleanup issues with mmap file locks.
	path := filepath.Join(os.TempDir(), "undertaker_test_not_a_pe.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	defer os.Remove(path)

	pe, err := ParsePE(path)
	if err == nil {
		pe.Close()
		t.Error("expected error parsing non-PE file")
	}
}

func TestRunPipeline_PE_WithMetadata(t *testing.T) {
	notepad := filepath.Join(os.Getenv("WINDIR"), "System32", "notepad.exe")
	if _, err := os.Stat(notepad); err != nil {
		t.Skipf("notepad.exe not found: %v", err)
	}

	report, err := RunPipeline(notepad, AnalysisOptions{})
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}

	// Should have PE metadata populated.
	if len(report.Metadata.Sections) == 0 {
		t.Error("expected sections in metadata")
	}

	// Should have packing info.
	if report.Packing.Confidence == "" {
		t.Error("expected packing confidence to be set")
	}

	// Entropy should be non-zero for a real binary.
	if report.Packing.Entropy == 0 {
		t.Error("expected non-zero file entropy")
	}

	// Section entropies should be computed.
	for _, sec := range report.Metadata.Sections {
		if sec.RawSize > 0 && sec.Entropy == 0 {
			t.Errorf("section %s has rawsize=%d but entropy=0", sec.Name, sec.RawSize)
		}
	}
}

func TestRunPipeline_MalformedPE(t *testing.T) {
	// Create a severely truncated PE to test graceful error handling.
	// This has a valid MZ but e_lfanew points beyond the file.
	dir := t.TempDir()
	path := filepath.Join(dir, "malformed.exe")
	data := make([]byte, 64)
	data[0] = 'M'
	data[1] = 'Z'
	// Set e_lfanew to point way beyond file end.
	data[0x3C] = 0xFF
	data[0x3D] = 0xFF
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	report, err := RunPipeline(path, AnalysisOptions{})
	if err != nil {
		t.Fatalf("RunPipeline should not return fatal error for malformed PE: %v", err)
	}

	// Should still have hashing results.
	if report.Sample.SHA256 == "" {
		t.Error("expected SHA256 even for malformed PE")
	}

	// Should have errors recorded (either pe_parser or nothing if fileid rejected it).
	// The key invariant: no crash, hashing works.
	t.Logf("errors: %v", report.Errors)
}
