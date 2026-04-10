package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunPipeline_ScriptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.ps1")
	content := []byte("Write-Host 'hello world'")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	report, err := RunPipeline(path, AnalysisOptions{})
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}

	if report.Sample.FileType != FileTypeScript {
		t.Errorf("FileType = %q, want %q", report.Sample.FileType, FileTypeScript)
	}
	if report.Sample.SHA256 == "" {
		t.Error("SHA256 should not be empty")
	}
	if report.Sample.MD5 == "" {
		t.Error("MD5 should not be empty")
	}
	if report.Sample.FileSize != int64(len(content)) {
		t.Errorf("FileSize = %d, want %d", report.Sample.FileSize, len(content))
	}
}

func TestRunPipeline_PE32(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.exe")
	pe := buildMinimalPE(false, false)
	if err := os.WriteFile(path, pe, 0o644); err != nil {
		t.Fatalf("writing test PE: %v", err)
	}

	report, err := RunPipeline(path, AnalysisOptions{})
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}

	if report.Sample.FileType != FileTypePE32 {
		t.Errorf("FileType = %q, want %q", report.Sample.FileType, FileTypePE32)
	}
	if report.Sample.Architecture != "x86" {
		t.Errorf("Architecture = %q, want x86", report.Sample.Architecture)
	}
	if report.Sample.SHA256 == "" {
		t.Error("SHA256 should not be empty")
	}
}

func TestRunPipeline_NonExistent(t *testing.T) {
	_, err := RunPipeline("/nonexistent/file.bin", AnalysisOptions{})
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestRunPipeline_Directory(t *testing.T) {
	dir := t.TempDir()
	_, err := RunPipeline(dir, AnalysisOptions{})
	if err == nil {
		t.Error("expected error for directory")
	}
}
