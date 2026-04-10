package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/urb4n3/undertaker/internal/config"
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

func TestRunPipeline_ProgressCallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.ps1")
	if err := os.WriteFile(path, []byte("echo hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	var messages []string
	opts := AnalysisOptions{
		OnProgress: func(msg string) {
			messages = append(messages, msg)
		},
	}

	_, err := RunPipeline(path, opts)
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}

	if len(messages) == 0 {
		t.Error("expected progress messages, got none")
	}
}

func TestRunPipeline_ZIPArchive(t *testing.T) {
	// ZIP magic: PK\x03\x04 + padding.
	dir := t.TempDir()
	path := filepath.Join(dir, "test.zip")
	data := append([]byte("PK\x03\x04"), make([]byte, 100)...)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := RunPipeline(path, AnalysisOptions{})
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}

	if report.Sample.FileType != FileTypeZIP {
		t.Errorf("FileType = %q, want %q", report.Sample.FileType, FileTypeZIP)
	}
	// Archives should only have hashing + file ID.
	if len(report.Strings) > 0 {
		t.Errorf("expected no strings for archive, got %d", len(report.Strings))
	}
	if report.Sample.SHA256 == "" {
		t.Error("SHA256 should not be empty for archive")
	}
}

func TestExceedsMaxFileSize(t *testing.T) {
	tests := []struct {
		name     string
		size     int64
		limit    string
		expected bool
	}{
		{"under limit", 100 * 1024 * 1024, "500MB", false},
		{"over limit", 600 * 1024 * 1024, "500MB", true},
		{"exactly at limit", 500 * 1024 * 1024, "500MB", false},
		{"over limit MB", 501 * 1024 * 1024, "500MB", true},
		{"KB limit", 2048, "1KB", true},
		{"GB limit", 2 * 1024 * 1024 * 1024, "1GB", true},
		{"empty limit", 999999999, "", false},
		{"invalid limit", 999999999, "abc", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Limits.MaxFileSize = tt.limit
			got := exceedsMaxFileSize(tt.size, cfg)
			if got != tt.expected {
				t.Errorf("exceedsMaxFileSize(%d, %q) = %v, want %v", tt.size, tt.limit, got, tt.expected)
			}
		})
	}
}
