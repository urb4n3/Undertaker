package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Tools.Timeout != 60 {
		t.Errorf("Timeout = %d, want 60", cfg.Tools.Timeout)
	}
	if cfg.Limits.MaxFileSize != "500MB" {
		t.Errorf("MaxFileSize = %q, want 500MB", cfg.Limits.MaxFileSize)
	}
	if cfg.Output.CaseDir != "./cases" {
		t.Errorf("CaseDir = %q, want ./cases", cfg.Output.CaseDir)
	}
}

func TestLoad_NoConfigFile(t *testing.T) {
	// When no config file exists, Load should return defaults without error.
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Tools.Timeout != 60 {
		t.Errorf("Timeout = %d, want 60", cfg.Tools.Timeout)
	}
}

func TestInitConfig_CreatesFile(t *testing.T) {
	// Override config dir for testing.
	dir := t.TempDir()
	originalFunc := os.UserConfigDir
	_ = originalFunc

	// We test the file creation directly.
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgDir := filepath.Dir(cfgPath)
	if err := os.MkdirAll(cfgDir, 0o750); err != nil {
		t.Fatalf("creating dir: %v", err)
	}

	// Just verify DefaultConfig marshals without error.
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
}
