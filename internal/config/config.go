package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds the global Undertaker configuration.
type Config struct {
	Tools     ToolsConfig `yaml:"tools"`
	YARARules []string    `yaml:"yara_rules"`
	Limits    Limits      `yaml:"limits"`
	Output    Output      `yaml:"output"`
}

type ToolsConfig struct {
	FLOSS   string `yaml:"floss"`
	Capa    string `yaml:"capa"`
	YARA    string `yaml:"yara"`
	Timeout int    `yaml:"timeout"`
}

type Limits struct {
	MaxFileSize string `yaml:"max_file_size"`
}

type Output struct {
	CaseDir string   `yaml:"case_dir"`
	Formats []string `yaml:"formats"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Tools: ToolsConfig{
			Timeout: 120,
		},
		YARARules: []string{},
		Limits: Limits{
			MaxFileSize: "500MB",
		},
		Output: Output{
			CaseDir: "./cases",
			Formats: []string{"markdown", "json"},
		},
	}
}

// ConfigDir returns the OS-standard config directory for Undertaker.
func ConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine config directory: %w", err)
	}
	return filepath.Join(base, "undertaker"), nil
}

// ConfigPath returns the full path to the config file.
func ConfigPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// Load reads configuration from the default config file, falling back to defaults.
func Load() (*Config, error) {
	cfg := DefaultConfig()

	path, err := ConfigPath()
	if err != nil {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return cfg, fmt.Errorf("parsing config: %w", err)
	}

	return cfg, nil
}

// InitConfig creates the default config file if it doesn't exist.
func InitConfig() (string, error) {
	path, err := ConfigPath()
	if err != nil {
		return "", err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("creating config directory: %w", err)
	}

	if _, err := os.Stat(path); err == nil {
		return path, fmt.Errorf("config file already exists at %s", path)
	}

	cfg := DefaultConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshaling default config: %w", err)
	}

	header := []byte("# Undertaker configuration\n# See docs/PRODUCT_PLAN_V2.md for details\n\n")
	if err := os.WriteFile(path, append(header, data...), 0o640); err != nil {
		return "", fmt.Errorf("writing config: %w", err)
	}

	return path, nil
}
