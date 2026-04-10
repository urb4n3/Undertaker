package analysis

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/urb4n3/undertaker/data"
	"github.com/urb4n3/undertaker/internal/config"
	"github.com/urb4n3/undertaker/internal/models"
)

const defaultIOCCap = 30

// IOCPatternConfig holds the loaded IOC patterns.
type IOCPatternConfig struct {
	Patterns []IOCPattern `json:"patterns"`
}

// IOCPattern defines a single IOC extraction regex.
type IOCPattern struct {
	Type        string `json:"type"`
	Regex       string `json:"regex"`
	Description string `json:"description"`
}

// ExtractIOCs extracts IOC indicators from string hits using regex patterns.
func ExtractIOCs(hits []models.StringHit, full bool) ([]models.IOC, error) {
	patterns, err := LoadIOCPatterns()
	if err != nil {
		return nil, fmt.Errorf("loading IOC patterns: %w", err)
	}

	// Compile patterns.
	type compiledPattern struct {
		Type   string
		Regexp *regexp.Regexp
	}
	var compiled []compiledPattern
	for _, p := range patterns.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			continue
		}
		compiled = append(compiled, compiledPattern{Type: p.Type, Regexp: re})
	}

	seen := make(map[string]bool) // Dedup by "type:value".
	var iocs []models.IOC

	for _, hit := range hits {
		for _, cp := range compiled {
			matches := cp.Regexp.FindAllString(hit.Value, -1)
			for _, match := range matches {
				key := cp.Type + ":" + match
				if seen[key] {
					continue
				}
				seen[key] = true

				// Filter out common false positives.
				if isFalsePositiveIOC(cp.Type, match) {
					continue
				}

				iocs = append(iocs, models.IOC{
					Type:   cp.Type,
					Value:  match,
					Source: "strings",
				})
			}
		}
	}

	// Cap unless --full.
	if !full && len(iocs) > defaultIOCCap {
		iocs = iocs[:defaultIOCCap]
	}

	return iocs, nil
}

// isFalsePositiveIOC filters out common false positive IOCs.
func isFalsePositiveIOC(iocType, value string) bool {
	switch iocType {
	case "ip":
		// Filter out common non-routable/version IPs.
		return value == "0.0.0.0" || value == "127.0.0.1" ||
			value == "255.255.255.255" || value == "255.255.255.0" ||
			// Common version-like patterns (e.g. 1.0.0.0, 10.0.0.0).
			isVersionLikeIP(value)
	case "domain":
		// Filter very short or common noise domains.
		return len(value) < 5
	}
	return false
}

// isVersionLikeIP checks if an IP looks like a version string (x.0.0.0 or x.x.0.0).
func isVersionLikeIP(ip string) bool {
	n := len(ip)
	if n >= 6 && ip[n-6:] == ".0.0.0" {
		return true
	}
	if n >= 4 && ip[n-4:] == ".0.0" {
		return true
	}
	return false
}

// LoadIOCPatterns loads embedded IOC patterns and merges with custom overrides.
func LoadIOCPatterns() (*IOCPatternConfig, error) {
	var patterns IOCPatternConfig
	if err := json.Unmarshal(data.IOCPatterns, &patterns); err != nil {
		return nil, fmt.Errorf("parsing embedded IOC patterns: %w", err)
	}

	// Try loading custom overrides.
	custom, err := loadCustomIOCPatterns()
	if err == nil && custom != nil {
		patterns = mergeIOCPatterns(patterns, *custom)
	}

	return &patterns, nil
}

// loadCustomIOCPatterns loads custom patterns from the config directory.
func loadCustomIOCPatterns() (*IOCPatternConfig, error) {
	dir, err := config.ConfigDir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, "ioc_patterns_custom.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var custom IOCPatternConfig
	if err := json.Unmarshal(data, &custom); err != nil {
		return nil, fmt.Errorf("parsing custom IOC patterns: %w", err)
	}

	return &custom, nil
}

// mergeIOCPatterns merges custom patterns with defaults. Custom patterns are appended.
func mergeIOCPatterns(defaults, custom IOCPatternConfig) IOCPatternConfig {
	merged := IOCPatternConfig{
		Patterns: append(defaults.Patterns, custom.Patterns...),
	}
	return merged
}
