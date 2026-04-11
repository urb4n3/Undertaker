package analysis

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/urb4n3/undertaker/data"
	"github.com/urb4n3/undertaker/internal/config"
	"github.com/urb4n3/undertaker/internal/models"
)

//go:generate echo "embedded data loaded from data/ directory"

// Embedded data files are loaded via LoadStringFilters.

// StringFilterConfig holds the loaded string filter patterns.
type StringFilterConfig struct {
	Categories   []StringCategory `json:"categories"`
	NoiseFilters []string         `json:"noise_filters"`
}

// StringCategory defines a category with priority and regex patterns.
type StringCategory struct {
	Name     string   `json:"name"`
	Priority int      `json:"priority"`
	Patterns []string `json:"patterns"`
}

// compiledCategory holds pre-compiled regex patterns for a category.
type compiledCategory struct {
	Name     string
	Priority int
	Regexps  []*regexp.Regexp
}

// scoredHit is an internal wrapper for sorting string hits by relevance.
type scoredHit struct {
	models.StringHit
	score int
}

const (
	defaultStringCap = 50
	minASCIILength   = 6
	minBase64Length   = 20
)

// ExtractStrings extracts interesting strings from a file, categorizes, ranks,
// deduplicates, and caps them. Returns []StringHit.
func ExtractStrings(path string, full bool) ([]models.StringHit, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file for strings: %w", err)
	}

	filters, err := LoadStringFilters()
	if err != nil {
		return nil, fmt.Errorf("loading string filters: %w", err)
	}

	// Compile noise filters.
	var noiseRegexps []*regexp.Regexp
	for _, pattern := range filters.NoiseFilters {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		noiseRegexps = append(noiseRegexps, re)
	}

	// Compile category patterns.
	var categories []compiledCategory
	for _, cat := range filters.Categories {
		cc := compiledCategory{Name: cat.Name, Priority: cat.Priority}
		for _, p := range cat.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				continue
			}
			cc.Regexps = append(cc.Regexps, re)
		}
		categories = append(categories, cc)
	}

	var hits []scoredHit
	seen := make(map[string]bool)

	// Extract raw ASCII strings.
	asciiStrings := extractASCII(data, minASCIILength)
	for _, s := range asciiStrings {
		if seen[s.Value] || isNoise(s.Value, noiseRegexps) {
			continue
		}
		seen[s.Value] = true
		cat, score := categorize(s.Value, categories)
		s.Category = cat
		hits = append(hits, scoredHit{StringHit: s, score: score})
	}

	// Extract UTF-16LE strings.
	utf16Strings := extractUTF16LE(data, minASCIILength)
	for _, s := range utf16Strings {
		if seen[s.Value] || isNoise(s.Value, noiseRegexps) {
			continue
		}
		seen[s.Value] = true
		cat, score := categorize(s.Value, categories)
		s.Category = cat
		hits = append(hits, scoredHit{StringHit: s, score: score})
	}

	// Detect and decode Base64 blobs.
	base64Hits := detectBase64(data)
	for _, s := range base64Hits {
		if seen[s.Value] {
			continue
		}
		seen[s.Value] = true
		cat, score := categorize(s.Value, categories)
		s.Category = cat
		hits = append(hits, scoredHit{StringHit: s, score: score})
	}

	// Sort by score (lower priority number = higher relevance).
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score < hits[j].score
		}
		return hits[i].Value < hits[j].Value
	})

	// Cap unless --full.
	if !full && len(hits) > defaultStringCap {
		hits = hits[:defaultStringCap]
	}

	// Convert to []StringHit for return.
	result := make([]models.StringHit, len(hits))
	for i, h := range hits {
		result[i] = h.StringHit
	}

	return result, nil
}

// extractASCII extracts printable ASCII strings of at least minLen bytes.
func extractASCII(data []byte, minLen int) []models.StringHit {
	var results []models.StringHit
	var current []byte
	startOffset := 0

	for i, b := range data {
		if b >= 0x20 && b < 0x7F {
			if len(current) == 0 {
				startOffset = i
			}
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				results = append(results, models.StringHit{
					Value:    string(current),
					Offset:   int64(startOffset),
					Encoding: "ascii",
					Source:   "raw",
				})
			}
			current = current[:0]
		}
	}
	// Handle trailing string.
	if len(current) >= minLen {
		results = append(results, models.StringHit{
			Value:    string(current),
			Offset:   int64(startOffset),
			Encoding: "ascii",
			Source:   "raw",
		})
	}

	return results
}

// extractUTF16LE extracts UTF-16LE encoded strings.
func extractUTF16LE(data []byte, minLen int) []models.StringHit {
	var results []models.StringHit
	var current []rune
	startOffset := 0

	for i := 0; i+1 < len(data); i += 2 {
		lo := data[i]
		hi := data[i+1]
		r := rune(uint16(hi)<<8 | uint16(lo))

		if r >= 0x20 && r < 0x7F {
			if len(current) == 0 {
				startOffset = i
			}
			current = append(current, r)
		} else {
			if len(current) >= minLen {
				results = append(results, models.StringHit{
					Value:    string(current),
					Offset:   int64(startOffset),
					Encoding: "utf16",
					Source:   "raw",
				})
			}
			current = current[:0]
		}
	}
	if len(current) >= minLen {
		results = append(results, models.StringHit{
			Value:    string(current),
			Offset:   int64(startOffset),
			Encoding: "utf16",
			Source:   "raw",
		})
	}

	return results
}

// base64Regex matches potential Base64 blobs.
var base64Regex = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)

// detectBase64 finds Base64-encoded blobs and decodes them.
func detectBase64(data []byte) []models.StringHit {
	var results []models.StringHit

	matches := base64Regex.FindAllIndex(data, -1)
	for _, loc := range matches {
		blob := string(data[loc[0]:loc[1]])

		// Validate: length must be divisible by 4.
		if len(blob)%4 != 0 {
			// Try trimming to nearest multiple of 4.
			trimLen := len(blob) - (len(blob) % 4)
			if trimLen < minBase64Length {
				continue
			}
			blob = blob[:trimLen]
		}

		if len(blob) < minBase64Length {
			continue
		}

		decoded, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			continue
		}

		// Only include if the decoded content is mostly printable.
		if !isMostlyPrintable(decoded) {
			continue
		}

		decodedStr := string(decoded)
		if len(decodedStr) < 4 {
			continue
		}

		results = append(results, models.StringHit{
			Value:    decodedStr,
			Offset:   int64(loc[0]),
			Encoding: "ascii",
			Source:   "base64_decoded",
		})
	}

	return results
}

// isMostlyPrintable returns true if >75% of bytes are printable ASCII/UTF-8.
func isMostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	total := utf8.RuneCount(data)
	if total == 0 {
		return false
	}
	for _, r := range string(data) {
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(total) > 0.75
}

// isNoise returns true if the string matches any noise filter pattern.
func isNoise(s string, filters []*regexp.Regexp) bool {
	for _, re := range filters {
		if re.MatchString(s) {
			return true
		}
	}
	// Filter short strings with low alphanumeric density (likely data section garbage).
	if len(s) <= 16 {
		alnum := 0
		for _, r := range s {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				alnum++
			}
		}
		ratio := float64(alnum) / float64(len(s))
		// Stricter threshold for very short strings.
		if len(s) <= 10 && ratio < 0.75 {
			return true
		}
		if ratio < 0.65 {
			return true
		}
	}
	return false
}

// knownGoodURLDomains are legitimate domains whose URLs should not be categorized as C2.
var knownGoodURLDomains = []string{
	"microsoft.com",
	"schemas.microsoft.com",
	"go.microsoft.com",
	"www.microsoft.com",
	"learn.microsoft.com",
	"support.microsoft.com",
	"windows.microsoft.com",
	"aka.ms",
	"w3.org",
	"www.w3.org",
	"xmlsoap.org",
	"schemas.xmlsoap.org",
	"openxmlformats.org",
	"schemas.openxmlformats.org",
	"google.com",
	"www.google.com",
	"apple.com",
	"github.com",
	"digicert.com",
	"verisign.com",
	"globalsign.com",
	"letsencrypt.org",
	"symantec.com",
	"thawte.com",
}

// isKnownGoodURL returns true if the string is a URL pointing to a known-good domain.
func isKnownGoodURL(s string) bool {
	lower := strings.ToLower(s)
	for _, domain := range knownGoodURLDomains {
		if strings.Contains(lower, "://"+domain+"/") ||
			strings.Contains(lower, "://"+domain+"?") ||
			strings.HasSuffix(lower, "://"+domain) {
			return true
		}
	}
	return false
}

// categorize classifies a string into a category and returns priority score.
func categorize(s string, categories []compiledCategory) (string, int) {
	bestCategory := "uncategorized"
	bestPriority := 100 // uncategorized has lowest priority

	for _, cat := range categories {
		for _, re := range cat.Regexps {
			if re.MatchString(s) {
				// Skip C2 classification for known-good URLs.
				if cat.Name == "c2" && isKnownGoodURL(s) {
					break
				}
				if cat.Priority < bestPriority {
					bestCategory = cat.Name
					bestPriority = cat.Priority
				}
				break
			}
		}
	}

	return bestCategory, bestPriority
}

// LoadStringFilters loads embedded string filters and merges with custom overrides.
func LoadStringFilters() (*StringFilterConfig, error) {
	var filters StringFilterConfig
	if err := json.Unmarshal(data.StringFilters, &filters); err != nil {
		return nil, fmt.Errorf("parsing embedded string filters: %w", err)
	}

	// Try loading custom overrides from config dir.
	custom, err := loadCustomStringFilters()
	if err == nil && custom != nil {
		filters = mergeStringFilters(filters, *custom)
	}

	return &filters, nil
}

// loadCustomStringFilters loads custom filters from the config directory.
func loadCustomStringFilters() (*StringFilterConfig, error) {
	dir, err := config.ConfigDir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, "string_filters_custom.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err // File doesn't exist — normal.
	}

	var custom StringFilterConfig
	if err := json.Unmarshal(data, &custom); err != nil {
		return nil, fmt.Errorf("parsing custom string filters: %w", err)
	}

	return &custom, nil
}

// mergeStringFilters merges custom filters into defaults. Custom entries take precedence.
func mergeStringFilters(defaults, custom StringFilterConfig) StringFilterConfig {
	// Custom categories override defaults by name.
	catMap := make(map[string]StringCategory)
	for _, cat := range defaults.Categories {
		catMap[cat.Name] = cat
	}
	for _, cat := range custom.Categories {
		catMap[cat.Name] = cat // Override.
	}
	merged := StringFilterConfig{}
	for _, cat := range catMap {
		merged.Categories = append(merged.Categories, cat)
	}

	// Merge noise filters (append custom).
	merged.NoiseFilters = append(defaults.NoiseFilters, custom.NoiseFilters...)

	return merged
}
