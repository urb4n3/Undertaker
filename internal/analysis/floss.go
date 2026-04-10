package analysis

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/urb4n3/undertaker/internal/models"
	"github.com/urb4n3/undertaker/internal/tools"
)

// flossJSON represents the top-level FLOSS JSON output (v3+).
type flossJSON struct {
	Strings flossStrings `json:"strings"`
}

type flossStrings struct {
	StaticStrings  []flossString `json:"static_strings"`
	StackStrings   []flossString `json:"stack_strings"`
	TightStrings   []flossString `json:"tight_strings"`
	DecodedStrings []flossString `json:"decoded_strings"`
}

type flossString struct {
	String   string `json:"string"`
	Offset   int64  `json:"offset"`
	Encoding string `json:"encoding"`
}

// RunFLOSS invokes FLOSS on the sample and returns categorized string hits.
// When FLOSS is available, its output replaces the built-in raw string extraction.
func RunFLOSS(ti tools.ToolInfo, samplePath string, full bool, timeoutSec int) ([]models.StringHit, error) {
	if !ti.Available {
		return nil, fmt.Errorf("floss not available: %s", ti.Error)
	}

	args := []string{"--json", samplePath}
	result, err := tools.Run(ti.Path, args, timeoutSec)
	if err != nil {
		return nil, fmt.Errorf("running floss: %w", err)
	}

	// FLOSS may exit non-zero on some samples but still produce partial output.
	stdout := result.Stdout
	if len(stdout) == 0 {
		return nil, fmt.Errorf("floss produced no output (exit code %d): %s",
			result.ExitCode, strings.TrimSpace(string(result.Stderr)))
	}

	var parsed flossJSON
	if err := json.Unmarshal(stdout, &parsed); err != nil {
		return nil, fmt.Errorf("parsing floss json: %w", err)
	}

	var hits []models.StringHit
	seen := make(map[string]bool)

	addHits := func(source string, items []flossString) {
		for _, s := range items {
			val := strings.TrimSpace(s.String)
			if val == "" || len(val) < minASCIILength {
				continue
			}
			if seen[val] {
				continue
			}
			seen[val] = true
			hits = append(hits, models.StringHit{
				Value:    val,
				Offset:   s.Offset,
				Encoding: s.Encoding,
				Source:   source,
			})
		}
	}

	addHits("floss_static", parsed.Strings.StaticStrings)
	addHits("floss_stack", parsed.Strings.StackStrings)
	addHits("floss_tight", parsed.Strings.TightStrings)
	addHits("floss_decoded", parsed.Strings.DecodedStrings)

	// Load string filters for categorization and scoring.
	filters, err := LoadStringFilters()
	if err == nil {
		hits = categorizeAndScore(hits, filters, full)
	}

	return hits, nil
}

// categorizeAndScore applies the same category/ranking/cap logic as the built-in
// string extractor, but operates on pre-extracted FLOSS hits.
func categorizeAndScore(hits []models.StringHit, filters *StringFilterConfig, full bool) []models.StringHit {
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

	var scored []scoredHit
	for _, h := range hits {
		if isNoise(h.Value, noiseRegexps) {
			continue
		}
		cat, prio := categorize(h.Value, categories)
		h.Category = cat
		scored = append(scored, scoredHit{StringHit: h, score: prio})
	}

	// Sort by score (lower priority number = higher relevance).
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score < scored[j].score
		}
		return scored[i].Value < scored[j].Value
	})

	cap := defaultStringCap
	if full {
		cap = len(scored)
	}
	if cap > len(scored) {
		cap = len(scored)
	}

	result := make([]models.StringHit, cap)
	for i := 0; i < cap; i++ {
		result[i] = scored[i].StringHit
	}
	return result
}
