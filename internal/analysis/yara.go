package analysis

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/urb4n3/undertaker/internal/models"
	"github.com/urb4n3/undertaker/internal/tools"
)

// RunYARA invokes YARA with the given rule paths against the sample.
// rulePaths is a list of .yar files or directories containing .yar files.
func RunYARA(ti tools.ToolInfo, samplePath string, rulePaths []string, timeoutSec int) ([]models.YARAMatch, error) {
	if !ti.Available {
		return nil, fmt.Errorf("yara not available: %s", ti.Error)
	}

	if len(rulePaths) == 0 {
		return nil, nil // No rules configured — nothing to scan.
	}

	var allMatches []models.YARAMatch
	seen := make(map[string]bool)

	for _, rulePath := range rulePaths {
		matches, err := runYARASingle(ti, samplePath, rulePath, timeoutSec)
		if err != nil {
			// Record error but continue with other rule files.
			continue
		}
		for _, m := range matches {
			if !seen[m.RuleName] {
				seen[m.RuleName] = true
				allMatches = append(allMatches, m)
			}
		}
	}

	return allMatches, nil
}

// runYARASingle runs YARA with a single rule file/directory against the sample.
func runYARASingle(ti tools.ToolInfo, samplePath, rulePath string, timeoutSec int) ([]models.YARAMatch, error) {
	// -s for string matches (not used in output, but provides detail)
	// -w to suppress warnings
	args := []string{"-w", rulePath, samplePath}
	result, err := tools.Run(ti.Path, args, timeoutSec)
	if err != nil {
		return nil, fmt.Errorf("running yara: %w", err)
	}

	// YARA outputs matches as: RuleName SamplePath
	// Tags appear as: RuleName [tag1,tag2] SamplePath
	return parseYARAOutput(string(result.Stdout)), nil
}

// parseYARAOutput parses YARA's text output into YARAMatch structs.
// Format: "rule_name sample_path" or "rule_name [tag1,tag2] sample_path"
func parseYARAOutput(output string) []models.YARAMatch {
	var matches []models.YARAMatch
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		match := parseYARALine(line)
		if match != nil {
			matches = append(matches, *match)
		}
	}

	return matches
}

// parseYARALine parses a single line of YARA output.
// Expected format: "RuleName /path/to/file" or "RuleName [tag1,tag2] /path/to/file"
func parseYARALine(line string) *models.YARAMatch {
	// Split on first space to get rule name.
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return nil
	}

	ruleName := parts[0]
	rest := parts[1]

	var tags []string
	// Check if there's a tag section [tag1,tag2].
	if strings.HasPrefix(rest, "[") {
		endBracket := strings.Index(rest, "]")
		if endBracket > 0 {
			tagStr := rest[1:endBracket]
			for _, t := range strings.Split(tagStr, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					tags = append(tags, t)
				}
			}
		}
	}

	return &models.YARAMatch{
		RuleName: ruleName,
		Tags:     tags,
	}
}
