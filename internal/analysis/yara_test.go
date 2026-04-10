package analysis

import (
	"testing"

	"github.com/urb4n3/undertaker/internal/tools"
)

func TestRunYARAUnavailable(t *testing.T) {
	ti := tools.ToolInfo{Name: "yara", Available: false, Error: "not found"}
	_, err := RunYARA(ti, "sample.exe", []string{"/rules"}, 10)
	if err == nil {
		t.Error("expected error for unavailable tool")
	}
}

func TestRunYARANoRules(t *testing.T) {
	ti := tools.ToolInfo{Name: "yara", Available: true, Path: "/usr/bin/yara"}
	matches, err := RunYARA(ti, "sample.exe", nil, 10)
	if err != nil {
		t.Errorf("unexpected error for empty rules: %v", err)
	}
	if matches != nil {
		t.Error("expected nil matches for empty rules")
	}
}

func TestParseYARAOutput(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected int
		ruleName string
	}{
		{
			name:     "single match",
			output:   "MalwareFamily C:\\samples\\evil.exe\n",
			expected: 1,
			ruleName: "MalwareFamily",
		},
		{
			name:     "multiple matches",
			output:   "Rule1 C:\\samples\\evil.exe\nRule2 C:\\samples\\evil.exe\n",
			expected: 2,
			ruleName: "Rule1",
		},
		{
			name:     "match with tags",
			output:   "SuspiciousRule [malware,trojan] C:\\samples\\evil.exe\n",
			expected: 1,
			ruleName: "SuspiciousRule",
		},
		{
			name:     "empty output",
			output:   "",
			expected: 0,
		},
		{
			name:     "whitespace only",
			output:   "  \n  \n",
			expected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := parseYARAOutput(tc.output)
			if len(matches) != tc.expected {
				t.Errorf("expected %d matches, got %d", tc.expected, len(matches))
			}
			if tc.expected > 0 && matches[0].RuleName != tc.ruleName {
				t.Errorf("expected rule %q, got %q", tc.ruleName, matches[0].RuleName)
			}
		})
	}
}

func TestParseYARALineWithTags(t *testing.T) {
	line := "SuspiciousRule [malware,trojan] C:\\samples\\evil.exe"
	match := parseYARALine(line)
	if match == nil {
		t.Fatal("expected non-nil match")
	}
	if match.RuleName != "SuspiciousRule" {
		t.Errorf("expected rule SuspiciousRule, got %q", match.RuleName)
	}
	if len(match.Tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(match.Tags))
	}
	if match.Tags[0] != "malware" || match.Tags[1] != "trojan" {
		t.Errorf("unexpected tags: %v", match.Tags)
	}
}
