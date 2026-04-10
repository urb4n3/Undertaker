package tools

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"floss style", "FLOSS v3.1.0", "3.1.0"},
		{"capa style", "capa v7.0.1", "7.0.1"},
		{"yara style", "YARA 4.5.1", "4.5.1"},
		{"bare version", "3.2.0", "3.2.0"},
		{"version with prefix text", "some tool version v2.0.0", "2.0.0"},
		{"two-part version", "v4.5", "4.5"},
		{"no version", "no version here", ""},
		{"empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseVersion(tc.input)
			if got != tc.expect {
				t.Errorf("parseVersion(%q) = %q, want %q", tc.input, got, tc.expect)
			}
		})
	}
}

func TestParseMajor(t *testing.T) {
	tests := []struct {
		input  string
		expect int
	}{
		{"3.1.0", 3},
		{"7.0.1", 7},
		{"4.5", 4},
		{"0.9.1", 0},
		{"", 0},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseMajor(tc.input)
			if got != tc.expect {
				t.Errorf("parseMajor(%q) = %d, want %d", tc.input, got, tc.expect)
			}
		})
	}
}

func TestDiscoverMissingTools(t *testing.T) {
	// With no config paths and tools not on PATH, all should be unavailable.
	// Use a fake config with empty tool paths.
	cfg := &fakeConfig{}
	reg := discoverWithPaths("", "", "")
	if reg.FLOSS.Available {
		t.Error("expected FLOSS unavailable with no config/PATH")
	}
	if reg.Capa.Available {
		t.Error("expected Capa unavailable with no config/PATH")
	}
	if reg.YARA.Available {
		t.Error("expected YARA unavailable with no config/PATH")
	}
	_ = cfg // just to suppress unused variable
}

// fakeConfig is used only to satisfy the test structure.
type fakeConfig struct{}

// discoverWithPaths is a test helper that calls discover for each tool with given paths.
func discoverWithPaths(floss, capa, yara string) *Registry {
	return &Registry{
		FLOSS: discover("floss_nonexistent_test_binary", floss, "--version"),
		Capa:  discover("capa_nonexistent_test_binary", capa, "--version"),
		YARA:  discover("yara_nonexistent_test_binary", yara, "--version"),
	}
}

func TestDiscoverBadPath(t *testing.T) {
	info := discover("floss", "/nonexistent/path/to/floss", "--version")
	if info.Available {
		t.Error("expected unavailable for nonexistent path")
	}
	if info.Error == "" {
		t.Error("expected error message for nonexistent path")
	}
}
