package analysis

import (
	"testing"

	"github.com/urb4n3/undertaker/internal/tools"
)

func TestRunCapaUnavailable(t *testing.T) {
	ti := tools.ToolInfo{Name: "capa", Available: false, Error: "not found"}
	_, err := RunCapa(ti, "sample.exe", 10)
	if err == nil {
		t.Error("expected error for unavailable tool")
	}
}

func TestCapaJSONParsing(t *testing.T) {
	// Test parsing a minimal capa JSON structure.
	jsonData := `{
		"meta": {"analysis": {"format": "pe"}},
		"rules": {
			"write file": {
				"meta": {
					"name": "write file",
					"namespace": "host-interaction/file-system/write",
					"attack": [{"technique": "Indicator Removal on Host", "id": "T1070"}]
				},
				"source": "built-in"
			},
			"contain loop": {
				"meta": {
					"name": "contain loop",
					"namespace": "internal",
					"attack": []
				},
				"source": "built-in"
			}
		}
	}`

	var parsed capaJSON
	if err := parseCapaJSON([]byte(jsonData), &parsed); err != nil {
		t.Fatalf("failed to parse capa JSON: %v", err)
	}

	if len(parsed.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(parsed.Rules))
	}

	rule, ok := parsed.Rules["write file"]
	if !ok {
		t.Fatal("expected 'write file' rule")
	}

	if len(rule.Meta.AttackRef) != 1 {
		t.Errorf("expected 1 attack ref, got %d", len(rule.Meta.AttackRef))
	}
	if rule.Meta.AttackRef[0].ID != "T1070" {
		t.Errorf("expected T1070, got %s", rule.Meta.AttackRef[0].ID)
	}
}
