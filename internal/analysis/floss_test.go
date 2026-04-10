package analysis

import (
	"testing"

	"github.com/urb4n3/undertaker/internal/models"
	"github.com/urb4n3/undertaker/internal/tools"
)

func TestRunFLOSSUnavailable(t *testing.T) {
	ti := tools.ToolInfo{Name: "floss", Available: false, Error: "not found"}
	_, err := RunFLOSS(ti, "sample.exe", false, 10)
	if err == nil {
		t.Error("expected error for unavailable tool")
	}
}

func TestCategorizeAndScoreEmpty(t *testing.T) {
	filters, err := LoadStringFilters()
	if err != nil {
		t.Fatalf("loading filters: %v", err)
	}

	result := categorizeAndScore(nil, filters, false)
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d items", len(result))
	}
}

func TestCategorizeAndScoreCap(t *testing.T) {
	filters, err := LoadStringFilters()
	if err != nil {
		t.Fatalf("loading filters: %v", err)
	}

	// Generate >50 hits.
	var hits []models.StringHit
	for i := 0; i < 100; i++ {
		hits = append(hits, models.StringHit{
			Value:    "http://example.com/" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)),
			Source:   "floss_static",
			Encoding: "ascii",
		})
	}

	// Without --full, should cap at 50.
	capped := categorizeAndScore(hits, filters, false)
	if len(capped) > defaultStringCap {
		t.Errorf("expected cap at %d, got %d", defaultStringCap, len(capped))
	}

	// With --full, should include all (minus noise).
	full := categorizeAndScore(hits, filters, true)
	if len(full) < len(capped) {
		t.Error("--full should return at least as many as capped")
	}
}
