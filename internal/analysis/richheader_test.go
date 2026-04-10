package analysis

import (
	"testing"

	peparser "github.com/saferwall/pe"
)

func TestAnalyzeRichHeader_NoRichHeader(t *testing.T) {
	pefile := &peparser.File{}
	// FileInfo.HasRichHdr defaults to false.
	rh := AnalyzeRichHeader(pefile)
	if rh != nil {
		t.Error("expected nil for PE without rich header")
	}
}

func TestAnalyzeRichHeader_EmptyCompIDs(t *testing.T) {
	pefile := &peparser.File{}
	pefile.FileInfo.HasRichHdr = true
	pefile.RichHeader = peparser.RichHeader{
		CompIDs: nil,
	}
	rh := AnalyzeRichHeader(pefile)
	if rh != nil {
		t.Error("expected nil for empty CompIDs")
	}
}

func TestAnalyzeRichHeader_WithEntries(t *testing.T) {
	pefile := &peparser.File{}
	pefile.FileInfo.HasRichHdr = true
	pefile.RichHeader = peparser.RichHeader{
		CompIDs: []peparser.CompID{
			{ProdID: 259, MinorCV: 30729, Count: 5},
			{ProdID: 260, MinorCV: 30729, Count: 3},
		},
	}

	rh := AnalyzeRichHeader(pefile)
	if rh == nil {
		t.Fatal("expected non-nil rich header")
	}
	if len(rh.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(rh.Entries))
	}

	// Entries should have non-empty toolchain names.
	for i, entry := range rh.Entries {
		if entry.Toolchain == "" {
			t.Errorf("entry[%d].Toolchain is empty", i)
		}
		if entry.Count == 0 {
			t.Errorf("entry[%d].Count = 0", i)
		}
	}
}

func TestProdIDToToolchain_KnownID(t *testing.T) {
	// Should not return empty for any prodID.
	result := prodIDToToolchain(0)
	if result == "" {
		t.Error("expected non-empty toolchain for prodID 0")
	}

	result = prodIDToToolchain(259)
	if result == "" {
		t.Error("expected non-empty toolchain for prodID 259")
	}
}

func TestProdIDToType(t *testing.T) {
	// Any prodID should return a non-empty type.
	result := prodIDToType(259)
	if result == "" {
		t.Error("expected non-empty type")
	}
}
