package analysis

import (
	"testing"

	peparser "github.com/saferwall/pe"
	"github.com/urb4n3/undertaker/internal/models"
)

func TestAnalyzeExports_NoExports(t *testing.T) {
	pefile := &peparser.File{}
	exports := AnalyzeExports(pefile)
	if exports != nil {
		t.Errorf("expected nil exports, got %d entries", len(exports))
	}
}

func TestAnalyzeExports_WithFunctions(t *testing.T) {
	pefile := &peparser.File{
		Export: peparser.Export{
			Functions: []peparser.ExportFunction{
				{Name: "DllGetClassObject", Ordinal: 1, FunctionRVA: 0x1000},
				{Name: "DllCanUnloadNow", Ordinal: 2, FunctionRVA: 0x2000},
				{Name: "ForwardedFunc", Ordinal: 3, FunctionRVA: 0x3000, Forwarder: "NTDLL.RtlAllocateHeap"},
			},
		},
	}

	exports := AnalyzeExports(pefile)
	if len(exports) != 3 {
		t.Fatalf("expected 3 exports, got %d", len(exports))
	}

	// Verify first export.
	if exports[0].Name != "DllGetClassObject" {
		t.Errorf("export[0].Name = %q, want DllGetClassObject", exports[0].Name)
	}
	if exports[0].Ordinal != 1 {
		t.Errorf("export[0].Ordinal = %d, want 1", exports[0].Ordinal)
	}

	// Verify forwarded export.
	if exports[2].Forwarded != "NTDLL.RtlAllocateHeap" {
		t.Errorf("export[2].Forwarded = %q, want NTDLL.RtlAllocateHeap", exports[2].Forwarded)
	}
}

func TestExportModel_OrdinalType(t *testing.T) {
	// Verify ordinal fits uint16 for high ordinal values.
	pefile := &peparser.File{
		Export: peparser.Export{
			Functions: []peparser.ExportFunction{
				{Name: "HighOrdinal", Ordinal: 65535, FunctionRVA: 0x1000},
			},
		},
	}

	exports := AnalyzeExports(pefile)
	if len(exports) != 1 {
		t.Fatalf("expected 1 export, got %d", len(exports))
	}

	want := models.Export{Name: "HighOrdinal", Ordinal: 65535}
	if exports[0] != want {
		t.Errorf("export = %+v, want %+v", exports[0], want)
	}
}
