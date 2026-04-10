package analysis

import (
	"testing"

	"github.com/urb4n3/undertaker/internal/models"
)

func TestDetectPacking_NoSignals(t *testing.T) {
	// Normal sections with low entropy and many imports → "none".
	meta := &models.PEMetadata{
		Sections: []models.SectionInfo{
			{Name: ".text", Entropy: 5.5},
			{Name: ".rdata", Entropy: 4.2},
			{Name: ".data", Entropy: 3.1},
		},
	}
	info := DetectPacking(nil, meta, 5.0)
	if info.Confidence != "none" {
		t.Errorf("confidence = %q, want none", info.Confidence)
	}
	if info.Label != "Not packed" {
		t.Errorf("label = %q, want 'Not packed'", info.Label)
	}
}

func TestDetectPacking_HighEntropy(t *testing.T) {
	// Single high entropy section alone → "low" (possibly compressed).
	meta := &models.PEMetadata{
		Sections: []models.SectionInfo{
			{Name: ".text", Entropy: 7.5},
			{Name: ".rdata", Entropy: 4.2},
		},
	}
	info := DetectPacking(nil, meta, 7.0)
	// One high-entropy section = 1 signal, but only 1 section fires.
	// With only 1 signal total, this is "low".
	if info.Confidence != "low" {
		t.Errorf("confidence = %q, want low", info.Confidence)
	}
}

func TestDetectPacking_UPXSectionNames(t *testing.T) {
	// UPX section names → "high".
	meta := &models.PEMetadata{
		Sections: []models.SectionInfo{
			{Name: "UPX0", Entropy: 7.8},
			{Name: "UPX1", Entropy: 7.9},
			{Name: "UPX2", Entropy: 2.0},
		},
	}
	info := DetectPacking(nil, meta, 7.5)
	if info.Confidence != "high" {
		t.Errorf("confidence = %q, want high", info.Confidence)
	}
	if info.PackerName != "UPX" {
		t.Errorf("packer = %q, want UPX", info.PackerName)
	}
}

func TestDetectPacking_VMProtectSections(t *testing.T) {
	meta := &models.PEMetadata{
		Sections: []models.SectionInfo{
			{Name: ".vmp0", Entropy: 6.5},
			{Name: ".vmp1", Entropy: 7.2},
		},
	}
	info := DetectPacking(nil, meta, 6.8)
	if info.Confidence != "high" {
		t.Errorf("confidence = %q, want high", info.Confidence)
	}
	if info.PackerName != "VMProtect" {
		t.Errorf("packer = %q, want VMProtect", info.PackerName)
	}
}

func TestDetectPacking_ThemidaSections(t *testing.T) {
	meta := &models.PEMetadata{
		Sections: []models.SectionInfo{
			{Name: ".themida", Entropy: 6.0},
			{Name: ".text", Entropy: 5.0},
		},
	}
	info := DetectPacking(nil, meta, 5.5)
	if info.Confidence != "high" {
		t.Errorf("confidence = %q, want high", info.Confidence)
	}
	if info.PackerName != "Themida" {
		t.Errorf("packer = %q, want Themida", info.PackerName)
	}
}

func TestDetectPacking_SignalCount(t *testing.T) {
	// Verify signals are collected correctly.
	meta := &models.PEMetadata{
		Sections: []models.SectionInfo{
			{Name: "UPX0", Entropy: 7.8},
			{Name: "UPX1", Entropy: 7.9},
		},
	}
	info := DetectPacking(nil, meta, 7.5)
	if len(info.Signals) == 0 {
		t.Error("expected non-empty signals slice")
	}
}
