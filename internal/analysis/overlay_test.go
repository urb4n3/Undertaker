package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectOverlay_NoOverlay(t *testing.T) {
	// Test with a real system PE — most don't have overlays.
	notepad := filepath.Join(os.Getenv("WINDIR"), "System32", "notepad.exe")
	if _, err := os.Stat(notepad); err != nil {
		t.Skipf("notepad.exe not found: %v", err)
	}

	pefile, err := ParsePE(notepad)
	if err != nil {
		t.Fatalf("ParsePE: %v", err)
	}
	defer pefile.Close()

	overlay, err := DetectOverlay(pefile, notepad)
	if err != nil {
		t.Fatalf("DetectOverlay: %v", err)
	}
	// notepad.exe may or may not have a small overlay (certificate data).
	// Just verify it doesn't crash and returns a valid result.
	if overlay != nil {
		t.Logf("notepad.exe has overlay: offset=%d size=%d entropy=%.2f",
			overlay.Offset, overlay.Size, overlay.Entropy)
	}
}

func TestDetectOverlay_WithOverlay(t *testing.T) {
	// Test with a real PE (notepad.exe) — it should parse cleanly.
	// We'll create a copy with appended data.
	notepad := filepath.Join(os.Getenv("WINDIR"), "System32", "notepad.exe")
	if _, err := os.Stat(notepad); err != nil {
		t.Skipf("notepad.exe not found: %v", err)
	}

	original, err := os.ReadFile(notepad)
	if err != nil {
		t.Fatalf("reading notepad.exe: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "with_overlay.exe")
	// Append 4KB of random-ish pattern as overlay.
	overlay := make([]byte, 4096)
	for i := range overlay {
		overlay[i] = byte(i % 256)
	}
	if err := os.WriteFile(path, append(original, overlay...), 0o644); err != nil {
		t.Fatalf("writing test PE: %v", err)
	}

	pefile, err := ParsePE(path)
	if err != nil {
		t.Fatalf("ParsePE: %v", err)
	}
	defer pefile.Close()

	result, err := DetectOverlay(pefile, path)
	if err != nil {
		t.Fatalf("DetectOverlay: %v", err)
	}
	if result == nil {
		t.Fatal("expected overlay to be detected")
	}
	if result.Size < 4096 {
		t.Errorf("overlay size = %d, want >= 4096", result.Size)
	}
	if result.Entropy == 0 {
		t.Error("expected non-zero overlay entropy")
	}
}

func TestShannonEntropy_OverlayData(t *testing.T) {
	// All 0xFF bytes → entropy = 0.
	data := make([]byte, 1024)
	for i := range data {
		data[i] = 0xFF
	}
	e := ShannonEntropy(data)
	if e != 0.0 {
		t.Errorf("entropy of all 0xFF = %f, want 0.0", e)
	}
}
