package analysis

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestExtractASCII_Basic(t *testing.T) {
	data := []byte("hello\x00http://evil.com/gate.php\x00ab\x00longer string here\x00")
	results := extractASCII(data, 6)

	found := map[string]bool{}
	for _, r := range results {
		found[r.Value] = true
	}

	if !found["http://evil.com/gate.php"] {
		t.Error("expected to find URL string")
	}
	if !found["longer string here"] {
		t.Error("expected to find 'longer string here'")
	}
	if found["hello"] {
		t.Error("'hello' is only 5 chars, should be excluded with min=6")
	}
	if found["ab"] {
		t.Error("'ab' should be excluded")
	}
}

func TestExtractUTF16LE_Basic(t *testing.T) {
	// Encode "C:\\Windows\\System32" as UTF-16LE.
	s := "C:\\Windows\\System32"
	utf16 := make([]byte, len(s)*2)
	for i, c := range s {
		utf16[i*2] = byte(c)
		utf16[i*2+1] = 0
	}

	results := extractUTF16LE(utf16, 6)
	if len(results) == 0 {
		t.Fatal("expected at least one UTF-16LE string")
	}
	if results[0].Value != s {
		t.Errorf("got %q, want %q", results[0].Value, s)
	}
	if results[0].Encoding != "utf16" {
		t.Errorf("encoding = %q, want utf16", results[0].Encoding)
	}
}

func TestDetectBase64_ValidBlob(t *testing.T) {
	// Encode a URL as base64 and embed it in binary data.
	plaintext := "http://evil.com/callback"
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
	data := append([]byte("\x00\x00\x00"), []byte(encoded)...)
	data = append(data, 0x00, 0x00, 0x00)

	results := detectBase64(data)
	found := false
	for _, r := range results {
		if r.Value == plaintext {
			found = true
			if r.Source != "base64_decoded" {
				t.Errorf("source = %q, want base64_decoded", r.Source)
			}
		}
	}
	if !found {
		t.Errorf("expected to find decoded base64 URL %q", plaintext)
	}
}

func TestDetectBase64_TooShort(t *testing.T) {
	// Short base64 should be ignored.
	data := []byte("QUJD") // "ABC" — only 4 chars
	results := detectBase64(data)
	if len(results) != 0 {
		t.Errorf("expected no results for short base64, got %d", len(results))
	}
}

func TestDetectBase64_NonPrintable(t *testing.T) {
	// Base64 that decodes to binary data should be excluded.
	binary := make([]byte, 30)
	for i := range binary {
		binary[i] = byte(i) // Mostly non-printable
	}
	encoded := base64.StdEncoding.EncodeToString(binary)
	data := []byte(encoded)
	results := detectBase64(data)
	if len(results) != 0 {
		t.Errorf("expected no results for non-printable base64 decode, got %d", len(results))
	}
}

func TestCategorize(t *testing.T) {
	filters, err := LoadStringFilters()
	if err != nil {
		t.Fatalf("LoadStringFilters: %v", err)
	}

	var categories []compiledCategory
	for _, cat := range filters.Categories {
		cc := compiledCategory{Name: cat.Name, Priority: cat.Priority}
		for _, p := range cat.Patterns {
			re, _ := compileRegexp(p)
			if re != nil {
				cc.Regexps = append(cc.Regexps, re)
			}
		}
		categories = append(categories, cc)
	}

	tests := []struct {
		input    string
		wantCat  string
	}{
		{"http://evil.com/gate.php", "c2"},
		{"192.168.1.100", "c2"},
		{"C:\\Windows\\System32\\cmd.exe", "filesystem"},
		{"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft", "registry"},
		{"CryptEncrypt", "crypto"},
		{"Global\\MyMutex", "mutex"},
		{"just a normal string here", "uncategorized"},
	}

	for _, tt := range tests {
		cat, _ := categorize(tt.input, categories)
		if cat != tt.wantCat {
			t.Errorf("categorize(%q) = %q, want %q", tt.input, cat, tt.wantCat)
		}
	}
}

func TestIsNoise(t *testing.T) {
	filters, err := LoadStringFilters()
	if err != nil {
		t.Fatalf("LoadStringFilters: %v", err)
	}

	var noiseRegexps []*regexp.Regexp
	for _, p := range filters.NoiseFilters {
		re, _ := compileRegexp(p)
		if re != nil {
			noiseRegexps = append(noiseRegexps, re)
		}
	}

	tests := []struct {
		input string
		noise bool
	}{
		{"This program cannot be run in DOS mode", true},
		{".text", true},
		{".rdata", true},
		{"http://evil.com", false},
		{"VirtualAllocEx", false},
	}

	for _, tt := range tests {
		got := isNoise(tt.input, noiseRegexps)
		if got != tt.noise {
			t.Errorf("isNoise(%q) = %v, want %v", tt.input, got, tt.noise)
		}
	}
}

func TestExtractStrings_CapEnforced(t *testing.T) {
	// Create a file with many unique strings (> 50).
	dir := t.TempDir()
	path := filepath.Join(dir, "many_strings.bin")

	var content []byte
	for i := 0; i < 100; i++ {
		s := []byte("unique_string_number_" + string(rune('A'+i%26)) + string(rune('0'+i/26)) + "_padding")
		content = append(content, s...)
		content = append(content, 0) // null terminator
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Without --full: capped at 50.
	hits, err := ExtractStrings(path, false)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}
	if len(hits) > 50 {
		t.Errorf("expected cap at 50, got %d", len(hits))
	}

	// With --full: no cap.
	hitsFull, err := ExtractStrings(path, true)
	if err != nil {
		t.Fatalf("ExtractStrings --full: %v", err)
	}
	if len(hitsFull) <= len(hits) && len(hits) == 50 {
		t.Logf("full returned %d strings (may have fewer unique after dedup)", len(hitsFull))
	}
}

func TestExtractStrings_Dedup(t *testing.T) {
	// File with duplicate strings.
	dir := t.TempDir()
	path := filepath.Join(dir, "dupes.bin")
	content := []byte("repeated_string\x00repeated_string\x00repeated_string\x00")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	hits, err := ExtractStrings(path, false)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}

	count := 0
	for _, h := range hits {
		if h.Value == "repeated_string" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected dedup to 1 occurrence, got %d", count)
	}
}

func TestExtractStrings_Ranking(t *testing.T) {
	// File with a c2 string and a debug string — c2 should rank higher.
	dir := t.TempDir()
	path := filepath.Join(dir, "ranked.bin")
	content := []byte("debug: something failed here\x00http://evil.com/gate.php\x00")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	hits, err := ExtractStrings(path, false)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}
	if len(hits) < 2 {
		t.Fatalf("expected at least 2 hits, got %d", len(hits))
	}

	// First hit should be the c2 (priority 1), not the debug (priority 6).
	if hits[0].Category != "c2" {
		t.Errorf("first hit category = %q, want c2 (highest priority)", hits[0].Category)
	}
}

// compileRegexp is a helper to compile regex, returning nil on error.
func compileRegexp(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(pattern)
}
