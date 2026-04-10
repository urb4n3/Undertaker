package reporting

import (
	"strings"
	"testing"
	"time"

	"github.com/urb4n3/undertaker/internal/models"
)

func TestGenerateMarkdownBasic(t *testing.T) {
	report := &models.AnalysisReport{
		Sample: models.Sample{
			Path:         "/samples/test.exe",
			SHA256:       "abc123def456",
			MD5:          "md5hash",
			SHA1:         "sha1hash",
			SSDeep:       "ssdeephash",
			ImpHash:      "imphash",
			FileType:     "PE64",
			Architecture: "AMD64",
			FileSize:     245760,
		},
		Packing: models.PackingInfo{
			Confidence: "none",
			Label:      "Not packed",
			Entropy:    5.2,
		},
		Imports: models.ImportAnalysis{
			TotalImports: 42,
		},
	}

	md := GenerateMarkdown(report)

	// Check essential sections exist.
	if !strings.Contains(md, "# Undertaker Static Analysis Report") {
		t.Error("missing report title")
	}
	if !strings.Contains(md, "## test.exe") {
		t.Error("missing filename header")
	}
	if !strings.Contains(md, "### Identity") {
		t.Error("missing Identity section")
	}
	if !strings.Contains(md, "### Summary") {
		t.Error("missing Summary section")
	}
	if !strings.Contains(md, "`abc123def456`") {
		t.Error("missing SHA256")
	}
	if !strings.Contains(md, "PE64") {
		t.Error("missing file type")
	}
	if !strings.Contains(md, "AMD64") {
		t.Error("missing architecture")
	}
}

func TestGenerateMarkdownWithFindings(t *testing.T) {
	report := &models.AnalysisReport{
		Sample: models.Sample{
			Path:     "/samples/evil.dll",
			SHA256:   "deadbeef12345678",
			MD5:      "md5",
			SHA1:     "sha1",
			SSDeep:   "ssdeep",
			ImpHash:  "imphash",
			FileType: "DLL64",
			FileSize: 102400,
		},
		Packing: models.PackingInfo{
			Confidence: "high",
			Label:      "Packed (high confidence)",
			PackerName: "UPX",
			Entropy:    7.42,
			Signals:    []string{"UPX signature", "high entropy"},
		},
		Imports: models.ImportAnalysis{
			TotalImports: 5,
			SuspiciousImports: []models.SuspiciousImport{
				{Name: "VirtualAllocEx", DLL: "kernel32.dll", Capability: "process_injection"},
				{Name: "CreateRemoteThread", DLL: "kernel32.dll", Capability: "process_injection"},
			},
			CapabilityTags: []string{"process_injection"},
		},
		Exports: []models.Export{
			{Name: "DllMain", Ordinal: 1},
			{Name: "ServiceMain", Ordinal: 2},
		},
		RichHeader: &models.RichHeader{
			Entries: []models.RichEntry{
				{Toolchain: "Visual C++ 2019", Type: "linker", Count: 1},
			},
		},
		Overlay: &models.OverlayInfo{
			Offset:  100000,
			Size:    2400,
			Entropy: 7.91,
		},
		Strings: []models.StringHit{
			{Value: "http://evil.com/gate.php", Category: "c2", Source: "raw"},
			{Value: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", Category: "registry", Source: "raw"},
		},
		IOCs: []models.IOC{
			{Type: "domain", Value: "evil.com", Source: "strings"},
			{Type: "url", Value: "http://evil.com/gate.php", Source: "strings"},
		},
		Capabilities: []models.Capability{
			{TechniqueID: "T1055", TechniqueName: "Process Injection", Source: "capa"},
			{TechniqueID: "T1055", TechniqueName: "process_injection", Source: "imports"},
		},
		YARAMatches: []models.YARAMatch{
			{RuleName: "cobalt_strike_beacon", Tags: []string{"malware"}},
		},
		Metadata: models.PEMetadata{
			CompileTimestamp: time.Date(2024, 1, 15, 8, 32, 11, 0, time.UTC),
			Sections: []models.SectionInfo{
				{Name: ".text", Entropy: 7.81, VirtualSize: 40960, RawSize: 40960},
				{Name: ".rdata", Entropy: 4.12, VirtualSize: 8192, RawSize: 8192},
			},
		},
		Errors: []models.AnalyzerError{
			{Analyzer: "richheader", Error: "corrupted rich header"},
		},
	}

	md := GenerateMarkdown(report)

	checks := []struct {
		label    string
		expected string
	}{
		{"packing label", "Packed (high confidence)"},
		{"packer name", "UPX"},
		{"export name", "DllMain"},
		{"rich header", "Visual C++ 2019"},
		{"overlay", "Overlay detected"},
		{"overlay entropy", "7.91"},
		{"suspicious import", "VirtualAllocEx"},
		{"capability group", "Process Injection"},
		{"string hit", "http://evil.com/gate.php"},
		{"IOC table header", "| Type | Value | Source |"},
		{"IOC domain", "evil.com"},
		{"YARA match", "cobalt_strike_beacon"},
		{"section entropy", ".text: 7.81 (high)"},
		{"compile timestamp", "2024-01-15 08:32:11 UTC"},
		{"errors section", "### Analyzer Errors"},
		{"error detail", "corrupted rich header"},
		{"capa section", "capa \u2014 ATT&CK techniques"},
		{"technique ID", "T1055"},
	}

	for _, c := range checks {
		if !strings.Contains(md, c.expected) {
			t.Errorf("missing %s: expected %q in report", c.label, c.expected)
		}
	}
}

func TestGenerateMarkdownWarnings(t *testing.T) {
	// Packed sample without FLOSS and few strings.
	report := &models.AnalysisReport{
		Sample: models.Sample{
			Path:     "/samples/packed.exe",
			SHA256:   "aabbccdd",
			FileType: "PE32",
			FileSize: 50000,
		},
		Packing: models.PackingInfo{
			Confidence: "high",
			Label:      "Packed (high confidence)",
			Entropy:    7.5,
		},
		Strings: []models.StringHit{
			{Value: "test", Category: "uncategorized", Source: "raw"},
			{Value: "test2", Category: "uncategorized", Source: "raw"},
		},
		Imports: models.ImportAnalysis{TotalImports: 3},
	}

	md := GenerateMarkdown(report)

	if !strings.Contains(md, "without FLOSS") {
		t.Error("missing FLOSS unavailability warning")
	}
	if !strings.Contains(md, "packed and FLOSS is not available") {
		t.Error("missing packed+no-FLOSS warning")
	}
	if !strings.Contains(md, "Unusually few strings") {
		t.Error("missing low string count warning")
	}
}

func TestGenerateJSON(t *testing.T) {
	report := &models.AnalysisReport{
		Sample: models.Sample{
			Path:   "/samples/test.exe",
			SHA256: "abc123",
			MD5:    "md5",
		},
	}

	data, err := GenerateJSON(report)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("empty JSON output")
	}

	s := string(data)
	if !strings.Contains(s, "abc123") {
		t.Error("missing SHA256 in JSON output")
	}
	if !strings.Contains(s, "\"sha256\"") {
		t.Error("missing sha256 field key in JSON output")
	}
}

func TestHumanSize(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{500, "500 bytes"},
		{1024, "1.0 KB"},
		{1048576, "1.00 MB"},
		{245760, "240.0 KB"},
	}
	for _, tc := range tests {
		got := humanSize(tc.input)
		if got != tc.expected {
			t.Errorf("humanSize(%d) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestTruncateString(t *testing.T) {
	short := "hello"
	if truncateString(short, 10) != "hello" {
		t.Error("short string should not be truncated")
	}

	long := "this is a very long string that should be truncated"
	result := truncateString(long, 20)
	if len(result) > 20 {
		t.Errorf("truncated string too long: %d chars", len(result))
	}
	if !strings.HasSuffix(result, "...") {
		t.Error("truncated string should end with ...")
	}
}
