package analysis

import (
	"strings"
	"testing"

	"github.com/urb4n3/undertaker/internal/models"
)

func TestLoadAPICapabilities(t *testing.T) {
	caps, err := LoadAPICapabilities()
	if err != nil {
		t.Fatalf("LoadAPICapabilities: %v", err)
	}

	if len(caps) == 0 {
		t.Fatal("expected non-empty capability map")
	}

	// Check a known entry.
	cap, ok := caps["virtualallocex"]
	if !ok {
		t.Fatal("expected VirtualAllocEx in capability map")
	}
	if cap.Capability != "process_injection" {
		t.Errorf("VirtualAllocEx capability = %q, want process_injection", cap.Capability)
	}
	if cap.TechniqueID != "T1055" {
		t.Errorf("VirtualAllocEx technique_id = %q, want T1055", cap.TechniqueID)
	}
}

func TestLoadAPICapabilities_CaseInsensitive(t *testing.T) {
	caps, err := LoadAPICapabilities()
	if err != nil {
		t.Fatalf("LoadAPICapabilities: %v", err)
	}

	// Keys should be lowercase.
	if _, ok := caps["createremotethread"]; !ok {
		t.Error("expected CreateRemoteThread in lowercase key")
	}
}

func TestStripAWSuffix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"CreateFileA", "CreateFile"},
		{"CreateFileW", "CreateFile"},
		{"WriteFile", "WriteFile"},
		{"A", "A"},
		{"VirtualAlloc", "VirtualAlloc"},
		{"InternetOpenUrlW", "InternetOpenUrl"},
	}
	for _, tt := range tests {
		got := stripAWSuffix(tt.input)
		if got != tt.want {
			t.Errorf("stripAWSuffix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDeriveCapabilities(t *testing.T) {
	caps := capabilityMap{
		"virtualallocex":     models.APICapability{API: "VirtualAllocEx", DLL: "kernel32.dll", Capability: "process_injection", TechniqueID: "T1055"},
		"createremotethread": models.APICapability{API: "CreateRemoteThread", DLL: "kernel32.dll", Capability: "process_injection", TechniqueID: "T1055"},
		"internetopena":      models.APICapability{API: "InternetOpenA", DLL: "wininet.dll", Capability: "network", TechniqueID: "T1071"},
	}

	imports := &models.ImportAnalysis{
		TotalImports: 10,
		SuspiciousImports: []models.SuspiciousImport{
			{Name: "VirtualAllocEx", DLL: "kernel32.dll", Capability: "process_injection"},
			{Name: "CreateRemoteThread", DLL: "kernel32.dll", Capability: "process_injection"},
			{Name: "InternetOpenA", DLL: "wininet.dll", Capability: "network"},
		},
		CapabilityTags: []string{"process_injection", "network"},
	}

	capabilities := DeriveCapabilities(imports, caps)
	if len(capabilities) == 0 {
		t.Fatal("expected non-empty capabilities")
	}

	// Should have entries for process_injection and network.
	foundInjection := false
	foundNetwork := false
	for _, c := range capabilities {
		if c.Source != "imports" {
			t.Errorf("Source = %q, want imports", c.Source)
		}
		if strings.Contains(c.TechniqueName, "process_injection") {
			foundInjection = true
		}
		if strings.Contains(c.TechniqueName, "network") {
			foundNetwork = true
		}
	}
	if !foundInjection {
		t.Error("expected process_injection capability")
	}
	if !foundNetwork {
		t.Error("expected network capability")
	}
}

func TestDeriveCapabilities_Empty(t *testing.T) {
	caps := capabilityMap{}
	imports := &models.ImportAnalysis{TotalImports: 5}

	capabilities := DeriveCapabilities(imports, caps)
	if len(capabilities) != 0 {
		t.Errorf("expected empty capabilities, got %d", len(capabilities))
	}
}
