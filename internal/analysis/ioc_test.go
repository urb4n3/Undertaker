package analysis

import (
	"fmt"
	"testing"

	"github.com/urb4n3/undertaker/internal/models"
)

func TestExtractIOCs_IPv4(t *testing.T) {
	hits := []models.StringHit{
		{Value: "connecting to 192.168.1.100 on port 443"},
		{Value: "fallback server 10.20.30.40"},
	}

	iocs, err := ExtractIOCs(hits, false)
	if err != nil {
		t.Fatalf("ExtractIOCs: %v", err)
	}

	found := map[string]bool{}
	for _, ioc := range iocs {
		if ioc.Type == "ip" {
			found[ioc.Value] = true
		}
	}
	if !found["192.168.1.100"] {
		t.Error("expected to find IP 192.168.1.100")
	}
	if !found["10.20.30.40"] {
		t.Error("expected to find IP 10.20.30.40")
	}
}

func TestExtractIOCs_Domain(t *testing.T) {
	hits := []models.StringHit{
		{Value: "http://evil-domain.com/gate.php"},
		{Value: "callback to updates.malware.ru"},
	}

	iocs, err := ExtractIOCs(hits, false)
	if err != nil {
		t.Fatalf("ExtractIOCs: %v", err)
	}

	foundDomains := map[string]bool{}
	for _, ioc := range iocs {
		if ioc.Type == "domain" {
			foundDomains[ioc.Value] = true
		}
	}
	if !foundDomains["evil-domain.com"] {
		t.Error("expected to find domain evil-domain.com")
	}
	if !foundDomains["updates.malware.ru"] {
		t.Error("expected to find domain updates.malware.ru")
	}
}

func TestExtractIOCs_URL(t *testing.T) {
	hits := []models.StringHit{
		{Value: "http://evil.com/gate.php?id=123"},
	}

	iocs, err := ExtractIOCs(hits, false)
	if err != nil {
		t.Fatalf("ExtractIOCs: %v", err)
	}

	found := false
	for _, ioc := range iocs {
		if ioc.Type == "url" && ioc.Value == "http://evil.com/gate.php?id=123" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find URL IOC")
	}
}

func TestExtractIOCs_Registry(t *testing.T) {
	hits := []models.StringHit{
		{Value: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
	}

	iocs, err := ExtractIOCs(hits, false)
	if err != nil {
		t.Fatalf("ExtractIOCs: %v", err)
	}

	found := false
	for _, ioc := range iocs {
		if ioc.Type == "registry" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find registry IOC")
	}
}

func TestExtractIOCs_FilePath(t *testing.T) {
	hits := []models.StringHit{
		{Value: "C:\\Windows\\System32\\malware.exe"},
		{Value: "%APPDATA%\\Microsoft\\svchost.exe"},
	}

	iocs, err := ExtractIOCs(hits, false)
	if err != nil {
		t.Fatalf("ExtractIOCs: %v", err)
	}

	found := false
	for _, ioc := range iocs {
		if ioc.Type == "filepath" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find filepath IOC")
	}
}

func TestExtractIOCs_Dedup(t *testing.T) {
	// Same IP in multiple strings should only appear once.
	hits := []models.StringHit{
		{Value: "connecting to 192.168.1.100"},
		{Value: "server at 192.168.1.100"},
		{Value: "192.168.1.100 is the C2"},
	}

	iocs, err := ExtractIOCs(hits, false)
	if err != nil {
		t.Fatalf("ExtractIOCs: %v", err)
	}

	count := 0
	for _, ioc := range iocs {
		if ioc.Type == "ip" && ioc.Value == "192.168.1.100" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 occurrence of 192.168.1.100, got %d", count)
	}
}

func TestExtractIOCs_CapEnforced(t *testing.T) {
	// Create many string hits with unique IPs to exceed cap.
	var hits []models.StringHit
	for i := 1; i <= 50; i++ {
		hits = append(hits, models.StringHit{
			Value: fmt.Sprintf("server at 10.0.%d.%d", i/256, i%256),
		})
	}

	iocs, err := ExtractIOCs(hits, false)
	if err != nil {
		t.Fatalf("ExtractIOCs: %v", err)
	}
	if len(iocs) > 30 {
		t.Errorf("expected cap at 30, got %d", len(iocs))
	}

	// With --full: no cap.
	iocsFull, err := ExtractIOCs(hits, true)
	if err != nil {
		t.Fatalf("ExtractIOCs --full: %v", err)
	}
	if len(iocsFull) < len(iocs) {
		t.Errorf("full should return >= capped: full=%d, capped=%d", len(iocsFull), len(iocs))
	}
}

func TestExtractIOCs_FalsePositiveFiltering(t *testing.T) {
	hits := []models.StringHit{
		{Value: "0.0.0.0"},
		{Value: "127.0.0.1"},
		{Value: "255.255.255.255"},
		{Value: "1.0.0.0"},   // Version-like
		{Value: "10.0.0.0"},  // Version-like
	}

	iocs, err := ExtractIOCs(hits, false)
	if err != nil {
		t.Fatalf("ExtractIOCs: %v", err)
	}

	for _, ioc := range iocs {
		if ioc.Type == "ip" {
			t.Errorf("expected false positive IP %q to be filtered", ioc.Value)
		}
	}
}

func TestExtractIOCs_Mutex(t *testing.T) {
	hits := []models.StringHit{
		{Value: "Global\\MyMutexName"},
	}

	iocs, err := ExtractIOCs(hits, false)
	if err != nil {
		t.Fatalf("ExtractIOCs: %v", err)
	}

	found := false
	for _, ioc := range iocs {
		if ioc.Type == "mutex" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find mutex IOC")
	}
}
