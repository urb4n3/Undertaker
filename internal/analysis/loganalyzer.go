package analysis

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/urb4n3/undertaker/data"
	"github.com/urb4n3/undertaker/internal/models"
)

// LogKeywordConfig holds keyword patterns for log analysis.
type LogKeywordConfig struct {
	Keywords []LogKeywordEntry `json:"keywords"`
}

// LogKeywordEntry represents a single suspicious keyword.
type LogKeywordEntry struct {
	Keyword     string `json:"keyword"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// EVTX magic bytes: "ElfFile\x00"
var evtxMagic = [8]byte{'E', 'l', 'f', 'F', 'i', 'l', 'e', 0x00}

// Well-known Windows Event IDs and their descriptions.
var knownEventIDs = map[int]string{
	1:    "Process Create (Sysmon)",
	3:    "Network Connection (Sysmon)",
	7:    "Image Loaded (Sysmon)",
	8:    "CreateRemoteThread (Sysmon)",
	10:   "Process Access (Sysmon)",
	11:   "File Create (Sysmon)",
	12:   "Registry Event (Sysmon)",
	13:   "Registry Value Set (Sysmon)",
	22:   "DNS Query (Sysmon)",
	4624: "Logon Success",
	4625: "Logon Failure",
	4648: "Explicit Credential Logon",
	4672: "Special Privileges Assigned",
	4688: "Process Creation",
	4697: "Service Installed",
	4698: "Scheduled Task Created",
	4699: "Scheduled Task Deleted",
	4702: "Scheduled Task Updated",
	4720: "User Account Created",
	4722: "User Account Enabled",
	4724: "Password Reset Attempt",
	4728: "Member Added to Security Group",
	4732: "Member Added to Local Group",
	4738: "User Account Changed",
	4768: "Kerberos TGT Requested",
	4769: "Kerberos Service Ticket Requested",
	4771: "Kerberos Pre-Auth Failed",
	4776: "NTLM Authentication",
	5140: "Network Share Accessed",
	5145: "Network Share Object Checked",
	7045: "Service Installed",
	1102: "Audit Log Cleared",
}

// Timestamp patterns for text log parsing.
var timestampPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}`),                   // ISO 8601
	regexp.MustCompile(`\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}`),                     // MM/DD/YYYY HH:MM:SS
	regexp.MustCompile(`[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}`),               // Syslog
	regexp.MustCompile(`\d{10,13}`),                                                    // Unix epoch
}

// Event ID extraction from various log formats.
var eventIDPattern = regexp.MustCompile(`(?i)(?:EventID|Event ID|event_id)[:\s=]+(\d{1,5})`)

// AnalyzeLog performs analysis on a log file (EVTX or text).
func AnalyzeLog(path string) (*models.LogAnalysis, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening log file: %w", err)
	}
	defer f.Close()

	// Read first 8 bytes to check for EVTX format.
	header := make([]byte, 8)
	n, _ := f.Read(header)
	f.Seek(0, 0)

	if n >= 8 {
		var magic [8]byte
		copy(magic[:], header[:8])
		if magic == evtxMagic {
			return analyzeEVTX(path)
		}
	}

	return analyzeTextLog(path)
}

// analyzeEVTX performs triage analysis on Windows EVTX files.
func analyzeEVTX(path string) (*models.LogAnalysis, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening EVTX: %w", err)
	}
	defer f.Close()

	result := &models.LogAnalysis{
		Format: "EVTX (Windows Event Log)",
	}

	stat, err := f.Stat()
	if err != nil {
		return result, nil
	}

	// Read file in chunks and do text-based extraction.
	// Full EVTX binary parsing is complex (BinXml format); we extract
	// useful data by scanning for XML fragments and patterns.
	readSize := stat.Size()
	if readSize > 50*1024*1024 {
		readSize = 50 * 1024 * 1024
	}

	data := make([]byte, readSize)
	n, err := f.Read(data)
	if err != nil {
		return result, nil
	}
	data = data[:n]

	content := string(data)

	// Count event records. Each record starts with magic 0x2A 0x2A 0x00 0x00.
	recordCount := 0
	for i := 0; i+4 <= len(data); i++ {
		if data[i] == 0x2A && data[i+1] == 0x2A && data[i+2] == 0x00 && data[i+3] == 0x00 {
			recordCount++
		}
	}
	result.TotalEntries = recordCount

	// Extract Event IDs from XML fragments.
	eventIDCounts := make(map[int]int)
	eidRe := regexp.MustCompile(`<EventID(?:\s[^>]*)?>(\d{1,5})</EventID>`)
	for _, match := range eidRe.FindAllStringSubmatch(content, -1) {
		if len(match) >= 2 {
			var eid int
			fmt.Sscanf(match[1], "%d", &eid)
			if eid > 0 {
				eventIDCounts[eid]++
			}
		}
	}

	// Build top Event IDs.
	type eidEntry struct {
		id    int
		count int
	}
	var sorted []eidEntry
	for id, count := range eventIDCounts {
		sorted = append(sorted, eidEntry{id, count})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})
	limit := 20
	if len(sorted) < limit {
		limit = len(sorted)
	}
	for _, e := range sorted[:limit] {
		desc := knownEventIDs[e.id]
		if desc == "" {
			desc = "Unknown"
		}
		result.TopEventIDs = append(result.TopEventIDs, models.EventIDCount{
			EventID:     e.id,
			Description: desc,
			Count:       e.count,
		})
	}

	// Flag high-value security events.
	flaggedIDs := map[int]string{
		4688: "Process creation events — review command lines",
		4624: "Logon events — check for anomalous logon types",
		4625: "Failed logons — potential brute force",
		4648: "Explicit credential usage — lateral movement indicator",
		4672: "Privileged logon — admin activity",
		7045: "Service installation — persistence mechanism",
		4698: "Scheduled task creation — persistence mechanism",
		4720: "Account creation — potential backdoor account",
		1102: "Event log cleared — anti-forensics",
		1:    "Sysmon process creation — execution tracking",
		3:    "Sysmon network connection — C2 communication",
		8:    "Sysmon CreateRemoteThread — process injection",
		10:   "Sysmon process access — credential dumping indicator",
	}
	for eid, desc := range flaggedIDs {
		if count, ok := eventIDCounts[eid]; ok && count > 0 {
			result.FlaggedEvents = append(result.FlaggedEvents, models.FlaggedEvent{
				EventID:     eid,
				Description: fmt.Sprintf("%s (%d occurrences)", desc, count),
			})
		}
	}

	// Sort flagged events by event ID for consistent output.
	sort.Slice(result.FlaggedEvents, func(i, j int) bool {
		return result.FlaggedEvents[i].EventID < result.FlaggedEvents[j].EventID
	})

	// Extract timestamps for time range.
	tsRe := regexp.MustCompile(`<TimeCreated SystemTime='(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})`)
	timestamps := tsRe.FindAllStringSubmatch(content, -1)
	if len(timestamps) > 0 {
		earliest := timestamps[0][1]
		latest := timestamps[len(timestamps)-1][1]
		result.TimeRange = &models.TimeRange{
			Earliest: earliest,
			Latest:   latest,
		}
	}

	// Keyword scan on the raw content.
	loadAndScanKeywords(content, result)

	return result, nil
}

// analyzeTextLog performs triage analysis on text-based log files.
func analyzeTextLog(path string) (*models.LogAnalysis, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening text log: %w", err)
	}
	defer f.Close()

	result := &models.LogAnalysis{
		Format: "Text Log",
	}

	// Read up to 20MB.
	stat, err := f.Stat()
	if err != nil {
		return result, nil
	}

	readSize := stat.Size()
	if readSize > 20*1024*1024 {
		readSize = 20 * 1024 * 1024
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var lineCount int
	var allContent strings.Builder
	var firstTimestamp, lastTimestamp string

	eventIDCounts := make(map[int]int)

	for scanner.Scan() {
		lineCount++
		line := scanner.Text()
		allContent.WriteString(line)
		allContent.WriteByte('\n')

		// Extract timestamps.
		for _, re := range timestampPatterns {
			if ts := re.FindString(line); ts != "" {
				if firstTimestamp == "" {
					firstTimestamp = ts
				}
				lastTimestamp = ts
				break
			}
		}

		// Extract event IDs.
		if match := eventIDPattern.FindStringSubmatch(line); len(match) >= 2 {
			var eid int
			fmt.Sscanf(match[1], "%d", &eid)
			if eid > 0 {
				eventIDCounts[eid]++
			}
		}
	}

	result.TotalEntries = lineCount

	if firstTimestamp != "" {
		result.TimeRange = &models.TimeRange{
			Earliest: firstTimestamp,
			Latest:   lastTimestamp,
		}
	}

	// Build top Event IDs if any were found.
	if len(eventIDCounts) > 0 {
		type eidEntry struct {
			id    int
			count int
		}
		var sorted []eidEntry
		for id, count := range eventIDCounts {
			sorted = append(sorted, eidEntry{id, count})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		limit := 20
		if len(sorted) < limit {
			limit = len(sorted)
		}
		for _, e := range sorted[:limit] {
			desc := knownEventIDs[e.id]
			if desc == "" {
				desc = "Unknown"
			}
			result.TopEventIDs = append(result.TopEventIDs, models.EventIDCount{
				EventID:     e.id,
				Description: desc,
				Count:       e.count,
			})
		}
	}

	// Keyword scan.
	content := allContent.String()
	loadAndScanKeywords(content, result)

	return result, nil
}

// loadAndScanKeywords loads keyword patterns and scans content for matches.
func loadAndScanKeywords(content string, result *models.LogAnalysis) {
	keywords, err := LoadLogKeywords()
	if err != nil {
		return
	}

	contentLower := strings.ToLower(content)

	for _, kw := range keywords.Keywords {
		kwLower := strings.ToLower(kw.Keyword)
		count := strings.Count(contentLower, kwLower)
		if count > 0 {
			result.KeywordHits = append(result.KeywordHits, models.LogKeywordHit{
				Keyword: kw.Keyword,
				Count:   count,
				Context: kw.Description,
			})
		}
	}

	// Sort by count descending.
	sort.Slice(result.KeywordHits, func(i, j int) bool {
		return result.KeywordHits[i].Count > result.KeywordHits[j].Count
	})
}

// LoadLogKeywords loads log keyword patterns from embedded data.
func LoadLogKeywords() (*LogKeywordConfig, error) {
	var config LogKeywordConfig
	if err := json.Unmarshal(data.LogKeywords, &config); err != nil {
		return nil, fmt.Errorf("parsing log keywords: %w", err)
	}
	return &config, nil
}

// IsLogFile checks if the file appears to be a log file based on extension and content.
func IsLogFile(path string, header []byte) bool {
	ext := strings.ToLower(path)

	// Extension-based detection.
	logExts := []string{".log", ".evtx", ".evt", ".txt", ".csv", ".tsv", ".syslog"}
	for _, le := range logExts {
		if strings.HasSuffix(ext, le) {
			return true
		}
	}

	// EVTX magic.
	if len(header) >= 8 {
		var magic [8]byte
		copy(magic[:], header[:8])
		if magic == evtxMagic {
			return true
		}
	}

	// Content heuristic: check if file looks like a log (has timestamps on multiple lines).
	if len(header) > 100 {
		content := string(header[:min(len(header), 2048)])
		timestampCount := 0
		for _, re := range timestampPatterns {
			timestampCount += len(re.FindAllString(content, 10))
		}
		if timestampCount >= 3 {
			return true
		}
	}

	return false
}

// IsPCAP checks if the file appears to be a network capture.
func IsPCAP(path string, header []byte) bool {
	ext := strings.ToLower(path)
	if strings.HasSuffix(ext, ".pcap") || strings.HasSuffix(ext, ".pcapng") || strings.HasSuffix(ext, ".cap") {
		return true
	}

	if len(header) >= 4 {
		// PCAP magic: 0xA1B2C3D4 (big-endian) or 0xD4C3B2A1 (little-endian)
		magic := binary.BigEndian.Uint32(header[:4])
		if magic == 0xA1B2C3D4 || magic == 0xD4C3B2A1 {
			return true
		}
		// PCAPNG magic: 0x0A0D0D0A (Section Header Block)
		if magic == 0x0A0D0D0A {
			return true
		}
	}

	return false
}

// Compile-time check that time package is used (for future EVTX timestamp parsing).
var _ = time.Now
