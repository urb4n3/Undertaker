package analysis

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/urb4n3/undertaker/internal/models"
)

// OLE magic bytes: D0 CF 11 E0 A1 B1 1A E1
var oleMagic = [8]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// Suspicious VBA macro keywords.
var macroKeywords = []struct {
	keyword  string
	category string
}{
	{"AutoOpen", "auto_exec"},
	{"Auto_Open", "auto_exec"},
	{"Document_Open", "auto_exec"},
	{"AutoExec", "auto_exec"},
	{"AutoClose", "auto_exec"},
	{"Document_Close", "auto_exec"},
	{"Workbook_Open", "auto_exec"},
	{"Shell", "execution"},
	{"WScript.Shell", "execution"},
	{"Shell.Application", "execution"},
	{"CreateObject", "object_creation"},
	{"GetObject", "object_access"},
	{"PowerShell", "execution"},
	{"cmd.exe", "execution"},
	{"Environ", "discovery"},
	{"CallByName", "obfuscation"},
	{"Chr(", "obfuscation"},
	{"ChrW(", "obfuscation"},
	{"ChrB(", "obfuscation"},
	{"URLDownloadToFile", "download"},
	{"XMLHTTP", "download"},
	{"ADODB.Stream", "file_write"},
	{"Scripting.FileSystemObject", "filesystem"},
	{"VirtualAlloc", "injection"},
	{"RtlMoveMemory", "injection"},
	{"CreateThread", "injection"},
	{"WriteProcessMemory", "injection"},
	{"RegWrite", "persistence"},
	{"RegRead", "registry"},
	{"Kill", "file_operation"},
	{"FileCopy", "file_operation"},
	{"DeleteFile", "file_operation"},
	{"SaveToFile", "file_write"},
	{"Open.*For.*Binary", "file_write"},
	{"MkDir", "filesystem"},
	{"Lib \"kernel32\"", "native_api"},
	{"Lib \"user32\"", "native_api"},
	{"Lib \"ntdll\"", "native_api"},
	{"Private Declare", "native_api"},
}

// AnalyzeDocument performs static analysis on an OLE compound document.
func AnalyzeDocument(path string) (*models.DocumentAnalysis, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening document: %w", err)
	}
	defer f.Close()

	// Read enough data for analysis.
	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat document: %w", err)
	}

	// Cap read at 10MB for safety.
	readSize := stat.Size()
	if readSize > 10*1024*1024 {
		readSize = 10 * 1024 * 1024
	}

	data := make([]byte, readSize)
	n, err := f.Read(data)
	if err != nil {
		return nil, fmt.Errorf("reading document: %w", err)
	}
	data = data[:n]

	result := &models.DocumentAnalysis{
		Metadata: make(map[string]string),
	}

	// Verify OLE magic.
	if n < 8 {
		return result, nil
	}
	var magic [8]byte
	copy(magic[:], data[:8])
	if magic != oleMagic {
		// Not an OLE file — could be OOXML or other format.
		result.Metadata["format"] = "non-OLE"
		// Still scan for macro keywords in raw content.
		scanRawForMacroKeywords(data, result)
		return result, nil
	}

	result.Metadata["format"] = "OLE Compound Document"

	// Parse OLE header for basic info.
	if n >= 48 {
		sectorSize := uint16(1) << binary.LittleEndian.Uint16(data[30:32])
		result.Metadata["sector_size"] = fmt.Sprintf("%d", sectorSize)
	}

	// Extract directory entries to find streams.
	streams := extractOLEStreamNames(data)
	result.Streams = streams

	// Check for VBA macro indicators.
	for _, stream := range streams {
		nameLower := strings.ToLower(stream.Name)
		if strings.Contains(nameLower, "vba") || strings.Contains(nameLower, "macro") ||
			strings.Contains(nameLower, "_vba_project") {
			result.HasMacros = true
			break
		}
	}

	// Scan raw content for macro keywords.
	scanRawForMacroKeywords(data, result)

	// If we found macro keywords, it's a strong macro indicator.
	if len(result.MacroKeywords) > 0 {
		result.HasMacros = true
	}

	return result, nil
}

// extractOLEStreamNames extracts stream names from OLE directory entries.
// This is a simplified parser that looks for directory entry structures.
func extractOLEStreamNames(data []byte) []models.OLEStream {
	var streams []models.OLEStream
	seen := make(map[string]bool)

	if len(data) < 512 {
		return streams
	}

	// OLE directory entries are 128 bytes each. They appear in directory sectors.
	// We do a brute-force scan since full OLE parsing is complex.
	// Each directory entry has a UTF-16LE name at offset 0, name length at offset 64,
	// object type at offset 66, and size at offset 120 (for root/stream).
	for offset := 512; offset+128 <= len(data); offset += 128 {
		entry := data[offset : offset+128]

		// Name size in bytes (at offset 64).
		nameSize := int(binary.LittleEndian.Uint16(entry[64:66]))
		if nameSize < 2 || nameSize > 64 {
			continue
		}

		// Object type at offset 66: 1=storage, 2=stream, 5=root.
		objType := entry[66]
		if objType == 0 || objType > 5 {
			continue
		}

		// Read name (UTF-16LE, nameSize includes null terminator).
		nameChars := (nameSize - 2) / 2 // Exclude null terminator.
		if nameChars <= 0 || nameChars > 31 {
			continue
		}
		runes := make([]rune, nameChars)
		valid := true
		for i := 0; i < nameChars; i++ {
			r := rune(binary.LittleEndian.Uint16(entry[i*2 : i*2+2]))
			if r == 0 {
				runes = runes[:i]
				break
			}
			if r > 0xFFFD {
				valid = false
				break
			}
			runes[i] = r
		}
		if !valid {
			continue
		}

		name := string(runes)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true

		// Size at offset 120 (little-endian uint32).
		size := int64(binary.LittleEndian.Uint32(entry[120:124]))

		streams = append(streams, models.OLEStream{
			Name: name,
			Size: size,
		})
	}

	return streams
}

// scanRawForMacroKeywords scans raw file data for suspicious VBA keywords.
func scanRawForMacroKeywords(data []byte, result *models.DocumentAnalysis) {
	content := string(data)
	contentLower := strings.ToLower(content)

	seen := make(map[string]bool)
	for _, kw := range macroKeywords {
		kwLower := strings.ToLower(kw.keyword)
		idx := strings.Index(contentLower, kwLower)
		if idx >= 0 && !seen[kw.keyword] {
			seen[kw.keyword] = true

			// Extract context around the keyword.
			start := idx
			if start > 20 {
				start = idx - 20
			}
			end := idx + len(kw.keyword) + 40
			if end > len(content) {
				end = len(content)
			}
			ctx := strings.TrimSpace(content[start:end])
			// Clean non-printable chars from context.
			ctx = cleanNonPrintable(ctx)

			result.MacroKeywords = append(result.MacroKeywords, models.MacroKeyword{
				Keyword:  kw.keyword,
				Category: kw.category,
				Context:  truncateContext(ctx, 100),
			})
		}
	}
}

// cleanNonPrintable replaces non-printable characters with spaces.
func cleanNonPrintable(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			sb.WriteRune(r)
		} else {
			sb.WriteByte(' ')
		}
	}
	return sb.String()
}
