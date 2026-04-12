package analysis

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/urb4n3/undertaker/internal/models"
)

// LNK shell link header CLSID: 00021401-0000-0000-C000-000000000046
var lnkCLSID = [16]byte{
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// LNK Link flags (from MS-SHLLINK spec).
const (
	lnkHasLinkTargetIDList        = 0x00000001
	lnkHasLinkInfo                = 0x00000002
	lnkHasName                    = 0x00000004
	lnkHasRelativePath            = 0x00000008
	lnkHasWorkingDir              = 0x00000010
	lnkHasArguments               = 0x00000020
	lnkHasIconLocation            = 0x00000040
)

// ShowCommand constants.
const (
	swShowNormal    = 0x00000001
	swShowMaximized = 0x00000003
	swShowMinNoActive = 0x00000007
)

// AnalyzeLNK parses a Windows shortcut (.lnk) file and extracts forensic details.
func AnalyzeLNK(path string) (*models.LNKAnalysis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading LNK file: %w", err)
	}

	if len(data) < 76 {
		return nil, fmt.Errorf("file too small to be a valid LNK (%d bytes)", len(data))
	}

	// Verify header size (0x4C = 76 bytes) and CLSID.
	headerSize := binary.LittleEndian.Uint32(data[0:4])
	if headerSize != 0x4C {
		return nil, fmt.Errorf("invalid LNK header size: 0x%X", headerSize)
	}

	var fileCLSID [16]byte
	copy(fileCLSID[:], data[4:20])
	if fileCLSID != lnkCLSID {
		return nil, fmt.Errorf("invalid LNK CLSID")
	}

	result := &models.LNKAnalysis{}

	linkFlags := binary.LittleEndian.Uint32(data[20:24])

	// Parse flags.
	var flags []string
	if linkFlags&lnkHasLinkTargetIDList != 0 {
		flags = append(flags, "HasLinkTargetIDList")
	}
	if linkFlags&lnkHasLinkInfo != 0 {
		flags = append(flags, "HasLinkInfo")
	}
	if linkFlags&lnkHasName != 0 {
		flags = append(flags, "HasName")
	}
	if linkFlags&lnkHasRelativePath != 0 {
		flags = append(flags, "HasRelativePath")
	}
	if linkFlags&lnkHasWorkingDir != 0 {
		flags = append(flags, "HasWorkingDir")
	}
	if linkFlags&lnkHasArguments != 0 {
		flags = append(flags, "HasArguments")
	}
	if linkFlags&lnkHasIconLocation != 0 {
		flags = append(flags, "HasIconLocation")
	}
	result.Flags = flags

	// ShowCommand.
	showCmd := binary.LittleEndian.Uint32(data[60:64])
	switch showCmd {
	case swShowNormal:
		result.ShowCommand = "Normal"
	case swShowMaximized:
		result.ShowCommand = "Maximized"
	case swShowMinNoActive:
		result.ShowCommand = "Minimized (no activate)"
	default:
		result.ShowCommand = fmt.Sprintf("0x%08X", showCmd)
	}

	// Navigate through the variable-length sections.
	offset := 76 // Past ShellLinkHeader.

	// Skip LinkTargetIDList if present.
	if linkFlags&lnkHasLinkTargetIDList != 0 {
		if offset+2 > len(data) {
			return result, nil
		}
		idListSize := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2 + idListSize
	}

	// Parse LinkInfo if present — extract local base path.
	if linkFlags&lnkHasLinkInfo != 0 {
		if offset+4 > len(data) {
			return result, nil
		}
		linkInfoSize := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		if linkInfoSize > 4 && offset+linkInfoSize <= len(data) {
			linkInfoData := data[offset : offset+linkInfoSize]
			result.TargetPath = extractLinkInfoPath(linkInfoData)
		}
		offset += linkInfoSize
	}

	// Parse StringData sections.
	if linkFlags&lnkHasName != 0 {
		s, newOff := readLNKStringData(data, offset)
		result.Description = s
		offset = newOff
	}
	if linkFlags&lnkHasRelativePath != 0 {
		s, newOff := readLNKStringData(data, offset)
		if result.TargetPath == "" {
			result.TargetPath = s
		}
		offset = newOff
	}
	if linkFlags&lnkHasWorkingDir != 0 {
		s, newOff := readLNKStringData(data, offset)
		result.WorkingDir = s
		offset = newOff
	}
	if linkFlags&lnkHasArguments != 0 {
		s, newOff := readLNKStringData(data, offset)
		result.Arguments = s
		offset = newOff
	}
	if linkFlags&lnkHasIconLocation != 0 {
		s, newOff := readLNKStringData(data, offset)
		result.IconLocation = s
		offset = newOff
	}

	// Check for appended data after the parsed LNK structure.
	// This is a simplified check — real LNK may have ExtraData blocks.
	// We flag if there's substantial data remaining that could be a payload.
	remaining := len(data) - offset
	if remaining > 1024 { // Ignore small ExtraData blocks.
		result.HasAppendedData = true
		result.AppendedSize = int64(remaining)
	}

	return result, nil
}

// extractLinkInfoPath extracts the local base path from a LinkInfo structure.
func extractLinkInfoPath(info []byte) string {
	if len(info) < 28 {
		return ""
	}

	// LinkInfoHeaderSize.
	headerSize := binary.LittleEndian.Uint32(info[4:8])

	// LocalBasePathOffset (at offset 16 in LinkInfo).
	if headerSize >= 28 {
		localBasePathOff := binary.LittleEndian.Uint32(info[16:20])
		if localBasePathOff > 0 && int(localBasePathOff) < len(info) {
			return readNullTermString(info[localBasePathOff:])
		}
	}

	return ""
}

// readLNKStringData reads a counted Unicode string from StringData.
// Format: uint16 count (characters), then count * 2 bytes of UTF-16LE.
func readLNKStringData(data []byte, offset int) (string, int) {
	if offset+2 > len(data) {
		return "", offset
	}
	charCount := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2
	byteCount := charCount * 2
	if offset+byteCount > len(data) {
		return "", offset
	}

	// Decode UTF-16LE.
	runes := make([]rune, charCount)
	for i := 0; i < charCount; i++ {
		runes[i] = rune(binary.LittleEndian.Uint16(data[offset+i*2 : offset+i*2+2]))
	}
	return string(runes), offset + byteCount
}

// readNullTermString reads a null-terminated ASCII string.
func readNullTermString(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		if b == 0 {
			break
		}
		sb.WriteByte(b)
	}
	return sb.String()
}
