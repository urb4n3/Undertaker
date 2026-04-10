package analysis

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// FileType constants for identified file types.
const (
	FileTypePE32      = "PE32"
	FileTypePE64      = "PE64"
	FileTypeDLL32     = "DLL32"
	FileTypeDLL64     = "DLL64"
	FileTypeDotNet    = ".NET"
	FileTypeOLE       = "OLE"
	FileTypeLNK       = "LNK"
	FileTypeScript    = "script"
	FileTypeMSI       = "MSI"
	FileTypeISO       = "ISO"
	FileTypeZIP       = "ZIP"
	FileTypeRAR       = "RAR"
	FileType7Z        = "7z"
	FileTypeShellcode = "shellcode"
	FileTypeUnknown   = "unknown"
)

// FileIDResult holds the results of file type identification.
type FileIDResult struct {
	FileType     string
	Architecture string
	IsPE         bool
	IsDLL        bool
	IsDotNet     bool
}

// IdentifyFile detects the file type from magic bytes and PE header parsing.
func IdentifyFile(path string) (*FileIDResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	// Read first 4KB for magic byte detection.
	header := make([]byte, 4096)
	n, err := f.Read(header)
	if err != nil {
		return nil, fmt.Errorf("reading file header: %w", err)
	}
	header = header[:n]

	if n < 2 {
		return &FileIDResult{FileType: FileTypeUnknown}, nil
	}

	// Check non-PE types first by magic bytes.
	if result := checkNonPEMagic(header, path); result != nil {
		return result, nil
	}

	// Check for MZ header (PE).
	if n >= 2 && header[0] == 'M' && header[1] == 'Z' {
		return identifyPE(f, header)
	}

	// Check if it might be a script by content.
	if isScriptContent(header, path) {
		return &FileIDResult{FileType: FileTypeScript}, nil
	}

	return &FileIDResult{FileType: FileTypeUnknown}, nil
}

// checkNonPEMagic checks for known non-PE file signatures.
func checkNonPEMagic(header []byte, path string) *FileIDResult {
	n := len(header)

	// OLE Compound Document (DOC, XLS, PPT)
	if n >= 8 && header[0] == 0xD0 && header[1] == 0xCF && header[2] == 0x11 && header[3] == 0xE0 &&
		header[4] == 0xA1 && header[5] == 0xB1 && header[6] == 0x1A && header[7] == 0xE1 {
		// Check if it's an MSI (OLE with specific CLSID) — simplified check.
		ext := strings.ToLower(path)
		if strings.HasSuffix(ext, ".msi") {
			return &FileIDResult{FileType: FileTypeMSI}
		}
		return &FileIDResult{FileType: FileTypeOLE}
	}

	// LNK file (Windows shortcut)
	if n >= 20 && header[0] == 0x4C && header[1] == 0x00 && header[2] == 0x00 && header[3] == 0x00 &&
		header[4] == 0x01 && header[5] == 0x14 && header[6] == 0x02 && header[7] == 0x00 {
		return &FileIDResult{FileType: FileTypeLNK}
	}

	// ZIP archive
	if n >= 4 && header[0] == 'P' && header[1] == 'K' && header[2] == 0x03 && header[3] == 0x04 {
		return &FileIDResult{FileType: FileTypeZIP}
	}

	// RAR archive
	if n >= 7 && header[0] == 'R' && header[1] == 'a' && header[2] == 'r' && header[3] == '!' &&
		header[4] == 0x1A && header[5] == 0x07 {
		return &FileIDResult{FileType: FileTypeRAR}
	}

	// 7z archive
	if n >= 6 && header[0] == '7' && header[1] == 'z' && header[2] == 0xBC && header[3] == 0xAF &&
		header[4] == 0x27 && header[5] == 0x1C {
		return &FileIDResult{FileType: FileType7Z}
	}

	// ISO 9660 (check at offset 0x8001 for "CD001" — but we only have the first 4KB).
	// Fall back to extension-based detection for ISO/IMG.
	ext := strings.ToLower(path)
	if strings.HasSuffix(ext, ".iso") || strings.HasSuffix(ext, ".img") {
		return &FileIDResult{FileType: FileTypeISO}
	}

	return nil
}

// identifyPE parses the PE headers to determine PE32/PE64/DLL/.NET.
func identifyPE(f *os.File, header []byte) (*FileIDResult, error) {
	n := len(header)
	if n < 64 {
		return &FileIDResult{FileType: FileTypeUnknown}, nil
	}

	// Read e_lfanew (offset to PE signature) at offset 0x3C.
	peOffset := int(binary.LittleEndian.Uint32(header[0x3C:0x40]))
	if peOffset < 0 || peOffset > 1024 {
		return &FileIDResult{FileType: FileTypeUnknown}, nil
	}

	// We may need to read more if peOffset is beyond our initial header.
	var peHeader []byte
	if peOffset+256 <= n {
		peHeader = header[peOffset:]
	} else {
		// Seek and read PE header.
		buf := make([]byte, 256)
		if _, err := f.Seek(int64(peOffset), 0); err != nil {
			return &FileIDResult{FileType: FileTypeUnknown}, nil
		}
		nn, err := f.Read(buf)
		if err != nil || nn < 6 {
			return &FileIDResult{FileType: FileTypeUnknown}, nil
		}
		peHeader = buf[:nn]
	}

	// Verify PE signature "PE\0\0".
	if len(peHeader) < 6 || peHeader[0] != 'P' || peHeader[1] != 'E' || peHeader[2] != 0 || peHeader[3] != 0 {
		return &FileIDResult{FileType: FileTypeUnknown}, nil
	}

	// COFF header starts at PE+4.
	machine := binary.LittleEndian.Uint16(peHeader[4:6])
	characteristics := uint16(0)
	if len(peHeader) >= 24 {
		characteristics = binary.LittleEndian.Uint16(peHeader[22:24])
	}

	isDLL := characteristics&0x2000 != 0 // IMAGE_FILE_DLL

	var arch string
	switch machine {
	case 0x014C:
		arch = "x86"
	case 0x8664:
		arch = "AMD64"
	case 0xAA64:
		arch = "ARM64"
	default:
		arch = fmt.Sprintf("0x%04X", machine)
	}

	// Determine PE32 vs PE64 from optional header magic.
	is64 := false
	if len(peHeader) >= 28 {
		optMagic := binary.LittleEndian.Uint16(peHeader[24:26])
		is64 = optMagic == 0x020B // PE32+
	}

	// Check for .NET (CLR header).
	isDotNet := checkDotNet(f, peHeader, peOffset, is64)

	result := &FileIDResult{
		IsPE:         true,
		IsDLL:        isDLL,
		IsDotNet:     isDotNet,
		Architecture: arch,
	}

	if isDotNet {
		result.FileType = FileTypeDotNet
	} else if isDLL && is64 {
		result.FileType = FileTypeDLL64
	} else if isDLL {
		result.FileType = FileTypeDLL32
	} else if is64 {
		result.FileType = FileTypePE64
	} else {
		result.FileType = FileTypePE32
	}

	return result, nil
}

// checkDotNet checks if the PE has a CLR runtime header (data directory entry 14).
func checkDotNet(f *os.File, peHeader []byte, peOffset int, is64 bool) bool {
	// Optional header starts at PE+24.
	// Data directories start after the optional header standard/NT fields.
	// PE32: optional header = 28 standard + 68 NT = 96 bytes before data dirs.
	// PE64: optional header = 24 standard + 88 NT = 112 bytes before data dirs.
	// CLR header is data directory index 14.
	// Each data directory entry is 8 bytes (VA + Size).

	var dataDirOffset int
	if is64 {
		dataDirOffset = 24 + 112 // offset from PE sig to data directories
	} else {
		dataDirOffset = 24 + 96
	}

	clrEntryOffset := dataDirOffset + 14*8
	neededOffset := int64(peOffset) + int64(clrEntryOffset) + 8

	buf := make([]byte, 8)
	if _, err := f.Seek(int64(peOffset)+int64(clrEntryOffset), 0); err != nil {
		return false
	}
	_ = neededOffset
	if _, err := f.Read(buf); err != nil {
		return false
	}

	clrVA := binary.LittleEndian.Uint32(buf[0:4])
	clrSize := binary.LittleEndian.Uint32(buf[4:8])

	return clrVA != 0 && clrSize != 0
}

// isScriptContent checks if the file content or extension suggests a script.
func isScriptContent(header []byte, path string) bool {
	ext := strings.ToLower(path)
	scriptExts := []string{".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta", ".wsf", ".py"}
	for _, se := range scriptExts {
		if strings.HasSuffix(ext, se) {
			return true
		}
	}

	// Check for shebang or common script markers.
	if len(header) > 2 && header[0] == '#' && header[1] == '!' {
		return true
	}

	// Check for HTML/HTA markers.
	content := strings.ToLower(string(header[:min(len(header), 512)]))
	if strings.Contains(content, "<hta:application") || strings.Contains(content, "<script") {
		return true
	}

	return false
}

// IsPEType returns true if the file type is a PE variant.
func IsPEType(fileType string) bool {
	switch fileType {
	case FileTypePE32, FileTypePE64, FileTypeDLL32, FileTypeDLL64, FileTypeDotNet:
		return true
	}
	return false
}
