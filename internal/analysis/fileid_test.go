package analysis

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentifyFile_Script(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name     string
		filename string
		content  []byte
		wantType string
	}{
		{"ps1", "test.ps1", []byte("Write-Host 'hello'"), FileTypeScript},
		{"bat", "test.bat", []byte("@echo off"), FileTypeScript},
		{"vbs", "test.vbs", []byte("MsgBox \"hello\""), FileTypeScript},
		{"js", "test.js", []byte("console.log('hello')"), FileTypeScript},
		{"hta", "test.hta", []byte("<hta:application>"), FileTypeScript},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.filename)
			if err := os.WriteFile(path, tt.content, 0o644); err != nil {
				t.Fatalf("writing test file: %v", err)
			}
			result, err := IdentifyFile(path)
			if err != nil {
				t.Fatalf("IdentifyFile: %v", err)
			}
			if result.FileType != tt.wantType {
				t.Errorf("FileType = %q, want %q", result.FileType, tt.wantType)
			}
			if result.IsPE {
				t.Error("script should not be identified as PE")
			}
		})
	}
}

func TestIdentifyFile_ZIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.zip")
	// PK\x03\x04 magic
	content := []byte{'P', 'K', 0x03, 0x04, 0x00, 0x00}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	result, err := IdentifyFile(path)
	if err != nil {
		t.Fatalf("IdentifyFile: %v", err)
	}
	if result.FileType != FileTypeZIP {
		t.Errorf("FileType = %q, want %q", result.FileType, FileTypeZIP)
	}
}

func TestIdentifyFile_OLE(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.doc")
	// OLE magic bytes
	content := []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00, 0x00}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	result, err := IdentifyFile(path)
	if err != nil {
		t.Fatalf("IdentifyFile: %v", err)
	}
	if result.FileType != FileTypeOLE {
		t.Errorf("FileType = %q, want %q", result.FileType, FileTypeOLE)
	}
}

func TestIdentifyFile_LNK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.lnk")
	// LNK magic bytes
	content := make([]byte, 32)
	content[0] = 0x4C
	content[1] = 0x00
	content[2] = 0x00
	content[3] = 0x00
	content[4] = 0x01
	content[5] = 0x14
	content[6] = 0x02
	content[7] = 0x00
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	result, err := IdentifyFile(path)
	if err != nil {
		t.Fatalf("IdentifyFile: %v", err)
	}
	if result.FileType != FileTypeLNK {
		t.Errorf("FileType = %q, want %q", result.FileType, FileTypeLNK)
	}
}

// buildMinimalPE creates a minimal valid PE32 file in memory.
func buildMinimalPE(isDLL bool, is64 bool) []byte {
	buf := make([]byte, 512)

	// DOS header
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], 0x80) // e_lfanew

	// PE signature at 0x80
	buf[0x80] = 'P'
	buf[0x81] = 'E'
	buf[0x82] = 0
	buf[0x83] = 0

	// COFF header at 0x84
	if is64 {
		binary.LittleEndian.PutUint16(buf[0x84:], 0x8664) // Machine: AMD64
	} else {
		binary.LittleEndian.PutUint16(buf[0x84:], 0x014C) // Machine: i386
	}
	binary.LittleEndian.PutUint16(buf[0x86:], 1)  // NumberOfSections
	binary.LittleEndian.PutUint16(buf[0x90:], 0)  // SizeOfOptionalHeader (will set below)
	chars := uint16(0x0102)                         // EXECUTABLE_IMAGE | 32BIT_MACHINE
	if isDLL {
		chars |= 0x2000 // IMAGE_FILE_DLL
	}
	binary.LittleEndian.PutUint16(buf[0x96:], chars) // Characteristics

	// Optional header at 0x98
	if is64 {
		binary.LittleEndian.PutUint16(buf[0x98:], 0x020B) // PE32+
		binary.LittleEndian.PutUint16(buf[0x90:], 240)     // SizeOfOptionalHeader for PE32+
	} else {
		binary.LittleEndian.PutUint16(buf[0x98:], 0x010B) // PE32
		binary.LittleEndian.PutUint16(buf[0x90:], 224)     // SizeOfOptionalHeader for PE32
	}

	return buf
}

func TestIdentifyFile_PE32(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.exe")
	pe := buildMinimalPE(false, false)
	if err := os.WriteFile(path, pe, 0o644); err != nil {
		t.Fatalf("writing test PE: %v", err)
	}
	result, err := IdentifyFile(path)
	if err != nil {
		t.Fatalf("IdentifyFile: %v", err)
	}
	if result.FileType != FileTypePE32 {
		t.Errorf("FileType = %q, want %q", result.FileType, FileTypePE32)
	}
	if result.Architecture != "x86" {
		t.Errorf("Architecture = %q, want x86", result.Architecture)
	}
	if !result.IsPE {
		t.Error("expected IsPE=true")
	}
}

func TestIdentifyFile_PE64(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test64.exe")
	pe := buildMinimalPE(false, true)
	if err := os.WriteFile(path, pe, 0o644); err != nil {
		t.Fatalf("writing test PE: %v", err)
	}
	result, err := IdentifyFile(path)
	if err != nil {
		t.Fatalf("IdentifyFile: %v", err)
	}
	if result.FileType != FileTypePE64 {
		t.Errorf("FileType = %q, want %q", result.FileType, FileTypePE64)
	}
	if result.Architecture != "AMD64" {
		t.Errorf("Architecture = %q, want AMD64", result.Architecture)
	}
}

func TestIdentifyFile_DLL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.dll")
	pe := buildMinimalPE(true, false)
	if err := os.WriteFile(path, pe, 0o644); err != nil {
		t.Fatalf("writing test PE: %v", err)
	}
	result, err := IdentifyFile(path)
	if err != nil {
		t.Fatalf("IdentifyFile: %v", err)
	}
	if result.FileType != FileTypeDLL32 {
		t.Errorf("FileType = %q, want %q", result.FileType, FileTypeDLL32)
	}
	if !result.IsDLL {
		t.Error("expected IsDLL=true")
	}
}

func TestIdentifyFile_Unknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	if err := os.WriteFile(path, []byte{0xFF, 0xFE, 0x00, 0x01}, 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	result, err := IdentifyFile(path)
	if err != nil {
		t.Fatalf("IdentifyFile: %v", err)
	}
	if result.FileType != FileTypeUnknown {
		t.Errorf("FileType = %q, want %q", result.FileType, FileTypeUnknown)
	}
}

func TestIdentifyFile_NonExistent(t *testing.T) {
	_, err := IdentifyFile("/nonexistent/file.bin")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestIsPEType(t *testing.T) {
	peTypes := []string{FileTypePE32, FileTypePE64, FileTypeDLL32, FileTypeDLL64, FileTypeDotNet}
	for _, ft := range peTypes {
		if !IsPEType(ft) {
			t.Errorf("IsPEType(%q) = false, want true", ft)
		}
	}
	nonPETypes := []string{FileTypeScript, FileTypeOLE, FileTypeLNK, FileTypeZIP, FileTypeUnknown}
	for _, ft := range nonPETypes {
		if IsPEType(ft) {
			t.Errorf("IsPEType(%q) = true, want false", ft)
		}
	}
}
