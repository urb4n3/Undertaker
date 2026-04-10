package analysis

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestHashFile_KnownContent(t *testing.T) {
	// Create a temp file with known content.
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	content := []byte("Hello, Undertaker!")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	result, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}

	// Compute expected hashes.
	md5sum := md5.Sum(content)
	sha1sum := sha1.Sum(content)
	sha256sum := sha256.Sum256(content)

	expectedMD5 := hex.EncodeToString(md5sum[:])
	expectedSHA1 := hex.EncodeToString(sha1sum[:])
	expectedSHA256 := hex.EncodeToString(sha256sum[:])

	if result.MD5 != expectedMD5 {
		t.Errorf("MD5 = %q, want %q", result.MD5, expectedMD5)
	}
	if result.SHA1 != expectedSHA1 {
		t.Errorf("SHA1 = %q, want %q", result.SHA1, expectedSHA1)
	}
	if result.SHA256 != expectedSHA256 {
		t.Errorf("SHA256 = %q, want %q", result.SHA256, expectedSHA256)
	}
	if result.SSDeep == "" {
		t.Log("SSDeep empty — may require minimum file size")
	}
}

func TestHashFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	result, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}

	// MD5 of empty content.
	expectedMD5 := "d41d8cd98f00b204e9800998ecf8427e"
	if result.MD5 != expectedMD5 {
		t.Errorf("MD5 = %q, want %q", result.MD5, expectedMD5)
	}
}

func TestHashFile_NonExistent(t *testing.T) {
	_, err := HashFile("/nonexistent/file.bin")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestComputeImpHash_NilPE(t *testing.T) {
	// Nil pefile should return empty.
	result := ComputeImpHash(nil)
	if result != "" {
		t.Errorf("ImpHash(nil) = %q, want empty", result)
	}
}
