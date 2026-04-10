package analysis

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/glaslos/ssdeep"
)

// HashResult holds all computed hash values for a file.
type HashResult struct {
	MD5    string
	SHA1   string
	SHA256 string
	SSDeep string
}

// HashFile computes MD5, SHA1, SHA256, and ssdeep for the given file.
// Uses streaming reads — never loads the full file into memory.
func HashFile(path string) (*HashResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file for hashing: %w", err)
	}
	defer f.Close()

	md5h := md5.New()
	sha1h := sha1.New()
	sha256h := sha256.New()

	// Stream through all three hash functions simultaneously.
	w := io.MultiWriter(md5h, sha1h, sha256h)
	if _, err := io.Copy(w, f); err != nil {
		return nil, fmt.Errorf("hashing file: %w", err)
	}

	result := &HashResult{
		MD5:    hex.EncodeToString(md5h.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1h.Sum(nil)),
		SHA256: hex.EncodeToString(sha256h.Sum(nil)),
	}

	// Compute ssdeep (fuzzy hash).
	result.SSDeep, err = computeSSDeep(path)
	if err != nil {
		// ssdeep failure is non-fatal; leave empty.
		result.SSDeep = ""
	}

	return result, nil
}

func computeSSDeep(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hash, err := ssdeep.FuzzyReader(f)
	if err != nil {
		return "", err
	}
	return hash, nil
}

// ComputeImpHash computes the import hash for a PE file.
// This is a stub that returns empty — completed in Stage 4 when imports are parsed.
func ComputeImpHash() string {
	return ""
}
