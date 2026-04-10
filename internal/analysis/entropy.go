package analysis

import (
	"fmt"
	"math"
	"os"

	peparser "github.com/saferwall/pe"
	"github.com/urb4n3/undertaker/internal/models"
)

// ShannonEntropy computes the Shannon entropy of a byte slice.
// Returns a value between 0.0 (uniform) and 8.0 (maximum randomness).
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}

	length := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// ComputeFileEntropy calculates the overall Shannon entropy of a file.
func ComputeFileEntropy(path string) (float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("reading file for entropy: %w", err)
	}
	return ShannonEntropy(data), nil
}

// ComputeSectionEntropies calculates entropy for each PE section and
// updates the SectionInfo entries in the provided metadata.
func ComputeSectionEntropies(pefile *peparser.File, meta *models.PEMetadata) {
	for i, sec := range pefile.Sections {
		if i >= len(meta.Sections) {
			break
		}
		rawSize := sec.Header.SizeOfRawData
		if rawSize == 0 {
			meta.Sections[i].Entropy = 0.0
			continue
		}
		data := sec.Data(0, rawSize, pefile)
		if len(data) == 0 {
			meta.Sections[i].Entropy = 0.0
			continue
		}
		meta.Sections[i].Entropy = ShannonEntropy(data)
	}
}
