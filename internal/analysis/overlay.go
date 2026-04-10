package analysis

import (
	"fmt"
	"os"

	peparser "github.com/saferwall/pe"
	"github.com/urb4n3/undertaker/internal/models"
)

// DetectOverlay checks for data appended after the last PE section.
func DetectOverlay(pefile *peparser.File, filePath string) (*models.OverlayInfo, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}
	fileSize := fileInfo.Size()

	// Find the end of the last section (highest PointerToRawData + SizeOfRawData).
	var lastSectionEnd int64
	for _, sec := range pefile.Sections {
		end := int64(sec.Header.PointerToRawData) + int64(sec.Header.SizeOfRawData)
		if end > lastSectionEnd {
			lastSectionEnd = end
		}
	}

	if lastSectionEnd == 0 || lastSectionEnd >= fileSize {
		return nil, nil // No overlay.
	}

	overlaySize := fileSize - lastSectionEnd

	// Read overlay data to compute entropy.
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening file for overlay: %w", err)
	}
	defer f.Close()

	if _, err := f.Seek(lastSectionEnd, 0); err != nil {
		return nil, fmt.Errorf("seeking to overlay: %w", err)
	}

	overlayData := make([]byte, overlaySize)
	n, err := f.Read(overlayData)
	if err != nil {
		return nil, fmt.Errorf("reading overlay: %w", err)
	}
	overlayData = overlayData[:n]

	return &models.OverlayInfo{
		Offset:  lastSectionEnd,
		Size:    overlaySize,
		Entropy: ShannonEntropy(overlayData),
	}, nil
}
