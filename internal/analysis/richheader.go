package analysis

import (
	"fmt"

	peparser "github.com/saferwall/pe"
	"github.com/urb4n3/undertaker/internal/models"
)

// AnalyzeRichHeader extracts the rich header from a PE file and maps tool IDs
// to human-readable compiler/linker names. Returns nil if no rich header.
func AnalyzeRichHeader(pefile *peparser.File) *models.RichHeader {
	if !pefile.FileInfo.HasRichHdr {
		return nil
	}

	compIDs := pefile.RichHeader.CompIDs
	if len(compIDs) == 0 {
		return nil
	}

	rh := &models.RichHeader{}
	for _, comp := range compIDs {
		entry := models.RichEntry{
			Toolchain: prodIDToToolchain(comp.ProdID),
			Type:      prodIDToType(comp.ProdID),
			Count:     comp.Count,
		}
		rh.Entries = append(rh.Entries, entry)
	}

	return rh
}

// prodIDToToolchain maps ProdID ranges to compiler/linker toolchain names.
// Based on well-known Rich header ProdID values.
func prodIDToToolchain(prodID uint16) string {
	// Try saferwall/pe's built-in mapping first.
	if name := peparser.ProdIDtoStr(prodID); name != "" && name != "Unknown" {
		return name
	}

	// Fallback to broad ranges.
	switch {
	case prodID >= 256 && prodID <= 280:
		return fmt.Sprintf("VS2015-2022 (ProdID %d)", prodID)
	case prodID >= 240 && prodID < 256:
		return fmt.Sprintf("VS2013 (ProdID %d)", prodID)
	case prodID >= 220 && prodID < 240:
		return fmt.Sprintf("VS2012 (ProdID %d)", prodID)
	case prodID >= 200 && prodID < 220:
		return fmt.Sprintf("VS2010 (ProdID %d)", prodID)
	case prodID >= 150 && prodID < 200:
		return fmt.Sprintf("VS2008 (ProdID %d)", prodID)
	case prodID >= 100 && prodID < 150:
		return fmt.Sprintf("VS2005 (ProdID %d)", prodID)
	default:
		return fmt.Sprintf("ProdID %d", prodID)
	}
}

// prodIDToType categorizes the tool type based on ProdID.
func prodIDToType(prodID uint16) string {
	if name := peparser.ProdIDtoVSversion(prodID); name != "" && name != "Unknown" {
		return name
	}
	return "unknown"
}
