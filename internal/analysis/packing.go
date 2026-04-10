package analysis

import (
	"strings"

	peparser "github.com/saferwall/pe"
	"github.com/urb4n3/undertaker/internal/models"
)

// Known packer section name patterns.
var packerSectionNames = map[string]string{
	"UPX0":     "UPX",
	"UPX1":     "UPX",
	"UPX2":     "UPX",
	".UPX0":    "UPX",
	".UPX1":    "UPX",
	"UPX!":     "UPX",
	".MPRESS1": "MPRESS",
	".MPRESS2": "MPRESS",
	".aspack":  "ASPack",
	".adata":   "ASPack",
	"ASPack":   "ASPack",
	".petite":  "Petite",
	".pec":     "PECompact",
	"PEC2":     "PECompact",
	".themida":  "Themida",
	"Themida":  "Themida",
	".vmp0":    "VMProtect",
	".vmp1":    "VMProtect",
	".vmp2":    "VMProtect",
	"VMP0":     "VMProtect",
	"VMP1":     "VMProtect",
	".enigma1": "Enigma",
	".enigma2": "Enigma",
	"CODE":     "",
	".nsp0":    "NsPack",
	".nsp1":    "NsPack",
	".nsp2":    "NsPack",
}

// DetectPacking performs multi-signal packing analysis.
func DetectPacking(pefile *peparser.File, meta *models.PEMetadata, fileEntropy float64) *models.PackingInfo {
	info := &models.PackingInfo{
		Entropy: fileEntropy,
	}

	var signals []string
	packerName := ""

	// Signal 1: Section name heuristics — check for known packer section names.
	for _, sec := range meta.Sections {
		name := strings.TrimRight(sec.Name, "\x00 ")
		if packer, ok := packerSectionNames[name]; ok {
			signals = append(signals, "section_name:"+name)
			if packer != "" && packerName == "" {
				packerName = packer
			}
		}
	}

	// Signal 2: High entropy on code sections.
	// Exclude .rsrc sections — resource sections commonly have elevated entropy
	// from compressed icons/bitmaps and should not trigger packing detection alone.
	highEntropyCount := 0
	rsrcOnlyEntropy := true
	for _, sec := range meta.Sections {
		if sec.Entropy > 6.8 {
			highEntropyCount++
			signals = append(signals, "high_entropy:"+sec.Name)
			name := strings.TrimRight(sec.Name, "\x00 ")
			if !strings.EqualFold(name, ".rsrc") {
				rsrcOnlyEntropy = false
			}
		}
	}
	// If only .rsrc has high entropy, don't count it as a packing signal.
	if highEntropyCount > 0 && rsrcOnlyEntropy {
		highEntropyCount = 0
	}

	// Signal 3: Low import count (< 10 total functions).
	// Only check when we have a parsed PE file (pefile may be nil in tests).
	importCount := -1
	if pefile != nil {
		importCount = countImports(pefile)
		if importCount < 10 {
			signals = append(signals, "low_import_count")
		}
	}

	// Signal 4: Entry point location anomaly.
	if epAnomaly := checkEPAnomaly(pefile, meta); epAnomaly != "" {
		signals = append(signals, epAnomaly)
	}

	// Determine confidence level using graduated model.
	info.PackerName = packerName
	info.Signals = signals

	// Known packer signature → high confidence.
	hasPackerSig := packerName != ""

	switch {
	case hasPackerSig:
		info.Confidence = "high"
		info.Label = "Packed (high confidence)"
	case highEntropyCount > 0 && importCount >= 0 && importCount < 10:
		// Multiple signals converge.
		info.Confidence = "medium"
		info.Label = "Likely packed"
	case highEntropyCount > 0 && len(signals) >= 2:
		info.Confidence = "medium"
		info.Label = "Likely packed"
	case highEntropyCount > 0:
		// High entropy alone.
		info.Confidence = "low"
		info.Label = "Possibly compressed"
	default:
		info.Confidence = "none"
		info.Label = "Not packed"
	}

	return info
}

// countImports returns the total count of imported functions from the raw PE import directory.
func countImports(pefile *peparser.File) int {
	if pefile == nil {
		return 0
	}
	total := 0
	for _, imp := range pefile.Imports {
		total += len(imp.Functions)
	}
	return total
}

// checkEPAnomaly checks if the entry point is in an unusual section.
func checkEPAnomaly(pefile *peparser.File, meta *models.PEMetadata) string {
	if pefile == nil {
		return ""
	}
	var ep uint32
	if pefile.Is64 {
		oh, ok := pefile.NtHeader.OptionalHeader.(peparser.ImageOptionalHeader64)
		if !ok {
			return ""
		}
		ep = oh.AddressOfEntryPoint
	} else {
		oh, ok := pefile.NtHeader.OptionalHeader.(peparser.ImageOptionalHeader32)
		if !ok {
			return ""
		}
		ep = oh.AddressOfEntryPoint
	}

	if ep == 0 {
		return ""
	}

	// Find which section contains the entry point.
	for i, sec := range pefile.Sections {
		secStart := sec.Header.VirtualAddress
		secEnd := secStart + sec.Header.VirtualSize
		if ep >= secStart && ep < secEnd {
			// EP in the first section is normal.
			if i == 0 {
				return ""
			}
			// EP in a later section is suspicious.
			name := sec.String()
			return "ep_anomaly:" + name
		}
	}

	// EP not in any section — very suspicious.
	return "ep_outside_sections"
}
