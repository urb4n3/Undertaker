package analysis

import (
	"fmt"
	"strconv"
	"time"

	peparser "github.com/saferwall/pe"
	"github.com/urb4n3/undertaker/internal/models"
)

// ExtractMetadata populates PEMetadata from a parsed PE file.
func ExtractMetadata(pefile *peparser.File) (*models.PEMetadata, error) {
	meta := &models.PEMetadata{}

	// Compile timestamp from COFF header.
	ts := pefile.NtHeader.FileHeader.TimeDateStamp
	meta.CompileTimestamp = time.Unix(int64(ts), 0).UTC()
	meta.TimestampAnomaly = detectTimestampAnomaly(ts)

	// Sections.
	for _, sec := range pefile.Sections {
		info := models.SectionInfo{
			Name:        sec.String(),
			VirtualSize: sec.Header.VirtualSize,
			RawSize:     sec.Header.SizeOfRawData,
			// Entropy will be filled by the entropy analyzer.
			Characteristics: fmt.Sprintf("0x%08X", sec.Header.Characteristics),
		}
		meta.Sections = append(meta.Sections, info)
	}

	// Resources.
	if pefile.FileInfo.HasResource {
		meta.Resources = extractResources(pefile)
	}

	// Debug info.
	if pefile.FileInfo.HasDebug {
		meta.DebugInfo = extractDebugInfo(pefile)
	}

	// Version info.
	if pefile.FileInfo.HasResource {
		if vi, err := pefile.ParseVersionResources(); err == nil && len(vi) > 0 {
			meta.VersionInfo = vi
		}
	}

	// .NET detection.
	meta.IsDotNet = pefile.FileInfo.HasCLR

	return meta, nil
}

// detectTimestampAnomaly checks for suspicious compile timestamps.
func detectTimestampAnomaly(ts uint32) string {
	if ts == 0 {
		return "zeroed"
	}

	t := time.Unix(int64(ts), 0).UTC()

	// Epoch: very close to Unix epoch (within first day).
	if ts < 86400 {
		return "epoch"
	}

	// Pre-1990: PE format didn't exist before ~1993.
	if t.Year() < 1990 {
		return "pre-1990"
	}

	// Future: more than 1 day ahead of current time.
	if t.After(time.Now().UTC().Add(24 * time.Hour)) {
		return "future"
	}

	return ""
}

// extractResources walks the PE resource directory tree.
func extractResources(pefile *peparser.File) []models.ResourceInfo {
	var resources []models.ResourceInfo

	for _, typeEntry := range pefile.Resources.Entries {
		typeName := resourceTypeName(typeEntry.ID)
		if typeEntry.Name != "" {
			typeName = typeEntry.Name
		}

		if typeEntry.Directory.Entries == nil {
			continue
		}

		for _, nameEntry := range typeEntry.Directory.Entries {
			resName := fmt.Sprintf("#%d", nameEntry.ID)
			if nameEntry.Name != "" {
				resName = nameEntry.Name
			}

			if nameEntry.Directory.Entries == nil {
				continue
			}

			for _, langEntry := range nameEntry.Directory.Entries {
				ri := models.ResourceInfo{
					Type: typeName,
					Name: resName,
					Size: langEntry.Data.Struct.Size,
				}
				if langEntry.Data.Lang != 0 {
					ri.Lang = langEntry.Data.Lang.String()
				}
				resources = append(resources, ri)
			}
		}
	}

	return resources
}

// resourceTypeName maps well-known resource type IDs to names.
func resourceTypeName(id uint32) string {
	names := map[uint32]string{
		1:  "Cursor",
		2:  "Bitmap",
		3:  "Icon",
		4:  "Menu",
		5:  "Dialog",
		6:  "StringTable",
		7:  "FontDir",
		8:  "Font",
		9:  "Accelerator",
		10: "RCData",
		11: "MessageTable",
		12: "GroupCursor",
		14: "GroupIcon",
		16: "Version",
		24: "Manifest",
	}
	if name, ok := names[id]; ok {
		return name
	}
	return strconv.FormatUint(uint64(id), 10)
}

// extractDebugInfo parses debug directory entries.
func extractDebugInfo(pefile *peparser.File) []models.DebugEntry {
	var entries []models.DebugEntry

	for _, dbg := range pefile.Debugs {
		entry := models.DebugEntry{
			Type: dbg.Type,
		}

		// Try to extract PDB path from CodeView info.
		if pdb, ok := dbg.Info.(peparser.CVInfoPDB70); ok {
			entry.Value = pdb.PDBFileName
		} else if pdb, ok := dbg.Info.(peparser.CVInfoPDB20); ok {
			entry.Value = pdb.PDBFileName
		}

		entries = append(entries, entry)
	}

	return entries
}

// ParsePE opens a PE file with saferwall/pe. Caller must call Close().
func ParsePE(path string) (*peparser.File, error) {
	pefile, err := peparser.New(path, &peparser.Options{})
	if err != nil {
		return nil, fmt.Errorf("opening PE: %w", err)
	}
	if err := pefile.Parse(); err != nil {
		return nil, fmt.Errorf("parsing PE: %w", err)
	}
	return pefile, nil
}
