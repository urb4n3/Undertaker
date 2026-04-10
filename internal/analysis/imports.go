package analysis

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	peparser "github.com/saferwall/pe"
	"github.com/urb4n3/undertaker/data"
	"github.com/urb4n3/undertaker/internal/config"
	"github.com/urb4n3/undertaker/internal/models"
)

// capabilityMap is the in-memory lookup: lowercase(api) -> APICapability.
type capabilityMap map[string]models.APICapability

// LoadAPICapabilities loads the API capability mapping from embedded data
// and merges any analyst-provided custom overrides.
func LoadAPICapabilities() (capabilityMap, error) {
	var caps []models.APICapability
	if err := json.Unmarshal(data.APICapabilities, &caps); err != nil {
		return nil, fmt.Errorf("parsing embedded api_capabilities.json: %w", err)
	}

	// Build base map (lowercase key).
	m := make(capabilityMap, len(caps))
	for _, c := range caps {
		m[strings.ToLower(c.API)] = c
	}

	// Merge custom overrides from config dir.
	dir, err := config.ConfigDir()
	if err == nil {
		customPath := filepath.Join(dir, "api_capabilities_custom.json")
		if raw, err := os.ReadFile(customPath); err == nil {
			var custom []models.APICapability
			if err := json.Unmarshal(raw, &custom); err == nil {
				for _, c := range custom {
					m[strings.ToLower(c.API)] = c
				}
			}
		}
	}

	return m, nil
}

// AnalyzeImports parses the PE import table and cross-references APIs against
// the capability map. Returns a populated ImportAnalysis.
func AnalyzeImports(pefile *peparser.File) (*models.ImportAnalysis, error) {
	caps, err := LoadAPICapabilities()
	if err != nil {
		return nil, fmt.Errorf("loading API capabilities: %w", err)
	}

	result := &models.ImportAnalysis{}
	totalFuncs := 0
	capTags := make(map[string]bool)

	for _, imp := range pefile.Imports {
		dllName := strings.ToLower(imp.Name)
		for _, fn := range imp.Functions {
			totalFuncs++

			apiName := fn.Name
			if fn.ByOrdinal {
				apiName = fmt.Sprintf("ord_%d", fn.Ordinal)
			}
			if apiName == "" {
				continue
			}

			// Lookup: try exact name first, then strip A/W suffix.
			cap, found := caps[strings.ToLower(apiName)]
			if !found {
				stripped := stripAWSuffix(apiName)
				cap, found = caps[strings.ToLower(stripped)]
			}

			if found {
				result.SuspiciousImports = append(result.SuspiciousImports, models.SuspiciousImport{
					Name:       apiName,
					DLL:        dllName,
					Capability: cap.Capability,
				})
				capTags[cap.Capability] = true
			}
		}
	}

	result.TotalImports = totalFuncs
	for tag := range capTags {
		result.CapabilityTags = append(result.CapabilityTags, tag)
	}

	return result, nil
}

// DeriveCapabilities converts import analysis capability tags into
// Capability structs with technique IDs from the capability map.
func DeriveCapabilities(imports *models.ImportAnalysis, caps capabilityMap) []models.Capability {
	// Build technique map: capability -> set of technique_ids.
	type capInfo struct {
		techniqueIDs map[string]bool
	}
	byCapability := make(map[string]*capInfo)

	for _, si := range imports.SuspiciousImports {
		ci, ok := byCapability[si.Capability]
		if !ok {
			ci = &capInfo{techniqueIDs: make(map[string]bool)}
			byCapability[si.Capability] = ci
		}
		// Lookup technique ID from the capability map.
		if c, found := caps[strings.ToLower(si.Name)]; found && c.TechniqueID != "" {
			ci.techniqueIDs[c.TechniqueID] = true
		}
	}

	var result []models.Capability
	for capName, ci := range byCapability {
		for tid := range ci.techniqueIDs {
			result = append(result, models.Capability{
				TechniqueID:   tid,
				TechniqueName: capName,
				Source:        "imports",
			})
		}
	}

	return result
}

// stripAWSuffix removes trailing A or W from Win32 API names.
func stripAWSuffix(name string) string {
	if len(name) > 1 && (name[len(name)-1] == 'A' || name[len(name)-1] == 'W') {
		return name[:len(name)-1]
	}
	return name
}
