package analysis

import (
	peparser "github.com/saferwall/pe"
	"github.com/urb4n3/undertaker/internal/models"
)

// AnalyzeExports extracts the export table from a PE file (typically a DLL).
// Returns nil if the PE has no exports.
func AnalyzeExports(pefile *peparser.File) []models.Export {
	if pefile.Export.Functions == nil || len(pefile.Export.Functions) == 0 {
		return nil
	}

	var exports []models.Export
	for _, fn := range pefile.Export.Functions {
		exp := models.Export{
			Name:    fn.Name,
			Ordinal: uint16(fn.Ordinal),
		}
		if fn.Forwarder != "" {
			exp.Forwarded = fn.Forwarder
		}
		exports = append(exports, exp)
	}

	return exports
}
