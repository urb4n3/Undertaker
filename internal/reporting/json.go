package reporting

import (
	"encoding/json"
	"fmt"

	"github.com/urb4n3/undertaker/internal/models"
)

// GenerateJSON serializes an AnalysisReport to pretty-printed JSON bytes.
func GenerateJSON(report *models.AnalysisReport) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling report to JSON: %w", err)
	}
	return data, nil
}
