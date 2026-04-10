package analysis

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/urb4n3/undertaker/internal/models"
	"github.com/urb4n3/undertaker/internal/tools"
)

// capaJSON represents the top-level capa JSON output (v7+).
type capaJSON struct {
	Meta  capaMeta             `json:"meta"`
	Rules map[string]capaRule  `json:"rules"`
}

type capaMeta struct {
	Analysis capaAnalysisMeta `json:"analysis"`
}

type capaAnalysisMeta struct {
	Format string `json:"format"`
}

type capaRule struct {
	Meta  capaRuleMeta `json:"meta"`
	Source string      `json:"source"`
}

type capaRuleMeta struct {
	Name      string       `json:"name"`
	Namespace string       `json:"namespace"`
	AttackRef []capaAttack `json:"attack"`
}

type capaAttack struct {
	Technique string `json:"technique"`
	ID        string `json:"id"`
}

// RunCapa invokes capa on the sample and returns capabilities with ATT&CK mappings.
func RunCapa(ti tools.ToolInfo, samplePath string, timeoutSec int) ([]models.Capability, error) {
	if !ti.Available {
		return nil, fmt.Errorf("capa not available: %s", ti.Error)
	}

	args := []string{"--json", samplePath}
	result, err := tools.Run(ti.Path, args, timeoutSec)
	if err != nil {
		return nil, fmt.Errorf("running capa: %w", err)
	}

	stdout := result.Stdout
	if len(stdout) == 0 {
		return nil, fmt.Errorf("capa produced no output (exit code %d): %s",
			result.ExitCode, strings.TrimSpace(string(result.Stderr)))
	}

	var parsed capaJSON
	if err := parseCapaJSON(stdout, &parsed); err != nil {
		return nil, fmt.Errorf("parsing capa json: %w", err)
	}

	var caps []models.Capability
	seen := make(map[string]bool)

	for _, rule := range parsed.Rules {
		// Each rule may map to multiple ATT&CK techniques.
		if len(rule.Meta.AttackRef) > 0 {
			for _, atk := range rule.Meta.AttackRef {
				key := atk.ID
				if seen[key] {
					continue
				}
				seen[key] = true
				caps = append(caps, models.Capability{
					TechniqueID:   atk.ID,
					TechniqueName: atk.Technique,
					Source:        "capa",
				})
			}
		} else {
			// Rule with no ATT&CK mapping — still a capability.
			key := rule.Meta.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			caps = append(caps, models.Capability{
				TechniqueName: rule.Meta.Name,
				Source:        "capa",
			})
		}
	}

	return caps, nil
}

// parseCapaJSON unmarshals capa JSON output into the capaJSON struct.
func parseCapaJSON(data []byte, out *capaJSON) error {
	return json.Unmarshal(data, out)
}
