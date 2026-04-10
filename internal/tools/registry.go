package tools

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/urb4n3/undertaker/internal/config"
)

// ToolInfo describes a discovered external tool.
type ToolInfo struct {
	Name      string // "floss", "capa", "yara"
	Path      string // Absolute path to executable
	Version   string // Parsed version string (e.g. "3.1.0")
	Available bool   // true if found and version is sufficient
	Error     string // Reason the tool is unavailable, if any
}

// MinVersions defines the minimum acceptable versions for each tool.
var MinVersions = map[string]int{
	"floss": 3,
	"capa":  7,
	"yara":  4,
}

// Registry holds discovered tool information for all external tools.
type Registry struct {
	FLOSS ToolInfo
	Capa  ToolInfo
	YARA  ToolInfo
}

// Discover probes for all external tools using the config and PATH.
func Discover(cfg *config.Config) *Registry {
	reg := &Registry{
		FLOSS: discover("floss", cfg.Tools.FLOSS, "--version"),
		Capa:  discover("capa", cfg.Tools.Capa, "--version"),
		YARA:  discover("yara", cfg.Tools.YARA, "--version"),
	}
	return reg
}

// discover finds a single tool: first from the configured path, then from PATH.
// It runs the version flag and checks the minimum version.
func discover(name, configPath, versionFlag string) ToolInfo {
	info := ToolInfo{Name: name}

	// Find the binary.
	var binaryPath string
	if configPath != "" {
		// Config explicitly sets the path — use it directly.
		binaryPath = configPath
	} else {
		// Search PATH.
		p, err := exec.LookPath(name)
		if err != nil {
			info.Error = fmt.Sprintf("%s not found in PATH or config", name)
			return info
		}
		binaryPath = p
	}

	info.Path = binaryPath

	// Run version check.
	result, err := Run(binaryPath, []string{versionFlag}, 10)
	if err != nil {
		info.Error = fmt.Sprintf("failed to run %s %s: %v", binaryPath, versionFlag, err)
		return info
	}

	// Parse version from combined stdout+stderr (some tools write version to stderr).
	output := string(result.Stdout) + " " + string(result.Stderr)
	version := parseVersion(output)
	if version == "" {
		info.Error = fmt.Sprintf("could not parse version from %s output", name)
		return info
	}
	info.Version = version

	// Check minimum version.
	major := parseMajor(version)
	minMajor, hasMin := MinVersions[name]
	if hasMin && major < minMajor {
		info.Error = fmt.Sprintf("%s version %s is below minimum v%d+", name, version, minMajor)
		return info
	}

	info.Available = true
	return info
}

// versionRe matches common version patterns like "v3.1.0", "3.1.0", "YARA 4.5.1".
var versionRe = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?)`)

// parseVersion extracts the first version-like string from output.
func parseVersion(output string) string {
	matches := versionRe.FindStringSubmatch(output)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// parseMajor extracts the major version number from a version string like "3.1.0".
func parseMajor(version string) int {
	parts := strings.SplitN(version, ".", 2)
	if len(parts) == 0 {
		return 0
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}
	return major
}
