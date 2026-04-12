package analysis

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/urb4n3/undertaker/data"
	"github.com/urb4n3/undertaker/internal/models"
)

// ScriptCapabilityEntry represents a single entry from script_capabilities.json.
type ScriptCapabilityEntry struct {
	Pattern     string `json:"pattern"`
	Language    string `json:"language"`
	Capability  string `json:"capability"`
	TechniqueID string `json:"technique_id"`
	Description string `json:"description"`
}

// ScriptCapabilitiesConfig holds loaded script capability patterns.
type ScriptCapabilitiesConfig struct {
	Capabilities []ScriptCapabilityEntry `json:"capabilities"`
}

// Download cradle patterns (regex).
var downloadCradlePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:Invoke-WebRequest|iwr|wget|curl)\s+.+https?://`),
	regexp.MustCompile(`(?i)Net\.WebClient.*Download(?:String|File|Data)`),
	regexp.MustCompile(`(?i)DownloadString\s*\(\s*['"]https?://`),
	regexp.MustCompile(`(?i)DownloadFile\s*\(\s*['"]https?://`),
	regexp.MustCompile(`(?i)Start-BitsTransfer\s+.*https?://`),
	regexp.MustCompile(`(?i)certutil\s.*-urlcache\s.*https?://`),
	regexp.MustCompile(`(?i)bitsadmin\s.*/transfer\s.*https?://`),
	regexp.MustCompile(`(?i)Invoke-RestMethod\s+.*https?://`),
	regexp.MustCompile(`(?i)urllib\.request\.urlretrieve\s*\(\s*['"]https?://`),
	regexp.MustCompile(`(?i)requests\.get\s*\(\s*['"]https?://`),
	regexp.MustCompile(`(?i)XMLHTTP.*\.Open\s.*https?://`),
}

// Encoding detection patterns.
var encodingPatterns = []struct {
	re          *regexp.Regexp
	layerType   string
	description string
}{
	{regexp.MustCompile(`(?i)-[Ee](?:nc(?:odedcommand)?)\s+[A-Za-z0-9+/=]{20,}`), "base64_command", "PowerShell encoded command parameter"},
	{regexp.MustCompile(`(?i)\[System\.Convert\]::FromBase64String`), "base64_decode", "Base64 string decoding via .NET"},
	{regexp.MustCompile(`(?i)\[System\.Text\.Encoding\]::\w+\.GetString`), "byte_decode", "Byte array to string conversion"},
	{regexp.MustCompile(`(?i)base64\.b64decode`), "base64_decode", "Python base64 decoding"},
	{regexp.MustCompile(`(?i)atob\s*\(`), "base64_decode", "JavaScript base64 decoding"},
	{regexp.MustCompile(`(?i)-(?:join|split)\s*['"][^'"]{0,5}['"]\s*-(?:split|join)`), "string_manipulation", "String split/join obfuscation"},
	{regexp.MustCompile(`(?i)String\.fromCharCode`), "charcode", "Character code string construction"},
	{regexp.MustCompile(`(?i)chr\(\d+\)\s*[&+]\s*chr\(`), "charcode", "VBS Chr() concatenation obfuscation"},
	{regexp.MustCompile(`(?i)-replace\s+['"][^'"]+['"]\s*,\s*['"]`), "string_replace", "String replacement obfuscation"},
	{regexp.MustCompile(`(?i)IO\.Compression\.(?:GZip|Deflate)Stream`), "compression", "Compressed payload stream"},
	{regexp.MustCompile(`(?i)zlib\.decompress`), "compression", "Python zlib decompression"},
	{regexp.MustCompile(`(?i)-bxor\s+\d+`), "xor", "XOR byte operation"},
	{regexp.MustCompile(`(?i)\^\s*0x[0-9a-fA-F]+`), "xor", "XOR hex operation"},
}

// DetectScriptLanguage determines the script language from extension and content.
func DetectScriptLanguage(path string, content []byte) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".ps1", ".psm1", ".psd1":
		return "powershell"
	case ".py", ".pyw":
		return "python"
	case ".vbs", ".vbe":
		return "vbscript"
	case ".js", ".jse":
		return "javascript"
	case ".bat", ".cmd":
		return "batch"
	case ".hta":
		return "hta"
	case ".wsf":
		return "wsf"
	}

	// Content-based detection.
	head := strings.ToLower(string(content[:min(len(content), 1024)]))
	if strings.HasPrefix(head, "#!/") {
		if strings.Contains(head, "python") {
			return "python"
		}
		if strings.Contains(head, "bash") || strings.Contains(head, "/sh") {
			return "shell"
		}
		if strings.Contains(head, "perl") {
			return "perl"
		}
	}
	// PowerShell heuristics.
	if strings.Contains(head, "param(") || strings.Contains(head, "function ") && strings.Contains(head, "cmdlet") ||
		strings.Contains(head, "$psscriptroot") || strings.Contains(head, "write-host") {
		return "powershell"
	}
	if strings.Contains(head, "import ") && (strings.Contains(head, "def ") || strings.Contains(head, "print(")) {
		return "python"
	}
	if strings.Contains(head, "createobject") || strings.Contains(head, "wscript") {
		return "vbscript"
	}
	if strings.Contains(head, "<hta:application") {
		return "hta"
	}

	return "unknown"
}

// AnalyzeScript performs static analysis on a script file.
func AnalyzeScript(path string) (*models.ScriptAnalysis, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading script: %w", err)
	}

	language := DetectScriptLanguage(path, content)

	caps, err := LoadScriptCapabilities()
	if err != nil {
		return nil, fmt.Errorf("loading script capabilities: %w", err)
	}

	result := &models.ScriptAnalysis{
		Language:       language,
		ScriptMetadata: make(map[string]string),
	}

	contentStr := string(content)
	lines := splitLines(contentStr)

	// Detect dangerous calls.
	result.DangerousCalls = findDangerousCalls(lines, language, caps)

	// Detect encoding/obfuscation layers.
	result.EncodingLayers = findEncodingLayers(contentStr)

	// Detect download cradles.
	result.DownloadCradles = findDownloadCradles(contentStr)

	// Extract script metadata.
	result.ScriptMetadata["total_lines"] = fmt.Sprintf("%d", len(lines))
	result.ScriptMetadata["size_bytes"] = fmt.Sprintf("%d", len(content))

	// Count comments.
	commentCount := countComments(lines, language)
	if commentCount > 0 {
		result.ScriptMetadata["comment_lines"] = fmt.Sprintf("%d", commentCount)
	}

	// Detect if script is heavily obfuscated (high ratio of special chars).
	if isHeavilyObfuscated(contentStr) {
		result.ScriptMetadata["obfuscation_indicator"] = "high ratio of special characters — likely obfuscated"
	}

	return result, nil
}

// LoadScriptCapabilities loads script capability patterns from embedded data.
func LoadScriptCapabilities() (*ScriptCapabilitiesConfig, error) {
	var config ScriptCapabilitiesConfig
	if err := json.Unmarshal(data.ScriptCapabilities, &config); err != nil {
		return nil, fmt.Errorf("parsing script capabilities: %w", err)
	}
	return &config, nil
}

// findDangerousCalls scans script lines for known dangerous function calls.
func findDangerousCalls(lines []string, language string, caps *ScriptCapabilitiesConfig) []models.DangerousCall {
	var calls []models.DangerousCall
	seen := make(map[string]bool)

	for lineIdx, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comment-only lines.
		if isCommentLine(trimmed, language) {
			continue
		}

		for _, cap := range caps.Capabilities {
			// Match if language is "any" or matches the script's language.
			if cap.Language != "any" && cap.Language != language {
				continue
			}
			if strings.Contains(strings.ToLower(trimmed), strings.ToLower(cap.Pattern)) {
				key := cap.Pattern + "|" + cap.Capability
				if seen[key] {
					continue
				}
				seen[key] = true
				calls = append(calls, models.DangerousCall{
					Call:       cap.Pattern,
					Capability: cap.Capability,
					Line:       lineIdx + 1,
					Context:    truncateContext(trimmed, 120),
				})
			}
		}
	}
	return calls
}

// findEncodingLayers detects obfuscation/encoding patterns.
func findEncodingLayers(content string) []models.EncodingLayer {
	var layers []models.EncodingLayer
	seen := make(map[string]bool)

	for _, ep := range encodingPatterns {
		loc := ep.re.FindStringIndex(content)
		if loc != nil {
			if seen[ep.layerType] {
				continue
			}
			seen[ep.layerType] = true

			sample := content[loc[0]:min(loc[1], loc[0]+100)]
			layers = append(layers, models.EncodingLayer{
				Type:        ep.layerType,
				Description: ep.description,
				Offset:      loc[0],
				Sample:      truncateContext(sample, 80),
			})
		}
	}
	return layers
}

// findDownloadCradles detects download patterns.
func findDownloadCradles(content string) []string {
	var cradles []string
	seen := make(map[string]bool)

	for _, re := range downloadCradlePatterns {
		matches := re.FindAllString(content, 5)
		for _, m := range matches {
			truncated := truncateContext(m, 120)
			if !seen[truncated] {
				seen[truncated] = true
				cradles = append(cradles, truncated)
			}
		}
	}
	return cradles
}

func splitLines(content string) []string {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func isCommentLine(line, language string) bool {
	switch language {
	case "powershell", "python", "shell", "perl":
		return strings.HasPrefix(line, "#")
	case "vbscript":
		return strings.HasPrefix(line, "'") || strings.HasPrefix(strings.ToLower(line), "rem ")
	case "javascript":
		return strings.HasPrefix(line, "//")
	case "batch":
		return strings.HasPrefix(strings.ToLower(line), "rem ") || strings.HasPrefix(line, "::")
	}
	return false
}

func countComments(lines []string, language string) int {
	count := 0
	for _, line := range lines {
		if isCommentLine(strings.TrimSpace(line), language) {
			count++
		}
	}
	return count
}

func isHeavilyObfuscated(content string) bool {
	if len(content) < 100 {
		return false
	}
	specialCount := 0
	for _, c := range content {
		switch c {
		case '`', '^', '+', '&', '|', '{', '}', '[', ']', '(', ')', '$', '@', '!':
			specialCount++
		}
	}
	ratio := float64(specialCount) / float64(len(content))
	return ratio > 0.15
}

func truncateContext(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
