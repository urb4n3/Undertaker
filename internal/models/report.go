package models

import "time"

// AnalysisReport is the top-level container for all analysis results.
type AnalysisReport struct {
	Sample       Sample          `json:"sample"`
	Packing      PackingInfo     `json:"packing"`
	Imports      ImportAnalysis  `json:"imports"`
	Exports      []Export        `json:"exports,omitempty"`
	Overlay      *OverlayInfo    `json:"overlay,omitempty"`
	RichHeader   *RichHeader     `json:"rich_header,omitempty"`
	Strings      []StringHit     `json:"strings,omitempty"`
	IOCs         []IOC           `json:"iocs,omitempty"`
	Capabilities []Capability    `json:"capabilities,omitempty"`
	YARAMatches  []YARAMatch     `json:"yara_matches,omitempty"`
	Metadata     PEMetadata      `json:"metadata"`
	DotNet       *DotNetMetadata `json:"dotnet,omitempty"`
	Errors       []AnalyzerError `json:"errors,omitempty"`
}

type Sample struct {
	Path         string `json:"path"`
	MD5          string `json:"md5"`
	SHA1         string `json:"sha1"`
	SHA256       string `json:"sha256"`
	SSDeep       string `json:"ssdeep"`
	ImpHash      string `json:"imphash,omitempty"`
	FileSize     int64  `json:"file_size"`
	FileType     string `json:"file_type"`
	Architecture string `json:"architecture,omitempty"`
}

type PackingInfo struct {
	Confidence string   `json:"confidence"`
	Label      string   `json:"label"`
	Entropy    float64  `json:"entropy"`
	PackerName string   `json:"packer_name,omitempty"`
	Signals    []string `json:"signals,omitempty"`
}

type IOC struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Source  string `json:"source"`
	Context string `json:"context,omitempty"`
}

type ImportAnalysis struct {
	TotalImports      int                `json:"total_imports"`
	SuspiciousImports []SuspiciousImport `json:"suspicious_imports,omitempty"`
	CapabilityTags    []string           `json:"capability_tags,omitempty"`
}

type SuspiciousImport struct {
	Name       string `json:"name"`
	DLL        string `json:"dll"`
	Capability string `json:"capability"`
}

type StringHit struct {
	Value    string `json:"value"`
	Category string `json:"category"`
	Offset   int64  `json:"offset"`
	Encoding string `json:"encoding"`
	Source   string `json:"source"`
}

type Capability struct {
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	Source        string `json:"source"`
}

type YARAMatch struct {
	RuleName    string   `json:"rule_name"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type PEMetadata struct {
	CompileTimestamp time.Time         `json:"compile_timestamp,omitempty"`
	TimestampAnomaly string           `json:"timestamp_anomaly,omitempty"`
	Sections         []SectionInfo    `json:"sections,omitempty"`
	Resources        []ResourceInfo   `json:"resources,omitempty"`
	DebugInfo        []DebugEntry     `json:"debug_info,omitempty"`
	VersionInfo      map[string]string `json:"version_info,omitempty"`
	IsDotNet         bool             `json:"is_dotnet"`
}

type SectionInfo struct {
	Name            string  `json:"name"`
	VirtualSize     uint32  `json:"virtual_size"`
	RawSize         uint32  `json:"raw_size"`
	Entropy         float64 `json:"entropy"`
	Characteristics string  `json:"characteristics"`
}

type ResourceInfo struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Size uint32 `json:"size"`
	Lang string `json:"lang,omitempty"`
}

type DebugEntry struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Export struct {
	Name      string `json:"name"`
	Ordinal   uint16 `json:"ordinal"`
	Forwarded string `json:"forwarded,omitempty"`
}

type OverlayInfo struct {
	Offset  int64   `json:"offset"`
	Size    int64   `json:"size"`
	Entropy float64 `json:"entropy"`
}

type RichHeader struct {
	Entries []RichEntry `json:"entries"`
}

type RichEntry struct {
	Toolchain string `json:"toolchain"`
	Type      string `json:"type"`
	Count     uint32 `json:"count"`
}

type AnalyzerError struct {
	Analyzer string `json:"analyzer"`
	Error    string `json:"error"`
	Stderr   string `json:"stderr,omitempty"`
}

type DotNetMetadata struct {
	RuntimeVersion string          `json:"runtime_version"`
	Namespaces     []string        `json:"namespaces,omitempty"`
	Classes        []DotNetClass   `json:"classes,omitempty"`
	Resources      []DotNetResource `json:"resources,omitempty"`
	AssemblyRefs   []string        `json:"assembly_refs,omitempty"`
}

type DotNetClass struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Methods   []string `json:"methods,omitempty"`
}

type DotNetResource struct {
	Name string `json:"name"`
	Size uint32 `json:"size"`
}
