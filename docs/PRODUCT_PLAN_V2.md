# Undertaker Product Plan

## One-line definition

Undertaker is a static malware analysis tool that triages a sample and produces a structured report you hand to Claude alongside Ghidra MCP.

## Core insight

Before you open a binary in Ghidra, you need a map. What is this file? Is it packed? What does it import? Are there C2 strings? What capabilities does it have?

Today, that first-pass triage means running a dozen tools manually, copying outputs into notes, and assembling context by hand. Undertaker collapses that into one command:

```
undertaker analyze sample.dll
```

The output is a Markdown report covering identity, packing, imports, strings, IOCs, capabilities, and YARA matches — everything Claude needs to start targeted reverse engineering through Ghidra MCP instead of exploring a 10,000-function binary blind.

## Problem statement

Malware triage before reverse engineering is repetitive and fragmented:

- Hash the sample in one terminal
- Check entropy in another
- Run strings, grep for IOCs
- Open a PE parser, inspect imports
- Maybe run capa or YARA
- Copy interesting bits into notes
- Assemble context for Claude manually

Every sample. Every time. The same sequence of commands producing scattered outputs that you mentally stitch together.

Undertaker automates this entire pass and produces a single, structured report.

## What Undertaker is

- A **static analysis tool**. It reads bytes on disk. It never executes the sample.
- A **triage layer**. It runs before you open Ghidra, not instead of it.
- A **report generator**. Its primary output is a Markdown report designed to be pasted into Claude as context for Ghidra MCP work.
- A **Go CLI with a TUI**. Single binary, drop it in your VM, use it.

## What Undertaker is not

- Not a sandbox. No dynamic analysis, no execution.
- Not a Ghidra replacement. It does not decompile or disassemble.
- Not a Claude integration. It produces a report. You paste it. That's the interface.
- Not a case management framework. It saves outputs to disk, but it's not trying to be a investigation platform.
- Not an automation pipeline. The analyst drives the workflow.

## Primary workflow

```
1. Analyst receives a suspicious sample
2. $ undertaker analyze sample.dll
3. Undertaker runs all applicable static analyzers
4. TUI shows live progress and results
5. Report saved to cases/<name>/report.md
6. Analyst copies report, pastes to Claude
7. Claude uses the report + Ghidra MCP to do targeted reversing
```

The report bridges the gap between "I have a binary" and "Claude knows what to look at in Ghidra."

## What the analysis covers

| Analyzer | What it produces | Implementation |
|----------|-----------------|----------------|
| File ID | File type (PE32, PE64, DLL, .NET, script, etc.), architecture | Magic bytes + PE header parsing |
| Hashing | MD5, SHA1, SHA256, ssdeep, imphash | Go crypto stdlib |
| Metadata | Compile timestamp, sections, resources, debug info, version info | saferwall/pe |
| Entropy | Shannon entropy per section + overall | Math on raw bytes |
| Packing | Packed yes/no, packer name, detection method | Entropy thresholds + known packer signatures |
| Strings | Interesting strings filtered from noise (URLs, IPs, paths, registry, mutexes, crypto constants) | Raw extraction + FLOSS static mode (if available) |
| Imports | Import table parsed, suspicious APIs grouped by capability (injection, persistence, evasion, crypto, network) | saferwall/pe + embedded API-to-capability map |
| IOC extraction | Domains, IPs, URLs, file paths, registry keys, mutexes | Regex on extracted strings |
| capa | ATT&CK technique matches | Subprocess to capa binary, parse JSON output |
| YARA | Rule matches from analyst's rule sets | Subprocess to yara binary |

### File type routing

Not every analyzer applies to every file. The pipeline routes by detected file type:

| File type | Full pipeline | Notes |
|-----------|--------------|-------|
| PE (.exe, .dll, .sys, .scr, .ocx) | All analyzers | Primary target |
| .NET assemblies | All + .NET metadata (class names, methods, resources) | Detected via CLR header |
| Scripts (.ps1, .vbs, .js, .bat) | Hashing, strings, IOCs, YARA | No import/section analysis |
| Shellcode / raw blobs | Hashing, entropy, strings, IOCs, YARA | No structural analysis |
| Archives (.zip, .rar, .7z) | Hashing, file ID only | Detect but do not auto-extract |

### Graceful degradation

External tools are optional. If FLOSS is not installed, Undertaker falls back to raw string extraction. If capa is missing, that section is skipped. If no YARA rules are configured, YARA scanning is skipped. The core analysis (hashing, PE parsing, entropy, imports, strings, IOCs) runs with zero external dependencies.

## Report format

The report is Markdown, readable by both the analyst and Claude. Example:

```markdown
# Undertaker Static Analysis Report
## sample.dll

### Identity
- SHA256: 3a4b5c6d...
- MD5: ...
- SHA1: ...
- ssdeep: ...
- imphash: ...
- File type: PE64 DLL
- Architecture: AMD64
- File size: 245,760 bytes
- Compile timestamp: 2024-01-15 08:32:11 UTC

### Packing Assessment
- Status: Likely packed (UPX signature detected)
- Overall entropy: 7.42
- Section entropies:
  - .text: 7.81 (high)
  - .rdata: 4.12 (normal)
  - .rsrc: 7.65 (high — likely encrypted resource)

### Suspicious Imports
Process Injection:
  - VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
Anti-Debug:
  - IsDebuggerPresent, CheckRemoteDebuggerPresent
Persistence:
  - RegSetValueExA
Network:
  - InternetOpenA, HttpSendRequestA

### Strings of Interest
C2/Network:
  - "http://updates.legit-domain.com/gate.php"
  - "Mozilla/5.0 (compatible; MSIE 10.0)"
Filesystem:
  - "%APPDATA%\\Microsoft\\svchost.exe"
  - "\\\\.\\pipe\\interop_pipe"
Registry:
  - "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
Crypto:
  - "CryptEncrypt"
  - Base64 blob at offset 0x1A200 (412 bytes)

### IOCs
| Type | Value | Source |
|------|-------|--------|
| domain | updates.legit-domain.com | strings |
| url | http://updates.legit-domain.com/gate.php | strings |
| filepath | %APPDATA%\Microsoft\svchost.exe | strings |
| mutex | interop_pipe | strings |
| registry | ...\CurrentVersion\Run | strings |

### Capabilities (capa)
- T1055: Process Injection
- T1082: System Information Discovery
- T1547.001: Boot/Logon Autostart — Registry Run Keys
- T1071.001: Web Protocols

### YARA Matches
- cobalt_strike_beacon: matched
- apt_loader_generic: matched
```

This report tells Claude: "this is likely a packed DLL that does process injection, persists via Run key, and talks to a C2 over HTTP — start by tracing the injection chain from the VirtualAllocEx import."

## TUI

Undertaker uses Bubbletea for a terminal UI instead of plain text output. During analysis:

- Live progress as each analyzer completes
- Results displayed in styled, structured panels
- Keybindings: `r` to open full report, `c` to copy report to clipboard, `q` to quit

The TUI makes the tool faster to read during an investigation and gives immediate feedback on analysis progress. Analyzers run concurrently via goroutines; the TUI updates as each one finishes.

## Architecture

```
undertaker/
  cmd/
    undertaker/
      main.go                  # Entry point
  internal/
    cli/
      analyze.go               # `undertaker analyze` command
      root.go                  # Root command setup (cobra)
    tui/
      model.go                 # Bubbletea model
      update.go                # Message handling
      view.go                  # Rendering
      styles.go                # Lipgloss styles
    analysis/
      pipeline.go              # Routes file to correct analyzer set by file type
      hasher.go                # MD5, SHA1, SHA256, ssdeep, imphash
      fileid.go                # File type detection
      entropy.go               # Shannon entropy per section
      packing.go               # Pack detection (entropy + signatures)
      strings.go               # String extraction + filtering
      imports.go               # Import analysis + API capability mapping
      ioc.go                   # Regex IOC extraction
      metadata.go              # PE metadata, timestamps, resources
      yara.go                  # YARA subprocess wrapper
      capa.go                  # capa subprocess wrapper
      floss.go                 # FLOSS subprocess wrapper
    models/
      report.go                # AnalysisReport, Sample, IOC, Finding structs
      capabilities.go          # API-to-capability mapping types
    reporting/
      markdown.go              # Markdown report generation
      json.go                  # JSON export
    tools/
      registry.go              # Detect available tools on PATH
      runner.go                # Safe subprocess execution
    config/
      config.go                # Global config loading
  data/
    api_capabilities.json      # Embedded via go:embed
    ioc_patterns.json          # Embedded via go:embed
    string_filters.json        # Embedded via go:embed
  cases/                       # Case output directory (gitignored)
```

### Key design decisions

**Go + single binary.** No runtime dependencies. Build once, drop in VM.

**saferwall/pe for PE parsing.** Mature Go PE parser covering imports, exports, sections, resources, rich header, debug info, .NET metadata.

**External tools via subprocess.** FLOSS, capa, and YARA are invoked as subprocesses and their output parsed. This keeps Undertaker decoupled from their versions and avoids CGo complexity.

**go:embed for static data.** The API capability map, IOC patterns, and string filters are baked into the binary. No external data files to manage.

**Goroutines for concurrency.** Independent analyzers (hashing, entropy, strings) run in parallel. Results stream to the TUI as they complete.

**Cobra for CLI.** Standard Go CLI framework.

## Data model

```go
type AnalysisReport struct {
    Sample       Sample
    Packing      PackingInfo
    Imports      ImportAnalysis
    Strings      []StringHit
    IOCs         []IOC
    Capabilities []Capability
    YARAMatches  []YARAMatch
    Metadata     PEMetadata
}

type Sample struct {
    Path         string
    MD5          string
    SHA1         string
    SHA256       string
    SSDeep       string
    ImpHash      string
    FileSize     int64
    FileType     string    // "PE32", "PE64", "DLL", ".NET", "script", etc.
    Architecture string    // "x86", "AMD64", etc.
}

type PackingInfo struct {
    IsPacked        bool
    Entropy         float64
    SectionEntropies map[string]float64
    PackerName      string   // "UPX", "Themida", etc. or empty
    DetectionMethod string   // "entropy", "signature", "both"
}

type IOC struct {
    Type    string   // "domain", "ip", "url", "filepath", "mutex", "registry"
    Value   string
    Source  string   // "strings", "imports", "metadata"
    Context string   // Surrounding context or offset
}

type ImportAnalysis struct {
    TotalImports      int
    SuspiciousImports []SuspiciousImport
    CapabilityTags    []string  // "process_injection", "persistence", etc.
}

type SuspiciousImport struct {
    Name       string
    DLL        string
    Capability string
}

type StringHit struct {
    Value    string
    Category string   // "c2", "filesystem", "registry", "crypto", "mutex"
    Offset   int64
    Encoding string   // "ascii", "utf16"
}

type Capability struct {
    TechniqueID   string  // "T1055"
    TechniqueName string  // "Process Injection"
    Source        string  // "capa", "import_analysis"
}

type YARAMatch struct {
    RuleName    string
    Description string
    Tags        []string
}

type PEMetadata struct {
    CompileTimestamp string
    Sections        []SectionInfo
    Resources       []ResourceInfo
    DebugInfo       []DebugEntry
    VersionInfo     map[string]string
    IsDotNet        bool
}

type SectionInfo struct {
    Name           string
    VirtualSize    uint32
    RawSize        uint32
    Entropy        float64
    Characteristics string
}
```

## Configuration

Global config at `~/.undertaker/config.yaml`:

```yaml
# Paths to external tools (auto-detected if on PATH)
tools:
  floss: ""      # e.g. /usr/local/bin/floss
  capa: ""       # e.g. /usr/local/bin/capa
  yara: ""       # e.g. /usr/local/bin/yara

# YARA rule directories
yara_rules:
  - ~/yara-rules/

# Output preferences
output:
  case_dir: ./cases
  formats:
    - markdown
    - json
```

If a tool path is empty, Undertaker checks PATH. If not found, that analyzer is skipped.

## CLI commands

```
undertaker analyze <file>         # Run full static analysis, open TUI with results
undertaker analyze <file> --json  # Output JSON to stdout instead of TUI
undertaker analyze <file> --quiet # No TUI, just save report to case dir
undertaker config                 # Show current config and detected tools
undertaker config init            # Create default ~/.undertaker/config.yaml
```

That's it for MVP. The primary command is `analyze`. Everything else is support.

## Dependencies

```
github.com/saferwall/pe              # PE parsing
github.com/charmbracelet/bubbletea   # TUI framework
github.com/charmbracelet/bubbles     # TUI components (tables, progress, etc.)
github.com/charmbracelet/lipgloss    # TUI styling
github.com/spf13/cobra               # CLI framework
gopkg.in/yaml.v3                     # Config parsing
```

All compile into the binary. No CGo. No runtime dependencies.

Optional external tools (detected at runtime):
- FLOSS — enhanced string extraction
- capa — capability detection
- YARA — rule matching

## Security boundaries

Undertaker handles hostile inputs. All sample-derived content is untrusted:

1. **Never execute the sample.** Static analysis only — read bytes, parse structures, extract strings.
2. **Treat extracted strings as untrusted.** They appear in reports but are never evaluated, executed, or used in shell commands.
3. **Subprocess safety.** External tool invocations use explicit argument lists, never shell interpolation with sample-derived values.
4. **No network access.** Undertaker does not phone home, query APIs, or resolve extracted domains. Fully offline.

## Build order

1. **Project scaffold** — Go module, Cobra CLI skeleton, config loading
2. **Hashing + file ID** — Immediate value, simple to implement
3. **PE parsing + metadata** — saferwall/pe integration, section info, timestamps
4. **Entropy + packing detection** — Per-section entropy, packer signature matching
5. **String extraction + IOC regex** — Raw strings with category filtering, IOC pattern matching
6. **Import analysis + capability mapping** — Parse import table, map APIs to capabilities
7. **Tool registry + FLOSS/capa/YARA wrappers** — Detect tools, invoke as subprocesses
8. **Markdown + JSON reporting** — Generate the report from AnalysisReport struct
9. **TUI** — Bubbletea integration, live progress, keybindings

Steps 1–6 produce a working tool with pure-Go analysis. Step 7 adds optional enrichment. Step 8 makes the output useful. Step 9 makes it polished.

## Success criteria

Undertaker is successful when:

- You can run `undertaker analyze sample.exe` and get a useful report in seconds
- The report tells you whether it's packed, what it imports, what IOCs are present, and what capabilities it has — without opening any other tool
- You can paste that report into Claude and immediately start targeted Ghidra MCP work
- It runs in your VM with zero setup beyond copying the binary
