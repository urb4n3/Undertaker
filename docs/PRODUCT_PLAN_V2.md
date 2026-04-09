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
5. Report saved to cases/<sha256-prefix>/report.md
6. Analyst copies report, pastes to Claude
7. Claude uses the report + Ghidra MCP to do targeted reversing
```

The report bridges the gap between "I have a binary" and "Claude knows what to look at in Ghidra."

## What the analysis covers

| Analyzer | What it produces | Implementation |
|----------|-----------------|----------------|
| File ID | File type (PE32, PE64, DLL, .NET, script, etc.), architecture | Magic bytes + PE header parsing |
| Hashing | MD5, SHA1, SHA256, ssdeep, imphash | Go crypto stdlib for MD5/SHA1/SHA256; glaslos/ssdeep (pure Go) for fuzzy hashing; custom implementation for imphash (saferwall/pe imports + ordinal resolution + MD5) |
| Metadata | Compile timestamp, sections, resources, debug info, version info | saferwall/pe |
| Entropy | Shannon entropy per section + overall | Math on raw bytes |
| Packing | Packing confidence level, packer name, detection signals | Multi-signal analysis: entropy thresholds, known packer signatures, section name heuristics, import table size anomalies, entry point location. See Packing Detection below |
| Strings | Interesting strings filtered from noise (URLs, IPs, paths, registry, mutexes, crypto constants) | Raw extraction + built-in Base64 detection/decoding + FLOSS (all modes — runs in VM). Falls back to built-in extraction if FLOSS unavailable |
| Imports | Import table parsed, suspicious APIs grouped by capability (injection, persistence, evasion, crypto, network) | saferwall/pe + embedded API-to-capability map |
| Exports | Export table for DLLs — function names, ordinals, forwarded exports | saferwall/pe |
| IOC extraction | Domains, IPs, URLs, file paths, registry keys, mutexes | Regex on extracted strings |
| Overlay | Detects data appended after the last PE section (packer payloads, encrypted blobs) with size and entropy | Compare last section end offset to file size |
| Rich header | Compiler and linker versions, build environment fingerprint | saferwall/pe |
| capa | ATT&CK technique matches | Subprocess to capa binary, parse JSON output (targets capa v7+, checks schema version) |
| YARA | Rule matches from analyst's rule sets | Subprocess to yara binary |

### File type routing

Not every analyzer applies to every file. The pipeline routes by detected file type:

| File type | Full pipeline | Notes |
|-----------|--------------|-------|
| PE (.exe, .dll, .sys, .scr, .ocx) | All analyzers | Primary target |
| .NET assemblies | All + .NET metadata (class names, methods, resources) | Detected via CLR header |
| OLE documents (.doc, .xls, .ppt) | Hashing, strings, IOCs, YARA | Macro/OLE stream detection (future: stream extraction) |
| LNK files (.lnk) | Hashing, strings, IOCs, YARA, target path/arguments | Common delivery vector |
| HTA / scripts (.ps1, .vbs, .js, .bat, .hta) | Hashing, strings, IOCs, YARA | No import/section analysis |
| Shellcode / raw blobs | Hashing, entropy, strings, IOCs, YARA | No structural analysis |
| MSI / ISO / IMG | Hashing, file ID, strings, IOCs, YARA | Detect type, basic string/IOC extraction |
| Archives (.zip, .rar, .7z) | Hashing, file ID only | Detect but do not auto-extract |

### Graceful degradation

External tools are optional. If FLOSS is not installed, Undertaker falls back to raw string extraction. If capa is missing, that section is skipped. If no YARA rules are configured, YARA scanning is skipped. The core analysis (hashing, PE parsing, entropy, imports, exports, strings, IOCs) runs with zero external dependencies.

### Packing detection

Packing detection is inherently imprecise. Undertaker uses a graduated confidence model rather than binary yes/no:

| Confidence | Label | Meaning |
|------------|-------|---------|
| High | "Packed (high confidence)" | Known packer signature matched (e.g. UPX magic, MPRESS header) |
| Medium | "Likely packed" | Multiple signals converge: high entropy (.text > 6.8), very few imports (< 10), entry point in unusual section, suspicious section names (.UPX0, .themida, CODE) |
| Low | "Possibly compressed" | High entropy alone. Could be legitimate compressed resources, Authenticode padding, or .NET metadata |
| None | "Not packed" | Normal entropy, normal import count, no packer signatures |

Signals used (combined, not any single one):

- **Section entropy**: Shannon entropy > 6.8 on code sections
- **Packer signatures**: Known magic bytes and section names for UPX, MPRESS, ASPack, PECompact, Themida, VMProtect, Enigma
- **Import table anomaly**: Very few imports (< 10) combined with high entropy suggests a packer stub that resolves imports at runtime
- **Entry point location**: Entry point outside the first code section, or in a section with packer-associated characteristics
- **Section name heuristics**: Non-standard section names that match known packer patterns

Known limitations:

- **Custom packers** with no known signature and low entropy (e.g. single-byte XOR) will produce false negatives
- **Legitimate compressed resources** in .NET assemblies or Electron apps may trigger "Possibly compressed" — the .NET detector adjusts for this
- **Themida/VMProtect** are detected by section name heuristics but not by entropy alone (they can produce normal-looking entropy)
- **No emulation-based unpacking** — this is a static tool, not a sandbox

The report always shows the raw signals (entropy values, section names, import count) so the analyst can override the confidence assessment.

### String extraction quality

String quality is the most variable part of the analysis. Undertaker manages this with:

**Filtering and ranking strategy:**

1. Extract raw ASCII (min 6 chars) and UTF-16LE strings
2. Run built-in Base64 detection: identify potential Base64 blobs (min 20 chars, valid charset, length divisible by 4), attempt decode, include decoded result if it produces printable content
3. If FLOSS is available, use its output instead (covers stack strings, tight strings, decoded strings)
4. Categorize all strings by regex matching into: `c2` (URLs, domains, IPs), `filesystem` (paths, filenames), `registry` (registry keys), `crypto` (algorithm names, key material patterns), `mutex` (mutex/pipe names), `debug` (debug strings, error messages), `uncategorized`
5. Score by category relevance: `c2` > `registry` > `filesystem` > `mutex` > `crypto` > `debug` > `uncategorized`
6. Deduplicate, rank, take top 50 (or all with `--full`)

**Quality/confidence indicators in the report:**

- When FLOSS is unavailable: the report header notes "Strings extracted without FLOSS — XOR-encoded, stack-constructed, and obfuscated strings may be missing"
- When the sample appears packed but FLOSS is unavailable: an explicit warning: "Sample appears packed and FLOSS is not available — string results are likely incomplete. Install FLOSS for better coverage."
- When string count is very low (< 10) on a non-trivial binary: "Unusually few strings extracted — sample may be packed or obfuscated"
- Each `StringHit` carries its extraction source (`raw`, `base64_decoded`, `floss_static`, `floss_stack`, `floss_tight`) so the analyst knows provenance

### Resilience against malformed inputs

Malware routinely uses corrupted PE headers (overlapping sections, impossible offsets, circular resource trees) to crash analysis tools. If any individual analyzer fails on malformed input, Undertaker logs the error and continues with the remaining analyzers. A corrupted resource table should not prevent import analysis from running. The report notes which analyzers failed and why.

### Report size management

A complex sample can produce thousands of strings and hundreds of IOC hits. An oversized report pasted into Claude wastes context window and reduces quality. Undertaker manages report size by:

- Capping strings of interest at the top 50 (ranked by category relevance)
- Capping IOCs at the top 30 (deduplicated, ranked by type)
- Truncating YARA match details to rule name + description (no hex dumps)
- Including a focused **Summary** section at the top of every report with the 5–10 most important findings
- Providing `--full` flag to override caps when the analyst wants everything

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
- Timestamp anomalies: none

### Exports (DLL)
- DllMain
- ServiceMain
- StartW (ordinal 1)

### Rich Header
- Visual C++ 2019 (v16.0) linker
- Visual C++ 2019 compiler (x64)
- 3 unique toolchain entries

### Overlay
- Overlay detected: 102,400 bytes after last section
- Overlay entropy: 7.91 (high — likely encrypted payload)

### Packing Assessment
- Confidence: Likely packed (medium — high entropy + low import count + entry point in .rsrc)
- Packer: UPX signature detected
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
      exports.go               # Export table analysis (DLLs)
      ioc.go                   # Regex IOC extraction
      metadata.go              # PE metadata, timestamps, resources, timestamp anomaly detection
      richheader.go            # Rich header parsing (compiler/linker fingerprinting)
      overlay.go               # Overlay/appended data detection + entropy
      dotnet.go                # .NET CLR metadata (namespaces, classes, methods, resources)
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
      runner.go                # Safe subprocess execution (timeout + kill-on-expiry)
    config/
      config.go                # Global config loading
  data/
    api_capabilities.json      # Embedded via go:embed (Win32 + Nt*/Zw* syscalls)
    ioc_patterns.json          # Embedded via go:embed
    string_filters.json        # Embedded via go:embed
  cases/                       # Case output directory (gitignored)
```

### Key design decisions

**Go + single binary.** No runtime dependencies. Build once, drop in VM.

**saferwall/pe for PE parsing.** Mature Go PE parser covering imports, exports, sections, resources, rich header, debug info, .NET metadata.

**External tools via subprocess.** FLOSS, capa, and YARA are invoked as subprocesses and their output parsed. This keeps Undertaker decoupled from their versions and avoids CGo complexity. Each subprocess runs with a configurable timeout (default 60s) — if a tool hangs or runs too long, it is killed and the analyzer reports a timeout error without blocking the rest of the pipeline.

**External tool version management.** On detection, Undertaker runs each tool with its version flag and records the version. Minimum supported versions: capa v7+, FLOSS v3+, YARA v4+. If a tool is below the minimum version, Undertaker warns and skips it rather than parsing potentially incompatible output. `undertaker config` displays detected tool paths AND versions. Subprocess stderr is always captured and surfaced in `AnalyzerError` entries when a tool fails — "floss crashed" becomes "floss: error: unsupported file format" so the analyst knows why.

**go:embed for static data.** The API capability map, IOC patterns, and string filters are baked into the binary. No external data files to manage. The embedded `api_capabilities.json` includes both Win32 APIs and Nt*/Zw* syscall-level APIs (NtAllocateVirtualMemory, NtWriteVirtualMemory, etc.) since modern malware increasingly uses direct syscalls to bypass API hooks. The embedded map is versioned and updated with each Undertaker release.

**Analyst-extensible data files.** The global config directory can contain override files (`api_capabilities_custom.json`, `string_filters_custom.json`) that merge with the embedded defaults. This lets analysts add API mappings for new or niche APIs, custom string filter patterns, or organization-specific IOC patterns without waiting for an Undertaker release. Custom entries take precedence over embedded defaults.

**Goroutines for concurrency.** Independent analyzers (hashing, entropy, strings) run in parallel. Results stream to the TUI as they complete.

**Cobra for CLI.** Standard Go CLI framework.

## Data model

```go
type AnalysisReport struct {
    Sample       Sample
    Packing      PackingInfo
    Imports      ImportAnalysis
    Exports      []Export          // nil/empty for non-DLLs
    Overlay      *OverlayInfo      // nil if no overlay present
    RichHeader   *RichHeader       // nil if not present or corrupted
    Strings      []StringHit
    IOCs         []IOC
    Capabilities []Capability
    YARAMatches  []YARAMatch
    Metadata     PEMetadata
    DotNet       *DotNetMetadata   // nil if not a .NET assembly
    Errors       []AnalyzerError   // Analyzers that failed on malformed input
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
    Confidence      string             // "high", "medium", "low", "none"
    Label           string             // "Packed (high confidence)", "Likely packed", "Possibly compressed", "Not packed"
    Entropy         float64            // Overall file entropy
    PackerName      string             // "UPX", "Themida", etc. or empty
    Signals         []string           // Which signals fired: "high_entropy", "packer_signature", "low_import_count", "ep_anomaly", "section_name"
    // Per-section entropy lives in PEMetadata.Sections ([]SectionInfo)
    // to avoid lossy map keying — PE section names are not unique.
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
    Category string   // "c2", "filesystem", "registry", "crypto", "mutex", "debug"
    Offset   int64
    Encoding string   // "ascii", "utf16"
    Source   string   // "raw", "base64_decoded", "floss_static", "floss_stack", "floss_tight"
}

type Capability struct {
    TechniqueID   string  // "T1055"
    TechniqueName string  // "Process Injection"
    Source        string  // "capa", "import_analysis"
}

// Note: When capa is absent, capabilities are derived from import analysis only.
// The report notes: "Capability detection based on import analysis only — install capa for deeper coverage."

type YARAMatch struct {
    RuleName    string
    Description string
    Tags        []string
}

type PEMetadata struct {
    CompileTimestamp  time.Time
    TimestampAnomaly  string          // "future", "pre-1990", "epoch", "zeroed", "" if normal
    Sections          []SectionInfo
    Resources         []ResourceInfo
    DebugInfo         []DebugEntry
    VersionInfo       map[string]string
    IsDotNet          bool
}

type Export struct {
    Name      string
    Ordinal   uint16
    Forwarded string   // Target if forwarded export, empty otherwise
}

type OverlayInfo struct {
    Offset  int64
    Size    int64
    Entropy float64
}

type RichHeader struct {
    Entries []RichEntry
}

type RichEntry struct {
    Toolchain string   // e.g. "Visual C++ 2019 (v16.0)"
    Type      string   // "compiler", "linker", "assembler"
    Count     uint32   // Number of objects built with this tool
}

type AnalyzerError struct {
    Analyzer string   // e.g. "imports", "metadata", "floss"
    Error    string   // What went wrong
    Stderr   string   // Captured stderr from subprocess (if applicable)
}

type SectionInfo struct {
    Name           string
    VirtualSize    uint32
    RawSize        uint32
    Entropy        float64
    Characteristics string
}

type DotNetMetadata struct {
    RuntimeVersion string
    Namespaces     []string
    Classes        []DotNetClass
    Resources      []DotNetResource
    AssemblyRefs   []string          // Referenced assemblies
}

type DotNetClass struct {
    Namespace  string
    Name       string
    Methods    []string
}

type DotNetResource struct {
    Name string
    Size uint32
}
```

## Configuration

Global config at the OS-standard config directory (`os.UserConfigDir()` — `%APPDATA%\undertaker\` on Windows, `~/.config/undertaker/` on Linux):

```yaml
# Paths to external tools (auto-detected if on PATH)
tools:
  floss: ""      # e.g. /usr/local/bin/floss
  capa: ""       # e.g. /usr/local/bin/capa
  yara: ""       # e.g. /usr/local/bin/yara
  timeout: 60    # Seconds before killing a stuck subprocess (0 = no timeout)

# YARA rule directories
yara_rules:
  - ~/yara-rules/

# Analysis limits
limits:
  max_file_size: 500MB   # Skip entropy/strings/ssdeep for files above this size

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
undertaker analyze <file> --full  # No caps on strings/IOCs — include everything
undertaker config                 # Show current config, detected tools, and tool versions
undertaker config init            # Create default config file
```

That's it for MVP. The primary command is `analyze`. Everything else is support.

## Dependencies

```
github.com/saferwall/pe              # PE parsing
github.com/glaslos/ssdeep            # Fuzzy hashing (pure Go)
github.com/charmbracelet/bubbletea   # TUI framework
github.com/charmbracelet/bubbles     # TUI components (tables, progress, etc.)
github.com/charmbracelet/lipgloss    # TUI styling
github.com/spf13/cobra               # CLI framework
gopkg.in/yaml.v3                     # Config parsing
```

All compile into the binary. No CGo. No runtime dependencies.

Note: imphash computation is custom code (import table from saferwall/pe + ordinal-to-name lookup table + MD5). The ordinal resolution table for common DLLs (kernel32, ws2_32, oleaut32, etc.) is embedded via go:embed.

Optional external tools (detected at runtime, version-checked):
- FLOSS v3+ — enhanced string extraction (all modes: static, stack strings, tight strings)
- capa v7+ — capability detection (JSON schema version checked before parsing)
- YARA v4+ — rule matching

## Security boundaries

Undertaker handles hostile inputs. All sample-derived content is untrusted:

1. **Never execute the sample.** Static analysis only — read bytes, parse structures, extract strings.
2. **Treat extracted strings as untrusted.** They appear in reports but are never evaluated, executed, or used in shell commands.
3. **Subprocess safety.** External tool invocations use explicit argument lists, never shell interpolation with sample-derived values.
4. **No network access.** Undertaker does not phone home, query APIs, or resolve extracted domains. Fully offline.
5. **Safe case directory naming.** Case directories are named by SHA256 prefix (e.g., `cases/3a4b5c6d/`), never derived from the sample filename. This prevents path traversal, Windows reserved name issues, and encoding attacks from malicious filenames.
6. **Subprocess timeouts.** External tools (FLOSS, capa, YARA) run with a configurable timeout (default 60s). If a tool hangs, it is killed and the pipeline continues. No single stuck subprocess can block the analysis.
7. **File size limits.** Files above a configurable threshold (default 500MB) skip memory-intensive analyzers (entropy, strings, ssdeep). Hashing uses streaming reads (never loads the full file into memory). This prevents OOM on large ISOs, disk images, or bloated installers.

## Build order

1. **Project scaffold** — Go module, Cobra CLI skeleton, config loading
2. **Hashing + file ID** — Immediate value, simple to implement
3. **PE parsing + metadata** — saferwall/pe integration, section info, timestamps, timestamp anomaly flagging
4. **Entropy + packing detection + overlay** — Per-section entropy, packer signatures, overlay detection
5. **String extraction + IOC regex** — Raw strings with category filtering, IOC pattern matching
6. **Import + export analysis + capability mapping** — Parse import/export tables, map APIs to capabilities
7. **Rich header parsing** — Compiler/linker fingerprinting
8. **Tool registry + FLOSS/capa/YARA wrappers** — Detect tools, invoke as subprocesses
9. **Markdown + JSON reporting** — Generate the report with size management
10. **TUI** — Bubbletea integration, live progress, keybindings
Steps 1–7 produce a working tool with pure-Go analysis. Step 8 adds optional enrichment. Step 9 makes the output useful. Step 10 makes it polished.

## Success criteria

Undertaker is successful when:

- You can run `undertaker analyze sample.exe` and get a useful report in seconds
- The report tells you whether it's packed, what it imports, what IOCs are present, and what capabilities it has — without opening any other tool
- You can paste that report into Claude and immediately start targeted Ghidra MCP work
- It runs in your VM with zero setup beyond copying the binary
