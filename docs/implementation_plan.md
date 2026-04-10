# Implementation Plan: Undertaker — Staged Build

## Source of truth

**`PRODUCT_PLAN_V2.md` is the authoritative specification.** This implementation plan describes *how* and *when* to build what the product plan defines — it does not override, redefine, or omit product plan requirements. If there is ever a conflict between this document and the product plan, the product plan wins. When implementing a stage, always cross-reference the corresponding sections in the product plan (analyzer table, file type routing table, data model, configuration, security boundaries) to ensure nothing is missed.

## TL;DR
Build Undertaker as a Go static malware analysis CLI in 7 stages, each producing a testable, working increment. Each stage adds a layer of analyzers, culminating in the TUI and polish. The project follows the product plan's build order but groups steps into independently verifiable phases with clear entry/exit criteria.

---

## Prerequisites — install these manually

These are things the agent **cannot** install for you. Set these up before starting Stage 1.

### Required

| Tool | Minimum version | Purpose | Install |
|------|----------------|---------|---------|
| **Go** | 1.22+ | Build language | https://go.dev/dl/ |
| **Git** | any | Source control | https://git-scm.com/ |

Go module dependencies (`saferwall/pe`, `glaslos/ssdeep`, `cobra`, `bubbletea`, `lipgloss`, `yaml.v3`, etc.) are fetched automatically by `go mod tidy` — no manual action needed.

### Optional (needed for full analysis, but Undertaker runs without them)

| Tool | Minimum version | Used in | Purpose | Install |
|------|----------------|---------|---------|---------|
| **FLOSS** | v3+ | Stage 5 | Enhanced string extraction (stack strings, tight strings, decoded strings) | https://github.com/mandiant/flare-floss/releases |
| **capa** | v7+ | Stage 5 | Capability detection, ATT&CK technique mapping | https://github.com/mandiant/capa/releases |
| **YARA** | v4+ | Stage 5 | Rule-based pattern matching | https://github.com/VirusTotal/yara/releases |

If any optional tool is missing, Undertaker skips that analyzer gracefully and notes it in the report. You can add these at any point — they only become relevant in Stage 5.

### Test samples

You'll need a small set of PE binaries for verification across stages. Collect before starting:

- A clean, unpacked PE32 or PE64 executable
- A known UPX-packed sample (or pack one yourself with `upx`)
- A DLL with exports
- A .NET assembly
- A malformed/truncated PE (or truncate one with a hex editor)
- A non-PE file (`.ps1` script, `.lnk`, OLE document) for file-type guard testing

---

## Stage 1: Project Scaffold + Hashing + File ID
**Goal:** Runnable CLI that accepts a file, identifies it, and hashes it.

1. Initialize Go module (`github.com/<user>/undertaker`), set up directory structure per the architecture in the product plan
2. Add Cobra CLI skeleton: `cmd/undertaker/main.go`, `internal/cli/root.go`, `internal/cli/analyze.go` — wire up `undertaker analyze <file>` command with `--json`, `--quiet`, `--full` flags (flags can be no-ops initially)
3. Implement `internal/config/config.go` — load YAML config from `os.UserConfigDir()`, fallback to defaults. Wire up `undertaker config` and `undertaker config init` commands
4. Implement `internal/analysis/fileid.go` — detect file type from magic bytes + PE header parsing (PE32, PE64, DLL, .NET, script, etc.)
5. Implement `internal/analysis/hasher.go` — MD5, SHA1, SHA256 via Go crypto stdlib; ssdeep via `glaslos/ssdeep`; imphash stub (returns empty until imports are parsed in Stage 4)
6. Define `internal/models/report.go` — `AnalysisReport`, `Sample`, `AnalyzerError` structs per the data model
7. Implement `internal/analysis/pipeline.go` — skeleton that runs file ID + hashing, returns an `AnalysisReport`. Include a basic file-type guard so PE-specific analyzers are never invoked on non-PE files (scripts, LNK, OLE, etc.) — even though non-PE routing is completed in Stage 7, the guard prevents confusing errors during intermediate stages
8. Wire CLI → pipeline → print JSON to stdout as temporary output

**Key files:** `cmd/undertaker/main.go`, `internal/cli/root.go`, `internal/cli/analyze.go`, `internal/config/config.go`, `internal/analysis/fileid.go`, `internal/analysis/hasher.go`, `internal/analysis/pipeline.go`, `internal/models/report.go`

**Verification:**
- `go build ./...` compiles with zero errors
- `undertaker analyze sample.exe` outputs JSON with correct SHA256, MD5, SHA1, file type
- `undertaker config init` creates a default config YAML
- Unit tests for hashing (known hash values), file ID (PE32 vs PE64 vs DLL vs script)

---

## Stage 2: PE Parsing — Metadata, Entropy, Packing, Overlay
**Goal:** Full structural analysis of PE files. *Depends on Stage 1.*

1. Add `saferwall/pe` dependency
2. Implement `internal/analysis/metadata.go` — compile timestamp (with anomaly detection: future, pre-1990, epoch, zeroed), sections (`SectionInfo`), resources, debug info, version info. Populate `PEMetadata` struct
3. Implement `internal/analysis/entropy.go` — Shannon entropy per section + overall file entropy
4. Implement `internal/analysis/packing.go` — multi-signal packing detection using the graduated confidence model (high/medium/low/none). Signals: section entropy > 6.8, known packer signatures (UPX, MPRESS, ASPack, etc.), import count < 10 (requires import count — use raw PE import directory count here, full import analysis in Stage 4), EP location anomaly, section name heuristics. Populate `PackingInfo`
5. Implement `internal/analysis/overlay.go` — detect data past last PE section, compute overlay entropy. Populate `OverlayInfo`
6. Register all new analyzers in `pipeline.go`, run them concurrently via goroutines (independent analyzers in parallel)
7. Handle malformed PE inputs gracefully — if any analyzer panics/errors on corrupted headers, catch and record in `AnalyzerError` slice

**Key files:** `internal/analysis/metadata.go`, `internal/analysis/entropy.go`, `internal/analysis/packing.go`, `internal/analysis/overlay.go`, `internal/analysis/pipeline.go`

**Verification:**
- Test against a known UPX-packed sample: packing confidence = "high", packer name = "UPX"
- Test against a clean binary: packing confidence = "none"
- Test with a malformed PE (truncated headers): analyzers that fail are recorded in `Errors`, others succeed
- Unit tests for Shannon entropy calculation (known byte sequences), timestamp anomaly detection

---

## Stage 3: String Extraction + IOC Extraction
**Goal:** Extract, filter, rank strings and pull IOCs from them. *Depends on Stage 1.*

1. Embed static data files via `go:embed`: `data/ioc_patterns.json`, `data/string_filters.json`
2. Implement `internal/analysis/strings.go` — raw ASCII (min 6 chars) + UTF-16LE extraction, Base64 detection/decoding (min 20 chars, valid charset, length % 4 == 0), category regex matching (c2, filesystem, registry, crypto, mutex, debug), scoring/ranking, dedup, cap at top 50 (respect `--full`). Populate `[]StringHit`
3. Implement `internal/analysis/ioc.go` — regex extraction for domains, IPs, URLs, file paths, registry keys, mutexes from string hits. Populate `[]IOC`, cap at 30 (respect `--full`)
4. Support analyst-extensible override files loaded from config dir and merged with embedded defaults: `string_filters_custom.json` (custom string filter patterns) and `ioc_patterns_custom.json` (organization-specific IOC patterns). Custom entries take precedence over embedded defaults (see product plan: "Analyst-extensible data files")
5. Register in pipeline — strings and IOC extraction run sequentially (IOCs depend on strings), but both run in parallel with Stage 2 analyzers

**Key files:** `internal/analysis/strings.go`, `internal/analysis/ioc.go`, `data/ioc_patterns.json`, `data/string_filters.json`

**Verification:**
- Test string extraction on a binary with known embedded URLs, registry keys
- Test Base64 detection on crafted input containing Base64-encoded C2 URLs
- Test IOC regex against known patterns (IPv4, domain, URL, registry path)
- Unit tests for category classification, ranking, dedup, cap enforcement

---

## Stage 4: Imports, Exports, Rich Header, Capabilities
**Goal:** Full import/export analysis with capability mapping. *Depends on Stage 2 (saferwall/pe).*

1. Embed `data/api_capabilities.json` (Win32 + Nt*/Zw* syscall mappings) via `go:embed`
2. Implement `internal/analysis/imports.go` — parse import table via saferwall/pe, cross-reference against capability map, group suspicious APIs by capability (injection, persistence, evasion, crypto, network). Populate `ImportAnalysis`
3. Complete imphash in `hasher.go` — ordinal-to-name resolution table (embedded), compute imphash from parsed import table
4. Implement `internal/analysis/exports.go` — parse export table for DLLs (function names, ordinals, forwarded exports). Populate `[]Export`
5. Implement `internal/analysis/richheader.go` — parse rich header, map tool IDs to human-readable compiler/linker names. Populate `RichHeader`
6. Implement `internal/models/capabilities.go` — API-to-capability mapping types, derive `[]Capability` from import analysis (capa integration comes in Stage 5)
7. Support analyst-extensible override files (`api_capabilities_custom.json`) loaded from config dir and merged with embedded defaults
8. Register all in pipeline

**Key files:** `internal/analysis/imports.go`, `internal/analysis/exports.go`, `internal/analysis/richheader.go`, `internal/models/capabilities.go`, `internal/analysis/hasher.go`, `data/api_capabilities.json`

**Verification:**
- Test against a DLL with known exports — verify export names and ordinals
- Test import analysis against a sample with `VirtualAllocEx`, `CreateRemoteThread` — verify "process_injection" capability tag
- Test imphash against a sample with known imphash value
- Unit test for ordinal-to-name resolution, capability map lookup

---

## Stage 5: External Tool Integration (FLOSS, capa, YARA)
**Goal:** Detect, version-check, and invoke external tools. *Depends on Stages 3 and 4.*

1. Implement `internal/tools/registry.go` — detect FLOSS, capa, YARA on PATH (or from config), run version flags, check minimum versions (FLOSS v3+, capa v7+, YARA v4+), warn and skip if below minimum
2. Implement `internal/tools/runner.go` — safe subprocess execution with configurable timeout (default 60s), kill on expiry, capture stdout/stderr
3. Implement `internal/analysis/floss.go` — invoke FLOSS, parse output, produce `[]StringHit` with source tags (`floss_static`, `floss_stack`, `floss_tight`). When available, FLOSS output replaces raw string extraction
4. Implement `internal/analysis/capa.go` — invoke capa with `--json`, parse JSON output (check schema version), produce `[]Capability` with ATT&CK technique IDs
5. Implement `internal/analysis/yara.go` — invoke YARA with configured rule directories, parse matches, produce `[]YARAMatch`
6. Update pipeline: run external tool analyzers after core analyzers, handle graceful degradation (missing tool = skip + note in report)
7. Wire tool info into `undertaker config` output (paths + versions)

**Key files:** `internal/tools/registry.go`, `internal/tools/runner.go`, `internal/analysis/floss.go`, `internal/analysis/capa.go`, `internal/analysis/yara.go`

**Verification:**
- Test with FLOSS/capa/YARA installed: verify output is parsed correctly
- Test with tools absent: verify graceful skip, no crash, appropriate warnings in report
- Test timeout: mock a hanging subprocess, verify it's killed after timeout
- Test version check: verify below-minimum version is rejected with warning

---

## Stage 6: Report Generation
**Goal:** Produce the Markdown and JSON reports per the product plan format. *Depends on Stages 1–5.*

1. Implement `internal/reporting/markdown.go` — generate the full Markdown report per the example format in the product plan. Include: Summary section (top 5–10 findings), Identity, Exports, Rich Header, Overlay, Packing Assessment, Suspicious Imports, Strings of Interest, IOCs table, Capabilities, YARA Matches, Analyzer Errors
2. Include quality/confidence indicators: FLOSS unavailability warning, packed+no-FLOSS warning, low string count warning, "capabilities from imports only" note when capa absent
3. Implement report size management: string cap (50), IOC cap (30), YARA detail truncation. `--full` flag overrides all caps
4. Implement `internal/reporting/json.go` — serialize `AnalysisReport` to JSON
5. Wire into CLI: `--json` outputs JSON to stdout; default saves Markdown to `cases/<sha256-prefix>/report.md`; `--quiet` skips TUI (no TUI yet, but saves report silently)
6. Implement case directory creation: `cases/<sha256-prefix>/` with report + raw JSON

**Key files:** `internal/reporting/markdown.go`, `internal/reporting/json.go`, `internal/cli/analyze.go`

**Verification:**
- Generate report for a known sample, diff against expected Markdown structure
- Verify string/IOC caps are enforced (>50 strings → capped to 50 in report)
- Verify `--full` includes all strings/IOCs
- Verify `--json` produces valid, parseable JSON
- Verify case directory is created with correct SHA256-prefix naming

---

## Stage 7: TUI + File Type Routing + .NET + Polish
**Goal:** Add the Bubbletea TUI, extend to non-PE file types, .NET support, final hardening. *Depends on Stage 6.*

1. Add Bubbletea/Bubbles/Lipgloss dependencies
2. Implement `internal/tui/model.go`, `update.go`, `view.go`, `styles.go` — live progress as each analyzer completes, styled panels for results, keybindings (`r` open report, `c` copy to clipboard, `q` quit)
3. Wire TUI into the default `analyze` flow (non-`--json`, non-`--quiet`)
4. Implement `internal/analysis/dotnet.go` — .NET CLR metadata: runtime version, namespaces, classes/methods, resources, assembly references. Populate `DotNetMetadata`
5. Extend `pipeline.go` file type routing per the product plan's file type routing table: apply full pipeline to PE, subset to OLE/LNK/scripts/shellcode/archives. Specifically:
   - **OLE documents** (.doc, .xls, .ppt): hashing, strings, IOCs, YARA + macro/OLE stream detection (product plan notes future stream extraction)
   - **LNK files** (.lnk): hashing, strings, IOCs, YARA + parse target path and command-line arguments (common delivery vector)
   - **HTA / scripts** (.ps1, .vbs, .js, .bat, .hta): hashing, strings, IOCs, YARA (no import/section analysis)
   - **Shellcode / raw blobs**: hashing, entropy, strings, IOCs, YARA (no structural analysis)
   - **MSI / ISO / IMG**: hashing, file ID, strings, IOCs, YARA
   - **Archives** (.zip, .rar, .7z): hashing, file ID only (detect but do not auto-extract)
6. File size limit enforcement: skip memory-intensive analyzers for files > configured `max_file_size`, use streaming reads for hashing
7. Final pass: ensure all `AnalyzerError` entries are surfaced, all graceful degradation paths work, all warnings appear in reports
8. End-to-end testing with diverse sample types (PE32, PE64, DLL, .NET, packed, clean, malformed, script, LNK, OLE document, shellcode)

**Key files:** `internal/tui/model.go`, `internal/tui/update.go`, `internal/tui/view.go`, `internal/tui/styles.go`, `internal/analysis/dotnet.go`, `internal/analysis/pipeline.go`

**Verification:**
- TUI launches, shows live progress, all keybindings work
- .NET sample produces CLR metadata in report
- Script file (.ps1) produces hashing + strings + IOCs only (no PE-specific analysis)
- Malformed PE: partial results + error entries, no crash
- File > 500MB: heavy analyzers skipped, hashing still works
- Full end-to-end: `undertaker analyze sample.dll` produces correct, complete report

---

## Decisions
- Each stage produces a buildable, testable binary — no stage leaves the project in a broken state
- Stage 3 (strings/IOCs) can run in parallel with Stage 2 (PE parsing) during development since they're independent
- Similarly Stage 4 (imports/exports) can start once saferwall/pe is integrated in Stage 2
- imphash is split: stub in Stage 1, completed in Stage 4 when imports are available
- TUI is last because the tool is fully functional via `--json`/`--quiet` before it

## Scope
- **Included:** Everything in the product plan's MVP — refer to `PRODUCT_PLAN_V2.md` for the complete specification
- **Excluded:** Dynamic analysis, sandbox execution, case management, Claude integration, auto-extraction of archives

## Cross-reference checklist
Before marking a stage complete, verify against the product plan:
- [ ] All analyzers listed in the product plan's analyzer table that belong to this stage are implemented
- [ ] Data model structs match the product plan's data model (fields, types, comments)
- [ ] Analyst-extensible override files are supported where the product plan specifies them
- [ ] Graceful degradation and error handling match the product plan's resilience requirements
- [ ] Security boundaries (no execution, no shell interpolation, safe naming, timeouts, file size limits) are respected
