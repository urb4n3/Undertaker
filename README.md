![Undertaker](https://github.com/user-attachments/assets/699f7243-1bd8-46b7-aa68-b7fb6ca25f14)

Undertaker is a static malware analysis tool that triages a sample and produces a structured report.

Point it at a binary. Get hashes, packing detection, suspicious imports, IOCs, strings of interest, capability tags, and YARA matches — in one command:

```
undertaker analyze sample.dll
```

## Dependencies

### Go modules (managed via `go.mod`)

| Package | Purpose |
|---|---|
| `github.com/saferwall/pe` | PE file parsing |
| `github.com/glaslos/ssdeep` | Fuzzy hashing (ssdeep) |
| `github.com/charmbracelet/bubbletea` | TUI framework |
| `github.com/charmbracelet/bubbles` | TUI components |
| `github.com/charmbracelet/lipgloss` | TUI styling |
| `github.com/spf13/cobra` | CLI framework |
| `gopkg.in/yaml.v3` | YAML config parsing |
| `github.com/atotto/clipboard` | Clipboard support |

### External tools (optional, enhance analysis)

| Tool | Min version | Purpose |
|---|---|---|
| [FLOSS](https://github.com/mandiant/flare-floss) | 3.x | Deobfuscated string extraction |
| [capa](https://github.com/mandiant/capa) | 7.x | Capability detection |
| [YARA](https://github.com/VirusTotal/yara) | 4.x | YARA rule matching |

External tools are auto-discovered from `$PATH` or can be configured explicitly (see `~/.config/undertaker/config.yaml`).



## Build from source

```bash
git clone https://github.com/urb4n3/undertaker.git
cd undertaker
go build -o undertaker ./cmd/undertaker
```