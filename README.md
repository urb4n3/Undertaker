# Undertaker CLI Tool

**Undertaker** is a Python-based command-line utility for threat hunting and reporting. It supports two primary modes:

1. **Malware Analysis** (static):
   - Extracts strings, hashes, indicators of compromise (IoCs), risky imports, and more from PE files.
   - Optional flags:
     - `--yara` / `-y`: Generate a YARA ruleset for deployment in EDR or SIEM.
     - `--pdf` / `-p`: Produce a polished PDF report for easy SITREP logging.

2. **Link Analysis** (streaming):
   - Fetches and scans HTML content to flag phishing or suspicious patterns.
   - Also supports `--pdf` for an HTML-powered PDF.

---

## \U0001F4E6 Installation

1. **Clone the repo**
   ```bash
   git clone https://github.com/your-org/undertaker.git
   cd undertaker
   ```

2. **Create a virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure API keys**
   - Copy `config/api_keys.json.example` → `config/api_keys.json`
   - Fill in keys for VirusTotal, Shodan, AbuseIPDB, etc.

---

## \U0001F680 Usage

```bash
# Basic malware scan + PDF report + YARA
python main.py scan /path/to/sample.exe --yara --pdf

# Link scan + PDF report
python main.py scan https://phishy.example.com --pdf

# Show help
python main.py --help
```

### Options

- `scan <target>`: Analyze a file or URL.
- `--yara` / `-y`: Generate YARA rule (malware mode only).
- `--pdf` / `-p`: Create PDF report.
- `--save-raw`: Save raw JSON output to `reports/`.
- `--output <file>`: Specify custom output path.

---

## \U0001F4C1 Project Structure

```text
undertaker/
├── main.py              # CLI entry point (Click)
├── scanner/
│   ├── __init__.py
│   ├── malware_analyzer.py  # Static file analysis
│   ├── link_analyzer.py     # HTML streaming / phishing
│   └── yara_generator.py    # YARA rule builder
├── reporter/
│   ├── __init__.py
│   ├── pdf_report.py        # Jinja2 + WeasyPrint PDF
│   └── summary_builder.py   # Text summary logic
├── templates/
│   └── report.html          # Jinja2 HTML template
├── config/
│   └── api_keys.json        # API credentials (not checked in)
├── reports/                 # Output directory (PDF, YARA, JSON)
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

---

## \U0001F6E0 Development

- **Add analysis logic**:
  - Use [`pefile`](https://github.com/erocarrera/pefile) and [`lief`](https://github.com/lief-project/LIEF) in `malware_analyzer.py`.
  - Implement phishing heuristics in `link_analyzer.py`.
  - Craft YARA rules dynamically in `yara_generator.py`.
  - Flesh out Jinja2 template and PDF styling in `templates/report.html`.

- **Testing**:
  - Write unit tests for each analyzer module.
  - Use sample malware files and test URLs.

- **Iteration**:
  - Add additional flags or report formats (Markdown, HTML).
  - Integrate more CTI sources (AbuseIPDB, URLScan, etc.).

---

## \U0001F91D Contributing

1. Fork this repository.
2. Create a feature branch: `git checkout -b feature/awesome`
3. Commit your changes: `git commit -m "feat: add new analyzer"`
4. Push branch: `git push origin feature/awesome`
5. Open a Pull Request.

Please follow the code style, add tests, and update this README as needed.

---

## \u2696\uFE0F License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for details.
