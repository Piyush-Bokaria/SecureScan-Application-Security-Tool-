# 🛡️ SecureScan — Application Security Tool

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-brightgreen.svg)](https://github.com/Piyush-Bokaria/SecureScan-Application-Security-Tool-/actions)

A **lightweight Python-based security scanning tool** that automates Static Application Security Testing (SAST) using [Bandit](https://bandit.readthedocs.io/), maps findings to [OWASP Top 10:2021](https://owasp.org/www-project-top-ten/) vulnerability categories, and generates structured remediation reports — all integrated into your CI/CD pipeline via GitHub Actions.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Automated SAST** | Scans Python codebases for security vulnerabilities using Bandit |
| 🏛️ **OWASP Top 10 Mapping** | Maps every finding (via CWE) to its OWASP Top 10:2021 category |
| 💡 **Remediation Guidance** | Provides actionable fix suggestions for each vulnerability |
| 📊 **Multi-Format Reports** | Console (colorized), JSON (machine-readable), and HTML (shareable) |
| 🔄 **GitHub Actions CI/CD** | Automatically scans PRs, posts comments, and gates merges on severity |
| ⚡ **Configurable Thresholds** | Filter by severity (LOW/MEDIUM/HIGH) and confidence levels |
| 🚨 **CI Gate** | Fail builds when HIGH severity issues are detected |

---

## 📦 Installation

### From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/Piyush-Bokaria/SecureScan-Application-Security-Tool-.git
cd SecureScan-Application-Security-Tool-

# Install dependencies
pip install -r requirements.txt

# (Optional) Install as a CLI tool
pip install -e .
```

### Requirements

- Python 3.9+
- pip

---

## 🚀 Usage

### CLI — Quick Start

```bash
# Scan a directory (console output)
python -m securescanner ./your_project

# Scan with JSON report
python -m securescanner ./your_project --format json --output report.json

# Scan with HTML report
python -m securescanner ./your_project --format html --output report.html

# Filter by severity (only MEDIUM and above)
python -m securescanner ./your_project --severity MEDIUM

# Fail on HIGH severity (for CI/CD gating)
python -m securescanner ./your_project --fail-on-high
```

### CLI — Full Options

```
usage: securescanner [-h] [--format {console,json,html}] [--output FILE]
                     [--severity {LOW,MEDIUM,HIGH}]
                     [--confidence {LOW,MEDIUM,HIGH}]
                     [--fail-on-high] [--version]
                     target

🛡️ SecureScan — SAST Security Scanner with OWASP Top 10 Mapping

positional arguments:
  target                Path to the Python file or directory to scan

optional arguments:
  -h, --help            Show this help message
  --format FORMAT       Output format: console (default), json, html
  --output, -o FILE     Write report to a file
  --severity LEVEL      Minimum severity threshold (default: LOW)
  --confidence LEVEL    Minimum confidence threshold (default: LOW)
  --fail-on-high        Exit with code 1 if any HIGH severity issues are found
  --version             Show version
```

### Programmatic Usage

```python
from securescanner.scanner import SecurityScanner
from securescanner.owasp_mapper import OWASPMapper
from securescanner.report_generator import ReportGenerator

# 1. Scan
scanner = SecurityScanner(severity_threshold="MEDIUM")
result = scanner.scan("./your_project")

# 2. Map to OWASP
mapper = OWASPMapper()
mapper.enrich_findings(result.findings)
owasp_summary = mapper.get_owasp_summary(result.findings)

# 3. Generate Reports
reporter = ReportGenerator(result, owasp_summary)
reporter.generate_console()                        # Print to terminal
reporter.generate_json("report.json")              # JSON file
reporter.generate_html("report.html")              # HTML file
```

---

## 🏛️ OWASP Top 10:2021 Mapping

SecureScan maps each Bandit finding to an OWASP Top 10:2021 category using the CWE (Common Weakness Enumeration) identifier:

| OWASP ID | Category | Example CWEs Detected |
|----------|----------|-----------------------|
| A01:2021 | Broken Access Control | CWE-22 (Path Traversal), CWE-276 (Permissions), CWE-377 (Temp Files) |
| A02:2021 | Cryptographic Failures | CWE-327 (Weak Crypto), CWE-328 (Weak Hash), CWE-330 (Weak Random) |
| A03:2021 | Injection | CWE-78 (OS Command), CWE-89 (SQL), CWE-94 (Code Eval) |
| A04:2021 | Insecure Design | CWE-200 (Debug Mode) |
| A05:2021 | Security Misconfiguration | CWE-703 (Assert), CWE-609 (Wildcard Binding) |
| A06:2021 | Vulnerable Components | *(via pip-audit integration)* |
| A07:2021 | Authentication Failures | CWE-259 (Hardcoded Password), CWE-506 (Hardcoded Credentials) |
| A08:2021 | Data Integrity Failures | CWE-502 (Insecure Deserialization) |
| A09:2021 | Logging Failures | CWE-116 (Log Injection) |
| A10:2021 | SSRF | CWE-310 (URL Validation) |

---

## 📊 Report Formats

### Console Output
Colorized terminal output with severity indicators, OWASP breakdown table, and detailed finding cards with remediation advice.

### JSON Report
Machine-readable structured report for integration with other tools:
```json
{
  "report": { "tool": "SecureScan", "version": "1.0.0" },
  "scan": {
    "metadata": { "target": "...", "timestamp": "..." },
    "summary": { "total_findings": 12, "severity_counts": {"HIGH": 3, "MEDIUM": 5, "LOW": 4} },
    "findings": [ { "test_id": "B602", "owasp_id": "A03:2021", "remediation": "..." } ]
  },
  "owasp_summary": { "A03:2021": { "name": "Injection", "count": 5 } }
}
```

### HTML Report
Professional, self-contained HTML report with:
- Executive summary with severity distribution
- OWASP Top 10 breakdown table
- Collapsible finding cards with code snippets and remediation
- Dark theme with modern styling

---

## 🔄 GitHub Actions CI/CD Integration

SecureScan ships with a ready-to-use GitHub Actions workflow (`.github/workflows/security-scan.yml`) that:

1. **Triggers** on pull requests and pushes to `main`/`develop`
2. **Scans** the entire codebase with SecureScan
3. **Uploads** JSON and HTML reports as workflow artifacts
4. **Comments** on PRs with a summary of findings, severity counts, and OWASP categories
5. **Fails** the workflow if HIGH severity issues are detected

### Setup

The workflow is already included — just push to GitHub and it activates automatically. No additional configuration needed.

### Customization

Edit `.github/workflows/security-scan.yml` to:
- Change severity thresholds
- Scan specific directories
- Adjust failure conditions
- Add additional notification channels

---

## 🧪 Testing

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=securescanner --cov-report=term-missing

# Run specific test module
pytest tests/test_scanner.py -v
pytest tests/test_owasp_mapper.py -v
pytest tests/test_report_generator.py -v
```

### Sample Vulnerable Code

The `tests/sample_vulnerable/vulnerable_app.py` file contains intentionally vulnerable Python code covering multiple OWASP categories — use it to see SecureScan in action:

```bash
python -m securescanner tests/sample_vulnerable/
```

---

## 📁 Project Structure

```
SecureScan-Application-Security-Tool-/
├── securescanner/                  # Main Python package
│   ├── __init__.py                # Package metadata
│   ├── __main__.py                # python -m entry point
│   ├── cli.py                     # CLI (argparse)
│   ├── scanner.py                 # Bandit scanning engine
│   ├── owasp_mapper.py            # CWE → OWASP mapper
│   ├── report_generator.py        # Report generation (console/JSON/HTML)
│   └── mappings/
│       └── cwe_to_owasp.json      # Static CWE-to-OWASP mapping
├── templates/
│   └── report.html                # Jinja2 HTML report template
├── tests/                         # Test suite
│   ├── test_scanner.py
│   ├── test_owasp_mapper.py
│   ├── test_report_generator.py
│   └── sample_vulnerable/
│       └── vulnerable_app.py      # Intentionally vulnerable code
├── .github/workflows/
│   └── security-scan.yml          # GitHub Actions CI/CD workflow
├── requirements.txt               # Runtime dependencies
├── requirements-dev.txt           # Dev dependencies
├── pyproject.toml                 # Project metadata & config
├── .bandit.yml                    # Bandit configuration
└── README.md                     # This file
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`pytest tests/ -v`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

- [Bandit](https://bandit.readthedocs.io/) — Python SAST tool by PyCQA
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — Web application security risks
- [Rich](https://rich.readthedocs.io/) — Beautiful terminal formatting
- [Jinja2](https://jinja.palletsprojects.com/) — Template engine for HTML reports