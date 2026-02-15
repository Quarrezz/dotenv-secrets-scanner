<p align="center">
  <img src="https://img.shields.io/pypi/v/dotenv-secrets-scanner?style=flat-square" alt="PyPI Version">
  <img src="https://img.shields.io/github/actions/workflow/status/Quarrezz/dotenv-secrets-scanner/ci.yml?style=flat-square" alt="CI Status">
  <img src="https://img.shields.io/github/license/Quarrezz/dotenv-secrets-scanner?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue?style=flat-square" alt="Python Version">
</p>

<p align="center">
  <h1 align="center">🔐 Dotenv Secrets Scanner</h1>
    <strong>Lightweight, DevSecOps-friendly secret scanner with SARIF support. Detects accidentally committed secrets before they reach production.</strong>
  </p>
  <p align="center">
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#what-does-it-find">What Does It Find?</a> •
    <a href="#how-it-works">How It Works</a> •
    <a href="#configuration">Configuration</a>
  </p>
</p>

---

## 🎯 Problem

Developers accidentally commit API keys, database passwords, and tokens to source code. This leads to **data leaks**, **financial losses**, and **security breaches**.

> ⚠️ **Over 6 million secrets were exposed on public GitHub repositories in 2023.**

**Dotenv Secrets Scanner** solves this problem: it scans your code, detects secrets, and warns you — before you commit.

## ⚡ Quick Start

```bash
pip install dotenv-secrets-scanner
```

## 🔍 Why Not Other Tools?

| Feature | This Tool | Gitleaks | TruffleHog |
|---------|:---------:|:--------:|:----------:|
| **Regional payment providers support** | ✅ | ❌ | ❌ |
| **Entropy + Regex** | ✅ | ✅ | ✅ |
| **Baseline support** | ✅ | Limited | ❌ |

> Includes pattern support for region-specific services (e.g., Iyzico, PayTR) in addition to global ones.


## ✨ What Does It Do?

![Secrets Scanner Demo](https://raw.githubusercontent.com/Quarrezz/dotenv-secrets-scanner/main/docs/demo.gif)

```
$ secrets-scan scan .


  🔍 Scanning: ./config/production.py

  🚨 CRITICAL  AWS Access Key
     Line 12: AWS_KEY = "AKIA████████████████"
     Confidence: 95%

  ⚠️  HIGH  GitHub Personal Access Token
     Line 28: TOKEN = "ghp_████████████████████████████████████"
     Confidence: 90%

  📊 Scan Results
  ┌────────────────┬───────┐
  │ Files scanned  │    47 │
  │ Total findings │     3 │
  │   CRITICAL     │     1 │
  │   HIGH         │     2 │
  └────────────────┴───────┘

  🚨 Action required: Critical secrets must be rotated!
```

---

## 📦 Installation

```bash
# Install from PyPI
pip install dotenv-secrets-scanner

# or from source
git clone https://github.com/Quarrezz/dotenv-secrets-scanner.git
cd dotenv-secrets-scanner
pip install -e .
```

### 🐳 Docker

Run the scanner without installing Python:

```bash
# Pull the image
docker pull ghcr.io/Quarrezz/dotenv-secrets-scanner:latest

# Run scan on current directory
docker run --rm -v $(pwd):/app ghcr.io/Quarrezz/dotenv-secrets-scanner scan .
```

### Basic Scan

```bash
# Scan the current directory
secrets-scan scan .

# Scan a specific file
secrets-scan scan config/settings.py

# Scan a specific folder
secrets-scan scan src/
```

### Output Formats

```bash
# Colored output in Terminal (default)
secrets-scan scan .

# JSON format (for CI/CD integration)
secrets-scan scan . --output json

# Plain text
secrets-scan scan . --output text

# HTML report
secrets-scan scan . --output html

# SARIF format (for GitHub Code Scanning)
secrets-scan scan . --output sarif > results.sarif


# Save results to a file
secrets-scan scan . --output json --output-file report.json
```

### Filtering by Severity

```bash
# Show only critical findings
secrets-scan scan . --severity CRITICAL

# High and critical
secrets-scan scan . --severity HIGH

# Break CI if HIGH or above is found
secrets-scan scan . --fail-on-severity HIGH
```

### Performance and Output Control

```bash
# Show fewer context lines
secrets-scan scan . --context-lines 1

# Speed up scanning on multi-core machines
secrets-scan scan . --workers 8
```

### Suppressing Old Findings with Baseline

In real projects, there might be secrets committed in the past that you can't clean up immediately.
With Baseline, you can save the findings from the first scan and focus only on **new** secrets thereafter.

```bash
# Write current findings to baseline file in the first scan
secrets-scan scan . --write-baseline baseline.json

# Show only findings not in baseline (new) in subsequent scans
secrets-scan scan . --baseline baseline.json

# In CI: break job only if there are new and HIGH/CRITICAL findings
secrets-scan scan . --baseline baseline.json --fail-on-severity HIGH
```

### Git Integration

```bash
# Install pre-commit hook (automatic scan before every commit)
secrets-scan install-hook

# Uninstall hook
secrets-scan uninstall-hook

# Create .secretsignore file
secrets-scan init
```

---

## 🔍 What Does It Find?

### 🔴 Critical (CRITICAL)
| Type | Example Format |
|-----|-------------|
| AWS Access Key | 20-character key starting with `AKIA` |
| AWS Secret Key | `aws_secret_access_key = "..."` |
| GitHub Token | Tokens starting with `ghp_`, `gho_`, `ghs_` |
| Stripe Secret Key | Key starting with `sk_live_` |
| SSH Private Key | `-----BEGIN RSA PRIVATE KEY-----` format |
| PostgreSQL/MySQL URL | `postgres://user:pass@host` format |
| Iyzico API Key | Iyzico/iyzipay payment keys |
| PayTR Merchant Key | PayTR payment keys |

### 🟠 High (HIGH)
| Type | Example Format |
|-----|-------------|
| OpenAI API Key | Key starting with `sk-` |
| Google API Key | Key starting with `AIza` |
| Slack Bot Token | Token starting with `xoxb-` |
| Slack Webhook | `https://hooks.slack.com/...` |
| JWT Token | Token in `eyJ...` format |
| SendGrid API Key | Key starting with `SG.` |
| NPM / PyPI Token | Tokens starting with `npm_`, `pypi-` |

### 🟡 Medium (MEDIUM)
| Type | Example Format |
|-----|-------------|
| Azure Storage Key | `AccountKey = "..."` |
| Generic API Key | `api_key = "..."`, `api_secret = "..."` |
| Generic Password | `password = "..."`, `passwd = "..."` |
| Docker Auth | Docker registry tokens |

### 🔵 Low (LOW)
| Type | Example Format |
|-----|-------------|
| .env Secret | In `SECRET_KEY=value` format |
| High Entropy Hex | Long hex strings (potentially secret) |

> 📌 **Total 30+ different secret types** are detected. Includes regional provider support (e.g., Iyzico, PayTR, Türk Telekom Cloud, e-Devlet) in addition to global services.

---

## 🧠 How It Works

Scanner uses a 3-layer detection system:

```
  Source Code
      │
      ▼
┌─────────────────┐
│  1. Regex Match   │  ← Searches for known secret formats with 30+ patterns
└────────┬────────┘
         │ match found
         ▼
┌─────────────────┐
│ 2. Entropy Analysis│  ← Checks randomness with Shannon entropy
└────────┬────────┘    (low entropy = not password, high = likely password)
         │
         ▼
┌─────────────────┐
│ 3. FP Filtering   │  ← Filters out placeholders, templates, and
└────────┬────────┘    example values
         │
         ▼
    ✅ True Finding
    (With Confidence score)
```

**Thanks to this 3-layer system:**
- ❌ `API_KEY = "YOUR_API_KEY_HERE"` → Placeholder, **skipped**
- ❌ `API_KEY = "changeme"` → Known test value, **skipped**
- ❌ `API_KEY = "${ENV_VAR}"` → Template syntax, **skipped**
- ❌ `# API_KEY = "sk_live_..."` → Comment line, **low confidence score**
- ✅ `API_KEY = "sk_live_4eC39Hq████████████"` → **Real secret found!**

---

## ⚙️ Configuration

### `.secretsignore` File

Create a `.secretsignore` file in the project root to exclude specific files or directories from scanning:

```bash
# Create automatically
python -m scanner init
```

```gitignore
# .secretsignore example

# Skip test files
tests/
test_*.py
test_*.py

# Skip specific files
config/example.env
docs/api-guide.md

# Skip folders
fixtures/
examples/
```

### YAML Configuration

You can make detailed configuration by creating `.secretscan.yml` in the project root:

```yaml
# .secretscan.yml
excluded_dirs:
  - node_modules
  - .git
  - vendor
  - dist

excluded_extensions:
  - .png
  - .jpg
  - .lock

min_severity: MEDIUM
scan_hidden: false
follow_symlinks: false
max_file_size: 1048576  # 1 MB
```

---

## 📚 Listing All Patterns

To see which secret types the Scanner detects, you can list patterns via CLI:

```bash
# List all patterns
secrets-scan patterns

# List only HIGH and CRITICAL patterns
secrets-scan patterns --severity HIGH
```

This command shows pattern ID, name, severity level, and short description in a table.

---

## 🔗 Pre-commit Integration

### Direct Installation (Recommended)

```bash
secrets-scan install-hook
```

This command automatically adds the scanner hook to `.git/hooks/pre-commit`. Automatic scan is performed before every `git commit`.

### With pre-commit Framework

First, install `pre-commit`:

```bash
pip install pre-commit
pre-commit install
```

Then add this to your `.pre-commit-config.yaml` file:

```yaml
repos:
  - repo: https://github.com/Quarrezz/dotenv-secrets-scanner
    rev: v1.0.0
    hooks:
      - id: dotenv-secrets-scan
```

---

## 📊 CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/secrets-check.yml
name: Secrets Check
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install dotenv-secrets-scanner
      - run: secrets-scan scan . --severity HIGH --output json
```

### GitHub Code Scanning (SARIF)

You can upload the results to GitHub Security tab:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  sarif-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install dotenv-secrets-scanner
      - run: secrets-scan scan . --output sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: dotenv-secrets-scanner
```

---

## 🏗️ Project Structure

```
src/scanner/
├── __init__.py       # Package initialization
├── __main__.py       # python -m scanner support
├── models.py         # Data models (Finding, ScanResult, ScanConfig)
├── patterns.py       # 30+ regex pattern definitions
├── entropy.py        # Shannon entropy analysis
├── validators.py     # False positive filtering
├── core.py           # Main scanning engine
├── reports.py        # Report generators (JSON, Text, HTML)
├── cli/
│   └── main.py       # CLI commands (Click)
├── hooks/
│   └── pre_commit.py # Git pre-commit hook
└── utils/
    ├── config.py     # Configuration management
    └── git.py        # Git integration
```

## 🏗️ Architecture

- **core.py** → Scanning engine (orchestration, threading)
- **patterns.py** → Secret regex patterns (30+ types)
- **entropy.py** → Shannon entropy-based detection
- **reports.py** → Output formatting (JSON, HTML, Console)
- **baseline.json** → False positive suppression database

---

##  License

MIT License — See [LICENSE](LICENSE) file for details.

---

<p align="center">
  <sub>🇹🇷 By Turkish developers, for all developers.</sub>
</p>
