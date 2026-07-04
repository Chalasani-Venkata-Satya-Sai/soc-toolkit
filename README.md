# 🛡️ SOC Toolkit

**An all-in-one Python automation toolkit for SOC / security analysts.**
IOC enrichment, phishing triage, and YARA-based malware scanning — as a CLI *and* a web dashboard, with JSON/HTML reporting out of the box.

[![CI](https://github.com/YOUR_USERNAME/soc-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/soc-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-production--ready-brightgreen)

---

## Why this exists

SOC analysts lose hours a day to the same repetitive grind: pasting an IP into five browser tabs, manually reading email headers for spoofing, or eyeballing a suspicious file. **SOC Toolkit** automates that Tier-1 grind into three composable modules that mirror what real SOAR platforms (Shuffle, Cortex/TheHive) and CLI tools (Sooty, IntelOwl) do — but as a single, self-hostable, hackable Python project you fully own.

## ✨ Features

| Module | What it does |
|---|---|
| 🔍 **IOC Enrichment** | Classifies an indicator (IP / domain / URL / hash) and queries **VirusTotal**, **AbuseIPDB**, and **Shodan** in parallel, then rolls the results up into a single risk score + verdict |
| 📧 **Phishing Triage** | Parses raw `.eml` files: detects `From` / `Return-Path` / `Reply-To` spoofing, flags urgency-based social engineering language, extracts URLs/IPs/domains, hashes attachments, and flags risky attachment types |
| 🧬 **YARA Scanning** | Scans a single file or an entire directory tree against a bundled (or your own) YARA rule set — the same workflow used for live endpoint triage |
| 📄 **Reporting** | Every module can emit a machine-readable JSON report (for SIEM/ticket ingestion) or a styled, shareable HTML report |
| 🖥️ **Two interfaces** | A scriptable `click`-based CLI for pipelines/cron/SOAR playbooks, and a Streamlit dashboard for point-and-click analyst use |
| 🧠 **Resilient by design** | Missing an API key? That source is skipped, not a crash. Hit a rate limit? Logged and moved on. Every successful lookup is disk-cached to protect free-tier quotas |

## 🏗️ Architecture

```
soc_toolkit/
├── cli.py                 # click CLI — enrich / phishing / yara-scan / dashboard
├── config.py               # .env-driven settings, single source of truth for API keys
├── core/
│   ├── enrichment.py        # VirusTotal / AbuseIPDB / Shodan lookups + verdict scoring
│   ├── phishing.py          # .eml parsing, spoofing heuristics, IOC extraction
│   ├── yara_scan.py         # YARA rule compilation + file/dir scanning
│   └── report.py            # JSON + Jinja2 HTML report generation
├── utils/
│   ├── validators.py        # IOC type detection (ip/domain/url/hash/email)
│   ├── cache.py              # TTL disk cache to protect API rate limits
│   └── logger.py             # rich-based console logging
├── dashboard/app.py         # Streamlit UI wrapping the same core modules as the CLI
├── rules/sample_rules.yar   # starter YARA detection rules
└── templates/report.html    # shared HTML report template
```

The CLI and dashboard are both thin wrappers around `soc_toolkit/core/*` — there is exactly one implementation of each detection, so behavior never drifts between the two interfaces.

## 🚀 Quick start

### 1. Install

```bash
git clone https://github.com/YOUR_USERNAME/soc-toolkit.git
cd soc-toolkit
python -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
pip install -e .
```

### 2. Configure API keys (optional but recommended)

```bash
cp .env.example .env
```

Then fill in whichever keys you have — all are free-tier:

- VirusTotal: https://www.virustotal.com/gui/my-apikey
- AbuseIPDB: https://www.abuseipdb.com/account/api
- Shodan: https://account.shodan.io/

> You don't need every key. Any source without a key is automatically skipped rather than erroring out — the toolkit degrades gracefully.

### 3. Use it

```bash
# Enrich indicators
soc-toolkit enrich 8.8.8.8 example.com 44d88612fea8a8f36de82e1278abb02f

# Triage a phishing submission (try the bundled sample!)
soc-toolkit phishing sample_data/sample_phishing.eml --enrich-iocs

# Scan a file or directory with YARA
soc-toolkit yara-scan ./suspicious_folder

# Launch the dashboard
soc-toolkit dashboard
# -> http://localhost:8501
```

Every command supports `--format json|html` (or `table`/`summary`) so it slots straight into a SOAR playbook, a cron job, or a ticket attachment.

### 4. Or run it with Docker

```bash
docker compose up --build
# Dashboard: http://localhost:8501

# One-off CLI usage:
docker compose run soc-toolkit-cli enrich 8.8.8.8
```

## 🧪 Usage examples

```bash
# Bulk enrich a list of IOCs from a file, save both JSON + HTML reports
cat sample_data/sample_iocs.txt | xargs soc-toolkit enrich --save

# JSON output for piping into another tool / SIEM webhook
soc-toolkit enrich 1.2.3.4 --format json | jq .

# Full phishing triage with automatic IOC enrichment, HTML report
soc-toolkit phishing incoming.eml --enrich-iocs --format html

# Scan an entire downloads folder for malware indicators
soc-toolkit yara-scan ~/Downloads --rules soc_toolkit/rules/sample_rules.yar
```

## 🖥️ Dashboard

The Streamlit dashboard (`soc-toolkit dashboard`) exposes the same three modules with drag-and-drop file uploads for `.eml` files and files to scan, live API-key status in the sidebar, and one-click HTML report export — no terminal required for day-to-day triage.

## 🔧 Extending it

- **Add a new enrichment source** — add a `check_<source>()` function in `core/enrichment.py` following the existing pattern (return a dict with `source`/`status`, cache on success), then include it in `enrich_ioc()`.
- **Add your organization's YARA rules** — drop `.yar`/`.yara` files into `soc_toolkit/rules/` (or point `--rules` at any external directory).
- **Wire it into a SOAR playbook** — every command supports `--format json`, making it trivial to call from Shuffle, TheHive/Cortex responders, or a webhook-triggered Lambda.

## 🧵 Testing

```bash
pip install -e ".[dev]"
pytest -v
```

Tests cover IOC type detection, phishing header-spoofing heuristics against a bundled synthetic sample, and enrichment logic (with API calls mocked — no real keys needed to run the suite).

## ⚠️ Responsible use

This project is intended for **authorized security operations** — enriching indicators you've already observed, triaging phishing reports submitted to your own mailbox, and scanning systems/files you are authorized to inspect. The bundled YARA rules are illustrative starter patterns, not a substitute for a curated, actively maintained detection rule set.

## 📄 License

MIT — see [LICENSE](LICENSE).

## 🤝 Contributing

Issues and PRs welcome. If you add a new enrichment source or detection module, please include tests (mock any external API calls, as done in `tests/test_enrichment.py`).
