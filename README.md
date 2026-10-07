<div align="center">

![Synchunt Banner](https://img.shields.io/badge/SyncHunt-Advanced%20Recon%20Framework-ff6b6b?style=for-the-badge&logoColor=white)

# ⚔️ SyncHunt v2026 — Advanced Automated Bug Hunting Reconnaissance Framework

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status Active](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=for-the-badge)](https://github.com/ziroai/synchunt)
[![Platform Linux/macOS](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-black?style=for-the-badge&logo=linux)](https://github.com/ziroai/synchunt)

**Next-generation automated reconnaissance framework for bug bounty hunters, penetration testers, and security researchers**

> Combines subdomain discovery, API mapping, GitHub intelligence, cloud exposure checks, and vulnerability scanning into a single unified automated workflow.

[![GitHub Stars](https://img.shields.io/github/stars/ziroai/synchunt?style=social)](https://github.com/ziroai/synchunt)
[![GitHub Forks](https://img.shields.io/github/forks/ziroai/synchunt?style=social)](https://github.com/ziroai/synchunt)

[🎯 Features](#-features) • [⚡ Quick Start](#-quick-start) • [📖 Documentation](#-documentation) • [🛠️ Usage](#-usage) • [🔧 Configuration](#-configuration) • [📊 Architecture](#-architecture)

---

</div>

## 🎯 Features

### **Core Reconnaissance**

<div align="center">

| Feature | Tools | Coverage |
|---------|-------|----------|
| **🔍 Subdomain Enumeration** | Subfinder, Amass, Assetfinder, Findomain, crt.sh, Sublist3r, PureDNS | 8+ sources |
| **✅ Subdomain Validation** | httpx, dnsx, massdns | DNS + HTTP verification |
| **🌐 Content Discovery** | Katana, GoSpider, Hakrawler, waybackurls, gau, ParamSpider, dirsearch, feroxbuster, FFUF | 9+ crawlers |
| **🔓 Port Scanning** | Naabu, Nmap, Masscan | Fast + detailed scans |
| **🧩 Web Fingerprinting** | WhatWeb, wafw00f, webanalyze | Tech stack detection |

</div>

### **Advanced Intelligence**

<div align="center">

| Feature | Capability | Status |
|---------|-----------|--------|
| **🔌 API Discovery** | GraphQL, OpenAPI, Swagger detection | ✅ Advanced |
| **🐙 GitHub Recon** | Repos, issues, exposed secrets, commits | ✅ Advanced |
| **☁️ Cloud Enumeration** | S3, Azure Blob, GCP buckets | ✅ Advanced |
| **📄 JS Analysis** | Endpoint extraction, secret scanning, source maps | ✅ Advanced |
| **🔑 Sensitive Info** | Credentials, API keys, tokens, misconfigs | ✅ Advanced |
| **🎯 Finding Prioritization** | ML-based scoring, severity ranking, deduplication | ✅ Advanced |

</div>

### **Post-Processing & Reporting**

- 📊 **SQLite Correlation** - Result deduplication and relationship mapping
- 📈 **HTML Reports** - Interactive, professional findings summaries
- 📋 **CSV/JSON Exports** - Downstream analysis and integration
- 🎨 **Screenshot Capture** - Visual verification with Gowitness/Aquatone
- 🔔 **Notifications** - Slack, Discord, Telegram integration

---

## ⚡ Quick Start

### Prerequisites
- **Python 3.8+**
- **Linux/macOS** (WSL2 supported)
- **Optional**: External tools for extended scanning (Amass, Nmap, Nuclei)

### Installation

```bash
# Clone the repository
git clone https://github.com/ziroai/synchunt.git
cd synchunt

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
python3 main.py --check-deps
```

### First Scan (30 seconds)

```bash
# Quick recon on a single target
python3 main.py -d example.com --profile quick

# View results
open output/example.com/*/reports/findings.html
```

---

## 📖 Documentation

### 🚀 Usage Examples

#### **Full Recon Pipeline**
```bash
python3 main.py -d target.com --full
```
Runs all 15 phases: subdomain enum → validation → enrichment → portscan → fingerprint → github → content → api → js → cloud → vulnscan → sensitive → screenshot → prioritize → report

#### **Balanced Profile (Recommended)**
```bash
python3 main.py -d target.com --profile balanced
```
Optimized for most targets: fast but comprehensive (10 phases, ~5-15 min)

#### **Deep Recon**
```bash
python3 main.py -d target.com --profile deep
```
Aggressive scanning: all phases + extended timeout (full 15 phases)

#### **Quick Scan**
```bash
python3 main.py -d target.com --profile quick
```
Fast reconnaissance: subdomain → validation → enrichment → content → report (~2-3 min)

#### **Specific Phases Only**
```bash
python3 main.py -d target.com --phase subdomain,validation,github_recon,api_discovery
```
Run only selected phases

#### **Multiple Targets**
```bash
python3 main.py -l targets.txt --full --verbose
```
Scan a file of targets, one per line

#### **Custom Output Directory**
```bash
python3 main.py -d target.com --output-dir /custom/path --profile full
```

#### **Verbose Output & Resume**
```bash
python3 main.py -d target.com --verbose --resume
```

---

## 🔧 Configuration

### Profile Modes

| Profile | Phases | Time | Use Case |
|---------|--------|------|----------|
| **quick** | 5 | ~2-3 min | Quick assessment |
| **balanced** | 10 | ~5-15 min | Most targets (recommended) |
| **full** | 14 | ~15-30 min | Comprehensive hunt |
| **deep** | 15 | ~30-60+ min | Maximum coverage |

### Key Configuration File: `config.yaml`

```yaml
general:
  profile: balanced           # quick | balanced | full | deep
  threads: 50                 # Parallel workers
  timeout: 30                 # Per-tool timeout in seconds
  rate_limit: 150             # Requests/second
  verbose: true               # Verbose output
  resume: true                # Auto-resume on interrupt

profiles:
  balanced:
    phases:
      - subdomain             # Step 1: Find all subdomains
      - validation            # Step 2: Verify live hosts
      - enrichment            # Step 3: Collect host intelligence
      - portscan              # Step 4: Scan open ports
      - fingerprint           # Step 5: Detect tech stacks
      - github_recon          # Step 6: GitHub public intel
      - content               # Step 7: Content/endpoint discovery
      - api_discovery         # Step 8: API mapping
      - jsanalysis            # Step 9: JS secret extraction
      - cloud_enum            # Step 10: Cloud exposure checks
      - vulnscan              # Step 11: Vulnerability assessment
      - sensitive             # Step 12: Sensitive data hunt
      - screenshot            # Step 13: Visual screenshots
      - prioritize            # Step 14: Finding prioritization
      - report                # Step 15: Generate reports
```

### Tool Configuration

Edit `config.yaml` to enable/disable specific tools:

```yaml
subdomain_enum:
  subfinder:
    enabled: true
    threads: 30
    sources: "all"
  amass:
    enabled: true
    passive: true

content_discovery:
  katana:
    enabled: true
    depth: 3
    threads: 20
    js_crawl: true
  dirsearch:
    enabled: true
    threads: 30
    extensions: "php,asp,aspx,jsp,html,js,json"

api_introspection:
  enabled: true
  max_hosts: 100
```

---

## 📊 Architecture

```
synchunt/
├── main.py                 # Entry point & orchestrator
├── config.yaml             # Configuration & profiles
├── requirements.txt        # Python dependencies
│
├── core/
│   ├── config_manager.py   # Config handling
│   ├── database_manager.py # SQLite result storage
│   ├── logger.py           # Logging & output
│   ├── runner.py           # Tool execution
│   └── utils.py            # Helper utilities
│
├── modules/
│   ├── subdomain_enum.py           # Subdomain discovery
│   ├── subdomain_validation.py     # Live host verification
│   ├── asset_enrichment.py         # Asset intelligence
│   ├── port_scanning.py            # Port enumeration
│   ├── fingerprinting.py           # Tech detection
│   ├── github_recon.py             # GitHub intel
│   ├── api_introspection.py        # API discovery
│   ├── content_discovery.py        # URL/endpoint crawling
│   ├── js_analysis.py              # JS secret extraction
│   ├── cloud_enum.py               # Cloud exposure checks
│   ├── vuln_scanning.py            # Vulnerability testing
│   ├── sensitive_info.py           # Credential hunting
│   ├── finding_prioritizer.py      # Finding ranking
│   └── scope_manager.py            # Scope filtering
│
└── reports/
    ├── html_report.py              # HTML report generation
    ├── markdown_report.py          # Markdown reports
    └── notifier.py                 # Slack/Discord notifications
```

---

## 📈 Output Structure

```
output/
└── target.com/
    └── 20261007_113000/
        ├── subdomains/              # Discovered subdomains
        ├── dns/                     # Live hosts & DNS data
        ├── ports/                   # Open ports & services
        ├── fingerprinting/          # Tech stack info
        ├── content_discovery/       # URLs & endpoints
        │   ├── urls/
        │   ├── params/
        │   └── directories/
        ├── js_analysis/             # JS secrets & endpoints
        ├── api_intelligence/        # APIs discovered
        ├── github_recon/            # GitHub findings
        ├── cloud_enum/              # Cloud resources
        ├── vulnerabilities/         # CVEs & misconfigs
        ├── sensitive_info/          # Creds & exposed data
        ├── intel/                   # Asset enrichment
        ├── findings_prioritized/    # Ranked findings
        ├── reports/                 # HTML/JSON/CSV reports
        ├── screenshots/             # Visual captures
        └── synchunt_results.db      # SQLite correlation DB
```

---

## 🎮 Advanced Usage

### Environment Variables

```bash
# GitHub token for expanded repo search
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"

# Shodan API key
export SHODAN_API_KEY="xxxxxxxxxxxx"

# Slack webhook
export SLACK_WEBHOOK="https://hooks.slack.com/services/..."
```

### Scope Filtering

```yaml
# in config.yaml
general:
  scope_file: "scope.txt"         # Domains to include
  out_of_scope_file: "oos.txt"    # Domains to exclude
```

```bash
# scope.txt
example.com
*.example.com
api.example.com
```

### Resume Interrupted Scans

```bash
# Auto-resumes if config has resume: true
python3 main.py -d target.com --full --resume
```

### Database Queries

```bash
# Access SQLite results
sqlite3 output/target.com/*/synchunt_results.db

# List all findings
SELECT severity, type, COUNT(*) FROM findings GROUP BY severity, type;

# Export critical issues
SELECT * FROM findings WHERE severity='CRITICAL' ORDER BY score DESC;
```

---

## 🔐 Security & Legal

- ⚠️ **Authorization Required**: Only test targets you own or have explicit written permission to test
- 📋 **Respect Scope**: Follow bug bounty program rules and scope definitions
- 🛡️ **Rate Limiting**: Configured to avoid DoS; adjust if needed
- 📝 **Documentation**: Keep scan logs for audit trails and proof

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests and validation
5. Submit a pull request with clear description

---

## 📋 Requirements

### Python Packages
- pyyaml, requests, colorama, jinja2
- beautifulsoup4, aiohttp, tabulate
- Integrations: slack-sdk, python-telegram-bot

### External Tools (Optional but Recommended)
```bash
# Install common recon tools
sudo apt-get install nmap masscan dnsutils

# Go-based tools (install from GitHub)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

---

## 🚀 Roadmap

- [ ] GraphQL query fuzzing
- [ ] Custom vulnerability detection templates
- [ ] Multi-target parallel orchestration
- [ ] Real-time dashboard
- [ ] Mobile app scanning
- [ ] WAF bypass detection
- [ ] Automated exploitation verification

---

## 📚 Resources

- 📖 [Full Documentation](docs/README.md)
- 🎥 [Video Tutorials](https://youtube.com/@ziroai)
- 💬 [Discord Community](https://discord.gg/synchunt)
- 🐛 [Issue Tracker](https://github.com/ziroai/synchunt/issues)

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

---

<div align="center">

**Made with ❤️ by Security Researchers for Security Researchers**

[![Follow on GitHub](https://img.shields.io/github/followers/ziroai?style=social)](https://github.com/ziroai)
[![Twitter](https://img.shields.io/badge/Twitter-@ziroai-1DA1F2?style=flat&logo=twitter)](https://twitter.com/ziroai)

</div>
