<div align="center">

# ⚔️ SyncHunt — Advanced Automated Bug Hunting Recon Framework

<img src="https://img.shields.io/badge/Python-3.8%2B-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Status-Advanced-brightgreen?style=for-the-badge" alt="Status">
<img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-black?style=for-the-badge&logo=linux" alt="Platform">

> 🎯 Modern automated reconnaissance framework for advanced bug bounty hunting, recon automation, API discovery, cloud exposure checks, and deep target intelligence.

</div>

---

## Features

### Recon & Discovery
- Subdomain enumeration with multi-engine support
- Live host validation, DNS analysis, and IP correlation
- Content discovery, crawl enumeration, hidden file brute forcing
- Asset enrichment and HTTP exposure profiling
- In-scope / out-of-scope filtering

### API & JS Intelligence
- GraphQL / OpenAPI / Swagger discovery
- JS endpoint extraction and secret scanning
- parameter collection and endpoint mining
- API exposure classification and method detection

### Cloud & GitHub Recon
- S3 / Azure / GCP bucket checks
- GitHub repo and issue reconnaissance
- public secret and source exposure detection
- credential and cloud misconfiguration signals

### Advanced Post-Processing
- Finding prioritization and severity scoring
- SQLite-backed result correlation and deduplication
- CSV / JSON exports for downstream analysis
- structured reporting for quick triage

### Automation Profiles
- quick
- balanced
- full
- deep

---

## Quick Setup

```bash
git clone https://github.com/ziroai/synchunt.git
cd synchunt
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py --check-deps
```

---

## Usage

### Full recon pipeline
```bash
python3 main.py -d example.com --full
```

### Balanced profile
```bash
python3 main.py -d example.com --profile balanced
```

### Deep recon
```bash
python3 main.py -d example.com --profile deep --verbose
```

### Target list
```bash
python3 main.py -l targets.txt --full
```

### Specific phase set
```bash
python3 main.py -d example.com --phase subdomain,validation,github_recon,api_discovery,vulnscan
```

### Custom output dir
```bash
python3 main.py -d example.com --output-dir output/custom_run
```

---

## Configuration

The project uses `config.yaml` for all major controls, including:
- output directory and profiles
- rate limiting and concurrency
- scope files
- tool enablement flags
- API and JS recon settings
- cloud and GitHub recon settings
- reporting and notifications

---

## Requirements

- Python 3.8+
- Linux/macOS
- Optional toolchain: Amass, Subfinder, Nmap, Masscan, FFUF, Katana, etc.
- Recommended: Kali or Ubuntu-based environment

---

## Architecture Overview

- `main.py` — central orchestrator
- `core/` — config management, runtime, database, utility helpers
- `modules/` — recon modules for discovery, scanning, JS, API, GitHub, cloud
- `reports/` — HTML / Markdown / JSON reporting

---

## Legal & Ethical Use

This project is intended for authorized security testing only.

- Only test targets you own or are explicitly authorized to test
- Respect bug bounty scope and program rules
- Avoid destructive or unauthorized activity

---

## Contributing

Contributions are welcome.

1. Fork the repo
2. Create a feature branch
3. Implement improvements
4. Run validation checks
5. Submit a pull request

---

## License

MIT License
