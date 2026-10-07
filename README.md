# SyncHunt — Automated Bug Hunting Recon Framework

> Modular, automated reconnaissance framework for bug bounty hunters.

## Features

- 🔍 **Subdomain Enumeration** — Subfinder, Amass, Assetfinder, Findomain, crt.sh, Sublist3r
- ✅ **Subdomain Validation** — httpx, dnsx, massdns
- 🔓 **Port Scanning** — Naabu, Nmap, Masscan
- 🧩 **Fingerprinting** — WhatWeb, wafw00f, webanalyze
- 🌐 **Content Discovery** — Katana, GoSpider, Hakrawler, waybackurls, gau, ParamSpider, dirsearch, feroxbuster
- 🔬 **JS Analysis** — LinkFinder, SecretFinder, custom regex patterns
- 🚨 **Vuln Scanning** — Nuclei, Nikto, Dalfox, SQLMap, CRLFuzz, Corsy
- 🔑 **Sensitive Info** — S3Scanner, GitHub dorking, Shodan, Google dorks
- 📸 **Screenshots** — Gowitness, Aquatone
- 📊 **Reports** — HTML + Markdown with full findings

## Setup

```bash
# Clone
git clone https://github.com/YOURUSERNAME/synchunt.git
cd synchunt

# Install Python deps
pip3 install -r requirements.txt

# Check tool dependencies
python3 main.py --check-deps
```

## Usage

```bash
# Full scan
python3 main.py -d target.com --full

# Specific phases
python3 main.py -d target.com --phase subdomain,validation,vulnscan

# Multiple targets
python3 main.py -l targets.txt --full

# Verbose
python3 main.py -d target.com --full -v
```

## Requirements

- Python 3.8+
- Go 1.19+ (for Go-based tools)
- Kali Linux / Ubuntu recommended

## Legal

For use on systems you own or have **explicit written permission** to test. Unauthorized use is illegal.
