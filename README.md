<div align="center">

![SyncHunt Banner](https://img.shields.io/badge/SyncHunt-All--in--One%20Recon%20%26%20Vuln%20Scanning-ff6b6b?style=for-the-badge&logoColor=white)

# ⚔️ SyncHunt v2 — Automated Recon & Vulnerability Scanning Framework

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![CI](https://github.com/ziroai/synchunt/actions/workflows/ci.yml/badge.svg)](https://github.com/ziroai/synchunt/actions/workflows/ci.yml)
[![Platform Linux/macOS](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-black?style=for-the-badge&logo=linux)](https://github.com/ziroai/synchunt)

**One framework for the whole recon-to-report workflow**: subdomain discovery, live-host validation, asset intelligence, port and service scanning, fingerprinting, GitHub/cloud OSINT, content and API discovery, JavaScript analysis, vulnerability scanning, prioritisation, reporting and notifications.

> Built for bug-bounty hunters, penetration testers and security researchers working within an authorised scope.

</div>

---

## ✨ Highlights

- **15-phase pipeline, one command** — `--profile quick|balanced|full|deep` or pick phases with `--phase a,b,c`.
- **Scope enforced before active tooling** — wildcard domains, IPs/CIDRs and `host:port` entries; in-scope/out-of-scope files; nothing leaves your scope.
- **SQLite correlation store** — every scan writes `synchunt_results.db` (scans, phases, assets, findings) with fingerprint-based de-duplication.
- **Heuristic prioritisation, not just severity** — findings are scored (impact, confidence, exposure, CVSS-style bonuses) and ranked P1–P4 with reasons you can read.
- **Reports that are ready to share** — dark-theme HTML, Markdown, JSON and CSV exports, plus optional Slack/Discord/Telegram notifications.
- **Resumable** — re-run with `--resume` and completed phases are skipped.
- **Graceful degradation** — every phase works with the tools you have; missing optional tools are skipped with a clear hint, and several phases have built-in fallbacks (crt.sh, HTTP prober, header fingerprinting, OpenAPI/GraphQL probes, cloud-bucket enumeration).
- **Safe by construction** — no `shell=True` anywhere in the scanning path, rate-limited HTTP session, redacted secrets in output, escaped report rendering.
- **Tested** — 80+ unit/integration tests, CI across Python 3.9–3.12.

---

## ⚡ Quick Start

### Requirements

- Python **3.9+**
- Linux/macOS (WSL2 works)
- Everything else is optional: SyncHunt runs out of the box and uses external tools (`subfinder`, `nuclei`, `nmap`, …) when they are installed.

```bash
git clone https://github.com/ziroai/synchunt.git
cd synchunt

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Check your environment (python deps + external tools + config)
python3 main.py --doctor
```

### First scan

```bash
# See the plan without sending a single packet
python3 main.py -d example.com --dry-run

# Fast recon (subdomain → validation → enrichment → prioritize → report)
python3 main.py -d example.com --profile quick

# Full pipeline
python3 main.py -d example.com --profile deep

# Results
ls output/example.com/*/reports/
```

### External tools (optional but recommended)

```bash
sudo apt-get install nmap masscan dnsutils

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# wordlists used by puredns/dirsearch/feroxbuster
./scripts/fetch_wordlists.sh
```

`python3 main.py --check-deps` lists what is installed and what is missing; `--install-deps` prints install hints.

---

## 🛠️ Usage

```text
python3 main.py -d example.com [options]
```

| Option | Description |
|---|---|
| `-d, --domain` | target (comma-separated domains/IPs, accepts `host:port`, CIDR) |
| `-l, --list` | file with one target per line |
| `--profile` | `quick` \| `balanced` \| `full` \| `deep` (default from config) |
| `--phase` | comma-separated phases, e.g. `subdomain,validation,report` |
| `--full` | run all 15 phases |
| `--resume` | continue the latest run for this target (completed phases are skipped) |
| `--dry-run` | print the plan and exit |
| `--output-dir` | base output directory (default `output/`) |
| `--threads`, `--timeout`, `--rate-limit` | concurrency / per-tool timeout / HTTP rate limit |
| `--scope-file`, `--out-of-scope-file` | scope files loaded on top of `config.yaml` |
| `--config` | config file path (default `config.yaml`) |
| `-v`, `-q` | verbose / quiet |
| `--check-deps`, `--install-deps`, `--doctor` | dependency and configuration health |
| `--list-phases`, `--version` | introspection |

Examples:

```bash
# Specific phases only
python3 main.py -d target.com --phase subdomain,validation,api_discovery,prioritize,report

# Multiple targets
python3 main.py -l targets.txt --profile balanced --verbose

# Resume an interrupted run
python3 main.py -d target.com --full --resume

# Custom output location
python3 main.py -d target.com --profile full --output-dir /data/scans
```

### Profiles

| Profile | Phases | Notes |
|---|---|---|
| `quick` | 5 | subdomain → validation → enrichment → prioritize → report |
| `balanced` | 11 | quick + portscan, fingerprint, content, api, js, vulnscan |
| `full` | 14 | balanced + github_recon, cloud_enum, sensitive |
| `deep` | 15 | everything including screenshots |

`prioritize` and `report` are always appended automatically (reporting needs prioritised findings), so the numbers above already include them.

---

## 🔍 Phases & Tooling

| # | Phase | What it does | Tools (optional) |
|---|---|---|---|
| 1 | `subdomain` | subdomain discovery | subfinder, amass, assetfinder, findomain, sublist3r, puredns, gotator + built-in crt.sh |
| 2 | `validation` | live host detection | httpx, dnsx + built-in prober fallback |
| 3 | `enrichment` | DNS/TLS/header/CDN intel, exposure checks | built-in (uses the shared HTTP layer) |
| 4 | `portscan` | port & service discovery | naabu, nmap, masscan |
| 5 | `fingerprint` | tech-stack & WAF detection | whatweb, wafw00f, webanalyze + header heuristics |
| 6 | `github_recon` | repositories, issues, leaked secrets | GitHub API (set `github_recon.token`) |
| 7 | `content` | crawling, URLs, params, directories | katana, gospider, hakrawler, waybackurls, gau, paramspider, dirsearch, feroxbuster, ffuf, x8 |
| 8 | `api_discovery` | OpenAPI/Swagger, GraphQL, actuator probes | built-in |
| 9 | `jsanalysis` | JS endpoints + secret scanning (entropy-gated, redacted) | linkfinder, secretfinder, custom regex |
| 10 | `cloud_enum` | S3 / Azure / GCP bucket candidates | built-in |
| 11 | `vulnscan` | vulnerability scanning | nuclei, nikto, dalfox, sqlmap, crlfuzz, corsy |
| 12 | `sensitive` | dorking & exposed-data checks | GitHub/Google dorking, shodan, s3scanner |
| 13 | `screenshot` | visual recon | gowitness, aquatone |
| 14 | `prioritize` | de-dup, score, rank (P1–P4) | built-in |
| 15 | `report` | HTML/Markdown/JSON/CSV + notifications | built-in |

Each phase produces artifacts that the next phase consumes; artifact paths are resolved automatically even when only a subset of phases runs.

---

## 📁 Output

```
output/
└── target.com/
    └── 20261007_200120/
        ├── subdomains/            # discovered subdomains + per-tool output
        ├── dns/                   # live hosts, resolved IPs, httpx details
        ├── intel/                 # enrichment: hosts.json, interesting paths
        ├── ports/                 # open ports and services
        ├── fingerprinting/        # technologies.json, whatweb/wafw00f output
        ├── github_recon/          # repos, issues, secrets
        ├── content_discovery/     # urls/, params/, parameters, js_files.txt
        ├── api_intelligence/      # api_specs.json, graphql.json, endpoints.txt
        ├── js_analysis/           # endpoints/, secrets/ (redacted)
        ├── cloud_enum/            # buckets, public_buckets.txt
        ├── vulnerabilities/       # nuclei/sqlmap/... findings.json
        ├── sensitive_info/        # dorks and exposed-data results
        ├── screenshots/           # visual captures
        ├── findings_prioritized/  # findings.json/csv, prioritized.md, top_findings.txt
        ├── reports/               # report.html, report.md, findings.json/csv, scan_data.json
        ├── scan_state.json        # resume state
        └── synchunt_results.db    # SQLite correlation DB
```

Query the database directly:

```bash
sqlite3 output/target.com/*/synchunt_results.db

SELECT severity, category, COUNT(*) FROM findings GROUP BY severity, category;
SELECT title, url, score FROM findings ORDER BY score DESC LIMIT 20;
SELECT phase, status, result_count FROM phases ORDER BY id;
```

---

## 🔧 Configuration

`config.yaml` is fully commented and drives everything:

```yaml
general:
  profile: balanced
  threads: 50
  timeout: 30
  rate_limit: 50
  output_dir: output

profiles:
  quick:    { phases: [subdomain, validation, enrichment, report] }
  balanced: { phases: [subdomain, validation, enrichment, portscan, fingerprint,
                        content, api_discovery, jsanalysis, vulnscan, prioritize, report] }
  # full / deep also include github_recon, cloud_enum, sensitive, screenshot

scope:
  include: ["*.example.com", "203.0.113.0/24"]
  exclude: ["blog.example.com"]
  strict: false

github_recon:
  token: ""            # or export GITHUB_TOKEN / GH_TOKEN

notifications:
  enabled: false       # Slack / Discord / Telegram webhooks
```

- **Tool gates** — every tool has an `enabled` flag; disabled or missing tools are skipped without failing the phase.
- **Scope** — merged from `config.yaml`, `--scope-file`/`--out-of-scope-file`; supports domains, `*.` wildcards, IPs, CIDRs and `host:port`.
- **Secrets** — `github_recon.token`, `sensitive_info.shodan.api_key` etc. can be set in the file or via environment variables; detected secrets in reports are truncated/redacted.

---

## 🧪 Development

```bash
pip install -r requirements-dev.txt

python3 -m pytest tests -q                 # unit + integration tests
python3 -m pyflakes core modules reports main.py tests
python3 -m compileall -q core modules reports main.py

python3 main.py --doctor                   # environment check
python3 main.py -d example.com --dry-run   # no traffic
```

CI (`.github/workflows/ci.yml`) runs all of the above on Python 3.9–3.12.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design, the database schema and how to add a phase or a tool.

---

## 🔐 Security & Legal

- **Authorised testing only.** Only scan systems you own or have explicit written permission to test (bug-bounty scope, engagement contract, your own infrastructure).
- Unauthorised scanning can violate computer-misuse laws and the terms of service of the targets involved.
- Keep rate limits sensible; SyncHunt defaults to polite rates and exposes `--rate-limit`.
- Findings and reports may contain sensitive data — treat `output/` as confidential.

See [LICENSE](LICENSE) for the full terms and disclaimer.

---

## 🤝 Contributing

1. Fork the repository and create a feature branch.
2. Add tests for new behaviour (see `tests/`).
3. Run `pytest`, `pyflakes` and `compileall` before opening a PR.
4. Never add `shell=True` command construction — use the argument-list helpers in `core/utils.py` and `core/runner.py`.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

<div align="center">

**Made for security researchers, by security researchers.**

</div>
