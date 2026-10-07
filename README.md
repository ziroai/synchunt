<div align="center">

<img src="docs/assets/banner.svg" alt="SyncHunt" width="720">

# SyncHunt

**One command from a domain to a triaged, reportable engagement.**

Automated reconnaissance and vulnerability scanning — subdomain discovery, live-host validation, asset
intelligence, port and service scanning, OSINT, content/API/JavaScript analysis, vulnerability scanning,
prioritisation, reporting and notifications — in a single, dependency-tolerant Python framework.

[![CI](https://github.com/ziroai/synchunt/actions/workflows/ci.yml/badge.svg)](https://github.com/ziroai/synchunt/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-3776ab?logo=python&logoColor=white)](https://www.python.org/)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-1f6feb)](docs/DEPLOYMENT.md#9-platform-support)
[![Languages](https://img.shields.io/badge/output%20languages-8-8a5cf6)](docs/ARCHITECTURE.md#13-internationalisation)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tool coverage](https://img.shields.io/badge/tool%20coverage-81%25%20(63%2F78)-orange)](docs/TOOL-COVERAGE.md)

[Quick start](#-quick-start) ·
[Usage](#-usage) ·
[Pipeline](#-pipeline) ·
[Configuration](#-configuration) ·
[Automation](#-automation) ·
[Coverage](#-tool-coverage) ·
[Docs](#-documentation) ·
[Legal](#-authorised-testing-only)

</div>

---

## Why SyncHunt

- **16-phase pipeline, one command.** `--profile quick|balanced|full|deep`, or pick exactly what you want
  with `--phase a,b,c`. Every phase writes structured artifacts the next phase consumes.
- **Works with what you have.** Each phase uses the best available external tool (subfinder, httpx,
  naabu, nuclei, katana, ffuf, wpscan, …) and falls back to a built-in implementation when the binary is
  missing. Nothing hard-fails because a tool is absent — `--doctor` tells you what is missing and why it
  matters.
- **Authenticated scanning.** `--cookie "session=…"` and `--header "Authorization: Bearer …"` flow into
  the shared HTTP session *and* into every tool that accepts custom headers, so authenticated surface is
  in scope instead of invisible. Header *values* are never written to the console, database or reports.
- **Evidence, not guesses.** Findings are scored and ranked, blind bugs are confirmed out-of-band
  (webhook.site / interactsh / your own collector), and CVE findings are enriched with **CISA KEV** and
  **FIRST EPSS** before anything is called a priority.
- **Ready to hand over.** HTML/Markdown reports, SARIF for GitHub code scanning, JSON/CSV exports, a
  SQLite correlation database, re-scan diffing — and HackerOne / Intigriti / Bugcrowd submission drafts.
- **Runs anywhere.** Linux, macOS and Windows, Python 3.9–3.12, identical artifacts on every platform
  (UTF-8 I/O everywhere), eight report/CLI languages, Docker images and a GitHub Action.

> **Authorised testing only.** SyncHunt sends real traffic to real hosts. Use it only against systems you
> own or have explicit written permission to test. See [Authorised testing only](#-authorised-testing-only).

---

## 📖 Table of contents

- [Install](#-install)
- [Quick start](#-quick-start)
- [Usage](#-usage)
- [Pipeline](#-pipeline)
- [Output](#-output)
- [Configuration](#-configuration)
- [Languages](#-languages)
- [Platform support](#-platform-support)
- [Automation](#-automation)
- [Tool coverage](#-tool-coverage)
- [Documentation](#-documentation)
- [Development](#-development)
- [Authorised testing only](#-authorised-testing-only)

---

## 📦 Install

**Requirements:** Python 3.9–3.12 and `pip`. External recon tools are optional — SyncHunt degrades
gracefully and reports what is missing.

```bash
# 1. Framework
python3 -m pip install .            # or: python3 -m pip install -e ".[dev]" for development

# 2. Check the environment (Python deps + external tools + config health)
synchunt --doctor

# 3. Optional: print the install command for every missing external tool
synchunt --install-deps
```

Prefer containers?

```bash
docker build --target slim -t synchunt:slim .        # framework only
docker build -t synchunt .                           # + common recon tools (subfinder, httpx, nuclei, …)

docker run --rm -v "$PWD/output:/app/output" synchunt -d example.com --profile balanced
docker run --rm synchunt --doctor
```

Run it straight from a checkout:

```bash
git clone https://github.com/ziroai/synchunt.git && cd synchunt
python3 -m pip install -r requirements.txt
python3 main.py -d example.com --profile quick
```

---

## ⚡ Quick start

```bash
# Show the plan without sending a single packet
synchunt -d example.com --dry-run

# Fast pass: subdomain → validation → enrichment → prioritise → report
synchunt -d example.com --profile quick

# Full pipeline (16 phases)
synchunt -d example.com --full

# Several targets from a file, resumable
synchunt -l targets.txt --profile balanced --resume

# CI: machine-readable summary + SARIF for GitHub code scanning
synchunt -d example.com --profile balanced --json-report summary.json
```

> `python3 main.py …` works too if the console script is not on your `PATH`.

Results land in `output/<target>/<timestamp>/` — start with `reports/report.html`, then read
`findings_prioritized/top_findings.txt` for the ranked shortlist.

---

## 🛠 Usage

```
synchunt [targets] [options]
```

### Targets & scope

| Flag | Description |
|---|---|
| `-d, --domain DOMAIN` | Target domain / IP (comma-separated for several). |
| `-l, --list FILE` | File with one target per line. |
| `--scope-file FILE` | In-scope entries; everything else is refused before traffic is sent. |
| `--out-of-scope-file FILE` | Explicit exclusions (wins over the scope file). |

### Scanning

| Flag | Description |
|---|---|
| `--profile NAME` | `quick` (5 phases) · `balanced` · `full` (all 16) · `deep` (slower, broader). |
| `--phase LIST` | Exact phases to run, e.g. `--phase subdomain,validation,vulnscan`. |
| `--full` | Shortcut for all 16 phases. |
| `--resume` | Continue the latest run for this target from `scan_state.json`. |
| `--dry-run` | Print the plan and exit — no packets sent. |
| `--output-dir DIR` | Base output directory (default `output`). |
| `--threads N` · `--timeout S` · `--rate-limit RPS` | Concurrency, per-tool timeout, shared HTTP rate limit. |

### Requests & authentication

| Flag | Description |
|---|---|
| `--cookie VALUE` | `Cookie:` header for authenticated scanning (config: `general.cookie`). |
| `--header "Name: value"` | Extra header on every request and tool call (repeatable; config: `general.headers`). |
| `--proxy URL` | Route traffic through Burp Suite / OWASP ZAP / mitmproxy (config: `general.proxy`, env: `SYNCHUNT_PROXY`). |
| `--lang CODE` | CLI/report language: `de en es fr hi ja pt zh` (env: `SYNCHUNT_LANG`). |

### Diagnostics

| Flag | Description |
|---|---|
| `--doctor` | Dependency + configuration health check (prints the platform summary). |
| `--check-deps` | Exit non-zero if a required tool class is missing. |
| `--install-deps` | Print install commands for everything missing. |
| `--list-phases` · `--list-languages` · `--version` | Introspection. |

### Examples

```bash
# Authenticated engagement through Burp, focused phases, extra header
synchunt -d app.example.com --cookie "session=abc123" \
         --header "X-Engagement: 2026-Q1" --proxy http://127.0.0.1:8080 \
         --phase subdomain,validation,content,jsanalysis,vulnscan,report

# Re-scan and diff against the previous run
synchunt -d example.com --profile balanced        # second run adds "Compared to the previous scan"

# German report for a client
synchunt -d example.com --profile balanced --lang de

# Ranking with CISA KEV + EPSS, then HackerOne/Intigriti/Bugcrowd drafts in reports/
synchunt -d example.com --phase prioritize,report
```

---

## 🧭 Pipeline

Phases are ordered, individually runnable and resumable. `--profile` decides which ones run.

| # | Phase | What it does |
|---|---|---|
| 1 | `subdomain` | Passive/active subdomain discovery — subfinder, amass, crt.sh, theHarvester, Censys, permutations resolved by puredns. |
| 2 | `validation` | Live-host detection (httpx, or a built-in prober) and DNS sanity checks. |
| 3 | `enrichment` | DNS/TLS/header/CDN enrichment, technology hints, interesting-path probes. |
| 4 | `takeover` | Subdomain-takeover detection (CNAME + provider fingerprints). |
| 5 | `portscan` | naabu / nmap / masscan / rustscan service discovery (TCP-connect fallback without root). |
| 6 | `fingerprint` | whatweb / wafw00f / webanalyze — technologies and WAF detection. |
| 7 | `github_recon` | GitHub repositories, issues and leaked-secret scanning. |
| 8 | `content` | Crawling and discovery — katana, hakrawler, waybackurls, gau, ffuf, gobuster, feroxbuster, wfuzz, arjun. |
| 9 | `api_discovery` | OpenAPI/Swagger/GraphQL/actuator discovery and built-in route brute force. |
| 10 | `jsanalysis` | JavaScript endpoint extraction and secret scanning. |
| 11 | `cloud_enum` | S3 / Azure / GCP bucket enumeration, plus CloudBrute when installed. |
| 12 | `vulnscan` | nuclei, nikto, dalfox, sqlmap, crlfuzz, corsy, wpscan, joomscan, commix, tplmap, ssrfmap, Wapiti, out-of-band confirmation. |
| 13 | `sensitive` | GitHub dorks, Google dorks, optional Shodan / Hunter.io. |
| 14 | `screenshot` | gowitness / aquatone / EyeWitness visual recon. |
| 15 | `prioritize` | De-duplicate, score, KEV/EPSS-enrich, attach Exploit-DB entries, rank. |
| 16 | `report` | HTML/Markdown reports, SARIF, JSON/CSV, database, submission drafts, notifications. |

Every phase records a status and result count, so `scan_state.json` and the terminal summary always tell
you what ran, what was skipped and why.

---

## 📁 Output

```
output/
└── example.com/
    └── 20261008_101500/
        ├── subdomains/            # discovered hosts + per-tool output
        ├── dns/                   # live hosts, resolved IPs, httpx details
        ├── intel/                 # hosts.json, interesting paths
        ├── ports/                 # open ports and services
        ├── fingerprinting/        # technologies.json, whatweb/wafw00f output
        ├── github_recon/          # repos, issues, secrets
        ├── content_discovery/     # urls/, params/, parameters, js_files.txt, gf-pattern matches
        ├── api_intelligence/      # api_specs.json, graphql.json, endpoints.txt
        ├── js_analysis/           # endpoints/, secrets/ (values redacted)
        ├── cloud_enum/            # buckets, public_buckets.txt
        ├── vulnerabilities/       # nuclei/sqlmap/… findings.json
        ├── sensitive_info/        # dorks and exposed-data results
        ├── screenshots/           # visual captures
        ├── findings_prioritized/  # findings.json/csv, prioritized.md, top_findings.txt, threat_intel.json
        ├── reports/               # report.html, report.md, results.sarif, history.json,
        │                          # findings.json/csv, scan_data.json, submission_*.{json,csv}
        ├── scan_state.json        # resume state
        └── synchunt_results.db    # SQLite correlation database
```

```sql
-- query the correlation database directly
SELECT severity, category, COUNT(*) FROM findings GROUP BY severity, category;
SELECT title, url, score FROM findings ORDER BY score DESC LIMIT 20;
SELECT phase, status, result_count FROM phases ORDER BY id;
```

---

## ⚙️ Configuration

Everything lives in [`config.yaml`](config.yaml) — one section per phase. The defaults are safe: passive
where possible, no notifications, nothing leaves your machine.

```yaml
general:
  profile: "balanced"        # quick | balanced | full | deep
  threads: 50                # worker threads
  rate_limit: 50             # shared HTTP requests/second
  cookie: ""                 # authenticated scanning (--cookie)
  headers: []                # extra headers (--header "Name: value")
  proxy: ""                  # Burp/ZAP/mitmproxy (--proxy, SYNCHUNT_PROXY)
  language: "en"             # de en es fr hi ja pt zh (--lang, SYNCHUNT_LANG)

subdomain_enum:
  subfinder: { enabled: true }
  crtsh:     { enabled: true }
  puredns:   { enabled: true, resolvers: "wordlists/resolvers.txt" }

vuln_scanning:
  nuclei:  { enabled: true, severity: "critical,high,medium", templates: "" }
  sqlmap:  { enabled: false, risk: 1, level: 1, batch: true }
  oob:     { enabled: false, provider: webhook }   # webhook | interactsh | custom

finding_prioritizer:
  searchsploit: { enabled: true }                  # local Exploit-DB, no network
  threat_intel: { enabled: true, cache_hours: 12 }  # CISA KEV + FIRST EPSS

reporting:
  submission_exports: true   # HackerOne / Intigriti / Bugcrowd drafts
  sarif_export: true         # reports/results.sarif
  track_history: true        # diff against the previous run

notifications:
  enabled: false             # Slack / Discord / Telegram, off by default
```

Environment variables: `SYNCHUNT_PROXY`, `SYNCHUNT_LANG`, `SYNCHUNT_ASCII=1` (force ASCII console
output), plus API keys for optional integrations (`SHODAN_API_KEY`, `CENSYS_API_ID`/`CENSYS_API_SECRET`,
`HUNTER_API_KEY`, `GITHUB_TOKEN`).

---

## 🌍 Languages

CLI messages and generated reports are available in **English, Spanish, French, German, Portuguese,
Hindi, Japanese and Chinese**. Pick the language with any of (highest priority first):

```bash
synchunt -d example.com --lang ja        # CLI flag
# general.language: "ja"                 # config.yaml
export SYNCHUNT_LANG=ja                  # environment
export LANG=ja_JP.UTF-8                  # OS locale (fallback)
synchunt --list-languages                # show what is available
```

- Reports (`report.html`, `report.md`) and terminal output are translated; **identifiers stay English**
  — tool names, config keys, phase names, file names and JSON/CSV field names — so scripts and CI never
  break.
- Console output is UTF-8 with automatic ASCII degradation (`SYNCHUNT_ASCII=1` or a non-UTF-8 terminal)
  so box-drawing and emoji never turn into mojibake.

---

## 🖥 Platform support

| Platform | Status | Notes |
|---|---|---|
| **Linux** | Tested | Full support; process groups for clean tool shutdown. |
| **macOS** | Tested | Full support; same POSIX process handling as Linux. |
| **Windows** | Supported | Process-tree termination via `taskkill /F /T`, UTF-8 console reconfiguration, `scripts/check.py` instead of bash. |
| **Docker** | Supported | Slim and batteries-included images; runs unprivileged. |
| **CI** | Supported | GitHub Actions matrix on Python 3.9–3.12 plus container/action jobs. |

Cross-platform guarantees: every text file is opened with an explicit UTF-8 encoding, child processes get
`PYTHONIOENCODING=utf-8`, and there is no bash dependency in the Python code path. Run the verification
sweep on any OS with:

```bash
python3 scripts/check.py          # pure-Python, cross-platform (also: ./scripts/check.sh on POSIX)
```

---

## 🤖 Automation

**GitHub Action** (this repository ships [`action.yml`](action.yml)):

```yaml
- uses: ziroai/synchunt@main
  with:
    target: example.com
    profile: balanced
    fail-on: high            # fail the job when high/critical findings exist
    upload-sarif: "true"     # results.sarif → GitHub code scanning
```

**CLI in CI:**

```bash
synchunt -d example.com --profile balanced --quiet --json-report summary.json
synchunt -d example.com --full --json-report summary.json --output-dir artifacts
```

- `--json-report PATH` — counts by severity, per-phase status, top findings.
- `reports/results.sarif` — upload with `github/codeql-action/upload-sarif@v3`.
- `--quiet` — machine-friendly output; exit codes: `0` success, `1` error/failed check.
- `notifications.*` — push critical findings to Slack, Discord or Telegram.

---

## 🧰 Tool coverage

SyncHunt cross-checks the standard bug-bounty tool chain and states exactly where each tool stands:

| State | Meaning |
|---|---|
| **Integrated** | SyncHunt runs the external tool for you (phase + config key). Missing binary → skipped with a hint. |
| **Built-in** | SyncHunt implements the check itself — zero external dependencies. |
| **Hooked** | Interactive platform (Burp, ZAP, mitmproxy): route traffic through it with `--proxy`, or feed it SyncHunt artifacts. |
| **Manual / companion** | Deliberately not automated (commercial licences, host-level capture, interactive exploitation) with the reason and handover path documented. |

**Automated coverage: 63 of 78 tools (81%)** — full table in
[docs/TOOL-COVERAGE.md](docs/TOOL-COVERAGE.md). Beyond the tool list SyncHunt adds authenticated
scanning, KEV/EPSS threat-intel enrichment and submission drafts.

Offline helpers ship as a second console script:

```bash
synchunt-tools dedupe urls.txt                 # anew
synchunt-tools unfurl urls.txt --part domain   # unfurl
synchunt-tools gf ssrf all_urls.txt            # gf + gf-patterns
synchunt-tools meg-urls hosts.txt paths.txt    # meg URL matrix
synchunt-tools postman collection.json         # Postman → request URLs
synchunt-tools hash-id 5f4dcc3b5aa765d61d8327deb882cf99   # hash type + hashcat/john preflight
```

---

## 📚 Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module map, data flow, i18n and platform layers, extension points. |
| [docs/WORKFLOW.md](docs/WORKFLOW.md) | Phase-by-phase operator playbook, authenticated scanning, out-of-band confirmation, manual companions. |
| [docs/TOOL-COVERAGE.md](docs/TOOL-COVERAGE.md) | Every tool, its state, its config key and its handover path. |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Installation, platform support, Docker, CI, proxy configuration, hardening. |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Beginner roadmap: a staged learning path from zero to bug bounties, mapped to the phases. |
| [config.yaml](config.yaml) | Fully commented configuration. |
| [CHANGELOG.md](CHANGELOG.md) | Release history and recent changes. |

---

## 🧪 Development

```bash
python3 -m pip install -e ".[dev]"

python3 -m pytest tests -q          # full suite
./scripts/check.sh                  # POSIX: compile + pyflakes + pytest + doctor + dry-run
python3 scripts/check.py            # any OS: the same sweep, pure Python
```

- **Tests** cover every phase with fake runners, the reporting/export stack, packaging, the CLI surface,
  i18n catalogues and the platform layer — no network and no real targets required.
- **Style** — `pyflakes` clean, `compileall` clean, no `shell=True`, secrets never logged.
- **Packaging** — `pyproject.toml` exposes the `synchunt` and `synchunt-tools` console scripts; CI
  installs the package and smokes both entry points.
- **Extending** — add a phase module under `modules/`, register it in `main.py` (`PHASES`) and document
  the config block in `config.yaml`; see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#9-adding-a-phase).

---

## 🔐 Authorised testing only

SyncHunt is built for **authorised security testing** — bug-bounty programmes within scope, penetration
tests with a signed statement of work, or your own infrastructure.

- Stay inside the scope: use `--scope-file` / `--out-of-scope-file`; SyncHunt refuses out-of-scope
  targets before sending traffic.
- Respect rate limits and programme rules; `--rate-limit` and per-tool timeouts exist for that reason.
- Credential cracking, host-level interception and interactive exploitation are deliberately **not**
  automated — those steps are documented as manual handovers.
- You are responsible for the traffic you send. Unauthorised scanning may be illegal in your
  jurisdiction.

Found a vulnerability in SyncHunt itself? Open a private security advisory rather than a public issue.

---

## 🤝 Contributing

Issues and pull requests are welcome — especially new phase integrations, extra language catalogues and
platform fixes. Please run `./scripts/check.sh` (or `scripts/check.py`) before opening a PR, and describe
how the change was verified.

## 📄 License

MIT — see [LICENSE](LICENSE).

<div align="center">

**SyncHunt** — recon, scan, triage, report. Authorised testing only.

</div>
