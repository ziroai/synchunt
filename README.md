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

- **16-phase pipeline, one command** — `--profile quick|balanced|full|deep` or pick phases with `--phase a,b,c`.
- **Out-of-band confirmation** — blind XSS/SSRF/XXE callbacks via webhook.site, interactsh or your own
  collector (`vuln_scanning.oob`), so blind bugs become high-confidence findings instead of guesses.
- **API route brute forcing built in** — a 70-path built-in wordlist (supplementable) finds undocumented
  API routes, with sensitive ones flagged for manual authorisation testing.
- **Full interactive-platform hook-up** — `--proxy http://127.0.0.1:8080` routes every SyncHunt request *and*
  every child tool through Burp Suite, OWASP ZAP or mitmproxy (`general.proxy` / `SYNCHUNT_PROXY`).
- **gf-patterns classification built in** — the URL corpus is bucketed into `patterns/ssrf.txt`, `xss.txt`,
  `sqli.txt`, `lfi.txt`, `redirect.txt`, `ssti.txt`, `idor.txt`, … so the right scanner sees the right URLs.
- **Exploit intelligence** — findings that reference a CVE are matched against your local Exploit-DB
  (`searchsploit`), tagged `public-exploit` and scored up (`findings_prioritized/exploits.json`).
- **Offline helper CLI** — `synchunt-tools` covers anew (`dedupe`), unfurl (`unfurl`), gf (`gf`), meg
  (`meg-urls`), Postman collections (`postman`) and hashcat/john preflight (`hash-id`, `identify`).
- **Subdomain-takeover detection built in** — CNAME chains matched against 20 takeover-prone services
  (fingerprints and claimability rules from can-i-take-over-xyz), no binaries required.
- **Scope enforced before active tooling** — wildcard domains, IPs/CIDRs and `host:port` entries; in-scope/out-of-scope files; nothing leaves your scope.
- **SQLite correlation store** — every scan writes `synchunt_results.db` (scans, phases, assets, findings) with fingerprint-based de-duplication.
- **Heuristic prioritisation, not just severity** — findings are scored (impact, confidence, exposure, CVSS-style bonuses) and ranked P1–P4 with reasons you can read.
- **Reports that are ready to share** — dark-theme HTML, Markdown, JSON, CSV and **SARIF 2.1.0** (GitHub code scanning / CI dashboards), plus optional Slack/Discord/Telegram notifications.
- **Re-scan diffing** — every run is compared against the previous one for the same target: *new*, *fixed* and *persisting* findings are shown in the reports (`reports/history.json`).
- **CI-native** — `--json-report summary.json` writes a machine-readable run summary (findings, severities, top findings, artifact paths, history counts) and the exit code reflects the result.
- **Resumable** — re-run with `--resume` and completed phases are skipped.
- **Graceful degradation** — every phase works with the tools you have; missing optional tools are skipped with a clear hint, and several phases have built-in fallbacks (crt.sh, HTTP prober, header fingerprinting, OpenAPI/GraphQL probes, cloud-bucket enumeration).
- **Safe by construction** — no `shell=True` anywhere in the scanning path, rate-limited HTTP session, redacted secrets in output, escaped report rendering.
- **Tested** — 162 unit/integration tests, CI across Python 3.9–3.12, plus `./scripts/check.sh`.

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

Prefer a real command on your `PATH`? The repo is also an installable package:

```bash
pipx install .          # or: pip install .
synchunt --doctor       # console script; works outside the checkout
```

Both entry points are equivalent — everything below uses `python3 main.py` for clarity;
replace it with `synchunt` if you installed the package.

**Docker** (batteries included: framework + subfinder, httpx, dnsx, naabu, nuclei, katana, gobuster, nmap, whatweb):

```bash
docker build -t synchunt .                       # add --target slim for framework-only
docker run --rm -v "$PWD/output:/app/output" synchunt -d example.com --profile balanced
```

**GitHub Actions** — the repository is a composite action:

```yaml
- uses: actions/checkout@v4
- uses: ziroai/synchunt@main
  with:
    target: example.com
    profile: balanced
    fail-on: high          # fail the job on high/critical findings
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

Interactive platforms plug in through one flag: `synchunt -d example.com --proxy http://127.0.0.1:8080`
sends all traffic (built-in client *and* child tools) through Burp Suite, ZAP or mitmproxy.

The offline helpers ship with the package:

```bash
synchunt-tools dedupe urls.txt              # anew
synchunt-tools unfurl urls.txt --part keys  # unfurl
synchunt-tools gf ssrf urls.txt             # gf + gf-patterns
synchunt-tools meg-urls --hosts h.txt --paths p.txt
synchunt-tools postman collection.json      # Postman -> URL list
synchunt-tools hash-id hashes.txt           # hashcat/john preflight
```

`python3 main.py --check-deps` lists what is installed and what is missing; `--install-deps`
prints the install commands. Both exit `1` while anything required is missing, so they can gate a
CI job. SyncHunt deliberately never runs package managers for you.

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
| `--full` | run all 16 phases |
| `--resume` | continue the latest run for this target (completed phases are skipped) |
| `--dry-run` | print the plan and exit |
| `--output-dir` | base output directory (default `output/`) |
| `--json-report PATH` | write a machine-readable JSON summary of the run (CI-friendly) |
| `--threads`, `--timeout`, `--rate-limit` | concurrency / per-tool timeout / HTTP rate limit |
| `--scope-file`, `--out-of-scope-file` | scope files loaded on top of `config.yaml` |
| `--config` | config file path (default `config.yaml`) |
| `-v`, `-q` | verbose / quiet |
| `--check-deps`, `--install-deps` | dependency check / install hints (exit `1` if anything missing) |
| `--doctor` | dependency + configuration health check |
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

# CI: machine-readable summary + SARIF for GitHub code scanning
python3 main.py -d target.com --profile balanced --json-report summary.json
```


### Profiles

| Profile | Phases | Notes |
|---|---|---|
| `quick` | 5 | subdomain → validation → enrichment → takeover → report |
| `balanced` | 12 | quick + portscan, fingerprint, content, api, js, vulnscan |
| `full` | 15 | balanced + github_recon, cloud_enum, sensitive |
| `deep` | 16 | everything including screenshots |

`prioritize` and `report` are always appended automatically (reporting needs prioritised findings), so the numbers above already include them.

---

## 🔍 Phases & Tooling

| # | Phase | What it does | Tools (optional) |
|---|---|---|---|
| 1 | `subdomain` | subdomain discovery | subfinder, amass, assetfinder, findomain, chaos, sublist3r, theHarvester, puredns, gotator + built-in crt.sh, SecurityTrails, Shodan DNS, Censys |
| 2 | `validation` | live host detection | httpx, dnsx, dnsrecon, dnsenum (AXFR) + built-in prober fallback |
| 3 | `enrichment` | DNS/TLS/header/CDN intel, exposure checks | built-in (uses the shared HTTP layer) |
| 4 | `takeover` | subdomain takeover: CNAME chains + unclaimed-service fingerprints | built-in + optional subjack |
| 5 | `portscan` | port & service discovery | naabu, nmap, masscan, rustscan |
| 6 | `fingerprint` | tech-stack & WAF detection | whatweb, wafw00f, webanalyze + header heuristics |
| 7 | `github_recon` | repositories, issues, leaked secrets | GitHub API (set `github_recon.token`) |
| 8 | `content` | crawling, URLs, params, directories | katana, gospider, hakrawler, waybackurls, gau, waymore, paramspider, arjun, x8, dirsearch, feroxbuster, ffuf, gobuster, wfuzz + built-in gf-patterns classification |
| 9 | `api_discovery` | OpenAPI/Swagger, GraphQL, actuator probes + API route brute force | built-in (70-path wordlist) |
| 10 | `jsanalysis` | JS endpoints + secret scanning (entropy-gated, redacted) | linkfinder, secretfinder, jsluice, trufflehog, gitleaks, custom regex |
| 11 | `cloud_enum` | S3 / Azure / GCP bucket candidates | built-in (+ optional cloudbrute across 7 providers) |
| 12 | `vulnscan` | vulnerability scanning + OOB confirmation | nuclei, nikto, wapiti, dalfox, xsstrike, sqlmap, ghauri, commix, tplmap, ssrfmap, crlfuzz, corsy, wpscan, joomscan + built-in OOB client |
| 13 | `sensitive` | dorking & exposed-data checks | GitHub/Google dorking, shodan, s3scanner, hunter.io |
| 14 | `screenshot` | visual recon | gowitness, aquatone, EyeWitness |
| 15 | `prioritize` | de-dup, score, rank (P1–P4) + Exploit-DB enrichment | built-in + searchsploit |
| 16 | `report` | HTML/Markdown/JSON/CSV/SARIF + notifications | built-in |

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
        ├── reports/               # report.html, report.md, results.sarif,
        │                          # history.json, findings.json/csv, scan_data.json
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

## 🕓 Re-scan diffing

Point SyncHunt at the same target twice and the second report tells you what changed:

```text
[20:18:08] 🎯 [ FOUND ] History vs 20261007_201758: 1 new, 1 fixed, 3 persisting
```

- `reports/history.json` — machine-readable `new` / `fixed` / `persisting` lists and counts
- the HTML and Markdown reports gain a **"Since last scan"** section (new findings first, fixed ones collapsed)
- `reports/findings.csv` gains a `history` column (`new` / `persisting`)
- every finding is matched on category + title + location, so a changed response body is still the *same* finding, not a new one

Disable with `reporting.track_history: false`.

## 🤖 CI / automation

```bash
python3 main.py -d target.com --profile balanced --json-report summary.json
python3 main.py -d target.com --profile balanced --quiet
```

- `--json-report` writes the run summary (`tool`, `version`, `exit_code`, per-target `findings`, `severity`, `categories`, `top_findings`, `artifacts`, `history`).
- `reports/results.sarif` can be uploaded straight to GitHub code scanning:

```yaml
- run: python3 main.py -d example.com --profile balanced
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: output/example.com/**/reports/results.sarif
```

- Exit codes: `0` ok · `1` error · `2` usage · `3` no targets · `130` interrupted — fail your pipeline on anything `>= 2`.

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
./scripts/check.sh                         # everything below, in parallel

python3 -m pytest tests -q                 # 162 unit + integration tests
python3 -m pyflakes core modules reports main.py tests
python3 -m compileall -q core modules reports main.py

python3 main.py --doctor                   # environment check
python3 main.py -d example.com --dry-run   # no traffic
```

CI (`.github/workflows/ci.yml`) runs all of the above on Python 3.9–3.12.

### Documentation

| Document | Contents |
|---|---|
| [`docs/WORKFLOW.md`](docs/WORKFLOW.md) | the end-to-end hunt workflow: scope → recon → discovery → scanning → triage → report |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | beginner roadmap: what to learn in what order, with labs and practice loops |
| [`docs/TOOL-COVERAGE.md`](docs/TOOL-COVERAGE.md) | every tool in the standard bug-bounty stack and exactly what SyncHunt does with it |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | design, database schema, how to add a phase or a tool |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | local install, Docker, CI action, unattended scanning |

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
