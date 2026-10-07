# Changelog

All notable changes to SyncHunt are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic
Versioning](https://semver.org/).

## [2.1.0] — 2026-10-08

Internationalisation, cross-platform support and authenticated scanning.

### Added

- **Multi-language support** (`core/i18n.py`): CLI messages and generated reports in English, Spanish,
  French, German, Portuguese, Hindi, Japanese and Chinese. Select with `--lang`, `general.language`,
  `SYNCHUNT_LANG` or the OS `LANG` locale; `--list-languages` shows the catalogue. Identifiers (tool
  names, phase names, config keys, JSON/CSV fields) stay English so automation is unaffected.
- **Cross-platform layer** (`core/platform_compat.py`): UTF-8 stdio with automatic ASCII degradation
  (`SYNCHUNT_ASCII=1`), UTF-8 environment for child processes, process-group spawning on POSIX and
  process-tree termination on Windows (`taskkill /F /T`). Windows, macOS and Linux are now first-class;
  `--doctor` prints a platform summary.
- **Authenticated scanning**: `--cookie "session=…"` / `--header "Name: value"` (or `general.cookie` /
  `general.headers`) are applied to the shared HTTP session *and* to every tool that accepts custom
  headers (nuclei, httpx, katana, ffuf, gobuster, feroxbuster, wfuzz, dalfox, sqlmap, arjun, wpscan).
  Header values are never logged, stored or reported.
- **CISA KEV + FIRST EPSS enrichment** (`core/threatintel.py`): CVE findings are annotated with known-
  exploited status and exploit-prediction scores before ranking; bonuses are capped and the intel feed is
  cached for 12 hours. Output: `findings_prioritized/threat_intel.json`.
- **Exploit-DB attachment** (`finding_prioritizer.searchsploit`): local `searchsploit` lookups attach
  public exploits to CVE findings and raise their score.
- **Submission drafts** (`reports/submission_export.py`): HackerOne JSON, Intigriti JSON and Bugcrowd CSV
  skeletons for qualified findings, ready for a human to complete.
- **Cross-platform verification runner** (`scripts/check.py`): the compile + pyflakes + pytest + doctor +
  dry-run sweep in pure Python, so it runs on Windows as well as POSIX.
- **Offline helper CLI** (`synchunt-tools`): `dedupe` (anew), `unfurl`, `gf` pattern matching,
  `meg-urls` URL matrices, `postman` collection parsing, `hash-id` hash identification with
  hashcat/john preflight commands.
- **Proxy routing**: `--proxy` / `general.proxy` / `SYNCHUNT_PROXY` send all HTTP tooling through Burp
  Suite, OWASP ZAP or mitmproxy.

### Changed

- Every text file is now opened with an explicit UTF-8 encoding, making artifacts byte-identical across
  operating systems.
- Proxy documentation corrected: `--proxy` covers HTTP(S) tooling; raw-socket scanners (naabu, nmap,
  masscan, rustscan) and DNS tools cannot use an HTTP proxy and are marked accordingly.
- Test suite expanded to cover i18n catalogues, the platform layer, authentication, threat intel,
  submission exports and packaging entry points.

### Fixed

- Tool timeouts on POSIX now terminate the whole process group, so orphaned child processes no longer
  survive a cancelled scan.
- Console output no longer corrupts when the terminal encoding cannot represent box-drawing or emoji.

## [2.0.0] — 2026-10-06

First public release of the consolidated framework.

### Added

- **16-phase pipeline**: subdomain discovery, validation, enrichment, takeover, port scan, fingerprinting,
  GitHub recon, content discovery, API discovery, JavaScript analysis, cloud enumeration, vulnerability
  scanning, sensitive information, screenshots, prioritisation and reporting.
- **Profiles** (`quick`/`balanced`/`full`/`deep`), phase selection, resume, dry-run and scope enforcement.
- **Built-in fallbacks** for crt.sh, live-host probing, header fingerprinting, OpenAPI/GraphQL discovery,
  cloud enumeration and API route brute forcing — the pipeline works with no external tools installed.
- **Findings pipeline**: severity scoring, de-duplication, prioritisation, top-findings shortlist.
- **Reports**: HTML (escaped, CSP), Markdown, SARIF for GitHub code scanning, JSON/CSV exports, SQLite
  correlation database and re-scan diffing (`history.json`).
- **Out-of-band confirmation** for blind XSS/SSRF/XXE via webhook.site, interactsh or a custom collector.
- **Notifications** to Slack, Discord and Telegram (off by default).
- **Packaging**: `synchunt` and `synchunt-tools` console scripts, Docker images (`slim` and
  batteries-included), a GitHub Action with SARIF upload, and a CI matrix on Python 3.9–3.12.

[2.1.0]: https://github.com/ziroai/synchunt/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/ziroai/synchunt/releases/tag/v2.0.0
