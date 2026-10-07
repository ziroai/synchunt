# Tool coverage

Every category from the standard bug-bounty stack, mapped to what SyncHunt does with it.
Three states:

- **Integrated** — SyncHunt runs it for you (phase + config key). If the binary/token is missing the tool is
  skipped with a hint and the phase continues.
- **Built-in** — SyncHunt implements the check itself, so it works with zero external dependencies.
- **Manual / companion** — deliberately not automated (interactive testing, exploitation, mobile, training);
  the doc says where it fits in the workflow.

`python3 main.py --check-deps` shows what is installed; `--install-deps` prints the install command for
everything that is missing.

---

## Recon: subdomains and assets

| Tool | Status | Where |
|---|---|---|
| Subfinder | Integrated | `subdomain_enum.subfinder` (phase 1) |
| Amass | Integrated | `subdomain_enum.amass` (passive by default) |
| Assetfinder | Integrated | `subdomain_enum.assetfinder` |
| Findomain | Integrated | `subdomain_enum.findomain` |
| Chaos (ProjectDiscovery) | Integrated | `subdomain_enum.chaos` — needs `CHAOS_KEY` / `subdomain_enum.chaos.api_key` |
| crt.sh | Integrated (built-in, no binary) | `subdomain_enum.crtsh` |
| SecurityTrails | Integrated | `subdomain_enum.securitytrails` — needs `SECURITYTRAILS_API_KEY` / `subdomain_enum.securitytrails.api_key` |
| Shodan (passive DNS) | Integrated | `subdomain_enum.shodan` — reuses `SHODAN_API_KEY` / `sensitive_info.shodan.api_key` |
| Censys | Manual | no API key plumbing; use the Censys UI/API for confirmation, or add a key + endpoint in `modules/subdomain_enum.py` (see *Adding a tool*, `docs/ARCHITECTURE.md`) |
| httpx | Integrated | `subdomain_validation.httpx` (phase 2) |
| httprobe | Built-in equivalent | SyncHunt's dependency-free prober (`_builtin_probe`) checks both schemes for every host |
| dnsx | Integrated | `subdomain_validation.dnsx` |
| massdns | Integrated | used by puredns (`wordlists/resolvers.txt`) |
| puredns | Integrated | `subdomain_enum.puredns` (brute force + wordlists) |
| Naabu | Integrated | `port_scanning.naabu` (phase 5) |
| Nmap | Integrated | `port_scanning.nmap` |
| Masscan | Integrated | `port_scanning.masscan` |
| RustScan | Integrated | `port_scanning.rustscan` (greppable output parsed, ports merged with the rest) |

## Content and endpoint discovery

| Tool | Status | Where |
|---|---|---|
| ffuf | Integrated | `content_discovery.ffuf` (phase 8) |
| Gobuster | Integrated | `content_discovery.gobuster` |
| Feroxbuster | Integrated | `content_discovery.feroxbuster` |
| dirsearch | Integrated | `content_discovery.dirsearch` |
| Katana | Integrated | `content_discovery.katana` |
| Gospider | Integrated | `content_discovery.gospider` |
| Hakrawler | Integrated | `content_discovery.hakrawler` |
| Waybackurls | Integrated | `content_discovery.waybackurls` |
| gau | Integrated | `content_discovery.gau` |
| waymore | Integrated | `content_discovery.waymore` |
| Arjun | Integrated | `content_discovery.arjun` (results become `?param=FUZZ` URLs for the scanners) |
| Param Miner | Manual / companion | Burp extension — use it interactively on endpoints SyncHunt surfaces (its `arjun`/`x8` runs cover the automated 80 %) |
| LinkFinder | Integrated | `js_analysis.linkfinder` (phase 10) |
| JSluice | Integrated | `js_analysis.jsluice` |
| SecretFinder | Integrated | `js_analysis.secretfinder` |

## Vulnerability scanning

| Tool | Status | Where |
|---|---|---|
| Nuclei | Integrated | `vuln_scanning.nuclei` (phase 12) — JSONL parsed, template categories mapped |
| Nikto | Integrated | `vuln_scanning.nikto` |
| Wapiti | Integrated | `vuln_scanning.wapiti` (JSON report parsed, severity levels mapped) |
| OWASP ZAP | Manual / companion | run ZAP against the URL corpus (`content_discovery/all_urls.txt`) or point it at a host for a baseline scan; SyncHunt is a CLI pipeline, ZAP is an interactive platform |
| Burp Suite (Pro/Community) | Manual / companion | use SyncHunt's `live_hosts.txt` / `all_urls.txt` / `params/all_params.txt` as Burp scope + scan targets; export SyncHunt findings to SARIF/JSON for your tracker |
| WPScan | Integrated | `vuln_scanning.wpscan` (WordPress hosts auto-detected by name, JSON parsed, CVSS→severity) |
| CMSeek | Manual | use `--phase fingerprint` output (`webanalyze`/`whatweb`) to identify the CMS, then run CMSeek manually; the CMS-specific path for WordPress is automated via WPScan |

## Specific vulnerability classes

| Class | Tool | Status |
|---|---|---|
| SQLi | sqlmap | Integrated — `vuln_scanning.sqlmap` (argv-only, no shell) |
| SQLi | Ghauri | Integrated — `vuln_scanning.ghauri` |
| XSS | Dalfox | Integrated — `vuln_scanning.dalfox` (blind XSS via `-b`) |
| XSS | XSStrike | Integrated — `vuln_scanning.xsstrike` |
| XSS | XSS Hunter | Manual — supply a `dalfox.blind_xss` callback URL (or an interactsh URL) and skip running your own hunter |
| SSRF / OOB | Interactsh, Burp Collaborator, Webhook.site | **Integrated** — `core/oob.py` registers a callback endpoint and polls it: `webhook` (webhook.site, plaintext interactions), `interactsh` (register/poll; payloads are AES-encrypted so interactions are reported as observations), or `custom` (your own collector / Burp Collaborator). Dalfox blind XSS is wired automatically; `oob.probe_params` injects callbacks into parameters for SSRF/XXE. Interactions become high-confidence findings (`oob_interactions.json`) |
| Open redirect | Corsy (CORS) | Integrated — `vuln_scanning.corsy` for CORS, plus a built-in open-redirect **candidate** check that deliberately only lists URLs and never follows attacker-controlled redirects |
| Open redirect | Oralyzer | Manual — candidates are written by `vuln_scanning`; feed them to Oralyzer or a nuclei `-tags redirect` run |
| Subdomain takeover | Subjack | Integrated (optional cross-check) — `subdomain_takeover.subjack` |
| Subdomain takeover | Nuclei takeover templates | Built-in + Nuclei — the built-in phase (CNAME + service fingerprints from can-i-take-over-xyz) runs with no binaries; nuclei runs its own templates in phase 12 |
| Subdomain takeover | can-i-take-over-xyz | Built-in — 20 service fingerprints with the project's claimability rules and references |
| Secrets in repos | TruffleHog | Integrated — `js_analysis.trufflehog` (verified flag honoured, values redacted) |
| Secrets in repos | Gitleaks | Integrated — `js_analysis.gitleaks` (JSON report, redacted) |
| Secrets in repos | GitHub dorks | Integrated — `github_recon` + `sensitive_info.github_dorking` |
| LFI / path traversal | LFISuite, ffuf wordlists | Manual / companion — ffuf/dirsearch run with traversal payloads in a wordlist; nuclei `-tags lfi` catches the common cases |
| Template injection | tplmap, SSTImap | Manual — SyncHunt surfaces template-shaped params (`params/all_params.txt`); these tools need interactive tuning |
| Request smuggling | Smuggler, HTTP Request Smuggler | Manual — Burp extension workflow (desync probes are intentionally not automated) |
| CRLF injection | crlfuzz | Integrated — `vuln_scanning.crlfuzz` |

## API testing

| Tool | Status | Where |
|---|---|---|
| Postman / Insomnia | Manual / companion | use `api_intelligence/api_specs.json` and `endpoints.txt` as the collection source |
| Kiterunner | Built-in equivalent | `api_introspection.bruteforce` probes a 70-path built-in wordlist (supplementable, capped at `max_paths`/`max_hosts`) against every host and reports route hits, spec documents found by fuzzing, and sensitive routes (`admin`, `internal`, `private`, `debug`, `env`, `backup`) as findings |
| Akto | Manual | feed it exported traffic/URLs; SyncHunt's role is discovery |
| Burp extensions (Autorize, AuthMatrix, Param Miner, Logger++, Turbo Intruder, JWT Editor) | Manual / companion | authorization and JWT testing needs a human in the loop; SyncHunt hands over authenticated-request context and param lists |

## Mobile

| Tool | Status | Note |
|---|---|---|
| MobSF, Frida, Objection, apktool, jadx, Drozer, genymotion/emulator | Manual | out of scope for a web-recon pipeline: `api_intelligence` and `intelligence/hosts.json` often reveal the mobile API surface, which you can then proxy through Burp |

## Wordlists

| Source | Status | Note |
|---|---|---|
| SecLists | Fetched | `scripts/fetch_wordlists.sh` pulls raft/common/parameter lists into `wordlists/` |
| Assetnote wordlists | Manual | drop them into `wordlists/` and point the relevant config keys at them |
| FuzzDB | Manual | same — any path in config works |
| PayloadsAllTheThings | Manual | reference payloads for the manual classes above |

## Utilities and automation

| Tool | Status | Note |
|---|---|---|
| anew, qsreplace, gf, unfurl | Built-in equivalents | dedup, param swapping, grep-patterns and URL parsing are done in-process by `core/utils.py` — no shell pipelines needed |
| httpx pipelines (tomnomnom) | Built-in | the phases pass files between each other; `scan_state.json` + the SQLite DB keep the pipeline state |
| Notify | Integrated equivalent | `reports/notifier.py` posts scan summaries/critical findings to Slack, Discord or Telegram |
| Axiom, Interlace | Manual / companion | run one SyncHunt process per host/cloud agent and aggregate the `--json-report` outputs; `scripts/check.sh` runs the local verification suite in parallel |
| CyberChef | Manual | decoding step when triaging findings |
| Wappalyzer, BuiltWith | Integrated equivalent | `fingerprinting` (webanalyze + whatweb + header heuristics) |
| Google dorking | Integrated | `sensitive_info.google_dorking` generates ready-to-click dork URLs |
| Shodan dorks | Integrated | `sensitive_info.shodan` (+ the Shodan DNS source in phase 1) |
| GitHub dorking | Integrated | `github_recon` + `sensitive_info.github_dorking` (needs a token) |

## Learning platforms

| Platform | Note |
|---|---|
| PortSwigger Web Security Academy | the best free path through the vulnerability classes SyncHunt scans for; start here, then re-read your own findings in that light |
| HackTheBox / TryHackMe | practice targets — point SyncHunt at your own lab machines |
| PentesterLab | exercise-driven, good for API/authz gaps |
| OWASP Juice Shop, DVWA | run them locally and scan them with SyncHunt to see the full pipeline end-to-end, legally |

---

## What is deliberately *not* automated

- **Exploitation and impact demonstration** — SyncHunt finds and ranks candidates; proving them is a human step.
- **Destructive or state-changing tests** (desync, mass auth-bypass fuzzing) — out of scope for a pipeline that
  may be pointed at production.
- **Interactive proxy work** (Burp/ZAP) — complementary, not competing: bring the URL corpus and findings across.
- **Mobile binaries** — different toolchain, different lifecycle.

## Adding a missing tool

1. add a `tool: {enabled, ...}` block under the phase section in `config.yaml`
2. add an entry to `DependencyChecker.TOOLS` (check command, verify substring, install hint, category)
3. implement a `run_<tool>()` method in the phase module following the existing parsers, then call it behind
   `self.config.is_tool_enabled("<phase>", "<tool>")`
4. add a test in `tests/test_tool_integrations.py` that monkeypatches `runner.run` and asserts the argv + parsing

That is the whole loop — `docs/ARCHITECTURE.md` §10 has the details.
