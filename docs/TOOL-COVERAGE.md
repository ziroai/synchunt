# Tool coverage

Every tool from the standard bug-bounty stack, cross-checked against what SyncHunt actually does with it.
Four states:

- **Integrated** — SyncHunt runs it for you (phase + config key). Missing binary or token → the tool is
  skipped with a hint and the phase continues.
- **Built-in** — SyncHunt implements the check itself, so it works with zero external dependencies.
- **Hooked** — the tool is an interactive platform, and SyncHunt feeds it: all traffic can be routed through
  it (`--proxy`) or it consumes SyncHunt's artifacts (`live_hosts.txt`, `all_urls.txt`, `findings.json`).
- **Manual / companion** — deliberately not automated, with the reason and the workflow position stated.

`python3 main.py --check-deps` shows what is installed; `--install-deps` prints the install command for
everything missing. `synchunt-tools` exposes the offline helpers (dedupe/unfurl/gf/meg/postman/hash-id).

**Automated coverage: 63 of 78 tools (81%)** — the other 15 are manual/companion by design (licences,
host-level capture, interactive exploitation, credential brute force).

Beyond the tool list, SyncHunt adds three things the list does not cover: **authenticated scanning**
(`--cookie` / `--header`, applied to the session and to the tools that support headers), **CISA KEV +
FIRST EPSS enrichment** for every CVE in the findings (`finding_prioritizer.threat_intel`), and
**submission drafts** in HackerOne / Intigriti / Bugcrowd formats (`reports/submission_*`).

---

## Reconnaissance & subdomain enumeration

| Tool | Status | Where |
|---|---|---|
| Amass | Integrated | `subdomain_enum.amass` (passive by default) |
| Subfinder | Integrated | `subdomain_enum.subfinder` (phase 1) |
| Sublist3r | Integrated | `subdomain_enum.sublist3r` |
| Assetfinder | Integrated | `subdomain_enum.assetfinder` |
| Findomain | Integrated | `subdomain_enum.findomain` |
| crt.sh | Built-in | `subdomain_enum.crtsh` — certificate transparency, no binary |
| DNSDumpster | Manual / companion | web UI with no API: use it for a second opinion on the CNAME/A table, then drop the hostnames into `--scope-file` |
| Alterx | Built-in equivalence | permutation engine in `subdomain_enum.gotator` (wordlist-driven) resolved by `puredns` |

Also integrated in this phase: Chaos, SecurityTrails, Shodan passive DNS, **theHarvester** (hosts + emails,
`subdomain_enum.theharvester`), **Censys** (host search, `subdomain_enum.censys` — needs `CENSYS_API_ID` /
`CENSYS_API_SECRET`).

## Port scanning

| Tool | Status | Where |
|---|---|---|
| Nmap | Integrated | `port_scanning.nmap` (phase 5) |
| Masscan | Integrated | `port_scanning.masscan` |
| RustScan | Integrated | `port_scanning.rustscan` (greppable output merged with the rest) |
| Naabu | Integrated | `port_scanning.naabu` (primary fast pass) |

## Web crawling & content discovery

| Tool | Status | Where |
|---|---|---|
| Burp Suite | Hooked | `--proxy http://127.0.0.1:8080` routes every SyncHunt request *and* every child tool through Burp; use `live_hosts.txt` / `all_urls.txt` / `params/all_params.txt` as scope and scan targets |
| OWASP ZAP | Hooked | same proxy hook; or point ZAP's baseline scan at `live_hosts.txt` |
| Katana | Integrated | `content_discovery.katana` (phase 8) |
| Hakrawler | Integrated | `content_discovery.hakrawler` |
| Waybackurls | Integrated | `content_discovery.waybackurls` |
| gau | Integrated | `content_discovery.gau` |
| ParamSpider | Integrated | `content_discovery.paramspider` |
| Httpx | Integrated | `subdomain_validation.httpx` (phase 2) |

## Directory & file fuzzing

| Tool | Status | Where |
|---|---|---|
| ffuf | Integrated | `content_discovery.ffuf` |
| Gobuster | Integrated | `content_discovery.gobuster` |
| dirsearch | Integrated | `content_discovery.dirsearch` |
| Feroxbuster | Integrated | `content_discovery.feroxbuster` |
| Wfuzz | Integrated | `content_discovery.wfuzz` (secondary pass; raw output parsed generically) |

## Vulnerability scanning

| Tool | Status | Where |
|---|---|---|
| Nuclei | Integrated | `vuln_scanning.nuclei` (JSONL parsed, template categories mapped) |
| Nikto | Integrated | `vuln_scanning.nikto` |
| Wapiti | Integrated | `vuln_scanning.wapiti` (JSON report parsed) |
| Nessus | Manual / companion | commercial, licensed scanner that owns the host-network segment; feed it `live_hosts.txt`/`ports.json`, then import its results into your tracker next to SyncHunt's `findings.csv` |
| Acunetix | Manual / companion | commercial per-target licence; same handover via `live_hosts.txt` |

## SQL injection & command injection

| Tool | Status | Where |
|---|---|---|
| SQLMap | Integrated | `vuln_scanning.sqlmap` (argv-only, no shell; opt-in per profile) |
| Commix | Integrated | `vuln_scanning.commix` (off by default — command injection is opt-in, capped by `max_urls`) |

## XSS

| Tool | Status | Where |
|---|---|---|
| Dalfox | Integrated | `vuln_scanning.dalfox` — gets a blind-XSS callback from `core/oob.py` automatically |
| XSStrike | Integrated | `vuln_scanning.xsstrike` |

## SSRF / SSTI / LFI

| Tool | Status | Where |
|---|---|---|
| SSRFmap | Integrated | `vuln_scanning.ssrfmap` (off by default) — SyncHunt generates the raw request file from each parameterised URL and parses the verdict |
| Gopherus | Manual / companion | payload *generator*: take a confirmed SSRF (SyncHunt's `oob_interactions.json` or ssrfmap hit) and ask Gopherus for the gopher:// payload for the service behind it |
| Tplmap | Integrated | `vuln_scanning.tplmap` (off by default) — runs against parameterised URLs, hits become `ssti` findings |
| LFISuite | Manual / companion | interactive/py2; the automated 80% is covered by nuclei `-tags lfi` plus the built-in `lfi` pattern bucket (`patterns/lfi.txt`) |

Blind SSRF/XXE/BXSS confirmation itself is **Built-in** via `core/oob.py` (webhook / interactsh / custom
collector) — see `docs/WORKFLOW.md`.

## Parameter discovery

| Tool | Status | Where |
|---|---|---|
| Arjun | Integrated | `content_discovery.arjun` (results become `?param=FUZZ` URLs for the scanners) |
| Gf | Built-in | `synchunt-tools gf <pattern>` — same idea, no binary |
| Gf-Patterns | Built-in | 14 bundled pattern sets in `core/patterns.py` (ssrf, xss, sqli, lfi, redirect, rce, ssti, idor, debug, json-sec, takeovers, params, interestingparams) written to `content_discovery/patterns/<class>.txt` |

## JavaScript analysis

| Tool | Status | Where |
|---|---|---|
| LinkFinder | Integrated | `js_analysis.linkfinder` (phase 10) |
| SecretFinder | Integrated | `js_analysis.secretfinder` |

## DNS

| Tool | Status | Where |
|---|---|---|
| Dnsx | Integrated | `subdomain_validation.dnsx` |
| Dnsrecon | Integrated | `subdomain_validation.dnsrecon` — extra records *and* a real AXFR attempt; a successful transfer is a critical finding |
| Dnsenum | Integrated | `subdomain_validation.dnsenum` — NS/MX/SRV walk plus AXFR probe, names merged back into validation |

## WAF detection

| Tool | Status | Where |
|---|---|---|
| Wafw00f | Integrated | `fingerprinting.wafw00f` (phase 6) |

## Screenshot & visual recon

| Tool | Status | Where |
|---|---|---|
| Gowitness | Integrated | `screenshots.gowitness` (phase 14) |
| Aquatone | Integrated | `screenshots.aquatone` |
| EyeWitness | Integrated | `screenshots.eyewitness` — fallback when the other two are absent; writes screenshots + the header report |

## Cloud & S3

| Tool | Status | Where |
|---|---|---|
| S3Scanner | Integrated | `sensitive_info.s3scanner` (optional binary; built-in bucket checks run regardless) |
| Prowler | Manual / companion | needs real AWS credentials to review *your own* account; run it separately from an authorised engagement |
| CloudBrute | Integrated | `cloud_enum.cloudbrute` (off by default) — black-box buckets/apps across Amazon, Google, Microsoft, DigitalOcean, Vultr, Linode, Alibaba; reuses the names derived from the target when no wordlist is given |

Built-in cloud enumeration (`cloud_enum`) needs no tooling at all: AWS/Azure/GCP fingerprinting with
`NoSuchBucket`/`AccessDenied` semantics.

## API testing

| Tool | Status | Where |
|---|---|---|
| Kiterunner | Built-in equivalence | `api_introspection.bruteforce` — 70 built-in route paths (user wordlist takes priority), spec documents found while fuzzing are parsed, sensitive routes reported |
| Postman | Built-in importer | `synchunt-tools postman collection.json -o urls.txt` turns a collection (raw or structured URLs, variables substituted) into scope-ready URLs |

OpenAPI/Swagger discovery and GraphQL introspection are built into `api_introspection` too.

## CMS scanners

| Tool | Status | Where |
|---|---|---|
| WPScan | Integrated | `vuln_scanning.wpscan` (WordPress hosts auto-detected, CVSS→severity) |
| JoomScan | Integrated | `vuln_scanning.joomscan` — version detection plus CVE findings from its output |

## Network & traffic

| Tool | Status | Where |
|---|---|---|
| MITMproxy | Hooked | `--proxy http://127.0.0.1:8080` (or `general.proxy`) sends all traffic through it, including child tools; `mitmproxy` is in the dependency registry |
| Wireshark | Manual / companion | host-level packet capture: run it alongside a scan when you need the raw bytes (TLS-decrypted via the same proxy certificate) |
| Bettercap | Manual / companion | network-layer MITM/ARP tooling, outside an HTTP recon pipeline; use it in a lab, not against a bounty target |

## Exploitation

| Tool | Status | Where |
|---|---|---|
| Searchsploit | Integrated | `finding_prioritizer.searchsploit` (phase 15) — every CVE in the findings is matched against the local Exploit-DB, results land in `findings_prioritized/exploits.json`, tagged `public-exploit`, and the score is bumped |
| Metasploit | Manual / companion | exploitation is a human decision: SyncHunt hands over the CVE, the affected URL and the exploit reference | 

## Password & hash cracking

| Tool | Status | Where |
|---|---|---|
| Hashcat | Integrated (preflight) | `core/hashid.py` + `synchunt-tools hash-id` identify a hash's shape and print the exact `-m` mode; cracking stays with you |
| John the Ripper | Integrated (preflight) | same helper prints the `--format=` to use |
| Hydra | Manual / companion | credential brute forcing is not automated: it is usually prohibited by program rules and is a human decision even when in scope |

Hashes found in JS bundles or leaks can be triaged without leaving the tool:
`synchunt-tools identify bundle.js` lists hash-shaped tokens, `synchunt-tools hash-id hashes.txt` gives the
Hashcat/John commands.

## OSINT & frameworks

| Tool | Status | Where |
|---|---|---|
| theHarvester | Integrated | `subdomain_enum.theharvester` — passive hosts merged into phase 1, emails → `subdomains/emails.txt` |
| Shodan | Integrated | `sensitive_info.shodan` + passive DNS in phase 1 (`SHODAN_API_KEY`) |
| Censys | Integrated | `subdomain_enum.censys` (`CENSYS_API_ID` / `CENSYS_API_SECRET`) |
| Hunter.io | Integrated | `sensitive_info.hunter` (off by default; `HUNTER_API_KEY`) — domain email discovery into `sensitive_info/hunter/` |
| Recon-ng | Manual / companion | interactive workspace framework; SyncHunt's SQLite DB and JSON artifacts are the better handover for a single engagement |
| SpiderFoot | Manual / companion | long-running web UI that aggregates OSINT; complementary to a pipeline, not embeddable |
| Maltego | Manual / companion | commercial graph GUI; import `findings.csv` / `hosts.json` for visual link analysis |

## Utility & helpers

| Tool | Status | Where |
|---|---|---|
| Anew | Built-in | `synchunt-tools dedupe` (order-preserving, optional `--sort`, `--count`) |
| Unfurl | Built-in | `synchunt-tools unfurl --part domains\|keys\|values\|paths\|extensions` |
| Meg | Built-in | `synchunt-tools meg-urls --hosts hosts.txt --paths paths.txt` (host × path matrix) |
| Notify | Built-in | `notifications` (Slack, Discord, Telegram webhooks, `critical_only` option) |

## Adding a tool

1. Add the config block (`phase.tool.enabled`) to `config.yaml` and a registry entry to
   `core/dependency_checker.py` (check/install/required/category).
2. Add a `run_<tool>()` method in the phase module: `runner.require("<tool>")` to skip cleanly, an **argv
   list** (never a shell string), a timeout, then parse the tool's real output format.
3. Gate it with `config.is_tool_enabled("<phase>", "<tool>")`, wire it into `run_all()`, and write artifacts
   under the phase's output directory.
4. Add a test in `tests/test_tool_integrations.py` (or `tests/test_tooling_extras.py`) that monkeypatches
   `ToolRunner.run` and asserts both the argv and the parsing.
5. Update this file and `docs/WORKFLOW.md`.

Everything above is for **authorised testing only** — in-scope bug-bounty programs or systems you own.
