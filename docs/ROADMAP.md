# Beginner roadmap: from zero to bug bounties

A practical order to learn this stack. Each stage lists what to learn, the tools involved (all mapped in
[TOOL-COVERAGE.md](TOOL-COVERAGE.md)), and how to use SyncHunt to practise it **on targets you are allowed to test**
(your own lab, Juice Shop/DVWA, PortSwigger Academy, or an in-scope program).

> Rule zero: never point anything in this repository at a system you do not have written permission to test.

---

## Stage 0 — Foundations (1–2 weeks)

- **Learn**: HTTP in detail (methods, status codes, headers, cookies), DNS (A/AAAA/CNAME/NS/TXT), TLS, same-origin policy, how a browser talks to a server.
- **Do**: install Linux (or WSL2), Python 3.11+, Docker. Learn the shell enough to pipe tools together.
- **Practice**: `python3 main.py --doctor` until the environment check is clean; read `docs/ARCHITECTURE.md`.
- **Checkpoint**: you can explain what happens between typing a URL and seeing a page.

## Stage 1 — Recon (2–3 weeks)

- **Learn**: subdomain enumeration (passive vs brute force), live-host validation, ports, tech fingerprinting, the difference between `in-scope` and `interesting`.
- **Tools**: subfinder, amass, assetfinder, findomain, chaos, crt.sh, SecurityTrails, Shodan, httpx, dnsx, puredns, naabu/nmap, whatweb, webanalyze.
- **Practise with SyncHunt** on Juice Shop/DVWA/lab hosts:
  ```bash
  python3 main.py -d localhost:3000 --phase subdomain,validation,enrichment,takeover,portscan,fingerprint
  ```
- **Read the outputs**, not just the summary: `dns/live_hosts.txt`, `intel/hosts.json`, `fingerprinting/technologies.json`.
- **Checkpoint**: given a domain, you can produce an asset inventory and explain every line of it.

## Stage 2 — Content and API discovery (2–3 weeks)

- **Learn**: crawling vs historical URLs vs directory brute force; parameter discovery; how APIs differ from pages (specs, GraphQL, versioning, auth).
- **Tools**: katana, gospider, hakrawler, waybackurls, gau, waymore, ffuf, gobuster, feroxbuster, dirsearch, arjun, paramspider, x8, Postman/Insomnia.
- **Practise**: `--phase content,api_discovery,jsanalysis,cloud_enum` against your lab; then open `api_specs.json` in Postman and call every endpoint.
- **Checkpoint**: you can grow one URL into a full endpoint map and spot the endpoints that look under-tested.

## Stage 3 — The vulnerability classes (6–10 weeks, one per 1–2 weeks)

Work through these in order (PortSwigger Academy has a free lab path for each):

| Week | Class | Tools | SyncHunt side |
|---|---|---|---|
| 1 | XSS | dalfox, XSStrike, blind-XSS callbacks | `vulnscan` + `dalfox.blind_xss` |
| 2 | SQLi | sqlmap, ghauri | `vulnscan` (sqlmap/ghauri, argv-safe) |
| 3 | SSRF & OOB | Interactsh, Collaborator, Webhook.site | supply an OOB URL to dalfox; manual follow-up |
| 4 | Open redirect & CORS | Oralyzer, Corsy | `vulnscan` (corsy + built-in candidate listing) |
| 5 | Subdomain takeover | Subjack, can-i-take-over-xyz | **phase 4 is built-in** — study `takeover/candidates.json` |
| 6 | Secrets & repo leaks | TruffleHog, Gitleaks, GitHub dorks | `jsanalysis` + `github_recon` + `sensitive` |
| 7 | LFI/path traversal | ffuf wordlists, nuclei `-tags lfi` | `content` + `vulnscan`, then manual |
| 8 | Template injection | tplmap, SSTImap | params from `params/all_params.txt` |
| 9 | Request smuggling | Smuggler (Burp) | manual only — and only where allowed |
| 10 | Access control & JWT | Autorize, AuthMatrix, JWT Editor | manual; SyncHunt provides the endpoint inventory |

- **Checkpoint for every class**: you can find it in a lab, explain the root cause, and write a minimal repro.

## Stage 4 — Real programs (ongoing)

1. Pick a program whose scope you understand; load it into SyncHunt scope files.
2. Run `--profile balanced`, triage the ranked findings, verify by hand.
3. Report well: clear title, exact steps, impact, remediation, evidence. Use `report.md`/`report.html` as raw material, never paste scanner output unverified.
4. Re-scan after fixes; use the re-scan diff to confirm closure.

## Stage 5 — Scale and specialise (after ~10 reports)

- **Scaling**: run one process per target/cloud host, aggregate `--json-report` files; Notify-style alerting is built in (`reports/notifier.py`).
- **API depth**: Kiterunner, Akto, Postman collections from `api_specs.json`.
- **Mobile**: MobSF, Frida, Objection, apktool, jadx once web bugs are routine — the recon skills transfer.
- **Contribute**: add the missing tool you reach for most (see *Adding a tool* in `docs/ARCHITECTURE.md` and the checklist at the end of `docs/TOOL-COVERAGE.md`).

---

## Weekly practice loop

| Day | Focus |
|---|---|
| Mon | One PortSwigger Academy lab + notes |
| Tue | Recon on a new scoped domain (`--profile quick`, then `balanced`) |
| Wed | Read `top_findings.txt`, manually verify one finding |
| Thu | One harder lab in the same class |
| Fri | Hunt a real program; write/report anything confirmed |
| Sat | Re-scan Monday's domain; study the diff |
| Sun | Rest, or read write-ups (HackerOne Hacktivity is a goldmine) |

## Legal and ethical reminders

- Authorisation is binary: in-scope with permission, or not at all.
- Respect program rules on rate, test classes and data handling — a "found" vulnerability reported badly can still be a violation.
- Do not access, modify or exfiltrate more data than the minimal proof requires, and never test the same bug on a different host than the one you are scoped to.
- Keep accounts, keys and scan output private.
