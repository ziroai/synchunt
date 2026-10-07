# The workflow: from scope to report

A repeatable bug-bounty workflow with SyncHunt as the automation spine and manual testing where it belongs.
Every command below assumes an **authorised** target (in-scope program or your own infrastructure).

```
① scope & rules  →  ② passive recon  →  ③ active recon  →  ④ content & API mapping
      →  ⑤ automated scanning  →  ⑥ triage & manual testing  →  ⑦ report & re-scan
```

---

## ① Scope and rules — before any packet leaves your machine

1. Read the program page: in-scope assets, exclusions, rate limits, forbidden test classes, disclosure rules.
2. Write the scope down and let the tool enforce it:

```bash
cat > scope.txt <<'EOF'
*.example.com
203.0.113.0/24
EOF
cat > oos.txt <<'EOF'
blog.example.com
EOF

python3 main.py -d example.com --scope-file scope.txt --out-of-scope-file oos.txt --dry-run
```

`--dry-run` prints the plan, the scope summary and tool availability and sends nothing. SyncHunt filters
subdomains, live hosts and URLs against the scope as soon as host lists exist — out-of-scope entries are
dropped and counted in `reports/scope.json`.

**Rules of thumb**
- Start with a burst limit you can defend (`--rate-limit 10` for a fragile production app).
- No destructive tests (no `--risk 3` sqlmap, no desync probing) unless the program explicitly allows them.
- Keep credentials out of the report directory; SyncHunt redacts detected secrets, but your proxy history is yours to protect.

## ② Passive recon — learn without touching the target

```bash
python3 main.py -d example.com --phase subdomain,github_recon,sensitive --profile quick
```

- **Subdomains** (phase 1): subfinder, amass, assetfinder, findomain, chaos, crt.sh, SecurityTrails, Shodan DNS.
- **Code and dorks** (phases 7 & 13): GitHub repos/issues/leaks, Google dork URLs, Shodan lookups.
- Pass keys via environment variables (`GITHUB_TOKEN`, `SHODAN_API_KEY`, `SECURITYTRAILS_API_KEY`, `CHAOS_KEY`) — they are never written to disk.

Useful output: `subdomains/all_subdomains.txt`, `github_recon/repos.json`, `sensitive_info/dorks/`.

## ③ Active recon — confirm and expand

```bash
python3 main.py -d example.com --phase validation,enrichment,takeover,portscan,fingerprint \
  --profile balanced
```

- **Validation** (phase 2): which names actually resolve and answer (httpx or the built-in prober).
- **Enrichment** (phase 3): DNS/TLS/headers/CDN, exposed admin and management paths.
- **Takeover** (phase 4): CNAME chains matched against 20 takeover-prone services — the cheapest critical bug in recon.
- **Ports** (phase 5): naabu/nmap/masscan/rustscan.
- **Fingerprinting** (phase 6): tech stack + WAF (whatweb, waf00f, webanalyze, header heuristics).

Useful output: `dns/live_hosts.txt`, `takeover/candidates.json`, `ports/all_ports.txt`, `fingerprinting/technologies.json`.

## ④ Content, API and JavaScript mapping

```bash
python3 main.py -d example.com --phase content,api_discovery,jsanalysis,cloud_enum
```

- **Content** (phase 8): katana/gospider/hakrawler + waybackurls/gau/waymore + gobuster/feroxbuster/ffuf/dirsearch + paramspider/arjun/x8.
- **API** (phase 9): OpenAPI/Swagger specs, GraphQL endpoints (+ introspection), Spring actuator.
- **JS** (phase 10): endpoint extraction (linkfinder, jsluice) and secrets (secretfinder, trufflehog, gitleaks, entropy-gated regex).
- **Cloud** (phase 11): bucket candidates for the discovered names.

Useful output: `content_discovery/all_urls.txt`, `params/all_params.txt`, `api_intelligence/endpoints.txt`, `js_analysis/endpoints/`, `cloud_enum/public_buckets.txt`.

## ⑤ Automated scanning

```bash
python3 main.py -d example.com --phase vulnscan --profile balanced --rate-limit 25
```

- API route brute force first (`api_introspection.bruteforce`, on by default): a 70-path built-in
  wordlist finds undocumented routes; `admin`/`internal`/`private`/`debug`/`env`/`backup` hits are
  reported as findings so you can check authorisation by hand.
- nuclei (templates), nikto, wapiti, dalfox/xsstrike (XSS), sqlmap/ghauri (SQLi), crlfuzz, corsy, wpscan (WordPress), plus the built-in open-redirect candidate check.
### Out-of-band confirmation (blind XSS / SSRF / XXE)

Blind bugs only show up when the target calls *you*. Enable the built-in OOB client:

```yaml
vuln_scanning:
  oob:
    enabled: true
    provider: webhook        # webhook.site (plaintext) | interactsh | custom
    custom_url: ""           # provider: custom -> your collector / Burp Collaborator
    probe_params: false      # true = inject callbacks into parameters (SSRF/XXE)
```

- With OOB enabled, `dalfox` automatically receives a blind-XSS callback (`-b`) and any callback that
  arrives becomes a **high-confidence `oob` finding** (`vulnerabilities/oob_interactions.json`).
- `probe_params: true` additionally injects the callback into discovered parameters up to
  `oob.max_urls` - it modifies requests, so only turn it on where the program allows it.
- `interactsh` works too, but the Python standard library has no AES, so its encrypted interaction
  payloads are reported as observations (count/time) rather than decoded. Use `webhook` or
  `custom` when you need full request bodies.

Everything lands in the SQLite database, is de-duplicated by fingerprint and scored (P1–P4) in phase 15.

## ⑥ Triage and manual testing — where bounties actually come from

```bash
python3 main.py -d example.com --profile deep   # full pipeline, end to end
```

Then work the ranked list:

```bash
cat output/example.com/*/findings_prioritized/top_findings.txt
sqlite3 output/example.com/*/synchunt_results.db \
  "SELECT priority, score, severity, title, url FROM findings ORDER BY score DESC LIMIT 20;"
```

- **Verify every P1/P2 by hand.** Automated findings are candidates: confirm the impact, check for false positives, and write a minimal repro.
- Take the URL corpus into Burp/ZAP for the classes that need a human: authorization flaws (Autorize/AuthMatrix), request smuggling (Smuggler), tplmap/SSTImap, open redirect (Oralyzer), JS analysis in devtools.
- Postman/Insomnia against `api_specs.json`; Param Miner on endpoints that look parameter-poor.
- Mobile endpoints often appear in `api_intelligence` — proxy the app through Burp and reuse SyncHunt's scope rules mentally.

## ⑦ Report, re-scan, re-test

```bash
# second run: the report tells you what changed since the first
python3 main.py -d example.com --profile balanced --json-report summary.json
```

- `reports/report.html` / `report.md` — human-readable, with a "Since last scan" diff (new / fixed / persisting).
- `reports/results.sarif` — upload in CI; `--json-report` — machine-readable run summary.
- Re-run after a fix to confirm closure; `--resume` continues an interrupted scan instead of starting over.

---

## Which profile when

| Situation | Command |
|---|---|
| First contact, 5 minutes | `--profile quick` (5 phases: subdomain → validation → enrichment → takeover → report) |
| Standard assessment | `--profile balanced` (12 phases) |
| Full program, time available | `--profile full` (15 phases) or `--profile deep` (16 phases, adds screenshots) |
| Single class, focused | `--phase jsanalysis,vulnscan` etc. |
| CI / regression | `--profile balanced --json-report summary.json`, upload `results.sarif` |

## Safety checklist

- [ ] Target is in scope, and the program allows the test classes you are about to run.
- [ ] Rate limits set (`--rate-limit`), destructive flags off.
- [ ] Out-of-scope list loaded (`--out-of-scope-file`).
- [ ] Secrets in `output/` treated as confidential; do not commit the output directory.
- [ ] Findings verified manually before reporting — never submit an unconfirmed scanner hit.
