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

- **Validation** (phase 2): which names actually resolve and answer (httpx or the built-in prober);
  dnsrecon/dnsenum add record enumeration and a real **AXFR attempt** — a successful zone transfer is
  recorded as a critical finding.
- **Enrichment** (phase 3): DNS/TLS/headers/CDN, exposed admin and management paths.
- **Takeover** (phase 4): CNAME chains matched against 20 takeover-prone services — the cheapest critical bug in recon.
- **Ports** (phase 5): naabu/nmap/masscan/rustscan.
- **Fingerprinting** (phase 6): tech stack + WAF (whatweb, waf00f, webanalyze, header heuristics).

**Authenticated surface**: many programs require a logged-in account before anything interesting is
reachable. Carry the session everywhere with one flag (or the config keys):

```bash
synchunt -d example.com --cookie "session=abc123"          --header "Authorization: Bearer eyJ..." --header "X-Bug-Bounty: handle"
```

The headers go into the shared HTTP session (enrichment, API introspection, OOB probes, takeover and cloud
checks all use them) and into the tools that support custom headers (nuclei, httpx, katana, ffuf, gobuster,
feroxbuster, wfuzz, dalfox, sqlmap, arjun). SyncHunt only ever *logs header names* — values stay out of the
console, the report and the database. Never store another user's session: use an account you created for
the test.

Interception plugs in with one flag: `--proxy http://127.0.0.1:8080` routes every HTTP step — the built-in
client and the HTTP-based tools (nuclei, httpx, ffuf, katana, sqlmap, …) — through Burp Suite, ZAP or
mitmproxy, so you can watch (and replay) the whole scan. Raw-socket scanners (nmap, masscan, naabu,
rustscan) and DNS tools cannot use an HTTP proxy; sqlmap/nikto/wpscan receive their own proxy flag.

Useful output: `dns/live_hosts.txt`, `takeover/candidates.json`, `ports/all_ports.txt`, `fingerprinting/technologies.json`.

## ④ Content, API and JavaScript mapping

```bash
python3 main.py -d example.com --phase content,api_discovery,jsanalysis,cloud_enum
```

- **Content** (phase 8): katana/gospider/hakrawler + waybackurls/gau/waymore + gobuster/feroxbuster/ffuf/dirsearch + paramspider/arjun/x8.
- **API** (phase 9): OpenAPI/Swagger specs, GraphQL endpoints (+ introspection), Spring actuator.
- **JS** (phase 10): endpoint extraction (linkfinder, jsluice) and secrets (secretfinder, trufflehog, gitleaks, entropy-gated regex).
- **Cloud** (phase 11): bucket candidates for the discovered names (optionally cloudbrute across
  Amazon/Google/Microsoft/DigitalOcean/Vultr/Linode/Alibaba — `cloud_enum.cloudbrute.enabled`).
- **Pattern buckets**: the merged corpus is classified with the built-in gf/gf-patterns equivalent, one file
  per bug class in `content_discovery/patterns/` (`ssrf.txt`, `xss.txt`, `sqli.txt`, `lfi.txt`,
  `redirect.txt`, `ssti.txt`, `idor.txt`, `json-sec.txt`, …). Hand those straight to the matching scanner.
- **Existing Postman collection?** `synchunt-tools postman collection.json -o extra_urls.txt` turns it into
  scope-ready URLs.

Useful output: `content_discovery/all_urls.txt`, `params/all_params.txt`, `api_intelligence/endpoints.txt`, `js_analysis/endpoints/`, `cloud_enum/public_buckets.txt`.

## ⑤ Automated scanning

```bash
python3 main.py -d example.com --phase vulnscan --profile balanced --rate-limit 25
```

- API route brute force first (`api_introspection.bruteforce`, on by default): a 70-path built-in
  wordlist finds undocumented routes; `admin`/`internal`/`private`/`debug`/`env`/`backup` hits are
  reported as findings so you can check authorisation by hand.
- nuclei (templates), nikto, wapiti, dalfox/xsstrike (XSS), sqlmap/ghauri (SQLi), crlfuzz, corsy, wpscan (WordPress), joomscan (Joomla), plus the built-in open-redirect candidate check.
- Injection classes that are **off by default** because they are intrusive — enable per engagement:
  `vuln_scanning.commix` (command injection), `vuln_scanning.tplmap` (SSTI, needs `tplmap.py`),
  `vuln_scanning.ssrfmap` (SSRF; SyncHunt generates the raw request file from each parameterised URL).
  All three are capped by `max_urls` and only run against URLs already in `params/all_params.txt`.
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

### Exploit intelligence and hash triage

Phase 15 does two CVE passes:

1. **CISA KEV + FIRST EPSS** (`finding_prioritizer.threat_intel`, on by default) — the CVE list from your
   findings is checked against public feeds *by CVE id* (nothing about the target is sent). Known-exploited
   issues get `kev` as a tag, a score bump and a readable reason; EPSS percentiles add gradations.
   `findings_prioritized/threat_intel.json` keeps the raw data, and the response is cached for 12 hours.
   Offline? The lookup is skipped and the scan continues.
2. **Local Exploit-DB** (`searchsploit`, if installed) — CVEs are matched to exploit entries, tagged
   `public-exploit`, and the score is bumped (`findings_prioritized/exploits.json`).

So a critical that is *known exploited in the wild* sorts above one that merely scored critical.

Hashes (JS bundles, leaked files, GitHub dumps) get triaged without leaving the tool:

```bash
synchunt-tools identify bundle.js        # hash-shaped tokens inside free text
synchunt-tools hash-id hashes.txt        # shape + hashcat -m / john --format commands
```

SyncHunt never cracks anything: it hands you the exact command to run on data you are authorised to test.

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
