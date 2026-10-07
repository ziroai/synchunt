# Deployment: local, container, CI, unattended

SyncHunt runs the same way everywhere: a Python package with optional external tools. This page covers
the four environments that matter.

---

## 1. Local install

```bash
git clone https://github.com/ziroai/synchunt.git && cd synchunt
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # 4 runtime dependencies
python3 main.py --doctor                 # what is installed, what is missing
./scripts/fetch_wordlists.sh             # SecLists-derived wordlists into wordlists/
```

Requirements:

| Component | Needed for |
|---|---|
| Python 3.9+ | everything |
| `pyyaml`, `requests`, `colorama`, `urllib3` | pip installs them for you |
| external binaries | the optional tools in `docs/TOOL-COVERAGE.md`; every phase degrades gracefully without them |
| root | only for raw-socket scans (`masscan`, naabu SYN mode) — SyncHunt falls back to TCP connect scans |

Console script (optional): `pipx install .` gives you `synchunt` on your `PATH`.

## 2. Docker

```bash
docker build -t synchunt .              # full image: framework + subfinder/httpx/dnsx/naabu/nuclei/katana/gobuster/nmap/whatweb
docker build --target slim -t synchunt:slim .   # framework only

docker run --rm -v "$PWD/output:/app/output" synchunt --doctor
docker run --rm -v "$PWD/output:/app/output" \
    synchunt -d example.com --profile balanced --json-report /app/output/summary.json
```

Notes:

- The image runs as an unprivileged user (`hunter`, uid 10001). Port scans use TCP connect; add
  `--cap-add=NET_RAW` and run as root only if you need SYN scans.
- Wordlists: the full image fetches them at build time; if that fails (offline build), run
  `./scripts/fetch_wordlists.sh` inside the container or mount a `wordlists/` volume.
- Scope files and configs: mount them (`-v "$PWD/scope.txt:/app/scope.txt"`) or bake your own config
  with `--build-arg`-style layering (copy your `config.yaml` over the default before building).
- Image size is dominated by Go tools; use `--target slim` and install only what you need when size matters.

## 3. GitHub Actions / CI

The repository is a composite action:

```yaml
name: security-scan
on:
  schedule: [{ cron: "0 3 * * 1" }]
  workflow_dispatch:

jobs:
  synchunt:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write       # required for SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: ziroai/synchunt@main
        with:
          target: example.com
          profile: balanced
          scope-file: scope.txt
          out-of-scope-file: oos.txt
          rate-limit: "25"
          fail-on: high            # critical|high|medium|low|none
          upload-sarif: "true"
```

Action outputs: `findings`, `critical`, `high`, `report-dir`. Artifacts: the full report set plus
`synchunt-summary.json`.

Any other CI works the same way — install, run with `--json-report`, upload `results.sarif`, gate on
the exit code or on the summary:

```bash
pip install -r requirements.txt
python3 main.py -d example.com --profile balanced --json-report summary.json
python3 -m json.tool summary.json | head -40
```

Exit codes: `0` ok · `1` error · `2` usage/config · `3` no valid targets · `130` interrupted.
`--check-deps`/`--install-deps` exit `1` while required tools are missing.

## 4. Unattended / scheduled scanning

- **Re-scanning is cheap to reason about**: each run diffs against the previous one for the same target
  (`reports/history.json`, "Since last scan" section, `history` column in exports) and `--json-report`
  carries the counts (`new`, `fixed`, `persisting`).
- **Notify on changes**: point Slack/Discord/Telegram at the run (`notifications.enabled`) — summaries
  and critical findings are posted, `critical_only` filters the noise.
- **One process per target** scales better than one process with many targets: use `--output-dir` per
  target and aggregate the summary files. For cloud fleets, the same pattern applies with one container
  per host.
- **Resume** an interrupted run with `--resume` (phases already completed are skipped).
- **Keep credentials out of the image**: pass `GITHUB_TOKEN`, `SHODAN_API_KEY`,
  `SECURITYTRAILS_API_KEY`, `CHAOS_KEY`, `WPSCAN_API_TOKEN` as environment variables/secrets.

## 5. Interception (Burp Suite / OWASP ZAP / mitmproxy)

One flag routes SyncHunt's HTTP traffic through a proxy - the built-in client and every HTTP tool
(nuclei, httpx, ffuf, katana, sqlmap, ...) - because the standard proxy environment variables are exported
before any traffic starts. Tools that speak their own protocol are handled explicitly:

| Class | Behaviour |
|---|---|
| Built-in HTTP client, HTTP tools (nuclei, httpx, katana, ffuf, gobuster, feroxbuster, wfuzz, dalfox, arjun) | proxied via the standard env vars |
| sqlmap, nikto, wpscan | also receive their own flag (`--proxy` / `-useproxy`) |
| Raw-socket scanners (nmap, masscan, naabu, rustscan) and DNS resolvers | **cannot** use an HTTP proxy - they skip it by design |

```bash
synchunt -d example.com --full --proxy http://127.0.0.1:8080

# or in config.yaml / the environment
general:
  proxy: "http://127.0.0.1:8080"
export SYNCHUNT_PROXY=http://127.0.0.1:8080
```

Resolution order: `--proxy` > `general.proxy` > `SYNCHUNT_PROXY`. `NO_PROXY` is left intact and
`localhost`/`127.0.0.1` are always excluded, so a local proxy cannot loop back into itself.

- **Burp Suite**: set the proxy listener, install Burp's CA in the container/host trust store, then watch
  every request in the Proxy history. `synchunt-tools dedupe content_discovery/all_urls.txt` gives you a
  clean scope import.
- **OWASP ZAP**: same, or point ZAP's baseline scan at `dns/live_hosts.txt` and compare findings.
- **mitmproxy**: `mitmproxy -p 8080` and use `mitmdump -w flow.dump` to keep a replayable trace of the scan.
- Interception is off unless you configure it: without a proxy SyncHunt talks directly to the target.

## 6. Authenticated scanning

```bash
synchunt -d example.com --cookie "session=abc123" --header "Authorization: Bearer eyJ..."
```

or in `config.yaml`:

```yaml
general:
  cookie: "session=abc123"
  headers:
    - "Authorization: Bearer eyJ..."
    - "X-Bug-Bounty: handle"
```

- Applied to the shared HTTP session (every in-process request in every phase) and to the external tools
  that accept headers (nuclei, httpx, katana, ffuf, gobuster, feroxbuster, wfuzz, dalfox, sqlmap, arjun).
- Only header *names* are logged; values are kept out of the console, the SQLite database and the reports.
- Create a dedicated test account per program. Do not use a real user's session, and check the program's
  rules on automated scanning of authenticated areas before you enable the intrusive phases.

## 7. Offline helper CLI (`synchunt-tools`)

Shipped with the package (no extra install), for the small helpers that usually need `go install`:

```bash
synchunt-tools dedupe  urls.txt                  # anew
synchunt-tools unfurl  urls.txt --part keys      # unfurl
synchunt-tools gf      ssrf urls.txt             # gf + gf-patterns (14 built-in sets)
synchunt-tools meg-urls --hosts hosts.txt --paths paths.txt
synchunt-tools postman collection.json -o urls.txt
synchunt-tools hash-id hashes.txt                # hashcat -m / john --format preflight
synchunt-tools identify bundle.js                # hashes inside free text
```

Everything reads files or stdin and prints to stdout, so it composes in shell pipelines.

## 8. Hardening and data handling

- Run as a non-root user; the only privileged feature is raw-socket scanning.
- `output/` contains findings and possibly secrets: treat it as confidential, restrict permissions, and
  never commit it (`output/` is in `.gitignore`).
- Reports are written with escaped values and a restrictive CSP; the SARIF/JSON exports are plain data.
- `--dry-run` prints the plan without sending traffic; run it in CI to validate scope/config changes.
- Rate limits matter: `--rate-limit` and per-tool `rate`/`threads` settings are the knobs to turn down
  when a program asks for polite scanning.

## 9. Platform support

SyncHunt runs on Linux, macOS and Windows with the same command set and the same artifacts.

| Concern | Linux / macOS | Windows |
|---|---|---|
| Console encoding | UTF-8, with automatic ASCII fallback for legacy terminals | UTF-8 stdio reconfigured at start-up; ASCII fallback available with `SYNCHUNT_ASCII=1` |
| Child processes | new session + process group | same environment hygiene via `PYTHONIOENCODING=utf-8` |
| Tool shutdown | `SIGTERM` → `SIGKILL` to the whole process group | `taskkill /F /T /PID` (tree kill) |
| File I/O | explicit UTF-8 everywhere | explicit UTF-8 everywhere (byte-identical artifacts) |
| Verification | `./scripts/check.sh` or `python3 scripts/check.py` | `python3 scripts/check.py` (pure Python) |

Notes and caveats:

- Raw-socket scanners (`naabu`, `nmap -sS`, `masscan`, `rustscan`) require elevated privileges on Linux
  and macOS; SyncHunt falls back to TCP-connect scans when they are unavailable or unauthorised. On
  Windows, prefer the Go-based tools (`naabu`, `httpx`, `nuclei`) installed via `scoop`/`choco`.
- External tools are optional everywhere: a missing binary degrades the phase and is reported by
  `--doctor` / `--install-deps`.
- Container images (`Dockerfile`, targets `slim` and default) are Linux-based and run unprivileged; the
  same code paths are exercised on Windows by the CI matrix.
- `--doctor` prints a one-line platform summary (OS, release, Python, CPU count) so bug reports can
  state the exact environment.
