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

## 5. Hardening and data handling

- Run as a non-root user; the only privileged feature is raw-socket scanning.
- `output/` contains findings and possibly secrets: treat it as confidential, restrict permissions, and
  never commit it (`output/` is in `.gitignore`).
- Reports are written with escaped values and a restrictive CSP; the SARIF/JSON exports are plain data.
- `--dry-run` prints the plan without sending traffic; run it in CI to validate scope/config changes.
- Rate limits matter: `--rate-limit` and per-tool `rate`/`threads` settings are the knobs to turn down
  when a program asks for polite scanning.
