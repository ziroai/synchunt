# SyncHunt Architecture

This document explains how the framework is put together, where state lives, and how to extend it.

## 1. Design goals

1. **One pipeline, one entry point.** `main.py` orchestrates 16 phases; each phase is a self-contained module in `modules/`.
2. **Graceful degradation.** External tools are optional. If a tool is missing or disabled it is skipped with a hint, and where practical the phase has a built-in fallback (crt.sh, HTTP prober, header fingerprinting, OpenAPI/GraphQL probes, cloud enumeration).
3. **Safety by construction.** No `shell=True` in the scanning path, rate-limited HTTP, scope filtering enforced before active work, secrets redacted in reports.
4. **Everything correlates.** Every phase reports into a per-run SQLite database (`scans`, `phases`, `assets`, `findings`) with fingerprint-based de-duplication; reports and exports are generated from that database.
5. **Testable without the internet.** The core is pure Python; the test suite runs entirely against local fixtures, no external tool or network required.

## 2. Layering

```
main.py                      CLI + orchestrator (phase registry, resume, reports)
│
├── modules/                 one module per phase (subdomain_enum, subdomain_takeover,
│                            vuln_scanning, …)
│
├── core/
│   ├── context.py           ScanContext: target, paths, config, logger, DB, scope
│   ├── runner.py            ToolRunner: safe subprocess execution (timeouts, killpg)
│   ├── config_manager.py    config.yaml: profiles, dot-paths, tool gates, validate()
│   ├── database_manager.py  SQLite correlation store
│   ├── models.py            Finding / Asset / PhaseResult dataclasses
│   ├── net.py               shared HTTP layer (rate limiter, retries, TLS, DNS)
│   ├── secrets.py           secret pattern engine (entropy gate + redaction)
│   ├── history.py           re-scan diffing (new / fixed / persisting)
│   ├── utils.py             scope/domain/URL helpers, IO, shell-free command helpers
│   ├── logger.py            console + per-run file logging
│   ├── auth.py              --cookie/--header handling (values never logged)
│   ├── threatintel.py       CISA KEV + FIRST EPSS lookup and scoring bonus
│   ├── i18n.py              language catalogues and translation lookup
│   ├── platform_compat.py   UTF-8 console, child env, cross-platform process control
│   └── dependency_checker.py external tool detection and install hints
│
└── reports/                 html_report, markdown_report, data_export,
                             sarif_export, submission_export, notifier
```

Offline helpers for tools that are not safe or meaningful to run automatically live in `tools_cli.py`
(`synchunt-tools`): `dedupe` (anew), `unfurl`, `gf` pattern matching, `meg` URL matrices, Postman
collection parsing and hashcat/john preflight.

Dependency direction is one-way: `modules → core → (stdlib)`, and `reports → core`. Nothing in `core/` imports a phase module.

## 3. Phase pipeline

The phase registry lives in `main.py`:

```python
PHASES = [Phase("subdomain", "subdomain_enum", 1, build, produces=[...], requires=[...]), …]
PHASE_BY_NAME = {...}
PHASE_ORDER = [...]
```

Each `Phase` declares:

- `name` — CLI name (`--phase subdomain,validation`),
- `module` / `build` — how to construct the phase object,
- `requires` / `produces` — artifact keys used for resume and result counting.

### Artifact resolution

Phases write into canonical subdirectories under the run directory (`dns/live_hosts.txt`, `content_discovery/all_urls.txt`, …) and register them on the context:

```python
ctx.set_file("live_hosts", path)
```

Downstream phases read artifacts through:

```python
ctx.resolve_file("live_hosts", "dns", "live_hosts.txt")
```

which prefers an explicitly registered path, then the canonical location if it exists (for example after `--resume`, or when a previous phase ran in an earlier invocation), and finally the canonical path.

### Run flow (`SyncHunt._run_target`)

1. Validate phases (`_select_phases`) and targets (`_parse_targets`).
2. Open a scan row in the database (`DatabaseManager.start_scan`).
3. For each selected phase:
   - skip when `requires` artifacts are missing,
   - build the phase instance and run `run_all()`,
   - record a `PhaseResult` (status, duration, result count),
   - persist `scan_state.json` (resume) and sync artifact keys.
4. Enforce scope once a host list exists.
5. Print the summary, optionally notify, generate reports, close the DB.

Exit codes: `0` success, `1` error, `2` usage error, `3` no valid targets, `130` interrupted.

## 4. Data model

`core/models.py`:

- `Finding` — category, title, severity, confidence, target, url, evidence, source, score, tags, references, `extra`. `fingerprint()` hashes category + title + URL + evidence so the same issue is never stored twice.
- `Asset` — kind (`subdomain`, `host`, `port`, `url`, `bucket`, …), value, host/port, source, metadata.
- `PhaseResult` — phase name, status, duration, result count, notes.

`core/database_manager.py` schema:

```sql
scans(id, target, profile, output_dir, started_at, finished_at, status, stats_json)
phases(id, scan_id → scans.id, phase, status, duration, result_count, notes, updated_at,
       UNIQUE(scan_id, phase))
assets(id, scan_id → scans.id, kind, value, host, port, source, meta_json, created_at,
       UNIQUE(scan_id, kind, value))
findings(id, scan_id → scans.id, fingerprint, category, title, severity, confidence,
         target, url, evidence, source, score, tags_json, extra_json, created_at,
         UNIQUE(scan_id, fingerprint))
```

Helper queries used by the orchestrator and reports: `completed_phases`, `add_asset(s)`, `add_finding(s)`, `update_score`, `findings(min_severity=…)`, `severity_counts`, `category_counts`, `scan_summary`.

## 5. Networking, secrets, scope

- **`core/net.py`** — every HTTP call goes through a `requests.Session` built by `build_session()` with retries and a shared `RateLimiter`. `HttpResult` wraps status/headers/text/error and exposes `.ok`, `.reachable`, `.header(name)`. `probe()` never follows redirects; JSON APIs use `http_request`/`post_json`. TLS peer info, DNS resolution and scheme discovery live here too.
- **`core/secrets.py`** — ~20 built-in patterns (cloud keys, tokens, private keys, connection strings, …) combined with `js_analysis.custom_regex.patterns` from config via `build_patterns()`. Matches below the entropy threshold are dropped; `SecretMatch.to_dict()` redacts the value and `fingerprint()` supports de-duplication.
- **`core/utils.py`** — `target_slug()` is the single source of truth for the `output/<target>/<run>` directory names (used by `ConfigManager.get_output_dir`, `latest_output_dir` and scan history); scope matching (`is_in_scope`, `host_matches_domain`) is boundary-correct and supports domains, wildcards, IPs, CIDRs and `host:port`; `get_root_domain` understands multi-part TLDs; command construction uses argument lists (`runner_command`, `quote_args`) so nothing touches a shell.

## 6. Re-scan diffing

`core/history.py` compares a finished scan with the most recent earlier run for the same target:

- `find_previous_run(base_output, target, current_run_dir)` walks `base_output/<target_slug>/` newest-first, skipping the current run and any directory without a findings file (dry-runs, interrupted first passes).
- `load_findings(run_dir)` reads `findings_prioritized/findings.json` (falling back to `reports/findings.json`).
- `compare(current, previous)` matches on **identity** (category + title + location) first and the exact fingerprint second, annotates each current `Finding` with `extra["history"] = "new" | "persisting"` and returns a `HistoryReport` with `new`, `fixed`, `persisting` and `previous_total` counts.

Matching on identity rather than the fingerprint matters: the fingerprint includes evidence (correct for de-duplicating one run), so a response body changing one byte would otherwise look like one issue fixed plus one issue discovered.

The report phase writes `reports/history.json`, adds a "Since last scan" section to the HTML/Markdown reports, adds a `history` column to the CSV/JSON exports and includes the counts in `scan_data.json` and in `--json-report`.

## 7. CI exports

- **`reports/sarif_export.py`** — SARIF 2.1.0 log compatible with GitHub code scanning and other CI dashboards. One SARIF *rule* per finding category (`synchunt/<category>`), results sorted by severity, severities mapped to `error` / `warning` / `note`, fingerprints in `partialFingerprints` so alerts survive re-runs, and severity/priority/score/source preserved in `properties`.
- **`--json-report PATH`** — one JSON document per invocation: tool + version, duration, exit code, requested targets, and per-target status, severity/category counts, top findings, artifact paths and history counts. `run_reports` is built as targets finish and written by `_write_json_report()` in `main.py`.

Both are controlled by `reporting.sarif_export` / `reporting.track_history` and are on by default.

## 8. Configuration model

`ConfigManager` loads `config.yaml` and exposes:

- dot-path access (`get("vuln_scanning.nuclei.enabled")`),
- typed getters (`get_bool`, `get_int`, `get_float`, `get_list`),
- profile handling (`profile_phases()`, `available_profiles()`),
- tool gates (`is_tool_enabled(phase, tool)`, `disabled_tools(phase)`),
- output selection (`get_output_dir(target, run_id)`, `latest_output_dir(target)` for `--resume`),
- `validate(known_phases)` for `--doctor` (profiles, scope files, wordlists, rate limits).

`ConfigManager(..., allow_missing=True)` is used by the read-only commands (`--list-phases`,
`--check-deps`, `--install-deps`, `--doctor`) so an installed SyncHunt works outside a checkout;
scans still require a real config file and fail with exit `2` when it is missing. Those commands
are also the only ones that do not create the output directory.

CLI flags override config values; environment variables can supply secrets (GitHub token, Shodan key, webhooks).

## 9. Adding a phase

1. Create `modules/my_phase.py` with a class that takes `ScanContext` and implements `run_all() -> str | None`.
2. Read inputs via `ctx.resolve_file(key, *default_parts)`, write outputs under `ctx.path("my_phase")`.
3. Record findings with `ctx.add_finding(...)` / `ctx.database.add_finding(...)`; use `Finding.extra` for structure you want preserved.
4. Register the phase in `main.py` (`PHASES`), add artifact keys to `DEFAULT_FILES`, and add the phase to any profile that should include it.
5. Add tests under `tests/`. Use the `local_server` fixture rather than the network; mock `ToolRunner.run` for external tools.

## 10. Adding a tool to an existing phase

1. Add a `tool_name: {enabled: true}` block to the phase section in `config.yaml`.
2. In the module, gate on `self.config.is_tool_enabled("phase", "tool")` and run it through `ctx.runner.run(argv, timeout=…)`.
3. Prefer machine-readable output (`-json`, `-jsonl`) and parse it; never build commands with `shell=True`.

## 11. Testing strategy

- `tests/conftest.py` provides fixtures: `config_path` (minimal config with external tools disabled), `config`, `logger`, `runner`, `ctx` (temporary run directory + SQLite scan), and `local_server` (a deterministic HTTP fixture serving an OpenAPI spec, GraphQL introspection, admin paths, etc.).
- `tests/test_phases_local.py` runs real phases against the fixture server.
- `tests/test_cli.py` covers the documented CLI behaviour, including `--check-deps`, `--doctor`, `--list-phases`, phase selection and target parsing.
- `tests/test_reports_and_exports.py` covers HTML escaping, Markdown rendering and the JSON/CSV exporters.

## 12. Security model

- All command execution is argument-list based (`ToolRunner`); user/target-derived strings never reach a shell.
- Active work is scope-filtered; scope is enforced as soon as a host list exists and never loosens mid-run.
- Reports escape every interpolated value and set a restrictive CSP meta tag.
- Secrets found during scanning are redacted before they are written to reports; the raw corpus stays in the run directory.
- `--dry-run` prints the plan and exits before any traffic is sent.

## 13. Internationalisation

- `core/i18n.py` holds one catalogue per language (`en`, `es`, `fr`, `de`, `pt`, `hi`, `ja`, `zh`) under
  dotted keys (`cli.*`, `summary.*`, `report.*`, `notify.*`). `t()` looks up the current language, falls
  back to English, then to the key itself — a missing or malformed entry can never raise.
- Resolution order: `--lang` → `general.language` in `config.yaml` → `SYNCHUNT_LANG` → `LANG` → English.
- Only human-readable text is translated. Tool names, phase identifiers, config keys, file names and
  JSON/CSV field names stay English so automation and CI parsing are language-independent.
- `main.py` translates the CLI status lines; `reports/markdown_report.py`, `reports/html_report.py` and
  `reports/notifier.py` translate their human-facing headings. `--list-languages` prints the catalogue in
  its own language.

## 14. Platform compatibility

- `core/platform_compat.py` is the single place that knows about the operating system:
  - `configure_stdio()` reconfigures stdio to UTF-8 where the runtime supports it, and `sanitize()`
    degrades box-drawing and emoji to ASCII when needed (`SYNCHUNT_ASCII=1`, non-UTF-8 consoles).
  - `child_env()` gives every subprocess `PYTHONIOENCODING=utf-8` / `PYTHONUTF8=1` so tool output parses
    identically everywhere; `spawn_kwargs()` creates a new session/process group on POSIX only.
  - `kill_process_tree()` terminates a tool *and its children* — `killpg` on POSIX, `taskkill /F /T` on
    Windows — so a timed-out scanner cannot leave orphan processes behind.
  - `platform_summary()` reports OS, release, Python and CPU count (surfaced by `--doctor`).
- Every text read/write in the framework passes an explicit `encoding="utf-8"`, which makes artifacts
  byte-identical across platforms.
- `scripts/check.py` is the OS-neutral verification runner (bash is not required); `scripts/check.sh`
  wraps it for POSIX environments.
