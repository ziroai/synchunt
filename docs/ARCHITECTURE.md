# SyncHunt Architecture

This document explains how the framework is put together, where state lives, and how to extend it.

## 1. Design goals

1. **One pipeline, one entry point.** `main.py` orchestrates 15 phases; each phase is a self-contained module in `modules/`.
2. **Graceful degradation.** External tools are optional. If a tool is missing or disabled it is skipped with a hint, and where practical the phase has a built-in fallback (crt.sh, HTTP prober, header fingerprinting, OpenAPI/GraphQL probes, cloud enumeration).
3. **Safety by construction.** No `shell=True` in the scanning path, rate-limited HTTP, scope filtering enforced before active work, secrets redacted in reports.
4. **Everything correlates.** Every phase reports into a per-run SQLite database (`scans`, `phases`, `assets`, `findings`) with fingerprint-based de-duplication; reports and exports are generated from that database.
5. **Testable without the internet.** The core is pure Python; the test suite runs entirely against local fixtures, no external tool or network required.

## 2. Layering

```
main.py                      CLI + orchestrator (phase registry, resume, reports)
│
├── modules/                 one module per phase (subdomain_enum, vuln_scanning, …)
│
├── core/
│   ├── context.py           ScanContext: target, paths, config, logger, DB, scope
│   ├── runner.py            ToolRunner: safe subprocess execution (timeouts, killpg)
│   ├── config_manager.py    config.yaml: profiles, dot-paths, tool gates, validate()
│   ├── database_manager.py  SQLite correlation store
│   ├── models.py            Finding / Asset / PhaseResult dataclasses
│   ├── net.py               shared HTTP layer (rate limiter, retries, TLS, DNS)
│   ├── secrets.py           secret pattern engine (entropy gate + redaction)
│   ├── utils.py             scope/domain/URL helpers, IO, shell-free command helpers
│   ├── logger.py            console + per-run file logging
│   └── dependency_checker.py external tool detection and install hints
│
└── reports/                 html_report, markdown_report, data_export, notifier
```

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
- **`core/utils.py`** — scope matching (`is_in_scope`, `host_matches_domain`) is boundary-correct and supports domains, wildcards, IPs, CIDRs and `host:port`; `get_root_domain` understands multi-part TLDs; command construction uses argument lists (`runner_command`, `quote_args`) so nothing touches a shell.

## 6. Configuration model

`ConfigManager` loads `config.yaml` and exposes:

- dot-path access (`get("vuln_scanning.nuclei.enabled")`),
- typed getters (`get_bool`, `get_int`, `get_float`, `get_list`),
- profile handling (`profile_phases()`, `available_profiles()`),
- tool gates (`is_tool_enabled(phase, tool)`, `disabled_tools(phase)`),
- output selection (`get_output_dir(target, run_id)`, `latest_output_dir(target)` for `--resume`),
- `validate(known_phases)` for `--doctor` (profiles, scope files, wordlists, rate limits).

CLI flags override config values; environment variables can supply secrets (GitHub token, Shodan key, webhooks).

## 7. Adding a phase

1. Create `modules/my_phase.py` with a class that takes `ScanContext` and implements `run_all() -> str | None`.
2. Read inputs via `ctx.resolve_file(key, *default_parts)`, write outputs under `ctx.path("my_phase")`.
3. Record findings with `ctx.add_finding(...)` / `ctx.database.add_finding(...)`; use `Finding.extra` for structure you want preserved.
4. Register the phase in `main.py` (`PHASES`), add artifact keys to `DEFAULT_FILES`, and add the phase to any profile that should include it.
5. Add tests under `tests/`. Use the `local_server` fixture rather than the network; mock `ToolRunner.run` for external tools.

## 8. Adding a tool to an existing phase

1. Add a `tool_name: {enabled: true}` block to the phase section in `config.yaml`.
2. In the module, gate on `self.config.is_tool_enabled("phase", "tool")` and run it through `ctx.runner.run(argv, timeout=…)`.
3. Prefer machine-readable output (`-json`, `-jsonl`) and parse it; never build commands with `shell=True`.

## 9. Testing strategy

- `tests/conftest.py` provides fixtures: `config_path` (minimal config with external tools disabled), `config`, `logger`, `runner`, `ctx` (temporary run directory + SQLite scan), and `local_server` (a deterministic HTTP fixture serving an OpenAPI spec, GraphQL introspection, admin paths, etc.).
- `tests/test_phases_local.py` runs real phases against the fixture server.
- `tests/test_cli.py` covers the documented CLI behaviour, including `--check-deps`, `--doctor`, `--list-phases`, phase selection and target parsing.
- `tests/test_reports_and_exports.py` covers HTML escaping, Markdown rendering and the JSON/CSV exporters.

## 10. Security model

- All command execution is argument-list based (`ToolRunner`); user/target-derived strings never reach a shell.
- Active work is scope-filtered; scope is enforced as soon as a host list exists and never loosens mid-run.
- Reports escape every interpolated value and set a restrictive CSP meta tag.
- Secrets found during scanning are redacted before they are written to reports; the raw corpus stays in the run directory.
- `--dry-run` prints the plan and exits before any traffic is sent.
