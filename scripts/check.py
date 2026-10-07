#!/usr/bin/env python3
"""
SyncHunt - cross-platform verification runner

Same sweep as scripts/check.sh, but pure Python so it behaves identically on
Linux, macOS and Windows (no bash, no `timeout`, no coreutils):

    python scripts/check.py            # full sweep
    python scripts/check.py --quick    # skip the slower dry-run/doctor checks
    python scripts/check.py --jobs 4   # limit parallelism

Checks run in parallel, logs land in .check/<name>.log, and the exit code is
non-zero if anything real failed. The doctor check is informational: missing
external tools are expected on a fresh machine and never fail the sweep.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(ROOT, ".check")
PY = sys.executable or "python3"

PYTHON_FILES = ["core", "modules", "reports", "main.py", "tools_cli.py", "tests"]


def _run_pytest_in_process(log_path: str, pytest_args: List[str]) -> int:
    """
    Fallback for sandboxes that reap a pytest grandchild: run the suite in
    this interpreter instead, teeing output to the check log.
    """
    import contextlib

    import pytest

    with open(log_path, "w", encoding="utf-8", errors="replace") as handle:
        with contextlib.redirect_stdout(handle), contextlib.redirect_stderr(handle):
            return int(pytest.main(pytest_args))


def _run(argv: List[str], log_name: str, timeout: Optional[int] = None) -> Tuple[int, str, float]:
    """Run one check, capturing output to .check/<log_name>.log."""
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, f"{log_name}.log")
    started = time.time()
    try:
        with open(log_path, "w", encoding="utf-8", errors="replace") as handle:
            completed = subprocess.run(
                argv, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT,
                timeout=timeout, check=False,
            )
        code = completed.returncode
        if code is not None and code < 0 and "-m" in argv and "pytest" in argv:
            # killed by a signal (some sandboxes reap nested pytest runs)
            code = _run_pytest_in_process(log_path, argv[argv.index("pytest") + 1:])
    except subprocess.TimeoutExpired:
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(f"\n[check] timed out after {timeout}s\n")
        code = 124
    except FileNotFoundError:
        with open(log_path, "w", encoding="utf-8") as handle:
            handle.write(f"[check] command not found: {argv[0]}\n")
        code = 127
    return code, log_path, time.time() - started


def _tail(path: str, lines: int = 6) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            content = handle.read().splitlines()
        return "\n".join(content[-lines:])
    except OSError:
        return ""


def build_checks(quick: bool) -> List[Tuple[str, List[str], Optional[int], bool]]:
    """
    (name, argv, timeout, informational)

    `informational` checks are reported but never fail the sweep (the doctor
    exits 1 whenever optional external tools are missing).
    """
    checks: List[Tuple[str, List[str], Optional[int], bool]] = [
        ("pytest", [PY, "-m", "pytest", "tests", "-q"], 1800, False),
        ("pyflakes", [PY, "-m", "pyflakes", *PYTHON_FILES], 300, False),
        ("compile", [PY, "-m", "compileall", "-q", "core", "modules", "reports", "main.py", "tools_cli.py"], 300, False),
        ("list-phases", [PY, "main.py", "--list-phases"], 120, False),
        ("list-languages", [PY, "main.py", "--list-languages"], 120, False),
    ]
    if not quick:
        checks += [
            ("doctor", [PY, "main.py", "--doctor"], 300, True),
            ("dry-run", [PY, "main.py", "-d", "example.com", "--dry-run",
                         "--output-dir", os.path.join(LOG_DIR, "dryrun")], 300, False),
        ]
    return checks


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="check.py", description=__doc__.split("\n")[1])
    parser.add_argument("--quick", action="store_true", help="skip doctor + dry-run")
    parser.add_argument("--jobs", type=int, default=0, help="parallel checks (default: all)")
    args = parser.parse_args(argv)

    checks = build_checks(args.quick)
    jobs = args.jobs or len(checks)
    print("SyncHunt verification (cross-platform) — logs in .check/")

    results: Dict[str, Tuple[str, float, str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        futures = {
            pool.submit(_run, argv_, name, timeout): (name, informational)
            for name, argv_, timeout, informational in checks
        }
        for future in concurrent.futures.as_completed(futures):
            name, informational = futures[future]
            code, log_path, duration = future.result()
            if code == 0:
                status = "ok"
            elif informational:
                status = "ok (external tools missing)"
            else:
                status = f"FAILED (exit {code})"
            results[name] = (status, duration, log_path)
            print(f"  {name:<15} {status:<32} {duration:5.1f}s")

    failures = [
        name for name, (status, _duration, _log) in results.items()
        if status.startswith("FAILED")
    ]
    for name in failures:
        print(f"\n--- {name} (last lines) ---")
        print(_tail(results[name][2]))

    print()
    if failures:
        print(f"failed: {', '.join(failures)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
