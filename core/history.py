"""
SyncHunt - Scan history

Answers the only question that matters on a re-scan: *what is new, what got
fixed, and what is still there?*

The comparison is deliberately filesystem based: it reads the findings JSON
from the most recent earlier run directory for the same target. That keeps it
independent of any single correlation database, works after `--resume` runs,
and costs nothing when there is no previous run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from core.models import Finding
from core.utils import load_json, severity_rank, target_slug

# Where a finished run keeps its findings, in preference order.
FINDINGS_PATHS = (
    ("findings_prioritized", "findings.json"),
    ("reports", "findings.json"),
)

NEW = "new"
PERSISTING = "persisting"


# ----------------------------------------------------------------------
# Previous-run discovery
# ----------------------------------------------------------------------
def find_previous_run(base_output: str, target: str,
                      current_run_dir: str = "") -> Optional[str]:
    """
    Most recent earlier run directory for `target` that contains findings.

    Runs without a findings file (dry-runs, interrupted first passes) are
    skipped, and `current_run_dir` itself is never returned.
    """
    target_dir = os.path.join(base_output, target_slug(target))
    if not os.path.isdir(target_dir):
        return None

    current = os.path.abspath(current_run_dir) if current_run_dir else ""
    for name in sorted(os.listdir(target_dir), reverse=True):
        candidate = os.path.join(target_dir, name)
        if not os.path.isdir(candidate):
            continue
        if current and os.path.abspath(candidate) == current:
            continue
        if any(os.path.exists(os.path.join(candidate, *parts))
               for parts in FINDINGS_PATHS):
            return candidate
    return None


def load_findings(run_dir: str) -> List[Dict[str, Any]]:
    """Load the findings list from a finished run directory ([] if absent)."""
    for parts in FINDINGS_PATHS:
        data = load_json(os.path.join(run_dir, *parts), None)
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
    return []


# ----------------------------------------------------------------------
# Comparison
# ----------------------------------------------------------------------
def _row(finding: Finding) -> Dict[str, Any]:
    return {
        "fingerprint": finding.fingerprint(),
        "title": finding.title,
        "severity": finding.severity,
        "category": finding.category,
        "url": finding.url,
        "target": finding.target,
        "priority": finding.extra.get("priority", ""),
        "score": finding.score,
    }


def _identity(category: Any, title: Any, url: Any, target: Any) -> str:
    """
    Stable identity for cross-run matching.

    The database fingerprint includes evidence, which is right for de-duping a
    single run but too strict across runs: a response body changing one byte
    would look like "one issue fixed, one issue appeared". Matching on
    category + title + location keeps the diff honest.
    """
    def norm(value: Any) -> str:
        return " ".join(str(value or "").lower().split())

    return f"{norm(category)}|{norm(title)}|{norm(url or target)}"


def _sort_key(row: Dict[str, Any]):
    try:
        score = float(row.get("score") or 0)
    except (TypeError, ValueError):
        score = 0.0
    return (-severity_rank(str(row.get("severity") or "info")), -score,
            str(row.get("title") or ""))


@dataclass
class HistoryReport:
    """Difference between the current scan and the previous one."""

    previous_run: str = ""
    new: List[Dict[str, Any]] = field(default_factory=list)
    fixed: List[Dict[str, Any]] = field(default_factory=list)
    persisting: int = 0
    previous_total: int = 0

    @property
    def has_previous(self) -> bool:
        return bool(self.previous_run)

    @property
    def new_critical_high(self) -> int:
        return sum(
            1 for row in self.new
            if str(row.get("severity") or "").lower() in ("critical", "high")
        )

    def counts(self) -> Dict[str, int]:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "persisting": self.persisting,
            "previous_total": self.previous_total,
            "new_critical_high": self.new_critical_high,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "previous_run": self.previous_run,
            "counts": self.counts(),
            "new": self.new,
            "fixed": self.fixed,
        }


def compare(current: Iterable[Finding], previous: Iterable[Dict[str, Any]],
            previous_run: str = "") -> HistoryReport:
    """
    Compare current findings against the previous run's findings.

    Side effect: every current `Finding` is annotated with
    ``extra["history"] = "new" | "persisting"`` so reports and exports can
    show the status without recomputing anything.
    """
    rows = [row for row in previous if isinstance(row, dict)]
    index_by_fingerprint: Dict[str, int] = {}
    index_by_identity: Dict[str, int] = {}
    for index, row in enumerate(rows):
        fingerprint = str(row.get("fingerprint") or "")
        if fingerprint:
            index_by_fingerprint.setdefault(fingerprint, index)
        identity = _identity(row.get("category"), row.get("title"),
                             row.get("url"), row.get("target"))
        if identity.strip("|"):
            index_by_identity.setdefault(identity, index)

    report = HistoryReport(previous_run=previous_run,
                           previous_total=len(rows))
    matched: set = set()
    for finding in current:
        identity = _identity(finding.category, finding.title,
                             finding.url, finding.target)
        index = index_by_fingerprint.get(finding.fingerprint())
        if index is None and identity.strip("|"):
            index = index_by_identity.get(identity)
        if index is not None:
            matched.add(index)
            report.persisting += 1
            finding.extra["history"] = PERSISTING
        else:
            report.new.append(_row(finding))
            finding.extra["history"] = NEW

    report.new.sort(key=_sort_key)
    report.fixed = [row for index, row in enumerate(rows) if index not in matched]
    report.fixed.sort(key=_sort_key)
    return report
