"""
SyncHunt - SQLite Correlation Store
Persists assets, findings and phase state so results can be correlated,
resumed and exported across phases and scan runs.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any, Dict, Iterable, List, Optional

from core.models import Asset, Finding, PhaseResult
from core.utils import ensure_dir, normalize_severity, severity_rank

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT NOT NULL,
    profile      TEXT,
    output_dir   TEXT,
    started_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    finished_at  TEXT,
    status       TEXT DEFAULT 'running',
    stats_json   TEXT
);

CREATE TABLE IF NOT EXISTS phases (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    phase        TEXT NOT NULL,
    status       TEXT NOT NULL,
    duration     REAL DEFAULT 0,
    result_count INTEGER DEFAULT 0,
    notes        TEXT,
    updated_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, phase)
);

CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    host       TEXT,
    port       INTEGER,
    source     TEXT,
    meta_json  TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, kind, value)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    category    TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    confidence  TEXT,
    target      TEXT,
    url         TEXT,
    evidence    TEXT,
    source      TEXT,
    score       REAL DEFAULT 0,
    tags_json   TEXT,
    extra_json  TEXT,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_assets_kind ON assets(kind);
"""


class DatabaseManager:
    """Small thread-safe wrapper around SQLite used by every phase."""

    def __init__(self, db_path: str):
        ensure_dir(os.path.dirname(db_path))
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            try:
                self._conn.commit()
                self._conn.close()
            except sqlite3.Error:  # pragma: no cover - defensive
                pass

    def __enter__(self) -> "DatabaseManager":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Scans & phases
    # ------------------------------------------------------------------
    def start_scan(self, target: str, profile: str = "", output_dir: str = "") -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans (target, profile, output_dir) VALUES (?, ?, ?)",
                (target, profile, output_dir),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_scan(
        self,
        scan_id: int,
        status: str = "finished",
        stats: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET finished_at=CURRENT_TIMESTAMP, status=?, stats_json=? "
                "WHERE id=?",
                (status, json.dumps(stats or {}, default=str), scan_id),
            )
            self._conn.commit()

    def latest_scan(self, target: str) -> Optional[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM scans WHERE target=? ORDER BY id DESC LIMIT 1", (target,)
            )
            return cur.fetchone()

    def record_phase(self, scan_id: int, result: PhaseResult) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO phases (scan_id, phase, status, duration, result_count, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, phase) DO UPDATE SET
                    status=excluded.status,
                    duration=excluded.duration,
                    result_count=excluded.result_count,
                    notes=excluded.notes,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    scan_id,
                    result.name,
                    result.status,
                    float(result.duration or 0),
                    int(result.result_count or 0),
                    result.notes or "",
                ),
            )
            self._conn.commit()

    def completed_phases(self, scan_id: int) -> List[str]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT phase FROM phases WHERE scan_id=? AND status IN ('done','skipped')",
                (scan_id,),
            )
            return [row["phase"] for row in cur.fetchall()]

    def phase_rows(self, scan_id: int) -> List[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM phases WHERE scan_id=? ORDER BY id", (scan_id,)
            )
            return cur.fetchall()

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------
    def add_asset(
        self,
        scan_id: int,
        kind: str,
        value: str,
        host: str = "",
        port: Optional[int] = None,
        source: str = "",
        meta: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Insert an asset; returns False when it was already known."""
        if not value:
            return False
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT OR IGNORE INTO assets (scan_id, kind, value, host, port, source, meta_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    kind,
                    str(value),
                    host or "",
                    int(port) if port else None,
                    source or "",
                    json.dumps(meta or {}, default=str),
                ),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def add_assets(self, scan_id: int, assets: Iterable[Asset]) -> int:
        added = 0
        for asset in assets:
            if self.add_asset(
                scan_id,
                asset.kind,
                asset.value,
                host=asset.host,
                port=asset.port,
                source=asset.source,
                meta=asset.meta,
            ):
                added += 1
        return added

    def count_assets(self, scan_id: int, kind: Optional[str] = None) -> int:
        with self._lock:
            if kind:
                cur = self._conn.execute(
                    "SELECT COUNT(*) AS c FROM assets WHERE scan_id=? AND kind=?",
                    (scan_id, kind),
                )
            else:
                cur = self._conn.execute(
                    "SELECT COUNT(*) AS c FROM assets WHERE scan_id=?", (scan_id,)
                )
            return int(cur.fetchone()["c"])

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def add_finding(self, scan_id: int, finding: Finding) -> bool:
        """Insert a finding; returns False when it is a duplicate."""
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT OR IGNORE INTO findings
                    (scan_id, fingerprint, category, title, severity, confidence,
                     target, url, evidence, source, score, tags_json, extra_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    finding.fingerprint(),
                    finding.category,
                    finding.title,
                    normalize_severity(finding.severity),
                    finding.confidence,
                    finding.target,
                    finding.url,
                    finding.evidence,
                    finding.source,
                    float(finding.score or 0.0),
                    json.dumps(finding.tags, default=str),
                    json.dumps(finding.extra, default=str),
                ),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def add_findings(self, scan_id: int, findings: Iterable[Finding]) -> int:
        added = 0
        for finding in findings:
            if self.add_finding(scan_id, finding):
                added += 1
        return added

    def update_score(
        self,
        scan_id: int,
        fingerprint: str,
        score: float,
        priority: Optional[str] = None,
        reasons: Optional[Iterable[str]] = None,
    ) -> None:
        """Persist a prioritisation score (and optionally priority + reasons)."""
        with self._lock:
            if priority or reasons:
                cur = self._conn.execute(
                    "SELECT extra_json FROM findings WHERE scan_id=? AND fingerprint=?",
                    (scan_id, fingerprint),
                )
                row = cur.fetchone()
                try:
                    extra = json.loads(row["extra_json"] or "{}") if row else {}
                except ValueError:
                    extra = {}
                if priority:
                    extra["priority"] = priority
                if reasons:
                    extra["score_reasons"] = list(reasons)
                self._conn.execute(
                    "UPDATE findings SET score=?, extra_json=? WHERE scan_id=? AND fingerprint=?",
                    (float(score), json.dumps(extra, default=str), scan_id, fingerprint),
                )
            else:
                self._conn.execute(
                    "UPDATE findings SET score=? WHERE scan_id=? AND fingerprint=?",
                    (float(score), scan_id, fingerprint),
                )
            self._conn.commit()

    def findings(
        self,
        scan_id: int,
        min_severity: str = "info",
        limit: Optional[int] = None,
    ) -> List[Finding]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM findings WHERE scan_id=?", (scan_id,)
            )
            rows = cur.fetchall()
        findings = [self._row_to_finding(row) for row in rows]
        threshold = severity_rank(min_severity)
        findings = [f for f in findings if f.severity_rank >= threshold]
        findings.sort(key=lambda f: (-f.score, -f.severity_rank, f.title))
        return findings[:limit] if limit else findings

    def finding_count(self, scan_id: int) -> int:
        with self._lock:
            cur = self._conn.execute(
                "SELECT COUNT(*) AS c FROM findings WHERE scan_id=?", (scan_id,)
            )
            return int(cur.fetchone()["c"])

    def severity_counts(self, scan_id: int) -> Dict[str, int]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT severity, COUNT(*) AS c FROM findings WHERE scan_id=? "
                "GROUP BY severity",
                (scan_id,),
            )
            counts = {row["severity"]: int(row["c"]) for row in cur.fetchall()}
        for level in ("critical", "high", "medium", "low", "info"):
            counts.setdefault(level, 0)
        return counts

    def category_counts(self, scan_id: int) -> Dict[str, int]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT category, COUNT(*) AS c FROM findings WHERE scan_id=? "
                "GROUP BY category ORDER BY c DESC",
                (scan_id,),
            )
            return {row["category"]: int(row["c"]) for row in cur.fetchall()}

    def top_findings(self, scan_id: int, limit: int = 10) -> List[Finding]:
        return self.findings(scan_id, limit=limit)

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------
    def scan_summary(self, scan_id: int) -> Dict[str, Any]:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
            scan = cur.fetchone()
        if not scan:
            return {}
        return {
            "scan_id": scan_id,
            "target": scan["target"],
            "profile": scan["profile"],
            "status": scan["status"],
            "started_at": scan["started_at"],
            "finished_at": scan["finished_at"],
            "assets": self.count_assets(scan_id),
            "findings": self.finding_count(scan_id),
            "severity": self.severity_counts(scan_id),
            "categories": self.category_counts(scan_id),
            "phases": [dict(row) for row in self.phase_rows(scan_id)],
        }

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        try:
            tags = json.loads(row["tags_json"] or "[]")
        except ValueError:
            tags = []
        try:
            extra = json.loads(row["extra_json"] or "{}")
        except ValueError:
            extra = {}
        finding = Finding(
            category=row["category"],
            title=row["title"],
            severity=row["severity"],
            target=row["target"] or "",
            url=row["url"] or "",
            evidence=row["evidence"] or "",
            source=row["source"] or "",
            confidence=row["confidence"] or "medium",
            score=float(row["score"] or 0.0),
            tags=tags,
            extra=extra,
        )
        return finding


def default_db_path(output_dir: str) -> str:
    """Canonical DB filename inside an output directory."""
    return os.path.join(output_dir, "synchunt_results.db")
