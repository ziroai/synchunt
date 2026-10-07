"""
SyncHunt - Shared data models
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.utils import normalize_severity, short_hash, severity_rank, truncate


@dataclass
class Finding:
    """A normalised finding produced by any phase."""

    category: str
    title: str
    severity: str = "info"
    target: str = ""
    url: str = ""
    evidence: str = ""
    source: str = ""
    confidence: str = "medium"
    score: float = 0.0
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.severity = normalize_severity(self.severity)
        self.evidence = truncate(self.evidence, 2000)
        self.title = truncate(self.title, 300)

    # ------------------------------------------------------------------
    @property
    def severity_rank(self) -> int:
        return severity_rank(self.severity)

    def fingerprint(self) -> str:
        """Stable identity used for cross-phase de-duplication."""
        return short_hash(
            self.category.lower(),
            self.title.lower()[:120],
            (self.url or self.target).lower(),
            self.evidence[:200].lower(),
        )

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "target": self.target,
            "url": self.url,
            "evidence": self.evidence,
            "source": self.source,
            "confidence": self.confidence,
            "score": round(float(self.score or 0.0), 2),
            "tags": list(self.tags),
            "references": list(self.references),
            "fingerprint": self.fingerprint(),
        }
        if self.extra:
            data["extra"] = self.extra
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(
            category=data.get("category", "unknown"),
            title=data.get("title", ""),
            severity=data.get("severity", "info"),
            target=data.get("target", ""),
            url=data.get("url", ""),
            evidence=data.get("evidence", ""),
            source=data.get("source", ""),
            confidence=data.get("confidence", "medium"),
            score=float(data.get("score") or 0.0),
            tags=list(data.get("tags") or []),
            references=list(data.get("references") or []),
            extra=dict(data.get("extra") or {}),
        )


@dataclass
class Asset:
    """A discovered asset (host, URL, cloud bucket, repository, ...)."""

    kind: str
    value: str
    source: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)
    host: str = ""
    port: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "host": self.host,
            "port": self.port,
            "source": self.source,
            "meta": self.meta,
        }


@dataclass
class PhaseResult:
    """Bookkeeping for one executed phase."""

    name: str
    status: str = "pending"  # pending|done|failed|skipped
    duration: float = 0.0
    result_count: int = 0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.name,
            "status": self.status,
            "duration": round(self.duration, 2),
            "result_count": self.result_count,
            "notes": truncate(self.notes, 500),
        }
