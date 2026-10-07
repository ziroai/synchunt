"""
SyncHunt - Scan Context
A single object passed to every phase: config, logger, runner, database,
scope, shared HTTP session and rate limiter, plus resolved file paths.

Sharing one session + limiter keeps request rates honest across phases,
which matters both for target stability and for staying within program rules.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.config_manager import ConfigManager
from core.logger import BugHuntLogger
from core.auth import auth_headers as _auth_headers, header_pairs as _header_pairs
from core.net import RateLimiter, build_session
from core.runner import ToolRunner


@dataclass
class ScanContext:
    """Everything a phase needs to run."""

    target: str
    output_dir: str
    config: ConfigManager
    logger: BugHuntLogger
    runner: ToolRunner
    scope: Any = None
    database: Any = None
    scan_id: Optional[int] = None
    profile: str = ""

    # Shared network resources
    session: Any = None
    limiter: Any = None

    # Files produced/consumed between phases
    files: Dict[str, str] = field(default_factory=dict)
    install_hints: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.session is None:
            self.session = build_session(
                user_agent=self.config.get("general.user_agent", "") or None,
                retries=self.config.get_int("general.retry", 2),
                extra_headers=_auth_headers(self.config),
            )
        if self.limiter is None:
            self.limiter = RateLimiter(self.config.get_rate_limit())

    # ------------------------------------------------------------------
    def auth_headers(self) -> Dict[str, str]:
        """Cookie/token headers applied to every in-process request."""
        return _auth_headers(self.config)

    def header_pairs(self, flag: str = "-H") -> List[str]:
        """The same headers as argv pairs for external tools that accept them."""
        return _header_pairs(self.config, flag)

    # ------------------------------------------------------------------
    def path(self, *parts: str) -> str:
        """Build a path inside the run directory."""
        return os.path.join(self.output_dir, *parts)

    def get_file(self, key: str, default: str = "") -> str:
        return self.files.get(key, default)

    def resolve_file(self, key: str, *default_parts: str) -> str:
        """
        Best path for a phase artefact.

        Prefers an explicitly registered file, then the canonical location if
        it exists (e.g. left behind by a previous run), and finally the
        canonical location whether or not it exists yet.
        """
        explicit = self.files.get(key)
        if explicit and os.path.exists(explicit):
            return explicit
        candidate = self.path(*default_parts) if default_parts else ""
        if candidate and os.path.exists(candidate):
            return candidate
        return explicit or candidate

    def set_file(self, key: str, path: str) -> str:
        self.files[key] = path
        return path

    def threads(self, override: Optional[int] = None) -> int:
        return int(override or self.config.get_threads())

    # ------------------------------------------------------------------
    def record_assets(self, assets) -> int:
        if self.database is None or self.scan_id is None:
            return 0
        return self.database.add_assets(self.scan_id, assets)

    def record_findings(self, findings) -> int:
        if self.database is None or self.scan_id is None:
            return 0
        return self.database.add_findings(self.scan_id, findings)
