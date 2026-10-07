"""
SyncHunt - Scope Manager
Enforces in-scope / out-of-scope rules so a scan never leaves the authorised
attack surface.

Supported rule syntax
---------------------
example.com          apex + all subdomains
*.example.com        subdomains only (apex excluded)
api.example.com      exact host
10.0.0.0/24          CIDR range
192.168.1.10         single IP
!internal.corp       leading "!" marks an exclusion (same as the OOS file)
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

from core.utils import (
    host_from_url,
    is_cidr,
    is_ip,
    read_file_lines,
    split_host_port,
)


@dataclass
class Rule:
    """A single scope rule."""

    raw: str
    kind: str  # domain | wildcard | ip | cidr
    value: str
    network: Optional[ipaddress._BaseNetwork] = None

    def matches(self, host: str) -> bool:
        host = (host or "").lower().strip().rstrip(".")
        if not host:
            return False
        if self.kind == "ip":
            return host == self.value
        if self.kind == "cidr":
            try:
                return ipaddress.ip_address(host) in self.network
            except ValueError:
                return False
        if self.kind == "wildcard":
            return host.endswith("." + self.value) and host != self.value
        return host == self.value or host.endswith("." + self.value)

    def describe(self) -> str:
        return f"{self.kind}:{self.value}"


def parse_rule(raw: str) -> Optional[Rule]:
    """Parse one scope token into a Rule (None when the token is unusable)."""
    token = (raw or "").strip().lstrip("!").strip()
    if not token or token.startswith("#"):
        return None

    token = token.replace("https://", "").replace("http://", "")
    token = token.strip().lower().rstrip(".")

    wildcard = token.startswith("*.")
    if wildcard:
        token = token[2:]

    if is_cidr(token):
        try:
            return Rule(raw, "cidr", token, ipaddress.ip_network(token, strict=False))
        except ValueError:
            return None

    # Strip any port ("127.0.0.1:8080" -> "127.0.0.1") and URL paths.
    host, _port = split_host_port(token)
    token = host or token
    if "/" in token and not is_ip(token):
        token = token.split("/", 1)[0]

    if is_ip(token):
        return Rule(raw, "ip", token)
    if not token:
        return None
    if wildcard:
        return Rule(raw, "wildcard", token)
    return Rule(raw, "domain", token)


@dataclass
class ScopeManager:
    """Filter hosts/URLs against include and exclude rule sets."""

    include: List[Rule] = field(default_factory=list)
    exclude: List[Rule] = field(default_factory=list)
    strict: bool = False
    dropped: List[Tuple[str, str]] = field(default_factory=list)

    # ------------------------------------------------------------------
    @classmethod
    def from_config(
        cls,
        config,
        scope_file: Optional[str] = None,
        out_of_scope_file: Optional[str] = None,
        extra_scope: Optional[Sequence[str]] = None,
        extra_out_of_scope: Optional[Sequence[str]] = None,
    ) -> "ScopeManager":
        include_raw: List[str] = []
        exclude_raw: List[str] = []

        for path in [config.get("general.scope_file", ""), scope_file]:
            if path and os.path.exists(path):
                include_raw.extend(read_file_lines(path))

        for path in [config.get("general.out_of_scope_file", ""), out_of_scope_file]:
            if path and os.path.exists(path):
                exclude_raw.extend(read_file_lines(path))

        include_raw.extend(config.get_list("scope.include", []) or [])
        exclude_raw.extend(config.get_list("scope.exclude", []) or [])
        include_raw.extend(extra_scope or [])
        exclude_raw.extend(extra_out_of_scope or [])

        # "!"-prefixed entries in the include list are exclusions.
        cleaned_include: List[str] = []
        for entry in include_raw:
            entry = str(entry).strip()
            if entry.startswith("!"):
                exclude_raw.append(entry[1:])
            else:
                cleaned_include.append(entry)

        include = [rule for rule in (parse_rule(e) for e in cleaned_include) if rule]
        exclude = [rule for rule in (parse_rule(e) for e in exclude_raw) if rule]
        return cls(
            include=include,
            exclude=exclude,
            strict=config.get_bool("scope.strict", False),
        )

    # ------------------------------------------------------------------
    @property
    def has_rules(self) -> bool:
        return bool(self.include or self.exclude)

    def in_scope(self, value: str, reason: Optional[List[str]] = None) -> bool:
        """
        Decide whether a host/URL is in scope.

        With no include rules everything is considered in scope (minus
        exclusions) so that ad-hoc scans still work; `strict: true` inverts
        that default and requires an explicit include rule.
        """
        host = host_from_url(value)
        if not host:
            return False

        for rule in self.exclude:
            if rule.matches(host):
                if reason is not None:
                    reason.append(f"excluded by {rule.raw}")
                return False

        if not self.include:
            if self.strict:
                if reason is not None:
                    reason.append("no include rules and scope.strict is set")
                return False
            return True

        for rule in self.include:
            if rule.matches(host):
                return True
        if reason is not None:
            reason.append("not matched by any include rule")
        return False

    def filter(self, values: Iterable[str], record_drops: bool = False) -> List[str]:
        """Return only the in-scope values, preserving order and deduplicating."""
        kept: List[str] = []
        seen = set()
        for value in values:
            value = (value or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            reason: List[str] = []
            if self.in_scope(value, reason):
                kept.append(value)
            elif record_drops:
                self.dropped.append((value, reason[0] if reason else "out of scope"))
        return kept

    def summary(self) -> dict:
        return {
            "include_rules": [rule.describe() for rule in self.include],
            "exclude_rules": [rule.describe() for rule in self.exclude],
            "strict": self.strict,
            "dropped_count": len(self.dropped),
            "dropped_sample": [d[0] for d in self.dropped[:25]],
        }

    def describe(self) -> str:
        if not self.has_rules:
            return "no scope rules (everything in scope)"
        parts = []
        if self.include:
            parts.append(f"{len(self.include)} include rule(s)")
        if self.exclude:
            parts.append(f"{len(self.exclude)} exclude rule(s)")
        if self.strict:
            parts.append("strict mode")
        return ", ".join(parts)
