"""
SyncHunt - Secret Detection
Shared pattern library + entropy filtering used by JS analysis, GitHub recon
and sensitive-info discovery.

Matches are redacted before they are written to disk so that the scan output
itself does not become a secrets leak.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

# name, regex, severity, confidence, needs_entropy
DEFAULT_PATTERNS = [
    {
        "name": "AWS Access Key",
        "regex": r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
        "severity": "high",
        "confidence": "high",
        "entropy": False,
    },
    {
        "name": "AWS Secret Key",
        "regex": r"(?i)aws.{0,20}(secret|private).{0,20}['\"]([A-Za-z0-9/+]{40})['\"]",
        "severity": "critical",
        "confidence": "medium",
        "entropy": True,
        "entropy_group": 2,
    },
    {
        "name": "Google API Key",
        "regex": r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "severity": "high",
        "confidence": "high",
        "entropy": False,
    },
    {
        "name": "Google OAuth Client ID",
        "regex": r"\b[0-9]{12}-[0-9a-z_]{32}\.apps\.googleusercontent\.com\b",
        "severity": "medium",
        "confidence": "high",
        "entropy": False,
    },
    {
        "name": "GitHub Token",
        "regex": r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
        "severity": "critical",
        "confidence": "high",
        "entropy": False,
    },
    {
        "name": "Slack Token",
        "regex": r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b",
        "severity": "high",
        "confidence": "high",
        "entropy": False,
    },
    {
        "name": "Slack Webhook",
        "regex": r"https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]{40,}",
        "severity": "high",
        "confidence": "high",
        "entropy": False,
    },
    {
        "name": "Discord Webhook",
        "regex": r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]{15,25}/[A-Za-z0-9_-]{60,90}",
        "severity": "high",
        "confidence": "high",
        "entropy": False,
    },
    {
        "name": "Stripe Key",
        "regex": r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,64}\b",
        "severity": "critical",
        "confidence": "high",
        "entropy": False,
    },
    {
        "name": "Private Key Block",
        "regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        "severity": "critical",
        "confidence": "high",
        "entropy": False,
    },
    {
        "name": "JSON Web Token",
        "regex": r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
        "severity": "medium",
        "confidence": "medium",
        "entropy": False,
    },
    {
        "name": "SendGrid API Key",
        "regex": r"\bSG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}\b",
        "severity": "high",
        "confidence": "high",
        "entropy": False,
    },
    {
        "name": "Twilio API Key",
        "regex": r"\bSK[0-9a-fA-F]{32}\b",
        "severity": "medium",
        "confidence": "low",
        "entropy": True,
    },
    {
        "name": "Mailgun API Key",
        "regex": r"\bkey-[0-9a-zA-Z]{32}\b",
        "severity": "high",
        "confidence": "medium",
        "entropy": False,
    },
    {
        "name": "Telegram Bot Token",
        "regex": r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b",
        "severity": "high",
        "confidence": "medium",
        "entropy": False,
    },
    {
        "name": "Firebase URL",
        "regex": r"https://[a-z0-9-]+\.firebaseio\.com",
        "severity": "low",
        "confidence": "high",
        "entropy": False,
    },
    {
        "name": "S3 Bucket URL",
        "regex": r"(?:https?://)?[a-zA-Z0-9._-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com",
        "severity": "low",
        "confidence": "medium",
        "entropy": False,
    },
    {
        "name": "Database Connection String",
        "regex": r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)://[^\s'\"<>]{8,200}",
        "severity": "critical",
        "confidence": "medium",
        "entropy": True,
    },
    {
        "name": "Bearer Token",
        "regex": r"(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{20,}",
        "severity": "medium",
        "confidence": "medium",
        "entropy": True,
    },
    {
        "name": "Password Assignment",
        "regex": r"(?i)\b(?:password|passwd|pwd|db_pass(?:word)?)\s*[:=]\s*['\"]([^'\"\s]{6,64})['\"]",
        "severity": "high",
        "confidence": "low",
        "entropy": True,
        "entropy_group": 1,
    },
    {
        "name": "Generic API Key",
        "regex": r"(?i)\b(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"]([A-Za-z0-9._\-]{12,80})['\"]",
        "severity": "medium",
        "confidence": "low",
        "entropy": True,
        "entropy_group": 1,
    },
]

# Patterns that produce far too much noise to be worth reporting.
IGNORE_VALUES = {
    "your_api_key",
    "your-api-key",
    "apikey",
    "api_key",
    "changeme",
    "change_me",
    "password",
    "secret",
    "example",
    "placeholder",
    "xxxxxxxx",
    "0000000000000000",
    "test",
    "testkey",
    "dummy",
    "none",
    "null",
    "undefined",
    "insert_key_here",
}


@dataclass
class SecretMatch:
    """A single secret hit."""

    name: str
    value: str
    severity: str
    confidence: str
    entropy: float
    source: str = ""
    location: str = ""

    def to_dict(self) -> Dict:
        return {
            "type": self.name,
            "value": redact(self.value),
            "severity": self.severity,
            "confidence": self.confidence,
            "entropy": round(self.entropy, 2),
            "source": self.source,
            "location": self.location,
        }

    def fingerprint(self) -> str:
        from core.utils import short_hash

        return short_hash(self.name, self.value, self.location)


@dataclass
class _CompiledPattern:
    name: str
    regex: "re.Pattern"
    severity: str
    confidence: str
    needs_entropy: bool
    entropy_group: int = 0


def shannon_entropy(value: str) -> float:
    """Shannon entropy (bits per character) of a string."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def compile_patterns(patterns: Optional[Iterable[Dict]] = None) -> List[_CompiledPattern]:
    """
    Compile pattern definitions into regex objects.

    `patterns` entries may be dicts or raw {'name', 'regex'} pairs; unknown or
    invalid entries are skipped instead of aborting the scan.
    """
    compiled: List[_CompiledPattern] = []
    source = list(patterns) if patterns else DEFAULT_PATTERNS
    for entry in source:
        if not isinstance(entry, dict):
            continue
        regex = entry.get("regex")
        if not regex:
            continue
        try:
            compiled.append(
                _CompiledPattern(
                    name=entry.get("name", "Unnamed pattern"),
                    regex=re.compile(regex),
                    severity=entry.get("severity", "medium"),
                    confidence=entry.get("confidence", "medium"),
                    needs_entropy=bool(entry.get("entropy", False)),
                    entropy_group=int(entry.get("entropy_group", 0) or 0),
                )
            )
        except re.error:
            continue
    return compiled


def redact(value: str, keep_start: int = 6, keep_end: int = 4) -> str:
    """Redact the middle of a secret so reports are safe to share."""
    value = str(value or "")
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    return f"{value[:keep_start]}{'*' * 8}{value[-keep_end:]}"


def scan_text(
    text: str,
    patterns: Optional[Sequence[_CompiledPattern]] = None,
    source: str = "",
    location: str = "",
    entropy_threshold: float = 3.2,
    min_length: int = 12,
    ignore_values: Optional[Iterable[str]] = None,
) -> List[SecretMatch]:
    """Scan a blob of text for secret-looking strings."""
    if not text:
        return []
    if patterns is None:
        patterns = compile_patterns()
    ignored = {v.lower() for v in (ignore_values or IGNORE_VALUES)}
    findings: List[SecretMatch] = []
    seen = set()

    for pattern in patterns:
        for match in pattern.regex.finditer(text):
            raw = match.group(0)
            candidate = raw
            if pattern.entropy_group and match.re.groups >= pattern.entropy_group:
                try:
                    candidate = match.group(pattern.entropy_group) or raw
                except IndexError:  # pragma: no cover - defensive
                    candidate = raw
            candidate = candidate.strip().strip("'\"")

            if len(candidate) < min_length:
                continue
            if candidate.lower() in ignored:
                continue
            entropy = shannon_entropy(candidate)
            if pattern.needs_entropy and entropy < entropy_threshold:
                continue
            if not pattern.needs_entropy and len(set(candidate)) <= 4:
                continue  # something like AAAAAAAAAAAAAAAA

            key = (pattern.name, candidate)
            if key in seen:
                continue
            seen.add(key)

            findings.append(
                SecretMatch(
                    name=pattern.name,
                    value=candidate,
                    severity=pattern.severity,
                    confidence=pattern.confidence,
                    entropy=entropy,
                    source=source,
                    location=location,
                )
            )
    return findings


def build_patterns(custom_patterns: Optional[Iterable[Dict]] = None) -> List["_CompiledPattern"]:
    """Built-in library plus optional custom patterns coming from config."""
    combined: List[Dict] = list(DEFAULT_PATTERNS)
    for entry in custom_patterns or []:
        if isinstance(entry, dict) and entry.get("regex"):
            combined.append(entry)
    return compile_patterns(combined)


def scan_text_custom(text: str, custom_patterns: Optional[Iterable[Dict]]) -> List[SecretMatch]:
    """Scan with the default library plus user-supplied extra patterns."""
    return scan_text(text, patterns=build_patterns(custom_patterns))


def pattern_config_for_yaml() -> List[Dict]:
    """Serialisable default pattern list (used by docs/tests)."""
    return [
        {
            "name": p["name"],
            "regex": p["regex"],
            "severity": p["severity"],
            "confidence": p["confidence"],
            "entropy": p["entropy"],
        }
        for p in DEFAULT_PATTERNS
    ]
