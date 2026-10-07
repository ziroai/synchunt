"""
SyncHunt - Hash identification (Hashcat / John the Ripper preflight)

Credentials and hashes turn up during JS analysis, repository history and
leaked-file discovery. SyncHunt never cracks anything: this module identifies
the hash shape and prints the exact Hashcat mode / John format so the operator
can run the cracking tools themselves on data they are authorised to handle.

Everything here is offline and pure-python; no hashing or cracking is done.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List

DEFAULT_HASHCAT = "hashcat"
DEFAULT_JOHN = "john"


@dataclass
class HashPattern:
    name: str
    regex: str
    hashcat_mode: int
    john_format: str
    bits: int
    note: str = ""

    def matches(self, value: str) -> bool:
        return bool(re.match(self.regex, value))


@dataclass
class HashMatch:
    """One plausible interpretation of a hash-looking string."""

    name: str
    hashcat_mode: int
    john_format: str
    bits: int
    note: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "hashcat_mode": self.hashcat_mode,
            "john_format": self.john_format,
            "bits": self.bits,
            "note": self.note,
        }


# Ordered most-specific first: a bcrypt blob must not be reported as "hex".
HASH_PATTERNS: List[HashPattern] = [
    HashPattern("bcrypt", r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$", 3200, "bcrypt", 184,
                "cost factor is embedded in the string"),
    HashPattern("sha512crypt", r"^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$",
                1800, "sha512crypt", 512),
    HashPattern("sha256crypt", r"^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$",
                7400, "sha256crypt", 256),
    HashPattern("md5crypt", r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$", 500, "md5crypt", 128),
    HashPattern("argon2", r"^\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$",
                34000, "argon2", 256, "GPU cracking is impractical for argon2 - use john"),
    HashPattern("scrypt", r"^\$7\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$", 8900, "scrypt", 256),
    HashPattern("pbkdf2-sha256", r"^\$pbkdf2-sha256\$\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$",
                10900, "pbkdf2-sha256", 256),
    HashPattern("django", r"^pbkdf2_sha256\$\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9+/=]+$",
                10000, "django", 256, "Django hash - strip the algorithm prefix before hashing"),
    HashPattern("NetNTLMv2", r"^[^:]{1,64}::[^:]{1,64}:[0-9A-Fa-f]{16}:[0-9A-Fa-f]{32}:[0-9A-Fa-f]+$",
                5600, "netntlmv2", 128, "capture from a proxy/SMB session - not crackable offline from memory"),
    HashPattern("Kerberos 5 TGS-REP", r"^\$krb5tgs\$", 13100, "krb5tgs", 128,
                "AS-REP roast / kerberoast output"),
    HashPattern("MySQL 4.1+", r"^\*[0-9A-F]{40}$", 300, "mysql-sha1", 160),
    HashPattern("JWT", r"^eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*$",
                16500, "jwt", 0, "crack the signature secret - the payload is only signed, not encrypted"),
    HashPattern("WPA-PBKDF2", r"^[0-9a-f]{64}$", 22000, "wpapsk", 256,
                "64 hex chars: could also be a raw SHA-256 digest"),
    HashPattern("SHA-512", r"^[0-9a-f]{128}$", 1700, "raw-sha512", 512),
    HashPattern("SHA-384", r"^[0-9a-f]{96}$", 10800, "raw-sha384", 384),
    HashPattern("SHA-256", r"^[0-9a-f]{64}$", 1400, "raw-sha256", 256),
    HashPattern("SHA-224", r"^[0-9a-f]{56}$", 1300, "raw-sha224", 224),
    HashPattern("SHA-1", r"^[0-9a-f]{40}$", 100, "raw-sha1", 160),
    HashPattern("MD5 / NTLM", r"^[0-9a-f]{32}$", 0, "raw-md5", 128,
                "32 hex chars is ambiguous: MD5 is -m 0, NTLM is -m 1000"),
    HashPattern("MD4", r"^[0-9a-f]{32}$", 900, "raw-md4", 128),
    HashPattern("LM", r"^[0-9A-F]{16}$", 3000, "lm", 64),
    HashPattern("DES (traditional crypt)", r"^[./A-Za-z0-9]{13}$", 1500, "descrypt", 56),
]

# Shorter than this and the string is probably not a hash at all.
MIN_HASH_LENGTH = 13

HASHCAT_WORDLIST_PLACEHOLDER = "rockyou.txt"


def _normalise(value: str) -> str:
    return (value or "").strip().strip('"\'')


def identify(value: str, allow_short: bool = False) -> List[HashMatch]:
    """
    Return every pattern the value could be.

    Ambiguity is real (32 hex chars is MD5 *and* NTLM, 64 hex is SHA-256 *and*
    WPA), so all plausible interpretations are returned, most likely first.
    """
    candidate = _normalise(value)
    if not candidate or (len(candidate) < MIN_HASH_LENGTH and not allow_short):
        return []
    matches: List[HashMatch] = []
    for pattern in HASH_PATTERNS:
        if pattern.matches(candidate):
            matches.append(
                HashMatch(
                    name=pattern.name,
                    hashcat_mode=pattern.hashcat_mode,
                    john_format=pattern.john_format,
                    bits=pattern.bits,
                    note=pattern.note,
                )
            )
    return matches


def suggest_commands(
    value: str,
    wordlist: str = HASHCAT_WORDLIST_PLACEHOLDER,
    rules: str = "",
    hashcat: str = DEFAULT_HASHCAT,
    john: str = DEFAULT_JOHN,
) -> Dict[str, object]:
    """
    Identify a hash and build ready-to-paste Hashcat/John commands.

    SyncHunt does not run these - they are a handover for an operator working
    on credentials they are authorised to test.
    """
    candidate = _normalise(value)
    matches = identify(candidate)
    commands: List[str] = []
    john_commands: List[str] = []
    for match in matches:
        rule_flag = f" -r {rules}" if rules else ""
        if match.hashcat_mode:
            commands.append(
                f"{hashcat} -m {match.hashcat_mode} -a 0 '{candidate}' {wordlist}{rule_flag}"
            )
        john_commands.append(f"{john} --format={match.john_format} 'hashes.txt'")
    return {
        "value": candidate,
        "length": len(candidate),
        "candidates": [m.to_dict() for m in matches],
        "identified": bool(matches),
        "hashcat": commands,
        "john": john_commands,
        "wordlist": wordlist,
    }


def describe(value: str) -> str:
    """One-line human summary used by the CLI and the report."""
    result = suggest_commands(value)
    if not result["identified"]:
        return f"{result['value'][:24]}... - not a recognised hash shape"
    names = ", ".join(str(item["name"]) for item in result["candidates"])  # type: ignore[index]
    return f"possible {names} ({result['length']} chars)"


def find_hashes_in_text(text: str, limit: int = 25) -> List[Dict[str, object]]:
    """
    Scan free text (a JS bundle, a README, a leak dump) for hash-shaped tokens.

    Only tokens that match at least one known pattern are returned.
    """
    found: List[Dict[str, object]] = []
    seen = set()
    for token in re.findall(r"[A-Za-z0-9$./+_-]{13,200}", text or ""):
        token = _normalise(token)
        if token in seen:
            continue
        matches = identify(token)
        if not matches:
            continue
        seen.add(token)
        found.append(
            {
                "value": token,
                "candidates": [m.to_dict() for m in matches],
                "severity": "medium" if any(m.name not in ("SHA-256", "SHA-512") for m in matches) else "low",
            }
        )
        if len(found) >= limit:
            break
    return found
