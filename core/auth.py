"""
SyncHunt - authenticated scanning (cookies, headers, bearer tokens)

Most real bug-bounty surface sits behind a login. SyncHunt keeps that in one
place so every phase and every tool can carry the same session context:

    synchunt -d example.com --cookie "session=abc123" \
             --header "Authorization: Bearer eyJ..." \
             --header "X-Bug-Bounty: handle"

    general:
      cookie: "session=abc123"
      headers:
        - "Authorization: Bearer eyJ..."
        - "X-Bug-Bounty: handle"

The headers are applied to the shared HTTP session (so enrichment, API
introspection, OOB probes, takeover checks and cloud checks all use them) and
passed to the external tools that support custom headers (`-H`/`--header`).

Safety: values are never logged - only header *names* are summarised, and the
report/artefact layer keeps redacting secret-shaped values as before.
"""

from __future__ import annotations

from typing import Dict, List, Optional

HEADER_FLAGS = {
    "-H",              # nuclei, httpx, katana, ffuf, gobuster, feroxbuster, dalfox, wfuzz
    "--header",        # sqlmap-ish CLIs
    "--headers",       # arjun, dirsearch
}

SECRET_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token", "proxy-authorization")


def parse_header(raw: str) -> tuple:
    """
    Parse "Name: value" (also accepts "Name=value").

    Returns (name, value). Raises ValueError when the header cannot be parsed.
    """
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty header")
    for separator in (":", "="):
        if separator in text:
            name, _sep, value = text.partition(separator)
            name, value = name.strip(), value.strip()
            if not name:
                break
            if name.lower() in ("host", "content-length"):
                raise ValueError(f"'{name}' is set by the HTTP client - remove it")
            return name, value
    raise ValueError(f"header must look like 'Name: value' (got {raw!r})")


def _from_config_list(raw) -> List[tuple]:
    pairs: List[tuple] = []
    if isinstance(raw, dict):
        raw = [f"{key}: {value}" for key, value in raw.items()]
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return pairs
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            continue
        try:
            pairs.append(parse_header(item))
        except ValueError:
            continue
    return pairs


def auth_headers(config) -> Dict[str, str]:
    """
    All authentication material that should ride along, as a header dict.

    Resolution: `general.headers` (list or mapping) plus `general.cookie`, which
    becomes a `Cookie:` header. Missing config -> empty dict.
    """
    headers: Dict[str, str] = {}
    if config is None:
        return headers
    try:
        configured = config.get("general.headers", []) or []
        cookie = config.get("general.cookie", "") or ""
    except Exception:  # pragma: no cover - defensive
        return headers

    for name, value in _from_config_list(configured):
        headers[name] = value
    cookie = str(cookie).strip()
    if cookie:
        headers["Cookie"] = cookie
    return headers


def header_pairs(config, flag: str = "-H") -> List[str]:
    """
    Header values as CLI argv pairs for external tools.

    Usage:  cmd += header_pairs(self.config, "-H")
    """
    if flag not in HEADER_FLAGS:
        flag = "-H"
    pairs: List[str] = []
    for name, value in auth_headers(config).items():
        pairs += [flag, f"{name}: {value}"]
    return pairs


def sqlmap_args(config) -> List[str]:
    """sqlmap wants headers newline-separated, and the cookie explicitly."""
    headers = auth_headers(config)
    if not headers:
        return []
    args = ["--headers", "\n".join(f"{name}: {value}" for name, value in headers.items() if name != "Cookie")]
    if headers.get("Cookie"):
        args += ["--cookie", headers["Cookie"]]
    return args


def summary(config) -> str:
    """Log-safe summary: header names only, values never printed."""
    headers = auth_headers(config)
    if not headers:
        return "anonymous"
    names = ", ".join(sorted(headers))
    return f"authenticated ({names})"


def describe_secret_flags(config) -> List[str]:
    """Names of headers that carry credentials (used by the report layer)."""
    return sorted(
        name for name in auth_headers(config)
        if name.lower() in SECRET_HEADERS
    )


def mask_value(value: str, keep: int = 4) -> str:
    """Redact a token for logs/artifacts, keeping a short prefix."""
    text = value or ""
    if len(text) <= keep:
        return "*" * len(text)
    return text[:keep] + "*" * min(12, len(text) - keep)


def auth_context(config, cookie: Optional[str] = None, headers: Optional[List[str]] = None) -> Dict[str, str]:
    """Build a header dict from explicit CLI values, falling back to config."""
    merged: Dict[str, str] = dict(auth_headers(config))
    for raw in headers or []:
        try:
            name, value = parse_header(raw)
        except ValueError:
            continue
        merged[name] = value
    if cookie:
        merged["Cookie"] = str(cookie).strip()
    return merged
