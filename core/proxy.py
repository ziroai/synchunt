"""
SyncHunt - Outbound proxy support (Burp Suite / OWASP ZAP / mitmproxy)

The interactive platforms in the bug-bounty tool list (Burp, ZAP, mitmproxy,
Wireshark-adjacent tooling) are not scanners SyncHunt should replace - they are
where a human inspects traffic. SyncHunt plugs into them by routing *all* of its
own HTTP traffic and every child tool through a proxy:

    general.proxy: "http://127.0.0.1:8080"     # config.yaml
    synchunt -d example.com --proxy http://127.0.0.1:8080

requests honours the standard environment variables (trust_env), and child
processes inherit them, so setting the env once covers both the built-in HTTP
client and every external tool (nuclei, httpx, ffuf, sqlmap, ...).

Nothing here is required for normal scans: with no proxy configured the
environment is left untouched.
"""

from __future__ import annotations

import os
from typing import Optional

PROXY_ENV_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
SYNCHUNT_PROXY_ENV = "SYNCHUNT_PROXY"
DEFAULT_NO_PROXY = "localhost,127.0.0.1,::1"


def proxy_from_config(config=None, cli_value: str = "") -> str:
    """Resolution order: CLI flag > config key > SYNCHUNT_PROXY env."""
    value = (cli_value or "").strip()
    if value:
        return value
    if config is not None:
        try:
            configured = config.get("general.proxy", "")
        except Exception:  # pragma: no cover - defensive
            configured = ""
        if isinstance(configured, str) and configured.strip():
            return configured.strip()
    return (os.environ.get(SYNCHUNT_PROXY_ENV) or "").strip()


def apply_proxy_env(config=None, cli_value: str = "", logger=None) -> str:
    """
    Export proxy settings for requests + child tools. Returns the proxy used.

    Idempotent, and a no-op when no proxy is configured anywhere.
    """
    proxy = proxy_from_config(config, cli_value)
    if not proxy:
        return ""
    for key in PROXY_ENV_KEYS:
        os.environ[key] = proxy
        os.environ[key.lower()] = proxy
    existing_no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    merged = ",".join(
        part for part in [existing_no_proxy, DEFAULT_NO_PROXY] if part
    )
    os.environ["NO_PROXY"] = merged
    os.environ["no_proxy"] = merged
    if logger is not None:
        logger.warning(
            f"routing all SyncHunt traffic through {proxy} - "
            "only do this for targets you are authorised to test"
        )
        logger.debug(f"NO_PROXY={merged}")
    return proxy


def describe(proxy: str) -> str:
    if not proxy:
        return "direct (no proxy)"
    return f"via {proxy}"


def existing_proxy() -> Optional[str]:
    """Any proxy already visible in the environment (informational)."""
    for key in PROXY_ENV_KEYS:
        value = os.environ.get(key) or os.environ.get(key.lower())
        if value:
            return value
    return None
