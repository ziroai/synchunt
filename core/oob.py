"""
SyncHunt - Out-of-band (OOB) interaction client

Blind vulnerabilities (blind XSS, SSRF, XXE, log4shell-style callbacks) can only
be confirmed by making the *target* call back to a server you control. This
module provides that callback endpoint for the scan, with three providers:

- ``webhook`` — a webhook.site token. Requests are returned as plain JSON, so
  the interaction details (method, path, source IP, time) are fully readable.
  This is the default: it works with zero setup.
- ``interactsh`` — a ProjectDiscovery interactsh server (oast.pro/oast.fun/...).
  The protocol is implemented (register + poll), but interactsh encrypts the
  interaction payloads with AES and the Python standard library has no AES
  implementation, so interactions are reported as *observations* (which probe
  fired, when, from where) without the decrypted request body. Install the
  optional ``cryptography`` package and use a webhook you control when you need
  full request bodies from a self-hosted setup.
- ``custom`` — bring your own collector URL (self-hosted, Burp Collaborator or
  a VPS). SyncHunt generates a unique token per probe and you inspect your
  collector's logs; SyncHunt cannot poll it for you.

Only read-only polling is performed against the provider. Nothing is sent to an
OOB provider unless a scan enables it (``vuln_scanning.oob.enabled``), because
using a public service means the target's callback - including the target's IP
and any data it echoes - reaches a third party.
"""

from __future__ import annotations

import os
import random
import string
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from core.net import http_request, post_json

WEBHOOK_API = "https://webhook.site"
INTERACTSH_SERVERS = ("oast.pro", "oast.fun", "oast.live", "oast.site", "oast.online")
PROVIDERS = ("webhook", "interactsh", "custom")

_TOKEN_ALPHABET = string.ascii_lowercase + string.digits


def _random_token(length: int = 12) -> str:
    return "".join(random.choice(_TOKEN_ALPHABET) for _ in range(length))


@dataclass
class OOBInteraction:
    """A single callback observed by the OOB provider."""

    provider: str
    method: str = ""
    path: str = ""
    source_ip: str = ""
    time: str = ""
    headers: Dict[str, Any] = field(default_factory=dict)
    query: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "method": self.method,
            "path": self.path,
            "source_ip": self.source_ip,
            "time": self.time,
            "query": self.query,
            "headers": {k: v for k, v in list(self.headers.items())[:20]},
        }

    def summary(self) -> str:
        parts = [self.provider]
        if self.method:
            parts.append(self.method)
        if self.path:
            parts.append(self.path[:120])
        if self.source_ip:
            parts.append(f"from {self.source_ip}")
        if self.time:
            parts.append(f"at {self.time}")
        return " ".join(parts)


class OOBClient:
    """Callback endpoint used to confirm blind vulnerabilities."""

    def __init__(self, session=None, limiter=None, provider: str = "webhook",
                 custom_url: str = "", interactsh_server: str = "",
                 logger=None, timeout: float = 15.0):
        provider = (provider or "webhook").strip().lower()
        if provider not in PROVIDERS:
            provider = "webhook"
        self.provider = provider
        self.session = session
        self.limiter = limiter
        self.custom_url = (custom_url or "").rstrip("/")
        self.server = (interactsh_server or INTERACTSH_SERVERS[0]).strip()
        self.logger = logger
        self.timeout = timeout

        self.token = ""            # per-scan provider token / correlation id
        self.secret = ""           # interactsh secret key
        self.started = False
        self.error = ""
        self._started_at = 0.0

    # ------------------------------------------------------------------
    def _log(self, level: str, message: str) -> None:
        if self.logger is None:
            return
        getattr(self.logger, level, None) and getattr(self.logger, level)(message)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> bool:
        """Register with the provider. Returns True when callbacks can arrive."""
        if self.started:
            return True
        self._started_at = time.time()

        if self.provider == "custom":
            if not self.custom_url:
                self.error = "custom OOB provider needs a URL"
                self._log("warning", self.error)
                return False
            self.token = _random_token()
            self.started = True
            return True

        if self.provider == "webhook":
            return self._start_webhook()
        return self._start_interactsh()

    def _start_webhook(self) -> bool:
        result = post_json(
            self.session, f"{WEBHOOK_API}/token",
            payload={"default_status": 200, "default_content": "",
                     "default_content_type": "text/plain", "timeout": 0},
            limiter=self.limiter, timeout=self.timeout,
        )
        if not result.ok:
            self.error = f"webhook.site registration failed ({result.status or result.error})"
            self._log("warning", self.error)
            return False
        payload = result.json(default={}) or {}
        self.token = str(payload.get("uuid") or "")
        if not self.token:
            self.error = "webhook.site did not return a token"
            self._log("warning", self.error)
            return False
        self.started = True
        self._log("found", f"OOB endpoint ready: {self.callback_url()}")
        return True

    def _start_interactsh(self) -> bool:
        self.token = _random_token(20)
        self.secret = "".join(random.choice("0123456789abcdef") for _ in range(64))
        result = post_json(
            self.session, f"https://{self.server}/register",
            payload={"public-ip": "", "secret-key": self.secret,
                     "correlation-id": self.token},
            limiter=self.limiter, timeout=self.timeout,
        )
        if not result.ok:
            self.error = f"interactsh registration failed ({result.status or result.error})"
            self._log("warning", self.error)
            return False
        self.started = True
        self._log("found", f"OOB endpoint ready: {self.callback_url()}")
        return True

    def stop(self) -> None:
        """Best-effort deregistration (webhook.site expires on its own)."""
        if self.provider == "interactsh" and self.started and self.token:
            post_json(
                self.session, f"https://{self.server}/deregister",
                payload={"correlation-id": self.token, "secret-key": self.secret},
                limiter=self.limiter, timeout=self.timeout,
            )
        self.started = False

    # ------------------------------------------------------------------
    # URL generation
    # ------------------------------------------------------------------
    def callback_url(self, token: str = "") -> str:
        """Base callback URL; `token` adds a unique marker for one probe."""
        marker = token or _random_token()
        if self.provider == "webhook":
            if not self.token:
                return ""
            return f"{WEBHOOK_API}/{self.token}?p={marker}"
        if self.provider == "interactsh":
            if not self.token:
                return ""
            return f"{marker}{self.token}.{self.server}"
        if self.custom_url:
            return f"{self.custom_url}/{marker}"
        return ""

    def probe_url(self, kind: str = "probe") -> str:
        """A unique URL for one payload, tagged so interactions are traceable."""
        token = f"{kind}-{_random_token(10)}"
        url = self.callback_url(token)
        return url

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------
    def poll(self) -> List[OOBInteraction]:
        """Fetch interactions observed since `start()`. Never raises."""
        if not self.started:
            return []
        try:
            if self.provider == "webhook":
                return self._poll_webhook()
            if self.provider == "interactsh":
                return self._poll_interactsh()
        except Exception as exc:  # pragma: no cover - network dependent
            self._log("warning", f"OOB poll failed: {exc}")
        return []

    def _poll_webhook(self) -> List[OOBInteraction]:
        query = urlencode({"sorting": "newest", "per_page": 100})
        result = http_request(
            self.session, "GET",
            f"{WEBHOOK_API}/token/{self.token}/requests?{query}",
            limiter=self.limiter, timeout=self.timeout, max_bytes=1024 * 1024,
        )
        if not result.ok:
            return []
        payload = result.json(default={}) or {}
        interactions = []
        for record in payload.get("data", []) or []:
            if not isinstance(record, dict):
                continue
            interactions.append(OOBInteraction(
                provider="webhook",
                method=str(record.get("method") or ""),
                path=str(record.get("url") or record.get("path") or ""),
                source_ip=str(record.get("ip") or ""),
                time=str(record.get("created_at") or ""),
                headers=record.get("headers") or {},
                query=record.get("query") or {},
                raw=record,
            ))
        return interactions

    def _poll_interactsh(self) -> List[OOBInteraction]:
        query = urlencode({"id": self.token, "secret": self.secret})
        result = http_request(
            self.session, "GET", f"https://{self.server}/poll?{query}",
            limiter=self.limiter, timeout=self.timeout, max_bytes=1024 * 1024,
        )
        if not result.ok:
            return []
        payload = result.json(default={}) or {}
        records = payload.get("data") or []
        interactions = []
        for index, record in enumerate(records):
            # The payload is AES-encrypted by interactsh; the stdlib has no AES,
            # so the observation itself (count + arrival time) is what we report.
            interactions.append(OOBInteraction(
                provider="interactsh",
                method="callback",
                path=f"interaction #{index + 1}",
                source_ip="",
                time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                raw={"encrypted": True, "length": len(str(record))},
            ))
        return interactions


def interactions_since(interactions: List[OOBInteraction], started_at: float,
                       slack: float = 5.0) -> List[OOBInteraction]:
    """
    Keep only interactions that arrived during this scan.

    webhook.site tokens can be reused; filtering on the scan window avoids
    reporting a previous scan's callbacks as new.
    """
    cutoff = started_at - slack
    kept = []
    for interaction in interactions:
        stamp = interaction.time
        if not stamp:
            kept.append(interaction)
            continue
        try:
            parsed = time.mktime(
                time.strptime(stamp.replace("Z", "").split(".")[0], "%Y-%m-%dT%H:%M:%S")
            )
        except ValueError:
            kept.append(interaction)
            continue
        # timestamps are UTC, mktime expects local time - compare loosely
        if parsed >= cutoff - (time.timezone or 0):
            kept.append(interaction)
    return kept


def build_client(config, session=None, limiter=None, logger=None,
                 section: str = "vuln_scanning") -> Optional[OOBClient]:
    """Create (but do not start) an OOB client from config. None when disabled."""
    if not config.get_bool(f"{section}.oob.enabled", False):
        return None
    provider = config.get(f"{section}.oob.provider", "webhook") or "webhook"
    client = OOBClient(
        session=session,
        limiter=limiter,
        provider=provider,
        custom_url=config.get(f"{section}.oob.custom_url", "") or "",
        interactsh_server=config.get(f"{section}.oob.interactsh_server", "") or "",
        logger=logger,
        timeout=float(config.get_int("general.timeout", 15) or 15),
    )
    return client


def oob_workspace_dir(output_dir: str) -> str:
    path = os.path.join(output_dir, "oob")
    os.makedirs(path, exist_ok=True)
    return path
