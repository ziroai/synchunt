"""
SyncHunt - threat intelligence for CVE triage (CISA KEV + FIRST EPSS)

Severity alone does not tell you what to work on first. Two public, free feeds
do most of the work:

  * CISA KEV  - vulnerabilities confirmed to be exploited in the wild
                (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  * FIRST EPSS - probability that a CVE will be exploited in the next 30 days
                (https://api.first.org/data/v1/epss)

Both are bulk/public endpoints, queried once per scan, cached on disk, and only
for CVEs that SyncHunt already found. Nothing about the target is sent: the
lookups are by CVE id. When there is no network the enrichment is skipped with
a debug line and the scan continues unchanged.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from core.utils import load_json, save_json

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_CHUNK = 50
DEFAULT_CACHE_HOURS = 12


@dataclass
class ThreatIntel:
    """Cache-aware KEV + EPSS lookup (never raises on network problems)."""

    session: object = None
    limiter: object = None
    logger: object = None
    timeout: float = 20.0
    cache_path: str = ""
    cache_hours: float = DEFAULT_CACHE_HOURS
    kev: Dict[str, Dict] = field(default_factory=dict)
    epss: Dict[str, Dict] = field(default_factory=dict)
    used_cache: bool = False
    errors: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    def _log(self, level: str, message: str) -> None:
        if self.logger is not None:
            getattr(self.logger, level, self.logger.debug)(message)

    def _load_cache(self) -> None:
        if not self.cache_path or not os.path.exists(self.cache_path):
            return
        cached = load_json(self.cache_path, {}) or {}
        fetched_at = float(cached.get("fetched_at", 0) or 0)
        if fetched_at and (time.time() - fetched_at) < self.cache_hours * 3600:
            self.kev = cached.get("kev", {}) or {}
            self.epss = cached.get("epss", {}) or {}
            self.used_cache = bool(self.kev or self.epss)
            if self.used_cache:
                self._log("debug", f"threat intel cache hit ({self.cache_path})")

    def _save_cache(self) -> None:
        if not self.cache_path:
            return
        try:
            save_json(
                {"fetched_at": time.time(), "kev": self.kev, "epss": self.epss},
                self.cache_path,
            )
        except Exception as exc:  # pragma: no cover - defensive
            self._log("debug", f"could not write threat intel cache: {exc}")

    def _get_json(self, url: str, params: Optional[Dict] = None):
        from core.net import http_request

        target = _with_query(url, params) if params else url
        result = http_request(
            self.session, "GET", target, limiter=self.limiter, timeout=self.timeout,
        )
        if not result.ok:
            self.errors.append(f"{url.split('//')[-1].split('/')[0]}: HTTP {result.status or result.error}")
            return {}
        return result.json(default={}) or {}

    # ------------------------------------------------------------------
    def fetch_kev(self) -> int:
        if self.kev:
            return len(self.kev)
        payload = self._get_json(KEV_URL)
        for item in (payload.get("vulnerabilities") or []):
            cve = str(item.get("cveID", "")).upper()
            if not cve:
                continue
            self.kev[cve] = {
                "vendor": item.get("vendorProject"),
                "product": item.get("product"),
                "name": item.get("vulnerabilityName"),
                "date_added": item.get("dateAdded"),
                "due_date": item.get("dueDate"),
                "ransomware": item.get("knownRansomwareCampaignUse"),
            }
        if self.kev:
            self._log("debug", f"CISA KEV: {len(self.kev)} exploited CVEs known")
        return len(self.kev)

    def fetch_epss(self, cves: Iterable[str]) -> int:
        wanted = [cve for cve in dict.fromkeys(cves) if cve and cve not in self.epss]
        for start in range(0, len(wanted), EPSS_CHUNK):
            chunk = wanted[start:start + EPSS_CHUNK]
            payload = self._get_json(EPSS_URL, {"cve": ",".join(chunk)})
            for row in (payload.get("data") or []):
                cve = str(row.get("cve", "")).upper()
                if not cve:
                    continue
                try:
                    score = float(row.get("epss", 0) or 0)
                    percentile = float(row.get("percentile", 0) or 0)
                except (TypeError, ValueError):
                    continue
                self.epss[cve] = {"epss": round(score, 4), "percentile": round(percentile, 4)}
        return len(self.epss)

    # ------------------------------------------------------------------
    def lookup(self, cves: Iterable[str]) -> Dict[str, Dict]:
        """Return {CVE: {"epss":..., "percentile":..., "kev": bool, ...}}."""
        wanted = sorted({str(cve).upper() for cve in cves if cve})
        if not wanted:
            return {}
        self._load_cache()
        self.fetch_kev()
        self.fetch_epss(wanted)
        self._save_cache()

        entries: Dict[str, Dict] = {}
        for cve in wanted:
            entry: Dict = {}
            if cve in self.epss:
                entry.update(self.epss[cve])
            if cve in self.kev:
                entry["kev"] = True
                entry.update({key: value for key, value in self.kev[cve].items() if value})
            if entry:
                entries[cve] = entry
        if self.errors:
            self._log("debug", f"threat intel: {'; '.join(self.errors[:3])}")
        return entries


def _with_query(url: str, params: Dict) -> str:
    from urllib.parse import urlencode

    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urlencode(params)}"


def bonus_for(entry: Dict) -> tuple:
    """
    Score adjustment for one threat-intel entry.

    Returns (bonus, reasons). KEV membership dominates; EPSS adds gradations.
    """
    reasons: List[str] = []
    bonus = 0.0
    if entry.get("kev"):
        bonus += 3.0
        reasons.append("known exploited in the wild (CISA KEV)")
    percentile = float(entry.get("percentile", 0) or 0)
    score = float(entry.get("epss", 0) or 0)
    if percentile >= 0.9 and not entry.get("kev"):
        bonus += 1.5
        reasons.append(f"high exploitation probability (EPSS p{percentile:.2f})")
    elif score >= 0.1:
        bonus += 0.75
        reasons.append(f"moderate exploitation probability (EPSS {score:.2f})")
    return bonus, reasons
