"""
SyncHunt - Asset Enrichment
Turns a bare list of live hosts into enriched assets: DNS/IP data, CDN and
tech hints, TLS certificate facts, security-header posture and exposed
administrative surfaces.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from core.models import Asset, Finding
from core.net import find_scheme, probe, resolve_ips, reverse_dns, tls_peer_info
from core.utils import (
    ensure_dir,
    host_from_url,
    normalize_security_headers,
    read_file_lines,
    save_json,
    truncate,
    write_file_lines,
)

CDN_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "cloudfront": "AWS CloudFront",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "sucuri": "Sucuri",
    "incapsula": "Imperva Incapsula",
    "imperva": "Imperva",
    "varnish": "Varnish",
    "azure": "Azure Front Door",
    "google": "Google Cloud CDN",
}

INTERESTING_STATUSES = {200, 401, 403, 500}


class AssetEnricher:
    """Enrich live hosts with intel and surface low-hanging findings."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.runner = ctx.runner
        self.logger = ctx.logger
        self.output_dir = ctx.path("intel")
        self.target = ctx.target
        ensure_dir(self.output_dir)

        self.max_hosts = self.config.get_int("asset_enrichment.max_hosts", 150)
        self.probe_admin_paths = self.config.get_bool(
            "asset_enrichment.probe_admin_paths", True
        )
        self.report_headers = self.config.get_bool(
            "asset_enrichment.report_header_issues", True
        )
        self.admin_paths = self.config.get_list(
            "asset_enrichment.admin_paths",
            [
                "/admin",
                "/admin/login",
                "/administrator",
                "/login",
                "/wp-admin",
                "/wp-login.php",
                "/manager/html",
                "/phpmyadmin",
                "/.git/config",
                "/.env",
                "/server-status",
                "/actuator",
                "/debug",
                "/console",
                "/api/docs",
                "/swagger-ui.html",
                "/graphql",
                "/metrics",
                "/health",
                "/status",
            ],
        )
        self.results: List[Dict] = []
        self.findings: List[Finding] = []
        self.interesting: List[str] = []

    # ------------------------------------------------------------------
    def _candidate_hosts(self) -> List[str]:
        """Live hosts if available, otherwise the target itself."""
        hosts = read_file_lines(self.ctx.resolve_file("live_hosts", "dns", "live_hosts.txt"))
        if not hosts:
            hosts = [self.target]
            self.logger.info(
                "No live-hosts file yet - enriching the target directly"
            )
        scoped = self.ctx.scope.filter(hosts, record_drops=True) if self.ctx.scope else hosts
        return scoped[: self.max_hosts]

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("ASSET ENRICHMENT", 3)
        started = time.time()

        hosts = self._candidate_hosts()
        if not hosts:
            self.logger.warning("No in-scope hosts to enrich")
            return self.output_dir

        self.logger.info(
            f"Enriching {len(hosts)} host(s) "
            f"(threads={min(self.ctx.threads(), 32)})..."
        )
        workers = max(1, min(self.ctx.threads(), 32, len(hosts)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self._enrich_host, host): host for host in hosts}
            for index, future in enumerate(as_completed(futures), start=1):
                host = futures[future]
                try:
                    record = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    self.logger.debug(f"enrichment failed for {host}: {exc}")
                    continue
                if record:
                    self.results.append(record)
                self.logger.progress(index, len(hosts), "enrichment")

        self._write_outputs()
        self._record()

        duration = time.time() - started
        self.logger.result(
            f"Asset Enrichment Complete: {len(self.results)} hosts, "
            f"{len(self.interesting)} interesting endpoints in {duration:.1f}s"
        )
        return self.output_dir

    # ------------------------------------------------------------------
    def _enrich_host(self, host: str) -> Optional[Dict]:
        host = host.strip()
        name = host_from_url(host)
        if not name:
            return None

        record: Dict = {
            "input": host,
            "host": name,
            "ips": resolve_ips(name, timeout=self.config.get_int("general.resolve_timeout", 5)),
            "reverse_dns": [],
            "base_url": None,
            "status": None,
            "server": "",
            "powered_by": "",
            "cdn": None,
            "title": "",
            "tls": None,
            "security_headers": {},
            "interesting_paths": [],
        }

        for ip in record["ips"][:3]:
            ptr = reverse_dns(ip)
            if ptr:
                record["reverse_dns"].append(ptr)

        base_url = find_scheme(self.ctx.session, host, limiter=self.ctx.limiter)
        if not base_url:
            record["error"] = "no HTTP/HTTPS response"
            return record
        record["base_url"] = base_url

        response = probe(
            self.ctx.session,
            base_url,
            limiter=self.ctx.limiter,
            timeout=self.config.get_int("general.timeout", 10),
            max_bytes=131072,
        )
        record["status"] = response.status
        record["server"] = response.header("Server")
        record["powered_by"] = response.header("X-Powered-By")
        record["title"] = _extract_title(response.text)
        record["cdn"] = _detect_cdn(response.headers, record["server"])
        record["security_headers"] = normalize_security_headers(response.headers)

        if base_url.startswith("https"):
            tls = tls_peer_info(name, port=443,
                                timeout=self.config.get_int("general.resolve_timeout", 5))
            record["tls"] = {
                "issuer": tls.get("issuer", ""),
                "subject": tls.get("subject", ""),
                "not_after": tls.get("not_after", ""),
                "days_until_expiry": tls.get("days_until_expiry"),
                "san": tls.get("san", [])[:25],
                "error": tls.get("error"),
            }
            self._tls_findings(host, name, tls)

        self._header_findings(host, name, base_url, record)

        if self.probe_admin_paths:
            record["interesting_paths"] = self._probe_paths(base_url)

        return record

    # ------------------------------------------------------------------
    def _probe_paths(self, base_url: str) -> List[Dict]:
        found: List[Dict] = []
        for path in self.admin_paths:
            url = base_url.rstrip("/") + path
            response = probe(
                self.ctx.session,
                url,
                limiter=self.ctx.limiter,
                timeout=min(8, self.config.get_int("general.timeout", 10)),
                max_bytes=32768,
            )
            if response.status in INTERESTING_STATUSES:
                entry = {
                    "url": url,
                    "status": response.status,
                    "content_type": response.content_type,
                    "length": response.content_length,
                }
                found.append(entry)
                self.interesting.append(f"{response.status} {url}")
                if path in ("/.env", "/.git/config", "/server-status") and response.status == 200:
                    self.findings.append(
                        Finding(
                            category="exposure",
                            title=f"Sensitive path exposed: {path}",
                            severity="high",
                            target=self.target,
                            url=url,
                            evidence=f"HTTP {response.status} on {url}",
                            source="asset_enrichment",
                            confidence="high",
                            tags=["exposure", "misconfiguration"],
                        )
                    )
        if found:
            self.logger.found(f"{base_url}: {len(found)} interesting path(s)")
        return found

    def _header_findings(self, host: str, name: str, base_url: str, record: Dict) -> None:
        if not self.report_headers:
            return
        headers = record.get("security_headers", {})
        missing = [h for h, present in headers.items() if not present]
        # Only report on hosts that actually serve content.
        if record.get("status") not in (200, 301, 302, 401, 403):
            return
        if "strict-transport-security" in missing and base_url.startswith("https"):
            self.findings.append(
                Finding(
                    category="misconfiguration",
                    title="Missing HSTS header",
                    severity="low",
                    target=self.target,
                    url=base_url,
                    evidence="Strict-Transport-Security not set",
                    source="asset_enrichment",
                    confidence="high",
                    tags=["headers", "tls"],
                )
            )
        if "content-security-policy" in missing:
            self.findings.append(
                Finding(
                    category="misconfiguration",
                    title="Missing Content-Security-Policy header",
                    severity="low",
                    target=self.target,
                    url=base_url,
                    evidence="Content-Security-Policy not set",
                    source="asset_enrichment",
                    confidence="medium",
                    tags=["headers"],
                )
            )

    def _tls_findings(self, host: str, name: str, tls: Dict) -> None:
        days = tls.get("days_until_expiry")
        if tls.get("error"):
            self.findings.append(
                Finding(
                    category="tls",
                    title="TLS handshake problem",
                    severity="medium",
                    target=self.target,
                    url=f"https://{name}",
                    evidence=truncate(str(tls.get("error")), 200),
                    source="asset_enrichment",
                    confidence="medium",
                    tags=["tls"],
                )
            )
        elif isinstance(days, int) and days < 0:
            self.findings.append(
                Finding(
                    category="tls",
                    title="Expired TLS certificate",
                    severity="high",
                    target=self.target,
                    url=f"https://{name}",
                    evidence=f"Certificate expired {abs(days)} day(s) ago",
                    source="asset_enrichment",
                    confidence="high",
                    tags=["tls"],
                )
            )
        elif isinstance(days, int) and days <= 14:
            self.findings.append(
                Finding(
                    category="tls",
                    title="TLS certificate expiring soon",
                    severity="low",
                    target=self.target,
                    url=f"https://{name}",
                    evidence=f"Certificate expires in {days} day(s)",
                    source="asset_enrichment",
                    confidence="high",
                    tags=["tls"],
                )
            )

    # ------------------------------------------------------------------
    def _write_outputs(self) -> None:
        hosts_file = os.path.join(self.output_dir, "hosts.json")
        save_json(self.results, hosts_file)
        self.ctx.set_file("intel_hosts", hosts_file)

        interesting_file = os.path.join(self.output_dir, "interesting_paths.txt")
        write_file_lines(interesting_file, self.interesting)
        self.ctx.set_file("interesting_paths", interesting_file)

        summary = {
            "target": self.target,
            "hosts": len(self.results),
            "resolved": sum(1 for r in self.results if r.get("ips")),
            "with_https": sum(
                1 for r in self.results if str(r.get("base_url") or "").startswith("https")
            ),
            "interesting_paths": len(self.interesting),
            "cdn_usage": sorted(
                {r["cdn"] for r in self.results if r.get("cdn")}
            ),
            "missing_headers": _header_gap_summary(self.results),
        }
        save_json(summary, os.path.join(self.output_dir, "summary.json"))
        self.logger.info(
            f"Intel: {summary['resolved']}/{summary['hosts']} resolved, "
            f"CDN: {', '.join(summary['cdn_usage']) or 'none detected'}"
        )

    def _record(self) -> None:
        assets: List[Asset] = []
        for record in self.results:
            assets.append(
                Asset(
                    kind="host",
                    value=record["host"],
                    host=record["host"],
                    source="asset_enrichment",
                    meta={
                        "ips": record.get("ips", []),
                        "base_url": record.get("base_url"),
                        "server": record.get("server"),
                        "cdn": record.get("cdn"),
                    },
                )
            )
            for ip in record.get("ips", []):
                assets.append(Asset(kind="ip", value=ip, host=record["host"],
                                    source="asset_enrichment"))
            for entry in record.get("interesting_paths", []):
                assets.append(
                    Asset(
                        kind="endpoint",
                        value=entry["url"],
                        host=record["host"],
                        source="asset_enrichment",
                        meta={"status": entry["status"]},
                    )
                )
        self.ctx.record_assets(assets)
        added = self.ctx.record_findings(self.findings)
        if self.findings:
            self.logger.info(
                f"Recorded {len(self.findings)} enrichment finding(s) "
                f"({added} new)"
            )


def _extract_title(html: str, limit: int = 120) -> str:
    if not html:
        return ""
    lowered = html.lower()
    start = lowered.find("<title")
    if start == -1:
        return ""
    start = lowered.find(">", start)
    end = lowered.find("</title>", start if start != -1 else 0)
    if start == -1 or end == -1:
        return ""
    return truncate(" ".join(html[start + 1:end].split()), limit)


def _detect_cdn(headers: Dict[str, str], server: str = "") -> Optional[str]:
    haystack = " ".join(
        [server or ""]
        + [f"{k} {v}" for k, v in (headers or {}).items()]
    ).lower()
    for needle, label in CDN_SIGNATURES.items():
        if needle in haystack:
            return label
    return None


def _header_gap_summary(results: List[Dict]) -> Dict[str, int]:
    gaps: Dict[str, int] = {}
    for record in results:
        for header, present in (record.get("security_headers") or {}).items():
            if not present:
                gaps[header] = gaps.get(header, 0) + 1
    return dict(sorted(gaps.items(), key=lambda item: -item[1]))
