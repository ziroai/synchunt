"""
SyncHunt - Subdomain takeover detection

A subdomain is takeover-prone when its DNS still points at a service the owner
no longer controls (an S3 bucket that was deleted, an abandoned GitHub Pages
site, a deprovisioned Heroku app, ...). Whoever claims the backing resource
serves content on the victim's domain - a full account of the bug class lives
at https://github.com/EdOverflow/can-i-take-over-xyz.

Detection is two-stage:

1. the CNAME chain for the subdomain is resolved and matched against the
   fingerprint table below (cheap, DNS only);
2. when a service match is possible, the URL is fetched and the response body
   is compared against that service's "unclaimed resource" strings.

A CNAME match *and* a body match is a critical, high-confidence finding; a body
match alone is high; a CNAME match alone is a medium confidence lead that needs
a human, and is reported as such rather than as a confirmed takeover.

`safe_ranges` / `unsafe_ranges` from can-i-take-over-xyz are honoured: services
whose unclaimed resources cannot be claimed by a third party are never reported
as takeovers.
"""

from __future__ import annotations

import os
import time
from typing import Dict, List, Optional

from core.models import Asset, Finding
from core.net import http_request, resolve_cname_chain
from core.utils import read_file_lines, save_json, truncate, write_file_lines

# service -> (cname patterns, body fingerprints, claimable, reference)
# `claimable=False` means an unclaimed resource cannot be registered by a third
# party (per can-i-take-over-xyz) - the finding is informational only.
FINGERPRINTS: List[Dict] = [
    {
        "service": "Amazon S3",
        "cnames": [".s3.amazonaws.com", ".s3-website", ".s3.dualstack"],
        "bodies": ["NoSuchBucket", "The specified bucket does not exist"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#s3-bucket",
    },
    {
        "service": "GitHub Pages",
        "cnames": [".github.io", ".github.com"],
        "bodies": ["There isn't a GitHub Pages site here",
                   "For root URLs (like http://example.com/) you must provide an index.html"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#github-pages",
    },
    {
        "service": "Heroku",
        "cnames": [".herokudns.com", ".herokuapp.com"],
        "bodies": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#heroku",
    },
    {
        "service": "Netlify",
        "cnames": [".netlify.app", ".netlify.com"],
        "bodies": ["Not Found - Request ID", "Site not found"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#netlify",
    },
    {
        "service": "Azure",
        "cnames": [".azurewebsites.net", ".cloudapp.azure.com", ".azurefd.net",
                   ".azureedge.net", ".blob.core.windows.net"],
        "bodies": ["404 Web Site not found", "The resource you are looking for has been removed"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#azure",
    },
    {
        "service": "Shopify",
        "cnames": [".myshopify.com"],
        "bodies": ["Sorry, this shop is currently unavailable"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#shopify",
    },
    {
        "service": "Fastly",
        "cnames": [".fastly.net"],
        "bodies": ["Fastly error: unknown domain"],
        "claimable": False,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#fastly",
    },
    {
        "service": "Zendesk",
        "cnames": [".zendesk.com"],
        "bodies": ["Help Center Closed", "this help center no longer exists"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#zendesk",
    },
    {
        "service": "WordPress",
        "cnames": [".wordpress.com"],
        "bodies": ["Do you want to register"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#wordpress",
    },
    {
        "service": "WPEngine",
        "cnames": [".wpengine.com"],
        "bodies": ["The site you were looking for couldn't be found"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#wpengine",
    },
    {
        "service": "Tumblr",
        "cnames": [".tumblr.com"],
        "bodies": ["Whatever you were looking for doesn't currently exist at this address"],
        "claimable": False,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#tumblr",
    },
    {
        "service": "Pantheon",
        "cnames": [".pantheonsite.io"],
        "bodies": ["The gods are wise, but do not know of the site which you seek"],
        "claimable": False,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#pantheon",
    },
    {
        "service": "Surge.sh",
        "cnames": [".surge.sh"],
        "bodies": ["project not found"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#surge",
    },
    {
        "service": "Bitbucket",
        "cnames": [".bitbucket.io"],
        "bodies": ["Repository not found"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#bitbucket",
    },
    {
        "service": "Unbounce",
        "cnames": [".unbouncepages.com"],
        "bodies": ["The requested URL was not found on this server"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#unbounce",
    },
    {
        "service": "Ghost",
        "cnames": [".ghost.io"],
        "bodies": ["The thing you were looking for is no longer here"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#ghost",
    },
    {
        "service": "Vercel",
        "cnames": [".vercel-dns.com", ".now.sh"],
        "bodies": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#vercel",
    },
    {
        "service": "Fly.io",
        "cnames": [".fly.dev"],
        "bodies": ["Could not find App", "404 Not Found"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#flyio",
    },
    {
        "service": "Read the Docs",
        "cnames": [".readthedocs.io"],
        "bodies": ["unknown to Read the Docs"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#read-the-docs",
    },
    {
        "service": "Cargo (Rust)",
        "cnames": [".cargocollective.com"],
        "bodies": ["404 Not Found"],
        "claimable": True,
        "reference": "https://github.com/EdOverflow/can-i-take-over-xyz#cargo",
    },
]


class SubdomainTakeover:
    """Phase 4: flag DNS records that point at unclaimed services."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.logger = ctx.logger
        self.target = ctx.target
        self.output_dir = ctx.path("takeover")
        os.makedirs(self.output_dir, exist_ok=True)
        self.findings: List[Finding] = []
        self.candidates: List[Dict] = []
        self.max_hosts = self.config.get_int("subdomain_takeover.max_hosts", 300)
        self.checked = 0

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("SUBDOMAIN TAKEOVER", 4)
        started = time.time()

        subdomains = read_file_lines(
            self.ctx.resolve_file("subdomains", "subdomains", "all_subdomains.txt")
        )
        if not subdomains:
            hosts = read_file_lines(self.ctx.resolve_file("live_hosts", "dns", "live_hosts.txt"))
            subdomains = sorted({h.split("://")[-1].split("/")[0].split(":")[0] for h in hosts})
        subdomains = [name for name in subdomains if name]
        if not subdomains:
            self.logger.warning("No subdomains to check for takeover")
            self._write_outputs()
            return self.output_dir

        if self.ctx.scope is not None:
            subdomains = self.ctx.scope.filter(subdomains)

        targets = subdomains[: self.max_hosts]
        self.checked = len(targets)
        self.logger.info(f"Checking {len(targets)} host(s) for takeover-prone DNS...")

        for host in targets:
            self.check_host(host)

        if self.config.is_tool_enabled("subdomain_takeover", "subjack"):
            self.run_subjack()

        self._write_outputs()
        self.ctx.record_assets(
            [Asset(kind="takeover_candidate", value=c["host"], source="subdomain_takeover")
             for c in self.candidates]
        )
        self.ctx.record_findings(self.findings)

        confirmed = sum(1 for c in self.candidates if c["confidence"] == "high")
        self.logger.result(
            f"Takeover Check Complete: {confirmed} confirmed, "
            f"{len(self.candidates)} candidate(s) in {time.time() - started:.1f}s"
        )
        return self.output_dir

    # ------------------------------------------------------------------
    def match_service(self, cname: str) -> Optional[Dict]:
        """Return the fingerprint entry a CNAME belongs to, if any."""
        cname = (cname or "").lower().rstrip(".")
        for entry in FINGERPRINTS:
            if any(pattern in cname for pattern in entry["cnames"]):
                return entry
        return None

    @staticmethod
    def match_body(body: str, entry: Dict) -> str:
        """Return the service fingerprint string found in `body` ("" if none)."""
        if not body:
            return ""
        for needle in entry["bodies"]:
            if needle.lower() in body.lower():
                return needle
        return ""

    def check_host(self, host: str) -> Optional[Dict]:
        chain = resolve_cname_chain(host)
        if not chain:
            return None

        entry = None
        for cname in chain:
            entry = self.match_service(cname)
            if entry:
                break
        if entry is None:
            return None

        scheme, status, body, matched = "https", 0, "", ""
        for candidate_scheme in ("https", "http"):
            result = http_request(
                self.ctx.session, "GET", f"{candidate_scheme}://{host}/",
                limiter=self.ctx.limiter, timeout=15, max_bytes=256 * 1024,
                allow_redirects=True,
            )
            if result.reachable:
                scheme, status, body = candidate_scheme, result.status, result.text or ""
                matched = self.match_body(body, entry)
                break

        if matched and not entry["claimable"]:
            confidence, severity = "low", "info"
            reason = (
                f"{entry['service']} reports an unclaimed resource, but this service "
                "cannot be claimed by a third party - likely a stale record only"
            )
        elif matched:
            confidence, severity = "high", "critical"
            reason = (
                f"CNAME points at {entry['service']} and the response contains the "
                f"unclaimed-resource fingerprint {matched!r}"
            )
        else:
            confidence, severity = "medium", "high"
            reason = (
                f"CNAME points at {entry['service']} but no unclaimed-resource "
                "fingerprint was returned - verify the backing resource manually"
            )

        record = {
            "host": host,
            "service": entry["service"],
            "cname_chain": chain,
            "cname_target": chain[-1],
            "status": status,
            "scheme": scheme,
            "matched_body": matched,
            "confidence": confidence,
            "severity": severity,
            "claimable": entry["claimable"],
            "reason": reason,
            "reference": entry["reference"],
        }
        self.candidates.append(record)

        finding = Finding(
            category="takeover",
            title=f"Subdomain takeover candidate: {host} -> {entry['service']}",
            severity=severity,
            confidence=confidence,
            target=self.target,
            url=f"{scheme}://{host}/",
            evidence=truncate(
                f"{reason}\nCNAME chain: {' -> '.join([host] + chain)}", 800
            ),
            source="subdomain_takeover",
            tags=["takeover", "dns", entry["service"].lower().replace(" ", "-")],
            references=[entry["reference"]],
            extra={"takeover": record},
        )
        self.findings.append(finding)
        if severity in ("critical", "high"):
            self.logger.vuln(f"{host}: {reason}")
        else:
            self.logger.found(f"{host}: {reason}")
        return record

    # ------------------------------------------------------------------
    def run_subjack(self) -> None:
        """Optional: cross-check with subjack when it is installed."""
        subdomains_file = self.ctx.resolve_file("subdomains", "subdomains", "all_subdomains.txt")
        if not subdomains_file or not os.path.exists(subdomains_file):
            return
        if self.runner_require("subjack"):
            return

        cfg = self.config.get_tool_config("subdomain_takeover", "subjack")
        output_file = os.path.join(self.output_dir, "subjack.txt")
        cmd = [
            "subjack", "-w", subdomains_file, "-t", str(cfg.get("threads", 50)),
            "-timeout", str(cfg.get("timeout", 30)), "-ssl", "-v",
            "-o", output_file,
        ]
        if cfg.get("fingerprints"):
            cmd += ["-c", str(cfg["fingerprints"])]
        self.logger.info("Cross-checking with subjack...")
        self.ctx.runner.run(cmd, tool_name="subjack", timeout=1800)

        for line in read_file_lines(output_file):
            if "Vulnerable" not in line and "[!]" not in line:
                continue
            host = line.split()[0] if line.split() else ""
            if not host:
                continue
            finding = Finding(
                category="takeover",
                title=f"Subdomain takeover (subjack): {host}",
                severity="critical",
                confidence="medium",
                target=self.target,
                url=f"https://{host}/",
                evidence=truncate(line, 400),
                source="subjack",
                tags=["takeover", "subjack"],
                references=["https://github.com/haccer/subjack"],
            )
            self.findings.append(finding)
            self.logger.vuln(f"subjack: {line}")

    def runner_require(self, tool: str) -> bool:
        try:
            return self.ctx.runner.require(tool)
        except Exception:  # pragma: no cover - defensive
            return True

    # ------------------------------------------------------------------
    def _write_outputs(self) -> None:
        save_json(self.candidates, os.path.join(self.output_dir, "candidates.json"))
        if self.candidates:
            write_file_lines(
                os.path.join(self.output_dir, "candidates.txt"),
                [
                    f"[{c['confidence']}] {c['host']} -> {c['service']} ({c['cname_target']})"
                    for c in self.candidates
                ],
            )
        confirmed = [c for c in self.candidates if c["confidence"] == "high"]
        save_json(
            {
                "hosts_checked": self.checked,
                "candidates": len(self.candidates),
                "confirmed": len(confirmed),
                "services": sorted({c["service"] for c in self.candidates}),
            },
            os.path.join(self.output_dir, "summary.json"),
        )
        self.ctx.set_file("takeover_candidates", os.path.join(self.output_dir, "candidates.json"))


def run_all(ctx) -> str:  # pragma: no cover - convenience helper
    return SubdomainTakeover(ctx).run_all()
