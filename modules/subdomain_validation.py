"""
SyncHunt - Subdomain Validation
Determines which discovered names actually resolve and serve HTTP(S).

Uses httpx when available; falls back to a built-in threaded prober so the
framework still works on a bare machine with no ProjectDiscovery tooling.
"""

from __future__ import annotations

import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from core.models import Asset, Finding
from core.net import http_request, resolve_ips
from core.utils import (
    load_json,
    read_file_lines,
    read_json_lines,
    truncate,
    write_file_lines,
)


class SubdomainValidator:
    """Validate subdomains via DNS resolution and HTTP probing."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.runner = ctx.runner
        self.logger = ctx.logger
        self.target = ctx.target
        self.output_dir = ctx.path("dns")
        self.subdomains_file = ctx.resolve_file("subdomains", "subdomains", "all_subdomains.txt")
        os.makedirs(self.output_dir, exist_ok=True)
        self.live_hosts: List[str] = []
        self.details: List[Dict] = []
        self.findings: List[Finding] = []

    # ------------------------------------------------------------------
    def get_live_hosts_file(self) -> str:
        return os.path.join(self.output_dir, "live_hosts.txt")

    def get_resolved_ips_file(self) -> str:
        return os.path.join(self.output_dir, "resolved_ips.txt")

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("SUBDOMAIN VALIDATION", 2)
        started = time.time()

        subdomains = read_file_lines(self.subdomains_file)
        if not subdomains:
            self.logger.warning("No subdomains to validate")
            write_file_lines(self.get_live_hosts_file(), [])
            return self.get_live_hosts_file()

        extra = self._run_dns_tools()
        if extra:
            before = len(subdomains)
            subdomains = sorted(set(subdomains) | set(extra))
            self.logger.found(
                f"DNS enumeration contributed {len(subdomains) - before} new name(s)"
            )

        self.logger.info(f"Validating {len(subdomains)} subdomain(s)...")
        if self.runner.is_available("httpx"):
            self._run_httpx()
        elif self.runner.is_available("dnsx"):
            self._run_dnsx()
        else:
            self.logger.info(
                "httpx/dnsx not installed - using the built-in prober"
            )
            self._builtin_probe(subdomains)

        self._write_outputs()
        live = read_file_lines(self.get_live_hosts_file())
        self.logger.result(
            f"Validation Complete: {len(live)} live host(s) in {time.time() - started:.1f}s"
        )
        self.ctx.record_assets(
            [Asset(kind="host", value=h, host=h, source="subdomain_validation") for h in live]
        )
        if self.findings:
            self.ctx.record_findings(self.findings)
        return self.get_live_hosts_file()

    # ------------------------------------------------------------------
    # DNS record enumeration (dnsrecon / dnsenum): extra names + AXFR probe
    # ------------------------------------------------------------------
    def _run_dns_tools(self) -> List[str]:
        extra: set = set()
        for tool_name, method in (
            ("dnsrecon", self.run_dnsrecon),
            ("dnsenum", self.run_dnsenum),
        ):
            if not self.config.is_tool_enabled("subdomain_validation", tool_name):
                continue
            try:
                extra.update(method() or [])
            except Exception as exc:
                self.logger.error(f"{tool_name} failed: {exc}")
        return sorted(extra)

    def _names_in_text(self, text: str) -> List[str]:
        pattern = re.compile(
            r"([A-Za-z0-9_][A-Za-z0-9_.-]*\." + re.escape(self.target) + r")",
            re.IGNORECASE,
        )
        return sorted({
            match.group(1).lower().rstrip(".")
            for match in pattern.finditer(text or "")
        })

    def _zone_transfer_finding(self, tool: str, evidence: str) -> None:
        """A successful AXFR is a critical exposure - recorded once per zone."""
        key = f"axfr:{self.target}"
        if any(f.extra.get("axfr_key") == key for f in self.findings):
            return
        finding = Finding(
            category="dns",
            title=f"DNS zone transfer (AXFR) succeeded ({tool})",
            severity="critical",
            target=self.ctx.target,
            evidence=truncate(evidence, 600),
            source=tool,
            confidence="high",
            tags=["dns", "axfr", "zone-transfer"],
            references=["https://owasp.org/www-community/attacks/Zone_Transfer"],
        )
        finding.extra["axfr_key"] = key
        self.findings.append(finding)
        self.logger.vuln(f"Zone transfer succeeded for {self.target} ({tool})")

    def run_dnsrecon(self) -> List[str]:
        """dnsrecon: standard record enumeration with a zone-transfer attempt."""
        output_file = os.path.join(self.output_dir, "dnsrecon.json")
        if self.runner.require("dnsrecon", output_file):
            return []
        self.logger.info("Running dnsrecon...")
        cfg = self.config.get_tool_config("subdomain_validation", "dnsrecon")
        cmd = [
            "dnsrecon", "-d", self.target, "-j", output_file,
            "--lifetime", str(cfg.get("lifetime", 10)),
        ]
        if cfg.get("standard", True):
            cmd.append("-a")
        result = self.runner.run(cmd, tool_name="dnsrecon", timeout=900)
        combined = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"

        records = load_json(output_file, []) or []
        names = set()
        if isinstance(records, list):
            for record in records:
                if not isinstance(record, dict):
                    continue
                name = str(
                    record.get("name") or record.get("target") or ""
                ).strip().lower().rstrip(".")
                if name.endswith(self.target):
                    names.add(name)
        if "zone transfer was successful" in combined.lower():
            self._zone_transfer_finding("dnsrecon", combined)
        if names:
            write_file_lines(
                os.path.join(self.output_dir, "dnsrecon_names.txt"), sorted(names)
            )
        return sorted(names)

    def run_dnsenum(self) -> List[str]:
        """dnsenum: NS/MX/SRV enumeration plus an AXFR probe."""
        output_file = os.path.join(self.output_dir, "dnsenum.txt")
        if self.runner.require("dnsenum", output_file):
            return []
        self.logger.info("Running dnsenum...")
        cfg = self.config.get_tool_config("subdomain_validation", "dnsenum")
        cmd = ["dnsenum", "--noreverse", "--threads",
               str(cfg.get("threads", 5)), self.target]
        result = self.runner.run(cmd, tool_name="dnsenum", timeout=900)
        combined = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
        write_file_lines(output_file, combined.splitlines())
        if "axfr record list" in combined.lower():
            self._zone_transfer_finding("dnsenum", combined)
        return self._names_in_text(combined)


    # ------------------------------------------------------------------
    def _run_httpx(self) -> None:
        """Single httpx pass with JSON output (parsed, not just dumped)."""
        self.logger.info("Running httpx (live host detection + tech detection)...")
        cfg = self.config.get_tool_config("subdomain_validation", "httpx")
        json_file = os.path.join(self.output_dir, "httpx.jsonl")
        cmd = [
            "httpx", "-l", self.subdomains_file, "-silent", "-json",
            "-threads", str(cfg.get("threads", 50)),
            "-timeout", str(cfg.get("timeout", 10)),
            "-status-code", "-title", "-tech-detect", "-content-length",
            "-web-server", "-o", json_file,
        ]
        cmd += self.ctx.header_pairs("-H")
        if cfg.get("follow_redirects", True):
            cmd.append("-follow-redirects")
        self.runner.run(cmd, tool_name="httpx", timeout=900)

        records = read_json_lines(json_file)
        live: List[str] = []
        for record in records:
            url = record.get("url") or record.get("input") or ""
            if not url:
                continue
            live.append(url)
            self.details.append(
                {
                    "url": url,
                    "status": record.get("status_code"),
                    "title": record.get("title", ""),
                    "tech": record.get("tech") or [],
                    "server": record.get("webserver", ""),
                    "content_length": record.get("content_length"),
                    "host": record.get("host", ""),
                    "scheme": record.get("scheme", ""),
                }
            )
        if not records:
            self.logger.warning("httpx produced no JSON output - falling back to text mode")
            self._run_httpx_text()
            return
        self.live_hosts = sorted(set(live))
        write_file_lines(self.get_live_hosts_file(), self.live_hosts)
        self.logger.found(f"httpx: {len(self.live_hosts)} live host(s)")

    def _run_httpx_text(self) -> None:
        cfg = self.config.get_tool_config("subdomain_validation", "httpx")
        live_file = self.get_live_hosts_file()
        cmd = [
            "httpx", "-l", self.subdomains_file, "-silent",
            "-threads", str(cfg.get("threads", 50)),
            "-timeout", str(cfg.get("timeout", 10)),
        ]
        if cfg.get("follow_redirects", True):
            cmd.append("-follow-redirects")
        self.runner.run(cmd, output_file=live_file, tool_name="httpx-text", timeout=900)
        self.live_hosts = read_file_lines(live_file)

    def _run_dnsx(self) -> None:
        self.logger.info("Running dnsx (DNS resolution)...")
        cfg = self.config.get_tool_config("subdomain_validation", "dnsx")
        resolved_file = os.path.join(self.output_dir, "dnsx.txt")
        cmd = [
            "dnsx", "-l", self.subdomains_file, "-silent",
            "-threads", str(cfg.get("threads", 100)),
            "-a", "-resp", "-o", resolved_file,
        ]
        self.runner.run(cmd, tool_name="dnsx", timeout=900)
        resolved = read_file_lines(resolved_file)
        write_file_lines(self.get_resolved_ips_file(), resolved)
        self.logger.found(f"dnsx: {len(resolved)} record(s)")
        self.live_hosts = [line.split()[0] for line in resolved if line]
        write_file_lines(self.get_live_hosts_file(), self.live_hosts)

    def _builtin_probe(self, subdomains: List[str]) -> None:
        """Dependency-free fallback: resolve + probe both schemes."""
        timeout = self.config.get_int("general.timeout", 10)
        workers = max(1, min(self.ctx.threads(), 50))
        live: List[str] = []
        resolved_ips: List[str] = []

        def _probe(name: str) -> Dict:
            ips = resolve_ips(name, timeout=self.config.get_int("general.resolve_timeout", 5))
            record = {"host": name, "ips": ips, "url": "", "status": None}
            if not ips:
                return record
            for scheme in ("https", "http"):
                url = f"{scheme}://{name}"
                result = http_request(
                    self.ctx.session, "GET", url, limiter=self.ctx.limiter,
                    timeout=timeout, allow_redirects=True, max_bytes=32768,
                )
                if result.reachable:
                    record["url"] = result.final_url or url
                    record["status"] = result.status
                    return record
            return record

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_probe, name): name for name in subdomains}
            for index, future in enumerate(as_completed(futures), start=1):
                try:
                    record = future.result()
                except Exception:  # pragma: no cover - defensive
                    continue
                if record.get("url"):
                    live.append(record["url"])
                    self.details.append(record)
                for ip in record.get("ips", []):
                    resolved_ips.append(f"{record['host']} -> {ip}")
                self.logger.progress(index, len(futures), "validation")

        self.live_hosts = sorted(set(live))
        write_file_lines(self.get_live_hosts_file(), self.live_hosts)
        write_file_lines(self.get_resolved_ips_file(), sorted(set(resolved_ips)))
        self.logger.found(f"built-in prober: {len(self.live_hosts)} live host(s)")

    # ------------------------------------------------------------------
    def _write_outputs(self) -> None:
        if not os.path.exists(self.get_live_hosts_file()):
            write_file_lines(self.get_live_hosts_file(), self.live_hosts)
        from core.utils import save_json

        details_file = os.path.join(self.output_dir, "httpx_details.json")
        save_json(self.details, details_file)
        self.ctx.set_file("live_hosts", self.get_live_hosts_file())
        self.ctx.set_file("live_hosts_details", details_file)
