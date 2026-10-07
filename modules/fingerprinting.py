"""
SyncHunt - Web Fingerprinting
Tech-stack and WAF detection with whatweb / wafw00f / webanalyze, plus a
built-in passive fallback that reads headers from the validation phase.
"""

from __future__ import annotations

import json
import os
import time
from typing import Dict, List

from core.models import Asset, Finding
from core.net import http_request
from core.utils import read_file_lines, save_json, truncate


class Fingerprinter:
    """Detect technologies and WAFs on live hosts."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.runner = ctx.runner
        self.logger = ctx.logger
        self.output_dir = ctx.path("fingerprinting")
        self.live_hosts_file = ctx.resolve_file("live_hosts", "dns", "live_hosts.txt")
        os.makedirs(self.output_dir, exist_ok=True)
        self.technologies: Dict[str, List[str]] = {}
        self.waf: Dict[str, str] = {}
        self.findings: List[Finding] = []

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("WEB FINGERPRINTING", 6)
        started = time.time()

        hosts = read_file_lines(self.live_hosts_file)
        if not hosts:
            self.logger.warning("No live hosts to fingerprint")
            return self.output_dir

        self.logger.info(f"Fingerprinting {len(hosts)} host(s)...")
        if self.config.is_tool_enabled("fingerprinting", "whatweb"):
            self.run_whatweb()
        if self.config.is_tool_enabled("fingerprinting", "wafw00f"):
            self.run_wafw00f()
        if self.config.is_tool_enabled("fingerprinting", "webanalyze"):
            self.run_webanalyze()

        # Always run the passive fallback: it also back-fills from the
        # validation phase details so results exist even without binaries.
        self.passive_fingerprint(hosts)
        self._write_outputs()

        self.logger.result(
            f"Fingerprinting Complete: {len(self.technologies)} host(s) profiled "
            f"in {time.time() - started:.1f}s"
        )
        return self.output_dir

    # ------------------------------------------------------------------
    def run_whatweb(self) -> None:
        if self.runner.require("whatweb"):
            return
        cfg = self.config.get_tool_config("fingerprinting", "whatweb")
        json_file = os.path.join(self.output_dir, "whatweb.json")
        self.logger.info("Running whatweb...")
        cmd = [
            "whatweb", "-i", self.live_hosts_file,
            "-a", str(cfg.get("aggression", 3)),
            f"--log-json={json_file}", "--no-errors", "--quiet",
        ]
        self.runner.run(cmd, tool_name="whatweb", timeout=1200)
        self._parse_whatweb(json_file)

    def _parse_whatweb(self, json_file: str) -> None:
        if not os.path.exists(json_file):
            return
        with open(json_file, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                target = record.get("target") or ""
                plugins = record.get("plugins") or {}
                if target and isinstance(plugins, dict):
                    self.technologies.setdefault(target, [])
                    for name in plugins:
                        if name not in self.technologies[target]:
                            self.technologies[target].append(name)

    def run_wafw00f(self) -> None:
        if self.runner.require("wafw00f"):
            return
        json_file = os.path.join(self.output_dir, "wafw00f.json")
        self.logger.info("Running wafw00f...")
        cmd = ["wafw00f", "-i", self.live_hosts_file, "-o", json_file, "-f", "json"]
        self.runner.run(cmd, tool_name="wafw00f", timeout=900)
        from core.utils import load_json

        data = load_json(json_file, [])
        if not isinstance(data, list):
            data = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            target = entry.get("url") or entry.get("target") or ""
            detected = entry.get("detected") or entry.get("firewall")
            if target and detected:
                name = detected if isinstance(detected, str) else str(detected)
                if name.lower() not in ("none", "false", ""):
                    self.waf[target] = name
        if self.waf:
            self.logger.found(f"WAF detected on {len(self.waf)} host(s)")

    def run_webanalyze(self) -> None:
        if self.runner.require("webanalyze"):
            return
        self.logger.info("Running webanalyze...")
        results = []
        for host in read_file_lines(self.live_hosts_file)[:40]:
            result = self.runner.run(
                ["webanalyze", "-host", host, "-output", "json", "-silent"],
                tool_name=f"webanalyze-{host[:30]}",
                timeout=60,
            )
            output = (result.get("stdout") or "").strip()
            if result.get("success") and output:
                try:
                    parsed = json.loads(output)
                except ValueError:
                    continue
                for item in parsed if isinstance(parsed, list) else [parsed]:
                    name = (item or {}).get("app_name") or (item or {}).get("name")
                    if name:
                        self.technologies.setdefault(host, []).append(str(name))
                results.append({"host": host, "output": parsed})
        save_json(results, os.path.join(self.output_dir, "webanalyze.json"))

    def passive_fingerprint(self, hosts: List[str]) -> None:
        """Header-based fallback / enrichment (no external tools needed)."""
        from core.utils import load_json

        details = load_json(self.ctx.get_file("live_hosts_details", ""), [])
        for record in details if isinstance(details, list) else []:
            url = record.get("url") or ""
            if not url:
                continue
            self.technologies.setdefault(url, [])
            for tech in record.get("tech") or []:
                if tech not in self.technologies[url]:
                    self.technologies[url].append(str(tech))
            server = record.get("server") or ""
            if server and server not in self.technologies[url]:
                self.technologies[url].append(server)

        # Probe only hosts that have no intel yet, keeping the request volume low.
        missing = [h for h in hosts if h not in self.technologies][:25]
        for host in missing:
            url = host if host.startswith("http") else f"https://{host}"
            result = http_request(
                self.ctx.session, "GET", url, limiter=self.ctx.limiter,
                timeout=min(8, self.config.get_int("general.timeout", 10)),
                max_bytes=32768,
            )
            if not result.reachable:
                continue
            tech = []
            for header in ("Server", "X-Powered-By", "X-AspNet-Version", "Via", "X-Generator"):
                value = result.header(header)
                if value:
                    tech.append(value)
            if "wp-content" in result.text.lower() or "wordpress" in result.text.lower():
                tech.append("WordPress")
            if tech:
                self.technologies[url] = sorted(set(tech))

            waf_hint = _waf_from_headers(result.headers)
            if waf_hint:
                self.waf[url] = waf_hint

    # ------------------------------------------------------------------
    def _write_outputs(self) -> None:
        data = {
            "technologies": self.technologies,
            "waf": self.waf,
        }
        save_json(data, os.path.join(self.output_dir, "technologies.json"))
        self.ctx.set_file("fingerprint", os.path.join(self.output_dir, "technologies.json"))

        self.ctx.record_assets(
            [
                Asset(
                    kind="technology",
                    value=tech,
                    host=url,
                    source="fingerprinting",
                    meta={"url": url},
                )
                for url, techs in self.technologies.items()
                for tech in techs
            ]
        )
        if self.findings:
            self.ctx.record_findings(self.findings)


def _waf_from_headers(headers: Dict[str, str]) -> str:
    haystack = " ".join(f"{k} {v}" for k, v in (headers or {}).items()).lower()
    for needle, label in (
        ("cloudflare", "Cloudflare"),
        ("sucuri", "Sucuri"),
        ("incapsula", "Imperva"),
        ("akamai", "Akamai"),
        ("awselb", "AWS ELB/WAF"),
        ("mod_security", "ModSecurity"),
    ):
        if needle in haystack:
            return label
    return ""


def summarise_technologies(technologies: Dict[str, List[str]], limit: int = 400) -> str:
    """Small helper used by tests and reporting."""
    lines = []
    for url, techs in sorted(technologies.items()):
        lines.append(f"{truncate(url, 80)}: {', '.join(techs[:12])}")
    return "\n".join(lines[:limit])
