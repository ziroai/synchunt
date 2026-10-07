"""
SyncHunt - Vulnerability Scanning
Nuclei (primary), nikto, dalfox, sqlmap, crlfuzz and corsy, plus a built-in
open-redirect candidate finder.

Every external command is executed as an argv list: user-controlled data
(crawled URLs) is never interpolated into a shell string.
"""

from __future__ import annotations

import os
import re
import time
from typing import Dict, List

from core.models import Asset, Finding
from core.net import http_request
from core.oob import build_client as build_oob_client
from core.utils import (
    sanitize_filename,
    load_json,
    read_file_lines,
    read_json_lines,
    save_json,
    truncate,
    write_file_lines,
)

REDIRECT_PARAMS = [
    "redirect", "url", "next", "dest", "destination", "redir", "redirect_url",
    "redirect_uri", "return", "return_url", "returnto", "go", "goto", "out",
    "view", "to", "ref", "referrer", "continue", "forward", "target", "link",
    "callback",
]


class VulnScanner:
    """Run vulnerability scanners and normalise their output into findings."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.runner = ctx.runner
        self.logger = ctx.logger
        self.output_dir = ctx.path("vulnerabilities")
        self.live_hosts_file = ctx.resolve_file("live_hosts", "dns", "live_hosts.txt")
        self.urls_file = ctx.resolve_file("urls", "content_discovery", "all_urls.txt")
        self.params_file = ctx.resolve_file(
            "params", "content_discovery", "params", "all_params.txt"
        )
        os.makedirs(self.output_dir, exist_ok=True)
        self.findings: List[Finding] = []
        self.oob = None
        self.oob_interactions: List[dict] = []

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("VULNERABILITY SCANNING", 12)
        started = time.time()

        if not read_file_lines(self.live_hosts_file):
            self.logger.warning("No live hosts to scan")
            return self.output_dir

        self._start_oob()

        if self.config.is_tool_enabled("vuln_scanning", "nuclei"):
            self.run_nuclei()
        if self.config.is_tool_enabled("vuln_scanning", "nikto"):
            self.run_nikto()
        if self.config.is_tool_enabled("vuln_scanning", "dalfox"):
            self.run_dalfox()
        if self.config.is_tool_enabled("vuln_scanning", "sqlmap"):
            self.run_sqlmap()
        if self.config.is_tool_enabled("vuln_scanning", "crlfuzz"):
            self.run_crlfuzz()
        if self.config.is_tool_enabled("vuln_scanning", "corsy"):
            self.run_corsy()
        if self.config.is_tool_enabled("vuln_scanning", "wapiti"):
            self.run_wapiti()
        if self.config.is_tool_enabled("vuln_scanning", "ghauri"):
            self.run_ghauri()
        if self.config.is_tool_enabled("vuln_scanning", "xsstrike"):
            self.run_xsstrike()
        if self.config.is_tool_enabled("vuln_scanning", "wpscan"):
            self.run_wpscan()
        if self.config.is_tool_enabled("vuln_scanning", "joomscan"):
            self.run_joomscan()
        if self.config.is_tool_enabled("vuln_scanning", "commix"):
            self.run_commix()
        if self.config.is_tool_enabled("vuln_scanning", "tplmap"):
            self.run_tplmap()
        if self.config.is_tool_enabled("vuln_scanning", "ssrfmap"):
            self.run_ssrfmap()

        self._check_open_redirects()
        if self.oob is not None:
            self.run_oob_param_probes()
        self._collect_oob_findings()
        self._write_outputs()
        self.ctx.record_findings(self.findings)

        self.logger.result(
            f"Vulnerability Scanning Complete: {len(self.findings)} finding(s) "
            f"in {time.time() - started:.1f}s"
        )
        return self.output_dir

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # Out-of-band (OOB) collaboration
    # ------------------------------------------------------------------
    def _start_oob(self) -> None:
        """Bring up the callback endpoint when OOB is enabled in config."""
        client = build_oob_client(
            self.config, session=self.ctx.session, limiter=self.ctx.limiter,
            logger=self.logger, section="vuln_scanning",
        )
        if client is None:
            return
        if client.start():
            self.oob = client
        else:
            self.logger.warning(
                f"OOB provider unavailable ({client.error or 'unknown error'}) - "
                "blind vulnerabilities cannot be confirmed out-of-band"
            )

    def run_oob_param_probes(self) -> None:
        """
        Inject the callback URL into parameterised URLs to catch SSRF/XXE-style
        blind bugs. Disabled unless `vuln_scanning.oob.probe_params` is on: it
        modifies requests, so enabling it is a deliberate decision per program.
        """
        if not self.config.get_bool("vuln_scanning.oob.probe_params", False):
            return
        if not self.params_file or not os.path.exists(self.params_file):
            return
        max_urls = max(1, self.config.get_int("vuln_scanning.oob.max_urls", 10))
        urls = read_file_lines(self.params_file)[:max_urls]
        if not urls:
            return

        out_file = os.path.join(self.output_dir, "oob_probes.txt")
        probes = []
        self.logger.info(f"Injecting OOB callbacks into {len(urls)} parameterised URL(s)...")
        for url in urls:
            callback = self.oob.probe_url("ssrf")
            injected = _inject_callback(url, callback)
            if not injected:
                continue
            probes.append(injected)
            result = http_request(
                self.ctx.session, "GET", injected, limiter=self.ctx.limiter,
                timeout=15, max_bytes=16384,
            )
            if "oob" in injected and result.reachable:
                pass  # a callback arrives out-of-band, not in this response
        write_file_lines(out_file, probes)
        if probes:
            # give the target a moment to make its callback before polling
            time.sleep(min(10, max(2, self.config.get_int("vuln_scanning.oob.wait", 5))))
        self.logger.info(f"{len(probes)} OOB probe(s) sent")

    def _collect_oob_findings(self) -> None:
        """Turn observed callbacks into findings and artifacts, then stop."""
        if self.oob is None:
            return
        try:
            interactions = self.oob.poll()
        except Exception as exc:  # pragma: no cover - network dependent
            self.logger.warning(f"OOB polling failed: {exc}")
            interactions = []

        records = [interaction.to_dict() for interaction in interactions]
        self.oob_interactions = records
        if records:
            save_json(records, os.path.join(self.output_dir, "oob_interactions.json"))
            for record in records[:20]:
                target_desc = record.get("path") or record.get("provider")
                self.findings.append(
                    Finding(
                        category="oob",
                        title="Out-of-band interaction confirmed (blind injection)",
                        severity="high",
                        confidence="high",
                        target=self.ctx.target,
                        url=str(record.get("path") or ""),
                        evidence=truncate(
                            f"Callback received via {record.get('provider')}: "
                            f"{record.get('method')} {record.get('path')} "
                            f"from {record.get('source_ip')} at {record.get('time')}",
                            600,
                        ),
                        source="oob",
                        tags=["oob", "blind", "ssrf", "xss"],
                    )
                )
                self.logger.vuln(f"OOB interaction: {target_desc}")
        else:
            self.logger.info("OOB: no callbacks received during this scan")
        self.oob.stop()

    def run_nuclei(self) -> None:
        nuclei_dir = os.path.join(self.output_dir, "nuclei")
        os.makedirs(nuclei_dir, exist_ok=True)
        json_file = os.path.join(nuclei_dir, "nuclei.jsonl")
        if self.runner.require("nuclei", json_file):
            return

        cfg = self.config.get_tool_config("vuln_scanning", "nuclei")
        self.logger.info("Running nuclei...")
        cmd = [
            "nuclei", "-l", self.live_hosts_file, "-silent", "-jsonl",
            "-severity", str(cfg.get("severity", "critical,high,medium,low,info")),
            "-rl", str(cfg.get("rate_limit", 150)),
            "-bs", str(cfg.get("bulk_size", 25)),
            "-c", str(cfg.get("concurrency", 25)),
            "-o", json_file,
        ]
        cmd += self.ctx.header_pairs("-H")
        if cfg.get("templates"):
            cmd += ["-t", str(cfg["templates"])]
        if cfg.get("headless", False):
            cmd.append("-headless")
        if cfg.get("automatic_scan", True):
            cmd.append("-as")
        # NOTE: -nt/-new-templates performs a network template update; it is
        # opt-in because it changes state outside the run directory.
        if cfg.get("new_templates", False):
            cmd.append("-nt")

        self.runner.run(cmd, tool_name="nuclei", timeout=5400)

        records = read_json_lines(json_file)
        if not records:
            # Fall back to reading plain text output from older invocations.
            text_file = os.path.join(nuclei_dir, "nuclei.txt")
            if os.path.exists(text_file):
                for line in read_file_lines(text_file):
                    self.findings.append(
                        Finding(
                            category="vulnerability",
                            title=truncate(line, 200),
                            severity=_severity_from_line(line),
                            target=self.ctx.target,
                            evidence=line,
                            source="nuclei",
                            confidence="medium",
                        )
                    )
        for record in records:
            self._nuclei_finding(record)

        self.logger.found(f"nuclei: {len(records)} raw result(s)")

    def _nuclei_finding(self, record: Dict) -> None:
        info = record.get("info") or {}
        severity = (info.get("severity") or "info").lower()
        template_id = record.get("template-id") or info.get("name") or "nuclei"
        matched = record.get("matched-at") or record.get("host") or ""
        title = info.get("name") or template_id
        finding = Finding(
            category=_category_for_template(template_id, title),
            title=f"{title} [{template_id}]",
            severity=severity,
            target=self.ctx.target,
            url=matched,
            evidence=_nuclei_evidence(record),
            source="nuclei",
            confidence="high" if severity in ("critical", "high") else "medium",
            tags=list(info.get("tags") or [])[:10],
            references=list(info.get("reference") or [])[:5] if isinstance(info.get("reference"), list) else [],
            extra={
                "template": template_id,
                "matcher": record.get("matcher-name", ""),
                "extracted": record.get("extracted-results", [])[:5],
            },
        )
        self.findings.append(finding)
        if severity in ("critical", "high"):
            self.logger.vuln(f"[{severity.upper()}] {title} - {matched}")
        elif severity == "medium":
            self.logger.found(f"[medium] {title} - {matched}")

    # ------------------------------------------------------------------
    def run_nikto(self) -> None:
        nikto_dir = os.path.join(self.output_dir, "nikto")
        os.makedirs(nikto_dir, exist_ok=True)
        if self.runner.require("nikto"):
            return
        cfg = self.config.get_tool_config("vuln_scanning", "nikto")
        tuning = str(cfg.get("tuning", "1234567890"))
        self.logger.info("Running nikto...")
        for host in read_file_lines(self.live_hosts_file)[:10]:
            safe = host.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
            output_file = os.path.join(nikto_dir, f"nikto_{safe}.txt")
            cmd = [
                "nikto", "-h", host, "-Tuning", tuning,
                "-output", output_file, "-Format", "txt", "-nointeractive",
            ]
            proxy = self.config.get("general.proxy", "")
            if proxy:
                cmd += ["-useproxy", proxy]
            self.runner.run(cmd, tool_name=f"nikto-{safe[:30]}", timeout=1200)
        self.logger.found("nikto: scan complete")

    def run_dalfox(self) -> None:
        xss_dir = os.path.join(self.output_dir, "xss")
        os.makedirs(xss_dir, exist_ok=True)
        output_file = os.path.join(xss_dir, "dalfox.txt")
        if self.runner.require("dalfox", output_file):
            return

        scan_file = self.params_file if os.path.exists(self.params_file or "") else self.urls_file
        if not scan_file or not os.path.exists(scan_file):
            self.logger.skip("no URLs available for XSS scanning")
            return

        cfg = self.config.get_tool_config("vuln_scanning", "dalfox")
        self.logger.info("Running dalfox (XSS)...")
        cmd = [
            "dalfox", "file", scan_file,
            "-w", str(cfg.get("threads", 10)),
            "--silence", "-o", output_file,
        ]
        cmd += self.ctx.header_pairs("-H")
        blind = cfg.get("blind_xss") or ""
        if not blind and self.oob is not None:
            blind = self.oob.probe_url("blindxss")
        if blind:
            cmd += ["-b", str(blind)]
        self.runner.run(cmd, tool_name="dalfox", timeout=3600)

        for line in read_file_lines(output_file):
            finding = Finding(
                category="xss",
                title="Reflected XSS (dalfox)",
                severity="medium",
                target=self.ctx.target,
                url=line.split()[0] if line.split() else "",
                evidence=line,
                source="dalfox",
                confidence="medium",
                tags=["xss", "injection"],
            )
            self.findings.append(finding)
            self.logger.vuln(f"XSS candidate: {line}")

    def run_sqlmap(self) -> None:
        sqli_dir = os.path.join(self.output_dir, "sqli")
        os.makedirs(sqli_dir, exist_ok=True)
        if self.runner.require("sqlmap"):
            return
        if not self.params_file or not os.path.exists(self.params_file):
            self.logger.skip("no parameterised URLs available for sqlmap")
            return

        cfg = self.config.get_tool_config("vuln_scanning", "sqlmap")
        level = cfg.get("level", 1)
        risk = cfg.get("risk", 1)
        self.logger.info("Running sqlmap on parameterised URLs...")

        for url in read_file_lines(self.params_file)[:20]:
            safe_name = sanitize_filename(
                url.replace("https://", "").replace("http://", ""), 60
            )
            output_dir_sqli = os.path.join(sqli_dir, safe_name)
            # argv list => no shell parsing, so a crafted URL cannot execute code.
            cmd = [
                "sqlmap", "-u", url,
                "--level", str(level), "--risk", str(risk),
                "--batch", "--random-agent", "--threads", "5",
                "--output-dir", output_dir_sqli,
            ]
            from core.auth import sqlmap_args
            cmd += sqlmap_args(self.config)
            proxy = self.config.get("general.proxy", "")
            if proxy:
                cmd += ["--proxy", proxy]
            result = self.runner.run(cmd, tool_name="sqlmap", timeout=600)
            combined = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
            if "injectable" in combined.lower() or "sqlmap identified" in combined.lower():
                self.findings.append(
                    Finding(
                        category="sqli",
                        title="SQL injection (sqlmap)",
                        severity="critical",
                        target=self.ctx.target,
                        url=url,
                        evidence=truncate(combined, 600),
                        source="sqlmap",
                        confidence="medium",
                        tags=["sqli", "injection"],
                    )
                )
                self.logger.vuln(f"SQL injection candidate: {url}")

    # ------------------------------------------------------------------
    def run_wapiti(self) -> None:
        """wapiti: broad web-application scan with JSON output."""
        wapiti_dir = os.path.join(self.output_dir, "wapiti")
        os.makedirs(wapiti_dir, exist_ok=True)
        report_file = os.path.join(wapiti_dir, "wapiti.json")
        if self.runner.require("wapiti", report_file):
            return

        cfg = self.config.get_tool_config("vuln_scanning", "wapiti")
        self.logger.info("Running wapiti...")
        for host in read_file_lines(self.live_hosts_file)[: int(cfg.get("max_hosts", 5))]:
            safe = sanitize_filename(
                host.replace("https://", "").replace("http://", ""), 60
            )
            host_report = os.path.join(wapiti_dir, f"{safe}.json")
            cmd = [
                "wapiti", "-u", host, "-f", "json", "-o", host_report,
                "--flush-session", "-q",
                "--scope", "page",
            ]
            if cfg.get("modules"):
                cmd += ["-m", str(cfg["modules"])]
            self.runner.run(cmd, tool_name=f"wapiti-{safe[:30]}", timeout=3600)

        for name in sorted(os.listdir(wapiti_dir)):
            if not name.endswith(".json"):
                continue
            data = load_json(os.path.join(wapiti_dir, name), {})
            if not isinstance(data, dict):
                continue
            for category, entries in (data.get("vulnerabilities") or {}).items():
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    level = entry.get("level")
                    severity = {4: "critical", 3: "high", 2: "medium",
                                1: "low"}.get(int(level) if str(level).isdigit() else 0, "low")
                    path = str(entry.get("path") or "")
                    parameter = str(entry.get("parameter") or "")
                    self.findings.append(
                        Finding(
                            category=str(category).lower().replace(" ", "-"),
                            title=f"wapiti: {category}"
                                  + (f" ({parameter})" if parameter else ""),
                            severity=severity,
                            target=self.ctx.target,
                            url=path,
                            evidence=truncate(
                                str(entry.get("info") or entry.get("curl_command") or ""), 600
                            ),
                            source="wapiti",
                            confidence="medium",
                            tags=["wapiti", str(category).lower()],
                        )
                    )
            self.logger.info(f"wapiti: parsed {name}")

    def run_ghauri(self) -> None:
        """ghauri: SQL injection scanner (sqlmap alternative)."""
        ghauri_dir = os.path.join(self.output_dir, "sqli")
        os.makedirs(ghauri_dir, exist_ok=True)
        if self.runner.require("ghauri"):
            return
        if not self.params_file or not os.path.exists(self.params_file):
            self.logger.skip("no parameterised URLs available for ghauri")
            return

        cfg = self.config.get_tool_config("vuln_scanning", "ghauri")
        self.logger.info("Running ghauri on parameterised URLs...")
        for url in read_file_lines(self.params_file)[: int(cfg.get("max_urls", 10))]:
            safe = url.replace("https://", "").replace("http://", "")[:60]
            safe = safe.replace("/", "_").replace("?", "_").replace("&", "_")
            cmd = [
                "ghauri", "-u", url,
                "--level", str(cfg.get("level", 1)),
                "--risk", str(cfg.get("risk", 1)),
                "--batch", "--threads", "5",
                "--output-dir", os.path.join(ghauri_dir, safe),
            ]
            result = self.runner.run(cmd, tool_name="ghauri", timeout=600)
            combined = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
            lowered = combined.lower()
            if "injectable" in lowered or "is vulnerable" in lowered or "sql injection" in lowered:
                self.findings.append(
                    Finding(
                        category="sqli",
                        title="SQL injection (ghauri)",
                        severity="critical",
                        target=self.ctx.target,
                        url=url,
                        evidence=truncate(combined, 600),
                        source="ghauri",
                        confidence="medium",
                        tags=["sqli", "injection"],
                    )
                )
                self.logger.vuln(f"SQL injection candidate (ghauri): {url}")

    def run_xsstrike(self) -> None:
        """xsstrike: XSS scanner over parameterised URLs."""
        if self.runner.require("xsstrike"):
            return
        scan_file = self.params_file if os.path.exists(self.params_file or "") else ""
        if not scan_file:
            self.logger.skip("no parameterised URLs available for xsstrike")
            return

        cfg = self.config.get_tool_config("vuln_scanning", "xsstrike")
        xss_dir = os.path.join(self.output_dir, "xss")
        os.makedirs(xss_dir, exist_ok=True)
        self.logger.info("Running xsstrike...")
        for url in read_file_lines(scan_file)[: int(cfg.get("max_urls", 5))]:
            result = self.runner.run(
                ["xsstrike", "-u", url, "--skip", "--skip-dom"],
                tool_name="xsstrike", timeout=600,
            )
            combined = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
            if "payload" in combined.lower() and "vulnerable" in combined.lower():
                self.findings.append(
                    Finding(
                        category="xss",
                        title="Reflected XSS (xsstrike)",
                        severity="medium",
                        target=self.ctx.target,
                        url=url,
                        evidence=truncate(combined, 600),
                        source="xsstrike",
                        confidence="medium",
                        tags=["xss", "injection"],
                    )
                )
                self.logger.vuln(f"XSS candidate (xsstrike): {url}")

    def run_wpscan(self) -> None:
        """wpscan: WordPress-specific checks (needs an API token for vuln data)."""
        wp_dir = os.path.join(self.output_dir, "wpscan")
        os.makedirs(wp_dir, exist_ok=True)
        if self.runner.require("wpscan"):
            return

        hosts = read_file_lines(self.live_hosts_file)
        # Only bother with hosts that look like WordPress.
        wp_hosts = [
            host for host in hosts
            if any(marker in host.lower() for marker in ("wp", "wordpress", "blog"))
        ][:5] or hosts[: int(self.config.get_tool_config("vuln_scanning", "wpscan")
                             .get("max_hosts", 2))]
        cfg = self.config.get_tool_config("vuln_scanning", "wpscan")
        self.logger.info(f"Running wpscan on {len(wp_hosts)} host(s)...")
        for host in wp_hosts:
            safe = sanitize_filename(
                host.replace("https://", "").replace("http://", ""), 60
            )
            report_file = os.path.join(wp_dir, f"{safe}.json")
            cmd = [
                "wpscan", "--url", host, "--format", "json",
                "--output", report_file, "--no-banner",
                "--random-user-agent", "--disable-tls-checks",
                "--plugins-detection", "passive",
            ]
            proxy = self.config.get("general.proxy", "")
            if proxy:
                cmd += ["--proxy", proxy]
            if cfg.get("api_token"):
                cmd += ["--api-token", str(cfg["api_token"])]
            self.runner.run(cmd, tool_name=f"wpscan-{safe[:30]}", timeout=1800)

        for name in sorted(os.listdir(wp_dir)):
            if not name.endswith(".json"):
                continue
            data = load_json(os.path.join(wp_dir, name), {})
            if not isinstance(data, dict):
                continue
            target_url = str((data.get("target_url") or "").rstrip("/"))
            version = (data.get("version") or {})
            if isinstance(version, dict) and version.get("number"):
                self.findings.append(
                    Finding(
                        category="cms",
                        title=f"WordPress {version.get('number')} detected",
                        severity="info",
                        target=self.ctx.target,
                        url=target_url,
                        evidence=f"WordPress version {version.get('number')}",
                        source="wpscan",
                        confidence="high",
                        tags=["wordpress", "cms"],
                    )
                )
            for vuln in data.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                self.findings.append(
                    Finding(
                        category="cms",
                        title=f"WordPress core vulnerability: {vuln.get('title') or 'unknown'}",
                        severity=_severity_from_cvss(vuln.get("cvss")),
                        target=self.ctx.target,
                        url=target_url,
                        evidence=truncate(str(vuln.get("title") or ""), 400),
                        source="wpscan",
                        confidence="medium",
                        tags=["wordpress", "core", "cve"],
                    )
                )
            for plugin_name, plugin in (data.get("plugins") or {}).items():
                if not isinstance(plugin, dict):
                    continue
                for vuln in plugin.get("vulnerabilities") or []:
                    if not isinstance(vuln, dict):
                        continue
                    self.findings.append(
                        Finding(
                            category="cms",
                            title=f"WordPress plugin vulnerability: {plugin_name}",
                            severity=_severity_from_cvss(vuln.get("cvss")),
                            target=self.ctx.target,
                            url=f"{target_url}/wp-content/plugins/{plugin_name}/",
                            evidence=truncate(str(vuln.get("title") or ""), 400),
                            source="wpscan",
                            confidence="medium",
                            tags=["wordpress", "plugin", "cve"],
                        )
                    )

    def run_joomscan(self) -> None:
        """joomscan: Joomla-specific checks (CMS parity with wpscan)."""
        if self.runner.require("joomscan"):
            return
        joom_dir = os.path.join(self.output_dir, "joomscan")
        os.makedirs(joom_dir, exist_ok=True)
        cfg = self.config.get_tool_config("vuln_scanning", "joomscan")
        max_hosts = int(cfg.get("max_hosts", 2))
        hosts = read_file_lines(self.live_hosts_file)
        joom_hosts = [
            host for host in hosts
            if any(marker in host.lower() for marker in ("joomla", "joom"))
        ][:max_hosts] or hosts[:max_hosts]
        self.logger.info(f"Running joomscan on {len(joom_hosts)} host(s)...")
        for host in joom_hosts:
            safe = sanitize_filename(
                host.replace("https://", "").replace("http://", ""), 60
            )
            report = os.path.join(joom_dir, f"{safe}.txt")
            result = self.runner.run(
                ["joomscan", "-u", host], tool_name=f"joomscan-{safe[:30]}", timeout=1200
            )
            combined = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
            write_file_lines(report, combined.splitlines())
            if "not a joomla" in combined.lower():
                self.logger.debug(f"{host} is not Joomla")
                continue
            version = re.search(r"Joomla!?\s*(?:version\s*)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                                combined, re.IGNORECASE)
            if version:
                self.findings.append(
                    Finding(
                        category="cms",
                        title=f"Joomla {version.group(1)} detected",
                        severity="info",
                        target=self.ctx.target,
                        url=host,
                        evidence=truncate(combined, 400),
                        source="joomscan",
                        confidence="high",
                        tags=["joomla", "cms"],
                    )
                )
            for cve in sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", combined))):
                self.findings.append(
                    Finding(
                        category="cms",
                        title=f"Joomla vulnerability {cve} (joomscan)",
                        severity="medium",
                        target=self.ctx.target,
                        url=host,
                        evidence=truncate(combined, 600),
                        source="joomscan",
                        confidence="medium",
                        tags=["joomla", "cms", cve],
                        references=[f"https://www.cve.org/CVERecord?id={cve}"],
                    )
                )
                self.logger.vuln(f"Joomla CVE candidate on {host}: {cve}")

    def run_commix(self) -> None:
        """commix: OS command injection on parameterised URLs (opt-in)."""
        if self.runner.require("commix"):
            return
        if not self.params_file or not os.path.exists(self.params_file):
            self.logger.skip("no parameterised URLs available for commix")
            return
        cfg = self.config.get_tool_config("vuln_scanning", "commix")
        commix_dir = os.path.join(self.output_dir, "commix")
        os.makedirs(commix_dir, exist_ok=True)
        self.logger.info("Running commix on parameterised URLs...")
        for url in read_file_lines(self.params_file)[: int(cfg.get("max_urls", 10))]:
            safe_name = url.replace("https://", "").replace("http://", "")[:60]
            safe_name = safe_name.replace("/", "_").replace("?", "_").replace("&", "_")
            cmd = [
                "commix", "--url", url, "--batch",
                "--output-dir", os.path.join(commix_dir, safe_name),
            ]
            result = self.runner.run(cmd, tool_name="commix", timeout=600)
            combined = f"{result.get('stdout', '')}\n{result.get('stderr', '')}".lower()
            if "is vulnerable" in combined or "injectable" in combined:
                self.findings.append(
                    Finding(
                        category="rce",
                        title="OS command injection (commix)",
                        severity="critical",
                        target=self.ctx.target,
                        url=url,
                        evidence=truncate(combined, 600),
                        source="commix",
                        confidence="medium",
                        tags=["rce", "command-injection"],
                    )
                )
                self.logger.vuln(f"Command injection candidate: {url}")

    def _ssti_binary(self) -> str:
        for name in ("tplmap", "tplmap.py"):
            if self.runner.is_available(name):
                return name
        return ""

    def run_tplmap(self) -> None:
        """tplmap: server-side template injection on parameterised URLs (opt-in)."""
        binary = self._ssti_binary()
        if not binary:
            self.logger.debug("tplmap is not installed - skipping")
            return
        if not self.params_file or not os.path.exists(self.params_file):
            self.logger.skip("no parameterised URLs available for tplmap")
            return
        cfg = self.config.get_tool_config("vuln_scanning", "tplmap")
        ssti_dir = os.path.join(self.output_dir, "ssti")
        os.makedirs(ssti_dir, exist_ok=True)
        self.logger.info("Running tplmap on parameterised URLs...")
        for url in read_file_lines(self.params_file)[: int(cfg.get("max_urls", 5))]:
            safe_name = url.replace("https://", "").replace("http://", "")[:60]
            safe_name = safe_name.replace("/", "_").replace("?", "_").replace("&", "_")
            report = os.path.join(ssti_dir, f"{safe_name}.txt")
            cmd = [binary, "-u", url, "--level", str(cfg.get("level", 1))]
            result = self.runner.run(cmd, tool_name="tplmap", timeout=600)
            combined = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
            write_file_lines(report, combined.splitlines())
            lowered = combined.lower()
            if "injectable" in lowered or "template injection" in lowered:
                self.findings.append(
                    Finding(
                        category="ssti",
                        title="Server-side template injection (tplmap)",
                        severity="high",
                        target=self.ctx.target,
                        url=url,
                        evidence=truncate(combined, 600),
                        source="tplmap",
                        confidence="medium",
                        tags=["ssti", "injection"],
                    )
                )
                self.logger.vuln(f"SSTI candidate: {url}")

    def _ssrf_binary(self) -> str:
        for name in ("ssrfmap", "ssrfmap.py"):
            if self.runner.is_available(name):
                return name
        return ""

    def run_ssrfmap(self) -> None:
        """ssrfmap: SSRF on parameterised URLs via a generated request file (opt-in)."""
        binary = self._ssrf_binary()
        if not binary:
            self.logger.debug("ssrfmap is not installed - skipping")
            return
        if not self.params_file or not os.path.exists(self.params_file):
            self.logger.skip("no parameterised URLs available for ssrfmap")
            return
        from urllib.parse import parse_qsl, urlparse

        cfg = self.config.get_tool_config("vuln_scanning", "ssrfmap")
        ssrf_dir = os.path.join(self.output_dir, "ssrf")
        os.makedirs(ssrf_dir, exist_ok=True)
        self.logger.info("Running ssrfmap on parameterised URLs...")
        for url in read_file_lines(self.params_file)[: int(cfg.get("max_urls", 5))]:
            parsed = urlparse(url)
            params = [name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)]
            if not parsed.hostname or not params:
                continue
            safe_name = url.replace("https://", "").replace("http://", "")[:60]
            safe_name = safe_name.replace("/", "_").replace("?", "_").replace("&", "_")
            request_file = os.path.join(ssrf_dir, f"{safe_name}.req")
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            write_file_lines(
                request_file,
                [
                    f"GET {path} HTTP/1.1",
                    f"Host: {parsed.hostname}",
                    "User-Agent: SyncHunt",
                    "Accept: */*",
                    "Connection: close",
                    "",
                ],
            )
            cmd = [
                binary, "-r", request_file,
                "-p", params[0],
                "--level", str(cfg.get("level", 1)),
            ]
            result = self.runner.run(cmd, tool_name="ssrfmap", timeout=600)
            combined = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
            write_file_lines(os.path.join(ssrf_dir, f"{safe_name}.txt"), combined.splitlines())
            lowered = combined.lower()
            if "vulnerable" in lowered or "ssrf" in lowered and "found" in lowered:
                self.findings.append(
                    Finding(
                        category="ssrf",
                        title="Server-side request forgery (ssrfmap)",
                        severity="high",
                        target=self.ctx.target,
                        url=url,
                        evidence=truncate(combined, 600),
                        source="ssrfmap",
                        confidence="medium",
                        tags=["ssrf", "injection"],
                    )
                )
                self.logger.vuln(f"SSRF candidate: {url}")

    def run_crlfuzz(self) -> None:
        crlf_dir = os.path.join(self.output_dir, "crlf")
        os.makedirs(crlf_dir, exist_ok=True)
        output_file = os.path.join(crlf_dir, "crlfuzz.txt")
        if self.runner.require("crlfuzz", output_file):
            return
        cfg = self.config.get_tool_config("vuln_scanning", "crlfuzz")
        self.logger.info("Running crlfuzz...")
        cmd = [
            "crlfuzz", "-l", self.live_hosts_file,
            "-c", str(cfg.get("concurrency", 25)),
            "-s", "-o", output_file,
        ]
        self.runner.run(cmd, tool_name="crlfuzz", timeout=900)
        for line in read_file_lines(output_file):
            self.findings.append(
                Finding(
                    category="crlf",
                    title="CRLF injection (crlfuzz)",
                    severity="medium",
                    target=self.ctx.target,
                    url=line,
                    evidence=line,
                    source="crlfuzz",
                    confidence="medium",
                    tags=["crlf", "injection"],
                )
            )

    def run_corsy(self) -> None:
        cors_dir = os.path.join(self.output_dir, "cors")
        os.makedirs(cors_dir, exist_ok=True)
        output_file = os.path.join(cors_dir, "corsy.json")
        if self.runner.require("corsy", output_file):
            return
        cfg = self.config.get_tool_config("vuln_scanning", "corsy")
        self.logger.info("Running corsy (CORS misconfiguration)...")
        cmd = [
            "corsy", "-i", self.live_hosts_file,
            "-t", str(cfg.get("threads", 20)), "-o", output_file,
        ]
        self.runner.run(cmd, tool_name="corsy", timeout=900)

        data = load_json(output_file, {})
        entries = data.get("results") if isinstance(data, dict) else data
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url", "")
            self.findings.append(
                Finding(
                    category="cors",
                    title="CORS misconfiguration (corsy)",
                    severity="medium",
                    target=self.ctx.target,
                    url=url,
                    evidence=str(entry)[:400],
                    source="corsy",
                    confidence="medium",
                    tags=["cors", "misconfiguration"],
                )
            )

    # ------------------------------------------------------------------
    def _check_open_redirects(self) -> None:
        """Flag parameterised URLs whose query params look like redirects."""
        if not self.urls_file or not os.path.exists(self.urls_file):
            return
        redirect_dir = os.path.join(self.output_dir, "open_redirect")
        os.makedirs(redirect_dir, exist_ok=True)

        candidates = []
        for url in read_file_lines(self.urls_file):
            lowered = url.lower()
            for param in REDIRECT_PARAMS:
                if f"{param}=" in lowered:
                    candidates.append(url)
                    break

        output_file = os.path.join(redirect_dir, "candidates.txt")
        write_file_lines(output_file, candidates)
        self.logger.info(
            f"Open redirect: {len(candidates)} candidate URL(s) for manual testing"
        )
        # Candidates are deliberately only *listed*: actively confirming an open
        # redirect requires following untrusted Location headers off-scope.

    # ------------------------------------------------------------------
    def _write_outputs(self) -> None:
        save_json(
            [finding.to_dict() for finding in self.findings],
            os.path.join(self.output_dir, "findings.json"),
        )
        self.ctx.set_file("vulnerabilities", os.path.join(self.output_dir, "findings.json"))
        save_json(
            {
                "findings": len(self.findings),
                "by_severity": _count_severities(self.findings),
            },
            os.path.join(self.output_dir, "summary.json"),
        )
        self.ctx.record_assets(
            [
                Asset(kind="vuln", value=f.title, url=f.url, source="vuln_scanning")
                for f in self.findings[:200]
            ]
        )


def _nuclei_evidence(record: Dict) -> str:
    parts = []
    if record.get("matcher-name"):
        parts.append(f"matcher={record['matcher-name']}")
    if record.get("extracted-results"):
        parts.append(f"extracted={record['extracted-results'][:5]}")
    if record.get("curl-command"):
        parts.append(f"curl={record['curl-command']}")
    response = record.get("response")
    if response:
        parts.append(f"response={truncate(response, 400)}")
    return " | ".join(str(p) for p in parts) or truncate(str(record), 400)


def _category_for_template(template_id: str, title: str) -> str:
    haystack = f"{template_id} {title}".lower()
    for needle, category in (
        ("xss", "xss"),
        ("sql", "sqli"),
        ("sqli", "sqli"),
        ("ssrf", "ssrf"),
        ("lfi", "lfi"),
        ("rce", "rce"),
        ("takeover", "takeover"),
        ("redirect", "open_redirect"),
        ("cors", "cors"),
        ("crlf", "crlf"),
        ("exposure", "exposure"),
        ("disclosure", "exposure"),
        ("misconfig", "misconfiguration"),
        ("default-login", "auth"),
        ("cve-", "cve"),
    ):
        if needle in haystack:
            return category
    return "vulnerability"


def _severity_from_line(line: str) -> str:
    lowered = line.lower()
    for level in ("critical", "high", "medium", "low", "info"):
        if f"[{level}]" in lowered:
            return level
    return "medium"


def _inject_callback(url: str, callback: str) -> str:
    """
    Replace one parameter value with the callback URL.

    Returns "" when the URL has no parameters, so nothing is requested for it.
    """
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return ""
    name, _value = params[0]
    new_query = [(name, callback)] + params[1:]
    return urlunparse(parsed._replace(query=urlencode(new_query)))


def _severity_from_cvss(score) -> str:
    """Map a CVSS score (0-10, possibly a dict/None) to a severity band."""
    if isinstance(score, dict):
        score = score.get("score")
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "high"  # plugin vulns without a score are still worth reporting
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0:
        return "low"
    return "info"


def _count_severities(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts
