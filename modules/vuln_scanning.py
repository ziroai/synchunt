"""
SyncHunt - Vulnerability Scanning
Nuclei (primary), nikto, dalfox, sqlmap, crlfuzz and corsy, plus a built-in
open-redirect candidate finder.

Every external command is executed as an argv list: user-controlled data
(crawled URLs) is never interpolated into a shell string.
"""

from __future__ import annotations

import os
import time
from typing import Dict, List

from core.models import Asset, Finding
from core.utils import (
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

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("VULNERABILITY SCANNING", 11)
        started = time.time()

        if not read_file_lines(self.live_hosts_file):
            self.logger.warning("No live hosts to scan")
            return self.output_dir

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

        self._check_open_redirects()
        self._write_outputs()
        self.ctx.record_findings(self.findings)

        self.logger.result(
            f"Vulnerability Scanning Complete: {len(self.findings)} finding(s) "
            f"in {time.time() - started:.1f}s"
        )
        return self.output_dir

    # ------------------------------------------------------------------
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
        if cfg.get("blind_xss"):
            cmd += ["-b", str(cfg["blind_xss"])]
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
            safe_name = url.replace("https://", "").replace("http://", "")[:60]
            safe_name = safe_name.replace("/", "_").replace("?", "_").replace("&", "_")
            output_dir_sqli = os.path.join(sqli_dir, safe_name)
            # argv list => no shell parsing, so a crafted URL cannot execute code.
            cmd = [
                "sqlmap", "-u", url,
                "--level", str(level), "--risk", str(risk),
                "--batch", "--random-agent", "--threads", "5",
                "--output-dir", output_dir_sqli,
            ]
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


def _count_severities(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts
