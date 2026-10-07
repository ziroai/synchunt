"""
SyncHunt - Sensitive Information Discovery
GitHub dorking, Google dork generation and optional Shodan enrichment.

Cloud bucket checks live in modules/cloud_enum.py (they are a first-class
phase); this module focuses on OSINT that is not already covered there.
"""

from __future__ import annotations

import os
import time
from typing import Dict, List
from urllib.parse import quote as url_quote

from core.models import Finding
from core.secrets import build_patterns, scan_text
from core.utils import (
    get_timestamp,
    read_file_lines,
    save_json,
    truncate,
    write_file_lines,
)


class SensitiveInfoScanner:
    """Gather OSINT and hunt for leaked sensitive data."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.runner = ctx.runner
        self.logger = ctx.logger
        self.output_dir = ctx.path("sensitive_info")
        self.target = ctx.target
        os.makedirs(self.output_dir, exist_ok=True)
        self.findings: List[Finding] = []
        self.github_results: List[Dict] = []
        self.patterns = build_patterns(
            self.config.get("js_analysis.custom_regex.patterns", [])
        )
        self.token = (
            os.environ.get("GITHUB_TOKEN", "")
            or self.config.get("sensitive_info.github_dorking.token", "")
            or self.config.get("github_recon.token", "")
        )

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("SENSITIVE INFORMATION", 13)
        started = time.time()

        if self.config.is_tool_enabled("sensitive_info", "github_dorking", True):
            self.run_github_dorking()
        if self.config.get_bool("sensitive_info.google_dorking.enabled", True):
            self.generate_google_dorks()
        if self.config.is_tool_enabled("sensitive_info", "shodan", False):
            self.run_shodan()
        if self.config.is_tool_enabled("sensitive_info", "s3scanner", False):
            self.run_s3scanner()

        self._write_outputs()
        self.ctx.record_findings(self.findings)

        self.logger.result(
            f"Sensitive Info Complete: {len(self.findings)} finding(s) "
            f"in {time.time() - started:.1f}s"
        )
        return self.output_dir

    # ------------------------------------------------------------------
    def run_github_dorking(self) -> None:
        from core.net import http_request

        github_dir = os.path.join(self.output_dir, "github")
        os.makedirs(github_dir, exist_ok=True)
        dorks = self.config.get_list(
            "sensitive_info.github_dorking.dorks",
            ["password", "secret", "api_key", "access_token", "credentials"],
        )
        if not self.token:
            self.logger.warning(
                "GitHub dorking needs GITHUB_TOKEN for code search - "
                "skipping (issues/repos are covered by the github_recon phase)"
            )
            return

        self.logger.info("Running GitHub dorking (code search)...")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
        }
        for dork in dorks[:12]:
            url = f"https://api.github.com/search/code?q=%22{url_quote(self.target)}%22+{url_quote(dork)}"
            result = http_request(
                self.ctx.session, "GET", url, limiter=self.ctx.limiter,
                timeout=20, max_bytes=512 * 1024, headers=headers,
            )
            if result.status == 403:
                self.logger.warning("GitHub code-search rate limit reached - stopping")
                break
            if result.status != 200:
                continue
            data = result.json(default={})
            total = data.get("total_count", 0)
            if total:
                self.logger.found(f"GitHub dork '{dork}': {total} hit(s)")
            for item in (data.get("items") or [])[:5]:
                entry = {
                    "dork": dork,
                    "repo": (item.get("repository") or {}).get("full_name", ""),
                    "path": item.get("path", ""),
                    "url": item.get("html_url", ""),
                }
                self.github_results.append(entry)
                self.findings.append(
                    Finding(
                        category="github",
                        title=f"GitHub code hit for '{dork}'",
                        severity="medium",
                        target=self.target,
                        url=entry["url"],
                        evidence=f"{entry['repo']}/{entry['path']}",
                        source="sensitive_info",
                        confidence="low",
                        tags=["github", "osint"],
                    )
                )
            time.sleep(2 if self.token else 8)

    def generate_google_dorks(self) -> None:
        dorks_dir = os.path.join(self.output_dir, "google_dorks")
        os.makedirs(dorks_dir, exist_ok=True)

        templates = self.config.get_list("sensitive_info.google_dorking.dorks", [])
        generated = [str(t).replace("{target}", self.target) for t in templates]
        generated += [
            f"site:{self.target} inurl:login",
            f"site:{self.target} inurl:admin",
            f"site:{self.target} inurl:api",
            f"site:{self.target} inurl:swagger",
            f"site:{self.target} inurl:graphql",
            f"site:{self.target} filetype:pdf",
            f"site:{self.target} filetype:xls",
            f'site:{self.target} intitle:"index of"',
            f'"{self.target}" password OR secret OR credential',
            f'"{self.target}" api_key OR apikey OR access_token',
            f'site:pastebin.com "{self.target}"',
            f'site:github.com "{self.target}" password',
        ]
        generated = list(dict.fromkeys([d for d in generated if d.strip()]))

        write_file_lines(os.path.join(dorks_dir, "google_dorks.txt"), generated)
        write_file_lines(
            os.path.join(dorks_dir, "google_dork_urls.txt"),
            [f"https://www.google.com/search?q={url_quote(dork)}" for dork in generated],
        )
        self.logger.found(f"Generated {len(generated)} Google dork(s) for manual review")

    def run_shodan(self) -> None:
        api_key = self.config.get("sensitive_info.shodan.api_key", "") or os.environ.get(
            "SHODAN_API_KEY", ""
        )
        if not api_key:
            self.logger.skip("Shodan API key not configured")
            return
        try:
            import shodan  # type: ignore
        except ImportError:
            self.logger.skip("python 'shodan' package not installed (pip install shodan)")
            return

        shodan_dir = os.path.join(self.output_dir, "shodan")
        os.makedirs(shodan_dir, exist_ok=True)
        self.logger.info("Querying Shodan...")
        try:
            api = shodan.Shodan(api_key)
            results = api.search(f"hostname:{self.target}")
        except Exception as exc:
            self.logger.warning(f"Shodan query failed: {exc}")
            return

        save_json(results, os.path.join(shodan_dir, "results.json"))
        for match in results.get("matches", [])[:100]:
            self.findings.append(
                Finding(
                    category="exposure",
                    title="Shodan-exposed service",
                    severity="low",
                    target=self.target,
                    url=f"{match.get('ip_str', '')}:{match.get('port', '')}",
                    evidence=truncate(
                        f"{match.get('org', '')} {match.get('product', '')} "
                        f"{match.get('hostnames', [])}", 300
                    ),
                    source="sensitive_info",
                    confidence="medium",
                    tags=["shodan", "osint"],
                )
            )
        self.logger.found(f"Shodan: {results.get('total', 0)} result(s)")

    def run_s3scanner(self) -> None:
        """Optional: use the s3scanner binary against generated names."""
        s3_dir = os.path.join(self.output_dir, "s3")
        os.makedirs(s3_dir, exist_ok=True)
        if self.runner.require("s3scanner"):
            return

        from modules.cloud_enum import CloudEnumerator

        names = CloudEnumerator(self.ctx)._candidate_names()[:200]
        bucket_file = os.path.join(s3_dir, "bucket_names.txt")
        write_file_lines(bucket_file, names)
        output_file = os.path.join(s3_dir, "s3scanner.txt")
        self.logger.info("Running s3scanner...")
        self.runner.run(
            ["s3scanner", "scan", "-f", bucket_file],
            output_file=output_file, tool_name="s3scanner", timeout=1800,
        )
        for line in read_file_lines(output_file):
            if any(word in line.lower() for word in ("open", "public")):
                self.findings.append(
                    Finding(
                        category="cloud",
                        title="Public S3 bucket (s3scanner)",
                        severity="critical",
                        target=self.target,
                        url=line.split()[-1] if line.split() else "",
                        evidence=line,
                        source="sensitive_info",
                        confidence="high",
                        tags=["cloud", "s3"],
                    )
                )

    # ------------------------------------------------------------------
    def _write_outputs(self) -> None:
        save_json(
            {
                "target": self.target,
                "timestamp": get_timestamp(),
                "github_token_used": bool(self.token),
                "github_hits": len(self.github_results),
                "findings": len(self.findings),
            },
            os.path.join(self.output_dir, "summary.json"),
        )
        if self.github_results:
            save_json(
                self.github_results,
                os.path.join(self.output_dir, "github", "dorks.json"),
            )


def scan_dork_bodies(bodies: List[str], patterns=None) -> List[Dict]:
    """Scan arbitrary text bodies (used by tests and future sources)."""
    found = []
    for body in bodies:
        for match in scan_text(body, patterns=patterns, source="osint"):
            found.append(match.to_dict())
    return found
