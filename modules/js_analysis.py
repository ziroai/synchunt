"""
SyncHunt - JavaScript Analysis
Downloads in-scope JS bundles and extracts endpoints, source maps and
secrets. Secret detection uses the shared pattern engine with entropy
filtering, and every match is redacted before it is written to disk.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from core.models import Asset, Finding
from core.secrets import build_patterns, scan_text
from core.utils import (
    read_file_lines,
    save_json,
    write_file_lines,
)


class JSAnalyzer:
    """Analyse JavaScript files for endpoints and secrets."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.runner = ctx.runner
        self.logger = ctx.logger
        self.output_dir = ctx.path("js_analysis")
        self.files_dir = os.path.join(self.output_dir, "files")
        self.js_files_list = ctx.resolve_file("js_files", "content_discovery", "js_files.txt")
        self.endpoints: set = set()
        self.secrets: List[Dict] = []
        self.findings: List[Finding] = []

        for directory in (self.output_dir, self.files_dir):
            os.makedirs(directory, exist_ok=True)

        # Custom patterns supplement (not replace) the built-in library.
        self.patterns = build_patterns(
            self.config.get("js_analysis.custom_regex.patterns", [])
        )
        self.max_download = self.config.get_int("js_analysis.max_files", 200)
        self.check_sourcemaps = self.config.get_bool("js_analysis.check_sourcemaps", True)

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("JAVASCRIPT ANALYSIS", 9)
        started = time.time()

        js_urls = read_file_lines(self.js_files_list)
        if not js_urls:
            self.logger.warning("No JavaScript files to analyse")
            return self.output_dir

        scoped = self.ctx.scope.filter(js_urls) if self.ctx.scope else js_urls
        if len(scoped) != len(js_urls):
            self.logger.skip(f"{len(js_urls) - len(scoped)} out-of-scope JS file(s) dropped")

        self.logger.info(f"Analysing {len(scoped)} JavaScript file(s)...")
        downloaded = self._download_js_files(scoped[: self.max_download])

        if self.config.is_tool_enabled("js_analysis", "linkfinder"):
            self.run_linkfinder(scoped[:100])
        if self.config.is_tool_enabled("js_analysis", "secretfinder"):
            self.run_secretfinder(scoped[:100])

        self.run_custom_regex_scan()

        self._write_outputs()
        self.ctx.record_assets(
            [
                Asset(kind="js_file", value=url, source="js_analysis")
                for url in scoped[:500]
            ]
            + [
                Asset(kind="js_endpoint", value=e, source="js_analysis")
                for e in sorted(self.endpoints)[:500]
            ]
        )
        self.ctx.record_findings(self.findings)

        self.logger.result(
            f"JS Analysis Complete: {len(self.endpoints)} endpoint(s), "
            f"{len(self.secrets)} potential secret(s) from {downloaded} file(s) "
            f"in {time.time() - started:.1f}s"
        )
        return self.output_dir

    # ------------------------------------------------------------------
    def _download_js_files(self, js_urls: List[str]) -> int:
        """Download JS bodies for offline regex analysis."""
        from core.net import http_request
        from core.utils import sanitize_filename, short_hash

        def download(url: str) -> bool:
            result = http_request(
                self.ctx.session, "GET", url, limiter=self.ctx.limiter,
                timeout=20, max_bytes=2 * 1024 * 1024,
            )
            if result.status != 200 or not result.text:
                return False
            name = sanitize_filename(url.replace("https://", "").replace("http://", ""), 90)
            if not name.endswith(".js"):
                name += ".js"
            path = os.path.join(self.files_dir, f"{short_hash(url, length=6)}_{name}")
            with open(path, "w", errors="ignore") as fh:
                fh.write(result.text)
            if self.check_sourcemaps and "sourceMappingURL=" in result.text:
                self._check_sourcemap(url, result.text)
            return True

        downloaded = 0
        with ThreadPoolExecutor(max_workers=min(self.ctx.threads(), 20)) as executor:
            futures = {executor.submit(download, url): url for url in js_urls}
            for future in as_completed(futures):
                if future.result():
                    downloaded += 1
        self.logger.info(f"Downloaded {downloaded}/{len(js_urls)} JS file(s)")
        return downloaded

    def _check_sourcemap(self, js_url: str, body: str) -> None:
        """Exposed source maps leak original source code."""
        marker = "sourceMappingURL="
        index = body.find(marker)
        map_ref = body[index + len(marker):].splitlines()[0].strip()
        if not map_ref:
            return
        from urllib.parse import urljoin

        map_url = urljoin(js_url, map_ref)
        from core.net import http_request

        result = http_request(
            self.ctx.session, "GET", map_url, limiter=self.ctx.limiter,
            timeout=15, max_bytes=65536,
        )
        if result.status == 200 and '"sources"' in result.text:
            self.findings.append(
                Finding(
                    category="exposure",
                    title="JavaScript source map exposed",
                    severity="low",
                    target=self.ctx.target,
                    url=map_url,
                    evidence=f"Source map readable at {map_url}",
                    source="js_analysis",
                    confidence="high",
                    tags=["sourcemap", "exposure"],
                )
            )
            self.logger.found(f"Source map exposed: {map_url}")

    # ------------------------------------------------------------------
    def run_linkfinder(self, js_urls: List[str]) -> None:
        if self.runner.require("linkfinder"):
            return
        self.logger.info("Running LinkFinder...")
        endpoints_file = os.path.join(self.output_dir, "endpoints", "linkfinder.txt")
        os.makedirs(os.path.dirname(endpoints_file), exist_ok=True)
        found = set()
        for js_url in js_urls:
            result = self.runner.run(
                ["linkfinder", "-i", js_url, "-o", "cli"],
                tool_name="linkfinder", timeout=45,
            )
            for line in (result.get("stdout") or "").splitlines():
                line = line.strip()
                if line and not line.startswith("[") and "/" in line:
                    found.add(line)
        write_file_lines(endpoints_file, sorted(found))
        self.endpoints.update(found)
        self.logger.found(f"LinkFinder: {len(found)} endpoint(s)")

    def run_secretfinder(self, js_urls: List[str]) -> None:
        if self.runner.require("secretfinder"):
            return
        self.logger.info("Running SecretFinder...")
        secrets_file = os.path.join(self.output_dir, "secrets", "secretfinder.txt")
        os.makedirs(os.path.dirname(secrets_file), exist_ok=True)
        found = []
        for js_url in js_urls:
            result = self.runner.run(
                ["secretfinder", "-i", js_url, "-o", "cli"],
                tool_name="secretfinder", timeout=45,
            )
            for line in (result.get("stdout") or "").splitlines():
                if line.strip():
                    found.append(f"[{js_url}] {line.strip()}")
        write_file_lines(secrets_file, found)
        self.logger.found(f"SecretFinder: {len(found)} potential hit(s)")

    # ------------------------------------------------------------------
    def run_custom_regex_scan(self) -> None:
        """Entropy-filtered regex scan over the downloaded JS corpus."""
        self.logger.info("Scanning JS corpus for secrets (entropy-filtered)...")
        secrets_file = os.path.join(self.output_dir, "secrets", "custom_regex.txt")
        secrets_json = os.path.join(self.output_dir, "secrets", "custom_regex.json")
        os.makedirs(os.path.dirname(secrets_file), exist_ok=True)

        matches_by_fingerprint: Dict[str, Dict] = {}
        endpoint_patterns = set()

        for name in sorted(os.listdir(self.files_dir)):
            path = os.path.join(self.files_dir, name)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", errors="ignore") as fh:
                    content = fh.read()
            except OSError as exc:
                self.logger.debug(f"could not read {name}: {exc}")
                continue

            for match in scan_text(content, patterns=self.patterns, source="javascript",
                                   location=name):
                entry = match.to_dict()
                matches_by_fingerprint.setdefault(match.fingerprint(), entry)
                self.findings.append(
                    Finding(
                        category="secrets",
                        title=f"Secret in JavaScript: {match.name}",
                        severity=match.severity,
                        target=self.ctx.target,
                        url=name,
                        evidence=f"{match.name} -> {entry['value']} (entropy {entry['entropy']})",
                        source="js_analysis",
                        confidence=match.confidence,
                        tags=["secrets", "javascript"],
                    )
                )
                self.logger.vuln(f"Secret [{match.name}] in {name}: {entry['value']}")

            endpoint_patterns.update(_extract_endpoints(content))

        secrets = sorted(matches_by_fingerprint.values(), key=lambda item: item["type"])
        self.secrets.extend(secrets)
        write_file_lines(
            secrets_file,
            [f"[{s['type']}|{s['severity']}] {s['location']}: {s['value']}" for s in secrets],
        )
        save_json(secrets, secrets_json)

        self.endpoints.update(endpoint_patterns)
        endpoints_file = os.path.join(self.output_dir, "endpoints", "regex_endpoints.txt")
        write_file_lines(endpoints_file, sorted(endpoint_patterns))
        if endpoint_patterns:
            self.logger.found(f"Endpoint extraction: {len(endpoint_patterns)} path(s)")

    # ------------------------------------------------------------------
    def _write_outputs(self) -> None:
        endpoints_file = os.path.join(self.output_dir, "endpoints", "all_endpoints.txt")
        write_file_lines(endpoints_file, sorted(self.endpoints))
        self.ctx.set_file("js_endpoints", endpoints_file)
        save_json(
            {
                "endpoints": len(self.endpoints),
                "secrets": len(self.secrets),
                "high_severity_secrets": sum(
                    1 for s in self.secrets if s.get("severity") in ("critical", "high")
                ),
            },
            os.path.join(self.output_dir, "summary.json"),
        )


ENDPOINT_RE = None


def _extract_endpoints(content: str) -> set:
    """Pull interesting paths/URLs out of a JS bundle."""
    import re

    global ENDPOINT_RE
    if ENDPOINT_RE is None:
        ENDPOINT_RE = re.compile(
            r"""["'`]((?:https?://[^"'`\s]{4,200})|(?:/[A-Za-z0-9_\-./]{2,120}))["'`]"""
        )
    found = set()
    for match in ENDPOINT_RE.finditer(content):
        value = match.group(1)
        if value.startswith("//") or value.endswith((".png", ".jpg", ".gif", ".svg", ".css")):
            continue
        if value.count("/") < 1:
            continue
        found.add(value)
        if len(found) > 5000:  # guard against minified noise
            break
    return found
