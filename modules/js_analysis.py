"""
BugHuntRecon - JavaScript Analysis Module
Integrates: LinkFinder, SecretFinder, custom regex patterns
"""

import os
import re
import time
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import read_file_lines, write_file_lines, save_json

# Suppress InsecureRequestWarning from verify=False JS downloads
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class JSAnalyzer:
    """Analyze JavaScript files for endpoints, secrets, and sensitive data."""

    def __init__(self, config, runner, logger, output_dir, js_files_list):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = os.path.join(output_dir, "js_analysis")
        self.files_dir = os.path.join(self.output_dir, "files")
        self.js_files_list = js_files_list
        self.endpoints = set()
        self.secrets = []

        for d in [self.output_dir, self.files_dir]:
            os.makedirs(d, exist_ok=True)

    def run_all(self):
        """Run all JS analysis tools."""
        self.logger.phase_banner("JAVASCRIPT ANALYSIS", 6)
        start_time = time.time()

        js_urls = read_file_lines(self.js_files_list)
        if not js_urls:
            self.logger.warning("No JavaScript files to analyze!")
            return None

        self.logger.info(f"Analyzing {len(js_urls)} JavaScript files...")

        # Download JS files first
        self._download_js_files(js_urls[:200])  # Limit to 200 files

        # LinkFinder
        if self.config.is_tool_enabled('js_analysis', 'linkfinder'):
            try:
                self.run_linkfinder(js_urls)
            except Exception as e:
                self.logger.error(f"LinkFinder failed: {str(e)}")

        # SecretFinder
        if self.config.is_tool_enabled('js_analysis', 'secretfinder'):
            try:
                self.run_secretfinder(js_urls)
            except Exception as e:
                self.logger.error(f"SecretFinder failed: {str(e)}")

        # Custom regex scanning
        if self.config.get('js_analysis.custom_regex.enabled', True):
            try:
                self.run_custom_regex_scan()
            except Exception as e:
                self.logger.error(f"Custom regex scan failed: {str(e)}")

        duration = time.time() - start_time
        self.logger.result(
            f"JS Analysis Complete: {len(self.endpoints)} endpoints, "
            f"{len(self.secrets)} secrets found in {duration:.1f}s"
        )

        return self.output_dir

    def _download_js_files(self, js_urls):
        """Download JS files for local analysis."""
        self.logger.info(f"Downloading {len(js_urls)} JS files...")

        def download_file(url):
            try:
                resp = requests.get(url, timeout=15, verify=False)
                if resp.status_code == 200 and resp.text:
                    # Create filename from URL
                    safe_name = url.replace('https://', '').replace('http://', '')
                    safe_name = re.sub(r'[^\w\-.]', '_', safe_name)[:100]
                    if not safe_name.endswith('.js'):
                        safe_name += '.js'
                    filepath = os.path.join(self.files_dir, safe_name)
                    with open(filepath, 'w', errors='ignore') as f:
                        f.write(resp.text)
                    return True
            except Exception:
                pass
            return False

        downloaded = 0
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(download_file, url): url for url in js_urls}
            for future in as_completed(futures):
                if future.result():
                    downloaded += 1

        self.logger.info(f"Downloaded {downloaded}/{len(js_urls)} JS files")

    def run_linkfinder(self, js_urls):
        """Run LinkFinder on JS files to discover endpoints."""
        self.logger.info("Running LinkFinder for endpoint discovery...")

        endpoints_file = os.path.join(self.output_dir, "endpoints", "linkfinder.txt")
        os.makedirs(os.path.dirname(endpoints_file), exist_ok=True)

        all_endpoints = set()

        for js_url in js_urls[:100]:  # Limit
            cmd = f"linkfinder -i {js_url} -o cli"

            result = self.runner.run(
                cmd,
                tool_name="linkfinder",
                timeout=30
            )

            if result['success'] and result['stdout']:
                endpoints = [
                    l.strip() for l in result['stdout'].split('\n')
                    if l.strip() and not l.startswith('[')
                ]
                all_endpoints.update(endpoints)

        write_file_lines(endpoints_file, list(all_endpoints))
        self.endpoints.update(all_endpoints)
        self.logger.found(f"LinkFinder: {len(all_endpoints)} endpoints discovered")

    def run_secretfinder(self, js_urls):
        """Run SecretFinder on JS files to find sensitive data."""
        self.logger.info("Running SecretFinder for secret detection...")

        secrets_file = os.path.join(self.output_dir, "secrets", "secretfinder.txt")
        os.makedirs(os.path.dirname(secrets_file), exist_ok=True)

        all_secrets = []

        for js_url in js_urls[:100]:
            cmd = f"secretfinder -i {js_url} -o cli"

            result = self.runner.run(
                cmd,
                tool_name="secretfinder",
                timeout=30
            )

            if result['success'] and result['stdout']:
                secrets = [
                    l.strip() for l in result['stdout'].split('\n')
                    if l.strip()
                ]
                for secret in secrets:
                    all_secrets.append(f"[{js_url}] {secret}")

        write_file_lines(secrets_file, all_secrets)
        self.secrets.extend(all_secrets)
        self.logger.found(f"SecretFinder: {len(all_secrets)} potential secrets found")

    def run_custom_regex_scan(self):
        """Scan downloaded JS files with custom regex patterns."""
        self.logger.info("Running custom regex scan on JS files...")

        patterns_config = self.config.get('js_analysis.custom_regex.patterns', [])
        if not patterns_config:
            return

        # Compile regex patterns
        compiled_patterns = []
        for p in patterns_config:
            try:
                compiled_patterns.append({
                    'name': p['name'],
                    'regex': re.compile(p['regex'], re.IGNORECASE)
                })
            except re.error as e:
                self.logger.warning(f"Invalid regex pattern '{p['name']}': {e}")

        secrets_file = os.path.join(self.output_dir, "secrets", "custom_regex.txt")
        secrets_json = os.path.join(self.output_dir, "secrets", "custom_regex.json")
        os.makedirs(os.path.dirname(secrets_file), exist_ok=True)

        findings = []
        findings_text = []

        # Scan all downloaded JS files
        for filename in os.listdir(self.files_dir):
            filepath = os.path.join(self.files_dir, filename)
            if not os.path.isfile(filepath):
                continue

            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()

                for pattern in compiled_patterns:
                    matches = pattern['regex'].findall(content)
                    for match in matches:
                        finding = {
                            'file': filename,
                            'type': pattern['name'],
                            'match': match if isinstance(match, str) else match[0],
                            'severity': 'HIGH'
                        }
                        findings.append(finding)
                        findings_text.append(
                            f"[{pattern['name']}] {filename}: {match}"
                        )
                        self.logger.vuln(
                            f"Secret Found [{pattern['name']}] in {filename}: "
                            f"{str(match)[:80]}..."
                        )

            except Exception as e:
                self.logger.debug(f"Error scanning {filename}: {e}")

        write_file_lines(secrets_file, findings_text)
        save_json(findings, secrets_json)

        self.secrets.extend(findings_text)
        self.logger.found(
            f"Custom Regex: {len(findings)} potential secrets found"
        )