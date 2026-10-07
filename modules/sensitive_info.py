"""
BugHuntRecon - Sensitive Information Discovery Module
Integrates: S3Scanner, GitHub Dorking, Shodan, Google Dorks
"""

import os
import re
import json
import time
import requests
from urllib.parse import quote as url_quote
from core.utils import read_file_lines, write_file_lines, save_json


class SensitiveInfoScanner:
    """Discover sensitive information and exposed assets."""

    def __init__(self, config, runner, logger, output_dir, target):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = os.path.join(output_dir, "sensitive_info")
        self.target = target
        self.findings = []

        os.makedirs(self.output_dir, exist_ok=True)

    def run_all(self):
        """Run all sensitive info discovery tools."""
        self.logger.phase_banner("SENSITIVE INFO DISCOVERY", 8)
        start_time = time.time()

        # S3 Scanner
        if self.config.is_tool_enabled('sensitive_info', 's3scanner'):
            try:
                self.run_s3scanner()
            except Exception as e:
                self.logger.error(f"S3Scanner failed: {str(e)}")

        # GitHub Dorking
        if self.config.is_tool_enabled('sensitive_info', 'github_dorking'):
            try:
                self.run_github_dorking()
            except Exception as e:
                self.logger.error(f"GitHub dorking failed: {str(e)}")

        # Shodan
        if self.config.is_tool_enabled('sensitive_info', 'shodan'):
            try:
                self.run_shodan()
            except Exception as e:
                self.logger.error(f"Shodan failed: {str(e)}")

        # Google Dorks
        if self.config.get('sensitive_info.google_dorking.enabled', True):
            try:
                self.generate_google_dorks()
            except Exception as e:
                self.logger.error(f"Google dorking failed: {str(e)}")

        duration = time.time() - start_time
        self.logger.result(
            f"Sensitive Info Discovery Complete: {len(self.findings)} "
            f"findings in {duration:.1f}s"
        )

        return self.output_dir

    def run_s3scanner(self):
        """Run S3Scanner for open S3 bucket discovery."""
        self.logger.info("Running S3Scanner...")

        s3_dir = os.path.join(self.output_dir, "s3")
        os.makedirs(s3_dir, exist_ok=True)

        # Generate potential bucket names
        bucket_names = self._generate_s3_bucket_names()
        bucket_file = os.path.join(s3_dir, "bucket_names.txt")
        write_file_lines(bucket_file, bucket_names)

        output_file = os.path.join(s3_dir, "s3scanner_output.txt")

        cmd = f"s3scanner scan -f {bucket_file}"

        result = self.runner.run(
            cmd,
            output_file=output_file,
            tool_name="s3scanner",
            timeout=600
        )

        findings = read_file_lines(output_file)
        open_buckets = [f for f in findings if 'open' in f.lower() or 'public' in f.lower()]

        for bucket in open_buckets:
            self.findings.append(f"[S3] {bucket}")
            self.logger.vuln(f"Open S3 Bucket: {bucket}")

        self.logger.found(f"S3Scanner: {len(open_buckets)} open buckets found")

    def _generate_s3_bucket_names(self):
        """Generate potential S3 bucket names based on target."""
        base = self.target.replace('.com', '').replace('.org', '')
        base = base.replace('.net', '').replace('.io', '')
        parts = self.target.split('.')

        names = set()
        for part in parts:
            if len(part) > 2:
                names.add(part)
                names.add(f"{part}-assets")
                names.add(f"{part}-backup")
                names.add(f"{part}-backups")
                names.add(f"{part}-data")
                names.add(f"{part}-dev")
                names.add(f"{part}-development")
                names.add(f"{part}-staging")
                names.add(f"{part}-stage")
                names.add(f"{part}-prod")
                names.add(f"{part}-production")
                names.add(f"{part}-test")
                names.add(f"{part}-testing")
                names.add(f"{part}-uploads")
                names.add(f"{part}-media")
                names.add(f"{part}-static")
                names.add(f"{part}-files")
                names.add(f"{part}-private")
                names.add(f"{part}-public")
                names.add(f"{part}-internal")
                names.add(f"{part}-cdn")
                names.add(f"{part}-logs")
                names.add(f"{part}-db")
                names.add(f"{part}-database")
                names.add(f"{part}-config")
                names.add(f"{part}-api")
                names.add(f"{part}-app")
                names.add(f"{part}-web")
                names.add(f"{part}-images")
                names.add(f"{part}-docs")
                names.add(f"{part}-documents")

        # Also add full domain variations
        names.add(self.target)
        names.add(self.target.replace('.', '-'))
        names.add(base)

        return sorted(list(names))

    def run_github_dorking(self):
        """Search GitHub for leaked credentials and sensitive data."""
        self.logger.info("Running GitHub dorking...")

        github_dir = os.path.join(self.output_dir, "github")
        os.makedirs(github_dir, exist_ok=True)

        token = self.config.get('sensitive_info.github_dorking.token', '')
        dorks = self.config.get('sensitive_info.github_dorking.dorks', [])

        if not token:
            self.logger.warning("No GitHub token configured, using unauthenticated (rate limited)")

        headers = {'Accept': 'application/vnd.github.v3+json'}
        if token:
            headers['Authorization'] = f'token {token}'

        all_results = []

        for dork in dorks:
            query = f'"{self.target}" {dork}'
            self.logger.debug(f"GitHub search: {query}")

            try:
                url = f"https://api.github.com/search/code?q={query}"
                resp = requests.get(url, headers=headers, timeout=15)

                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get('total_count', 0)

                    if total > 0:
                        self.logger.found(
                            f"GitHub [{dork}]: {total} results found"
                        )

                        for item in data.get('items', [])[:5]:
                            result = {
                                'dork': dork,
                                'repo': item.get('repository', {}).get('full_name', ''),
                                'file': item.get('name', ''),
                                'path': item.get('path', ''),
                                'url': item.get('html_url', '')
                            }
                            all_results.append(result)
                            self.findings.append(
                                f"[GitHub] {dork}: {result['repo']}/{result['path']}"
                            )

                elif resp.status_code == 403:
                    self.logger.warning("GitHub API rate limit reached")
                    break

                # Rate limiting
                time.sleep(3 if token else 10)

            except Exception as e:
                self.logger.debug(f"GitHub search error: {e}")

        output_file = os.path.join(github_dir, "github_dorks.json")
        save_json(all_results, output_file)

        self.logger.found(f"GitHub Dorking: {len(all_results)} results found")

    def run_shodan(self):
        """Query Shodan for target intelligence."""
        self.logger.info("Running Shodan search...")

        shodan_dir = os.path.join(self.output_dir, "shodan")
        os.makedirs(shodan_dir, exist_ok=True)

        api_key = self.config.get('sensitive_info.shodan.api_key', '')
        if not api_key:
            self.logger.warning("No Shodan API key configured, skipping")
            return

        try:
            import shodan
            api = shodan.Shodan(api_key)

            # Search by hostname
            results = api.search(f'hostname:{self.target}')

            output_file = os.path.join(shodan_dir, "shodan_results.json")
            save_json(results, output_file)

            self.logger.found(
                f"Shodan: {results.get('total', 0)} results found"
            )

            # Extract interesting info
            for match in results.get('matches', []):
                ip = match.get('ip_str', '')
                port = match.get('port', '')
                org = match.get('org', '')
                product = match.get('product', '')

                self.findings.append(
                    f"[Shodan] {ip}:{port} - {org} - {product}"
                )

        except ImportError:
            self.logger.warning("Shodan Python module not installed")
        except Exception as e:
            self.logger.error(f"Shodan query failed: {str(e)}")

    def generate_google_dorks(self):
        """Generate Google dork queries for manual checking."""
        self.logger.info("Generating Google dorks...")

        dorks_dir = os.path.join(self.output_dir, "google_dorks")
        os.makedirs(dorks_dir, exist_ok=True)

        dork_templates = self.config.get(
            'sensitive_info.google_dorking.dorks', []
        )

        generated_dorks = []
        for template in dork_templates:
            dork = template.replace('{target}', self.target)
            generated_dorks.append(dork)

        # Additional auto-generated dorks
        extra_dorks = [
            f'site:{self.target} inurl:login',
            f'site:{self.target} inurl:admin',
            f'site:{self.target} inurl:dashboard',
            f'site:{self.target} inurl:api',
            f'site:{self.target} inurl:swagger',
            f'site:{self.target} inurl:graphql',
            f'site:{self.target} filetype:pdf',
            f'site:{self.target} filetype:doc',
            f'site:{self.target} filetype:xls',
            f'site:{self.target} "internal" OR "confidential" OR "private"',
            f'"{self.target}" password OR secret OR credential',
            f'"{self.target}" API_KEY OR api_key OR apikey',
            f'inurl:"{self.target}" ext:env OR ext:yml OR ext:config',
            f'site:{self.target} inurl:wp-admin OR inurl:wp-login',
            f'site:{self.target} "error" OR "warning" OR "exception"',
            f'site:{self.target} intitle:"index of" "parent directory"',
            f'site:{self.target} ext:sql OR ext:db OR ext:bak',
            f'site:pastebin.com "{self.target}"',
            f'site:trello.com "{self.target}"',
            f'site:github.com "{self.target}" password',
        ]

        generated_dorks.extend(extra_dorks)
        generated_dorks = list(dict.fromkeys(generated_dorks))  # Deduplicate

        output_file = os.path.join(dorks_dir, "google_dorks.txt")
        write_file_lines(output_file, generated_dorks)

        # Also generate clickable URLs
        url_file = os.path.join(dorks_dir, "google_dork_urls.txt")
        dork_urls = []
        for dork in generated_dorks:
            encoded = url_quote(dork)
            dork_urls.append(f"https://www.google.com/search?q={encoded}")

        write_file_lines(url_file, dork_urls)

        self.logger.found(f"Generated {len(generated_dorks)} Google dorks")