import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from core.utils import save_json, write_file_lines


class GitHubRecon:
    """Collect public GitHub intelligence: repos, issues, secrets, commits."""

    def __init__(self, config, runner, logger, output_dir, target):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = os.path.join(output_dir, 'github_recon')
        self.target = target
        self.token = config.get('github_recon.token') or os.getenv('GITHUB_TOKEN', '')
        os.makedirs(self.output_dir, exist_ok=True)

    def run_all(self):
        """Run GitHub reconnaissance with parallel queries."""
        self.logger.phase_banner('GITHUB RECONNAISSANCE', 8)
        start_time = time.time()

        queries = self._generate_queries()
        self.logger.info(f'Executing {len(queries)} GitHub search queries...')

        repositories = []
        issues = []
        secrets_exposed = []
        commits = []

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for query in queries:
                futures[executor.submit(self._search_repositories, query)] = f'repo:{query}'
                futures[executor.submit(self._search_issues, query)] = f'issue:{query}'
                futures[executor.submit(self._search_secrets, query)] = f'secret:{query}'
            
            for future in as_completed(futures):
                query_type = futures[future]
                try:
                    results = future.result()
                    if 'repo:' in query_type:
                        repositories.extend(results)
                    elif 'issue:' in query_type:
                        issues.extend(results)
                    elif 'secret:' in query_type:
                        secrets_exposed.extend(results)
                except Exception as e:
                    self.logger.debug(f'GitHub query {query_type} failed: {e}')

        # Deduplicate
        repositories = self._dedupe(repositories, 'full_name')
        issues = self._dedupe(issues, 'url')
        secrets_exposed = self._dedupe(secrets_exposed, 'url')

        # Save results
        output_json = os.path.join(self.output_dir, 'github_recon.json')
        save_json({
            'target': self.target,
            'timestamp': time.time(),
            'repositories': repositories,
            'issues': issues,
            'secrets_exposed': secrets_exposed,
        }, output_json)

        # Summary files
        write_file_lines(
            os.path.join(self.output_dir, 'repositories.txt'),
            [r.get('full_name', '') for r in repositories if r.get('full_name')]
        )
        write_file_lines(
            os.path.join(self.output_dir, 'issues.txt'),
            [f"{i.get('title', '')} - {i.get('html_url', '')}" for i in issues if i.get('title')]
        )
        write_file_lines(
            os.path.join(self.output_dir, 'secrets_exposed.txt'),
            [f"{s.get('type', 'unknown')}: {s.get('match', '')[:80]}" for s in secrets_exposed]
        )

        duration = time.time() - start_time
        self.logger.result(
            f'GitHub recon complete: {len(repositories)} repos / {len(issues)} issues / '
            f'{len(secrets_exposed)} secrets in {duration:.1f}s'
        )
        return output_json

    def _generate_queries(self):
        """Generate multiple search queries from target."""
        queries = [
            self.target,
            self.target.replace('.com', '').replace('.', ''),
            self.target.split('.')[0],
        ]
        # Add variations
        if '-' in self.target:
            queries.append(self.target.replace('-', '_'))
        if '_' in self.target:
            queries.append(self.target.replace('_', '-'))
        return list(dict.fromkeys(queries))[:5]

    def _headers(self):
        headers = {
            'Accept': 'application/vnd.github+json',
            'User-Agent': 'Synchunt-GitHub-Recon-2026',
        }
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        return headers

    def _search_repositories(self, query):
        """Search GitHub repositories."""
        url = 'https://api.github.com/search/repositories'
        params = {
            'q': f'{query} in:name,description',
            'per_page': 10,
            'sort': 'stars',
            'order': 'desc'
        }
        try:
            response = requests.get(url, headers=self._headers(), params=params, timeout=20)
            if response.status_code != 200:
                return []
            data = response.json()
            return data.get('items', [])
        except Exception as e:
            self.logger.debug(f'GitHub repo search failed: {e}')
            return []

    def _search_issues(self, query):
        """Search GitHub issues and discussions."""
        url = 'https://api.github.com/search/issues'
        params = {
            'q': f'{query} in:title,body is:issue',
            'per_page': 10,
            'sort': 'updated',
            'order': 'desc'
        }
        try:
            response = requests.get(url, headers=self._headers(), params=params, timeout=20)
            if response.status_code != 200:
                return []
            data = response.json()
            return data.get('items', [])
        except Exception as e:
            self.logger.debug(f'GitHub issue search failed: {e}')
            return []

    def _search_secrets(self, query):
        """Search for exposed secrets and sensitive patterns."""
        url = 'https://api.github.com/search/code'
        secret_patterns = [
            'password',
            'api_key',
            'secret',
            'token',
            'private_key',
            'aws_access_key'
        ]
        findings = []
        for pattern in secret_patterns[:3]:
            params = {
                'q': f'{query} {pattern} in:file',
                'per_page': 5
            }
            try:
                response = requests.get(url, headers=self._headers(), params=params, timeout=20)
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get('items', []):
                        findings.append({
                            'type': pattern,
                            'match': item.get('name', ''),
                            'url': item.get('html_url', ''),
                            'repository': item.get('repository', {}).get('full_name', '')
                        })
            except Exception:
                pass
        return findings

    def _dedupe(self, items, key):
        """Deduplicate items by key."""
        seen = set()
        cleaned = []
        for item in items:
            val = item.get(key, '')
            if val and val not in seen:
                seen.add(val)
                cleaned.append(item)
        return cleaned
