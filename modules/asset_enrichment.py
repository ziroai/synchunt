import json
import os
import re
import socket
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

from core.utils import read_file_lines, save_json, write_file_lines

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AssetEnrichment:
    """Collect additional intel around live hosts: DNS, IPs, headers, tech stack, and exposure hints."""

    COMMON_ADMIN_PATHS = [
        '/admin', '/login', '/signin', '/dashboard', '/phpmyadmin', '/wp-admin',
        '/manage', '/console', '/swagger', '/graphql', '/api', '/api/v1', '/.git',
        '/.env', '/.svn', '/.hg', '/.well-known', '/debug', '/actuator', '/health',
        '/.aws', '/config', '/settings', '/.env.local', '/secrets', '/private',
        '/docs', '/api-docs', '/swagger-ui', '/graphiql', '/v1', '/v2', '/v3'
    ]

    def __init__(self, config, runner, logger, output_dir, live_hosts_file, target):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = os.path.join(output_dir, 'intel')
        self.live_hosts_file = live_hosts_file
        self.target = target
        os.makedirs(self.output_dir, exist_ok=True)

    def run_all(self):
        """Run asset enrichment with parallel processing."""
        self.logger.phase_banner('ASSET ENRICHMENT & INTEL', 5)
        hosts = read_file_lines(self.live_hosts_file)
        if not hosts:
            self.logger.warning('No live hosts available for asset enrichment.')
            return None

        self.logger.info(f'Enriching {len(hosts)} hosts with parallel processing...')
        start_time = time.time()

        findings = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._enrich_host, host): host for host in hosts[:150]}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        findings.append(result)
                except Exception as e:
                    self.logger.debug(f'Enrichment error: {e}')

        output_file = os.path.join(self.output_dir, 'asset_summary.json')
        save_json(findings, output_file)

        summary_lines = []
        for item in findings:
            ips_str = ','.join(item['ips']) if item['ips'] else 'n/a'
            exposures_str = ','.join(item['exposure_hints']) if item['exposure_hints'] else 'none'
            summary_lines.append(
                f"{item['host']} | ip={ips_str} | status={item['status_code']} | "
                f"title={item['title'][:50]} | tech={','.join(item['tech_hints'][:2]) or 'unknown'} | "
                f"exposures={exposures_str}"
            )
        write_file_lines(os.path.join(self.output_dir, 'asset_summary.txt'), summary_lines)

        duration = time.time() - start_time
        self.logger.result(f'Asset enrichment complete: {len(findings)} hosts analyzed in {duration:.1f}s')
        return output_file

    def _enrich_host(self, host):
        """Enrich a single host with DNS, tech detection, and exposure analysis."""
        normalized = host.strip().rstrip('/')
        url = normalized if '://' in normalized else f'https://{normalized}'

        parsed = urlparse(url)
        hostname = parsed.netloc.split(':')[0]
        
        # DNS resolution
        ips = self._resolve_ips(hostname)

        title = 'n/a'
        status_code = 0
        exposure_hints = []
        tech_hints = []
        headers_info = {}

        try:
            user_agent = self.config.get('general.user_agent', 'Mozilla/5.0 Synchunt/2026')
            headers = {'User-Agent': user_agent, 'Accept': '*/*'}
            response = requests.get(
                url,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            status_code = response.status_code
            
            # Extract title
            title_match = re.search(r'<title[^>]*>(.*?)</title>', response.text, re.I | re.S)
            if title_match:
                title = re.sub(r'\s+', ' ', title_match.group(1)).strip()[:120]

            # Tech detection from headers
            headers_info = dict(response.headers)
            server = response.headers.get('Server', '')
            if server:
                tech_hints.append(f'Server:{server}')
            
            x_powered_by = response.headers.get('X-Powered-By', '')
            if x_powered_by:
                tech_hints.append(f'Powered:{x_powered_by}')
            
            # Check for common tech in HTML
            text = response.text.lower()
            for keyword in ['wordpress', 'joomla', 'drupal', 'react', 'angular', 'vue', 'django', 'flask', 'nodejs']:
                if keyword in text:
                    tech_hints.append(f'Likely:{keyword.upper()}')
                    break

            # Exposure detection
            for keyword in ['swagger', 'graphql', 'openapi', 'phpmyadmin', 'admin', 'login', 'api', 'debug', 'actuator', 'elastic']:
                if keyword in text:
                    exposure_hints.append(keyword)

            # Probe for common paths
            for path in self.COMMON_ADMIN_PATHS[:15]:
                try:
                    probe = requests.get(
                        f"{url}{path}",
                        headers=headers,
                        timeout=5,
                        verify=False,
                        allow_redirects=False
                    )
                    if probe.status_code in (200, 301, 302, 401, 403, 500):
                        exposure_hints.append(f'Found:{path}')
                except Exception:
                    pass
        except Exception as e:
            self.logger.debug(f'Enrichment HTTP probe failed for {host}: {e}')

        # Deduplicate
        exposure_hints = list(dict.fromkeys(exposure_hints))[:15]
        tech_hints = list(dict.fromkeys(tech_hints))[:10]

        return {
            'host': normalized,
            'url': url,
            'ips': ips,
            'status_code': status_code,
            'title': title,
            'tech_hints': tech_hints,
            'exposure_hints': exposure_hints,
            'headers_summary': {
                'Server': server if server else 'Unknown',
                'X-Powered-By': x_powered_by if x_powered_by else 'Unknown',
                'Content-Type': headers_info.get('Content-Type', 'Unknown')
            },
            'target': self.target,
        }

    def _resolve_ips(self, hostname):
        """Resolve hostname to IPs."""
        ips = []
        try:
            infos = socket.getaddrinfo(hostname, None)
            ips = sorted({info[4][0] for info in infos if info and info[4]})
        except Exception:
            pass
        return ips
