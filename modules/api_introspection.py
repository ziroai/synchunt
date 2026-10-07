import os
import re
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

from core.utils import read_file_lines, save_json, write_file_lines

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class APIIntrospection:
    """Deep API analysis: GraphQL introspection, OpenAPI/Swagger discovery, endpoint mapping."""

    COMMON_API_PATHS = [
        '/graphql', '/graphiql', '/playground',
        '/swagger.json', '/swagger.yaml', '/swagger-ui.html',
        '/api/openapi.json', '/api/swagger.json', '/api/v1/openapi.json',
        '/api/docs', '/api-docs', '/docs', '/documentation',
        '/actuator', '/actuator/health', '/health',
        '/.well-known/openid-configuration',
        '/api/.well-known/openapi.json',
        '/v1/swagger.json', '/v2/swagger.json', '/v3/swagger.json'
    ]

    def __init__(self, config, runner, logger, output_dir, live_hosts_file):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = os.path.join(output_dir, 'api_intelligence')
        self.live_hosts_file = live_hosts_file
        os.makedirs(self.output_dir, exist_ok=True)

    def run_all(self):
        """Discover and analyze APIs."""
        self.logger.phase_banner('API INTROSPECTION & DISCOVERY', 6)
        start_time = time.time()

        hosts = read_file_lines(self.live_hosts_file)
        if not hosts:
            self.logger.warning('No hosts for API introspection.')
            return None

        self.logger.info(f'Probing {len(hosts)} hosts for API endpoints...')
        apis_found = []

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(self._probe_host, host): host for host in hosts[:100]}
            for future in as_completed(futures):
                try:
                    results = future.result()
                    apis_found.extend(results)
                except Exception as e:
                    self.logger.debug(f'API probe error: {e}')

        # Process and dedupe
        apis_found = self._dedupe_apis(apis_found)

        # Save results
        output_json = os.path.join(self.output_dir, 'discovered_apis.json')
        save_json({
            'timestamp': time.time(),
            'apis': apis_found,
        }, output_json)

        # Summary
        summary_lines = [
            f"{api['host']} | {api['endpoint']} | type={api['api_type']} | methods={','.join(api.get('methods', [])[:3])}"
            for api in apis_found
        ]
        write_file_lines(os.path.join(self.output_dir, 'apis_discovered.txt'), summary_lines)

        # Save endpoints
        endpoints = []
        for api in apis_found:
            if 'endpoints' in api and api['endpoints']:
                endpoints.extend(api['endpoints'][:10])
        write_file_lines(os.path.join(self.output_dir, 'api_endpoints.txt'), endpoints)

        duration = time.time() - start_time
        self.logger.result(f'API introspection complete: {len(apis_found)} APIs in {duration:.1f}s')
        return output_json

    def _probe_host(self, host):
        """Probe a host for API endpoints."""
        normalized = host.strip().rstrip('/')
        url_base = normalized if '://' in normalized else f'https://{normalized}'
        results = []

        user_agent = self.config.get('general.user_agent', 'Mozilla/5.0 Synchunt')
        headers = {'User-Agent': user_agent, 'Accept': 'application/json'}

        for api_path in self.COMMON_API_PATHS:
            try:
                full_url = f"{url_base}{api_path}"
                response = requests.get(
                    full_url,
                    headers=headers,
                    timeout=8,
                    verify=False,
                    allow_redirects=False
                )

                if response.status_code in (200, 401, 403):
                    api_type = self._identify_api_type(api_path, response)
                    if api_type:
                        result = {
                            'host': normalized,
                            'url': full_url,
                            'endpoint': api_path,
                            'status_code': response.status_code,
                            'api_type': api_type,
                            'methods': self._extract_methods(response.text),
                            'endpoints': self._extract_endpoints(response.text, api_type)[:20],
                            'content_type': response.headers.get('Content-Type', 'unknown')
                        }
                        results.append(result)
                        self.logger.info(f'Found {api_type} at {full_url}')
            except Exception:
                pass

        return results

    def _identify_api_type(self, path, response):
        """Identify API type from path and response."""
        path_lower = path.lower()
        content_type = response.headers.get('Content-Type', '').lower()
        text = response.text.lower() if response.text else ''

        if 'graphql' in path_lower or 'graphiql' in path_lower:
            return 'GraphQL'
        if 'swagger' in path_lower or 'swagger' in text:
            return 'Swagger/OpenAPI'
        if 'openapi' in path_lower or 'openapi' in text:
            return 'OpenAPI'
        if 'health' in path_lower or 'actuator' in path_lower:
            return 'Health/Actuator'
        if 'json' in content_type and 'paths' in text:
            return 'REST API'
        return None

    def _extract_methods(self, text):
        """Extract HTTP methods from response."""
        methods = set()
        for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
            if method in text.upper():
                methods.add(method)
        return list(methods)

    def _extract_endpoints(self, text, api_type):
        """Extract endpoints from API response."""
        endpoints = []
        try:
            if api_type == 'Swagger/OpenAPI' or api_type == 'OpenAPI':
                data = json.loads(text)
                if 'paths' in data:
                    endpoints = list(data['paths'].keys())[:20]
            elif api_type == 'GraphQL':
                # Look for query/mutation definitions
                queries = re.findall(r'\b(\w+)\s*\{', text)
                endpoints = list(set(queries))[:20]
        except Exception:
            pass
        return endpoints

    def _dedupe_apis(self, apis):
        """Deduplicate APIs."""
        seen = set()
        deduped = []
        for api in apis:
            key = api['url']
            if key not in seen:
                seen.add(key)
                deduped.append(api)
        return deduped
