"""
SyncHunt - API Introspection
Discovers API surfaces: OpenAPI/Swagger documents, GraphQL endpoints
(including introspection), Spring Boot actuators and common API base paths.

Only read-only, low-impact requests are issued (`GET`, plus a single
`POST {__typename}` introspection probe when enabled).
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

from core.models import Asset, Finding
from core.net import find_scheme, post_json, probe
from core.utils import ensure_dir, host_from_url, read_file_lines, save_json, write_file_lines

GRAPHQL_PROBE = {"query": "{__typename}", "operationName": None, "variables": {}}
GRAPHQL_INTROSPECTION = {
    "query": "query IntrospectionQuery { __schema { queryType { name } types { name kind } } }"
}

DOC_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api/docs",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/docs",
    "/redoc",
    "/.well-known/openapi.json",
]

# Built-in API route wordlist. A config `wordlist` file supplements this list
# rather than replacing it, so a missing wordlist never disables the check.
BRUTEFORCE_PATHS = [
    "v1", "v2", "v3", "v0", "api", "api/v1", "api/v2", "api/v3",
    "api/internal", "api/private", "api/public", "api/admin", "api/users",
    "api/login", "api/token", "api/health", "api/status", "api/version",
    "api/config", "api/settings", "api/search", "api/upload", "api/files",
    "api/orders", "api/products", "api/payments", "api/webhooks",
    "rest", "rest/v1", "rpc", "graphql", "graphiql", "api/graphql",
    "gql", "query", "internal", "private", "admin", "admin/api",
    "manage", "management", "console", "debug", "metrics", "status",
    "health", "healthz", "readyz", "livez", "version", "info",
    "auth", "oauth", "oauth/token", "login", "logout", "register",
    "users", "user", "me", "profile", "accounts", "sessions",
    "config", "settings", "env", "backup", "export", "import",
    "test", "dev", "staging", "swagger", "swagger-ui", "openapi.json",
    "webhooks", "callbacks", "hooks", "events", "jobs", "tasks",
    "report", "reports", "dashboard", "monitor", "probe",
]

API_BASE_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/graphql",
    "/graphiql",
    "/rest",
    "/services",
    "/rpc",
]

ACTUATOR_PATHS = [
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/heapdump",
    "/metrics",
    "/health",
    "/healthz",
    "/readyz",
    "/status",
    "/debug",
    "/.well-known/security.txt",
]

SECRET_HINTS = ("swagger", "openapi", "graphql", "api", "docs", "introspection")


class APIIntrospector:
    """Enumerate and analyse API endpoints on in-scope hosts."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.logger = ctx.logger
        self.output_dir = ctx.path("api_intelligence")
        ensure_dir(self.output_dir)

        self.max_hosts = self.config.get_int("api_introspection.max_hosts", 100)
        self.detect_graphql = self.config.get_bool("api_introspection.graphql", True)
        self.detect_actuator = self.config.get_bool("api_introspection.actuator", True)
        self.bruteforce = self.config.get_bool("api_introspection.bruteforce.enabled", True)
        self.bruteforce_threads = max(
            1, self.config.get_int("api_introspection.bruteforce.threads", 15)
        )
        self.bruteforce_max = max(
            1, self.config.get_int("api_introspection.bruteforce.max_paths", 80)
        )
        self.bruteforce_max_hosts = max(
            1, self.config.get_int("api_introspection.bruteforce.max_hosts", 10)
        )
        self.bruteforce_hosts: set = set()
        self.bruteforce_statuses = self.config.get_list(
            "api_introspection.bruteforce.status_codes",
            [200, 201, 204, 301, 302, 401, 403, 405],
        ) or [200, 401, 403, 405]
        self.bruteforce_hits: List[str] = []
        self.report_health = self.config.get_bool("api_introspection.report_health", False)
        self.timeout = max(3, min(self.config.get_int("general.timeout", 10), 15))
        self.specs: List[Dict] = []
        self.graphql: List[Dict] = []
        self.endpoints: List[str] = []
        self.findings: List[Finding] = []

    # ------------------------------------------------------------------
    def _hosts(self) -> List[str]:
        hosts = read_file_lines(self.ctx.resolve_file("live_hosts", "dns", "live_hosts.txt"))
        if not hosts:
            hosts = [self.target_base()]
        if self.ctx.scope:
            hosts = self.ctx.scope.filter(hosts, record_drops=True)
        return hosts[: self.max_hosts]

    def target_base(self) -> str:
        base = find_scheme(self.ctx.session, self.ctx.target, limiter=self.ctx.limiter)
        return base or f"https://{host_from_url(self.ctx.target)}"

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("API DISCOVERY", 9)
        started = time.time()

        hosts = self._hosts()
        if not hosts:
            self.logger.warning("No in-scope hosts for API discovery")
            return self.output_dir

        # Route brute forcing is the loudest check in this phase, so it is
        # limited to the first N hosts (config: bruteforce.max_hosts).
        self.bruteforce_hosts = set(hosts[: self.bruteforce_max_hosts])
        if self.bruteforce and len(hosts) > len(self.bruteforce_hosts):
            self.logger.info(
                f"API route bruteforce limited to {len(self.bruteforce_hosts)} "
                f"of {len(hosts)} host(s)"
            )
        self.logger.info(f"Probing {len(hosts)} host(s) for API surfaces...")
        workers = max(1, min(self.ctx.threads(), 16, len(hosts)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(self._analyse_host, host) for host in hosts]
            for index, future in enumerate(as_completed(futures), start=1):
                try:
                    future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    self.logger.debug(f"api probe failed: {exc}")
                self.logger.progress(index, len(futures), "api-discovery")

        self._write_outputs()
        self._record()

        duration = time.time() - started
        self.logger.result(
            f"API Discovery Complete: {len(self.specs)} spec(s), "
            f"{len(self.graphql)} GraphQL endpoint(s), "
            f"{len(self.endpoints)} endpoint(s) in {duration:.1f}s"
        )
        return self.output_dir

    # ------------------------------------------------------------------
    def _analyse_host(self, host: str) -> None:
        base = host.strip().rstrip("/")
        if "://" not in base:
            base = find_scheme(self.ctx.session, base, limiter=self.ctx.limiter) or f"https://{base}"

        for path in DOC_PATHS:
            url = urljoin(base + "/", path.lstrip("/"))
            result = probe(
                self.ctx.session, url, limiter=self.ctx.limiter,
                timeout=self.timeout, max_bytes=262144,
            )
            if result.status != 200 or not result.text:
                continue
            spec = self._parse_spec(result, url)
            if spec:
                self.specs.append(spec)
                self.logger.found(
                    f"API spec: {spec.get('title') or 'unknown'} at {url} "
                    f"({len(spec.get('endpoints', []))} endpoints)"
                )
                self._spec_findings(spec)

        for path in API_BASE_PATHS:
            url = urljoin(base + "/", path.lstrip("/"))
            result = probe(
                self.ctx.session, url, limiter=self.ctx.limiter,
                timeout=self.timeout, max_bytes=65536,
            )
            if result.status in (200, 401, 403) and _looks_like_api(result):
                self.endpoints.append(url)
                if "graphql" in path and result.status == 200:
                    self._probe_graphql(url)
            elif self.detect_graphql and "graphql" in path and result.status in (400, 405):
                self._probe_graphql(url)

        if self.bruteforce and base in self.bruteforce_hosts:
            self._bruteforce_host(base)

        if self.detect_actuator:
            for path in ACTUATOR_PATHS:
                url = urljoin(base + "/", path.lstrip("/"))
                result = probe(
                    self.ctx.session, url, limiter=self.ctx.limiter,
                    timeout=self.timeout, max_bytes=131072,
                )
                if result.status == 200:
                    self.endpoints.append(url)
                    self._actuator_finding(url, path, result)

    # ------------------------------------------------------------------
    def _parse_spec(self, result, url: str) -> Optional[Dict]:
        data = result.json(default=None)
        if not isinstance(data, dict):
            return None
        if not any(key in data for key in ("swagger", "openapi", "paths", "basePath")):
            return None

        endpoints: List[str] = []
        for path, methods in (data.get("paths") or {}).items():
            if not isinstance(methods, dict):
                continue
            for method in methods:
                if method.lower() in ("get", "post", "put", "patch", "delete", "head", "options"):
                    endpoints.append(f"{method.upper()} {path}")

        servers = data.get("servers") or []
        server_urls = [s.get("url", "") for s in servers if isinstance(s, dict)]
        if data.get("host"):
            scheme = "https"
            for entry in data.get("schemes") or []:
                scheme = entry
                break
            server_urls.append(f"{scheme}://{data['host']}{data.get('basePath', '')}")

        spec = {
            "url": url,
            "source": "swagger" if "swagger" in data else "openapi",
            "version": str(data.get("openapi") or data.get("swagger") or ""),
            "title": ((data.get("info") or {}) if isinstance(data.get("info"), dict) else {}).get("title", ""),
            "auth_schemes": sorted(
                ((data.get("components") or {}).get("securitySchemes") or {}).keys()
            ),
            "servers": [s for s in server_urls if s],
            "endpoints": sorted(set(endpoints)),
            "endpoint_count": len(set(endpoints)),
        }
        return spec

    def _spec_findings(self, spec: Dict) -> None:
        url = spec["url"]
        has_auth = bool(spec.get("auth_schemes"))
        severity = "low" if has_auth else "medium"
        self.findings.append(
            Finding(
                category="api",
                title=f"Public {spec['source'].title()} specification exposed",
                severity=severity,
                target=self.ctx.target,
                url=url,
                evidence=(
                    f"{spec.get('title') or 'API'} ({spec['endpoint_count']} endpoints, "
                    f"auth schemes: {', '.join(spec.get('auth_schemes') or ['none'])})"
                ),
                source="api_introspection",
                confidence="high",
                tags=["api", "exposure"],
                extra={"endpoints": spec.get("endpoints", [])[:50]},
            )
        )

    def _probe_graphql(self, url: str) -> None:
        for payload, kind in ((GRAPHQL_PROBE, "probe"), (GRAPHQL_INTROSPECTION, "introspection")):
            result = post_json(
                self.ctx.session,
                url,
                payload,
                limiter=self.ctx.limiter,
                timeout=self.timeout,
                max_bytes=262144,
            )
            data = result.json(default=None)
            if isinstance(data, dict) and data.get("data"):
                entry = {
                    "url": url,
                    "kind": kind,
                    "status": result.status,
                    "introspection_enabled": "types" in str(data)[:2000],
                }
                if kind == "probe":
                    self.graphql.append(entry)
                    self.logger.found(f"GraphQL endpoint confirmed: {url}")
                    continue  # now try the introspection payload
                if entry["introspection_enabled"]:
                    self.findings.append(
                        Finding(
                            category="api",
                            title="GraphQL introspection enabled",
                            severity="medium",
                            target=self.ctx.target,
                            url=url,
                            evidence="Introspection query returned the schema",
                            source="api_introspection",
                            confidence="high",
                            tags=["graphql", "api"],
                        )
                    )
                return
            if result.status in (401, 403, 405):
                # Reachable but not introspectable - still worth recording.
                self.graphql.append(
                    {"url": url, "kind": kind, "status": result.status,
                     "introspection_enabled": False}
                )
                return

    def _actuator_finding(self, url: str, path: str, result) -> None:
        sensitive = any(
            key in path for key in
            ("env", "heapdump", "beans", "configprops", "mappings", "debug", "trace")
        )
        if not sensitive and not self.report_health:
            # Health/metrics/status endpoints are normal operational surface:
            # keep them as assets instead of inflating the findings list.
            self.logger.debug(f"management endpoint noted (not reported): {url}")
            return
        severity = "high" if sensitive else "info"
        body_hint = ""
        data = result.json(default=None)
        if isinstance(data, dict):
            body_hint = ", ".join(sorted(data.keys())[:8])
        self.findings.append(
            Finding(
                category="api",
                title=f"Exposed management endpoint: {path}",
                severity=severity,
                target=self.ctx.target,
                url=url,
                evidence=body_hint or f"HTTP {result.status}",
                source="api_introspection",
                confidence="high",
                tags=["actuator", "misconfiguration"],
            )
        )
        if sensitive:
            self.logger.vuln(f"Exposed management endpoint: {url}")

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # API route brute forcing (kiterunner-style, read-only probes)
    # ------------------------------------------------------------------
    def bruteforce_paths(self) -> List[str]:
        """User-supplied wordlist first (highest priority), built-ins after."""
        paths: List[str] = []
        wordlist = self.config.get("api_introspection.bruteforce.wordlist", "") or ""
        if wordlist:
            if os.path.exists(wordlist):
                paths.extend(
                    line.strip().lstrip("/")
                    for line in read_file_lines(wordlist)
                    if line.strip() and not line.strip().startswith("#")
                )
            else:
                self.logger.debug(f"api wordlist not found: {wordlist}")
        paths.extend(BRUTEFORCE_PATHS)
        # de-duplicate, keep a stable order, cap the run
        seen = set()
        ordered = []
        for path in paths:
            key = path.strip("/").lower()
            if key and key not in seen:
                seen.add(key)
                ordered.append(key)
        return ordered[: self.bruteforce_max]

    def _bruteforce_host(self, base: str) -> None:
        if not self.bruteforce_hosts:
            self.bruteforce_hosts = {base}
        paths = self.bruteforce_paths()
        if not paths:
            return
        base = base.rstrip("/")
        workers = max(1, min(self.bruteforce_threads, len(paths)))

        def probe_path(path: str):
            url = f"{base}/{path}"
            return url, probe(
                self.ctx.session, url, limiter=self.ctx.limiter,
                timeout=self.timeout, max_bytes=32768,
            )

        hits: List[str] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(probe_path, path) for path in paths]
            for future in as_completed(futures):
                try:
                    url, result = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    self.logger.debug(f"api bruteforce probe failed: {exc}")
                    continue
                if result.status not in self.bruteforce_statuses:
                    continue
                if not result.reachable:
                    continue
                hits.append(url)
                self.endpoints.append(url)
                self.bruteforce_hits.append(url)

                # A route that returns a spec document is as good as a published one.
                if result.status == 200 and result.text:
                    spec = self._parse_spec(result, url)
                    if spec:
                        self.specs.append(spec)
                        self.logger.found(
                            f"API spec via route bruteforce: {url} "
                            f"({len(spec.get('endpoints', []))} endpoints)"
                        )
                        self._spec_findings(spec)

                if any(keyword in url.lower() for keyword in
                       ("admin", "internal", "private", "debug", "env", "backup", "manage")):
                    self.findings.append(
                        Finding(
                            category="api",
                            title=f"Sensitive API route reachable: /{url.split('/', 3)[-1].lstrip('/')}",
                            severity="medium" if result.status == 200 else "low",
                            target=self.ctx.target,
                            url=url,
                            evidence=(
                                f"HTTP {result.status} for an administrative/internal "
                                "API route - verify authentication and authorisation manually"
                            ),
                            source="api_introspection",
                            confidence="medium",
                            tags=["api", "route-discovery", "access-control"],
                        )
                    )

        if hits:
            self.logger.found(f"{len(hits)} API route(s) discovered on {base}")
            self.ctx.record_assets(
                [Asset(kind="api_endpoint", value=url, source="api_introspection")
                 for url in hits[:200]]
            )

    def _write_outputs(self) -> None:
        specs_file = os.path.join(self.output_dir, "api_specs.json")
        save_json(self.specs, specs_file)
        self.ctx.set_file("api_specs", specs_file)

        graphql_file = os.path.join(self.output_dir, "graphql.json")
        save_json(self.graphql, graphql_file)

        endpoint_file = os.path.join(self.output_dir, "endpoints.txt")
        if self.bruteforce_hits:
            write_file_lines(
                os.path.join(self.output_dir, "bruteforce.txt"),
                sorted(set(self.bruteforce_hits)),
            )
        all_endpoints = list(self.endpoints)
        for spec in self.specs:
            all_endpoints.extend(
                f"{spec['url'].split('://')[0]}://{urlparse(spec['url']).netloc}{e.split(' ', 1)[1]}"
                for e in spec.get("endpoints", [])[:200]
                if " " in e
            )
        write_file_lines(endpoint_file, all_endpoints)
        self.ctx.set_file("api_endpoints", endpoint_file)

        save_json(
            {
                "specs": len(self.specs),
                "graphql_endpoints": len(self.graphql),
                "endpoints": len(set(all_endpoints)),
                "findings": len(self.findings),
            },
            os.path.join(self.output_dir, "summary.json"),
        )

    def _record(self) -> None:
        assets: List[Asset] = []
        for spec in self.specs:
            assets.append(
                Asset(kind="api_spec", value=spec["url"], host=host_from_url(spec["url"]),
                      source="api_introspection", meta={"endpoints": spec["endpoint_count"]})
            )
        for entry in self.graphql:
            assets.append(
                Asset(kind="graphql", value=entry["url"], host=host_from_url(entry["url"]),
                      source="api_introspection")
            )
        for url in set(self.endpoints):
            assets.append(
                Asset(kind="endpoint", value=url, host=host_from_url(url),
                      source="api_introspection")
            )
        self.ctx.record_assets(assets)
        self.ctx.record_findings(self.findings)


def _looks_like_api(result) -> bool:
    content_type = (result.content_type or "").lower()
    if "json" in content_type or "xml" in content_type:
        return True
    text = (result.text or "").lstrip()[:200].lower()
    return text.startswith("{") or text.startswith("[") or "swagger" in text or "openapi" in text
