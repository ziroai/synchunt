"""
Shared pytest fixtures: minimal config, a ScanContext bound to a temp
directory, and a local HTTP server that stands in for a target.
"""

import http.server
import json
import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config_manager import ConfigManager  # noqa: E402
from core.context import ScanContext  # noqa: E402
from core.database_manager import DatabaseManager, default_db_path  # noqa: E402
from core.logger import BugHuntLogger  # noqa: E402
from core.runner import ToolRunner  # noqa: E402
from core.utils import create_output_structure  # noqa: E402
from modules.scope_manager import ScopeManager  # noqa: E402

MINIMAL_CONFIG = """
general:
  profile: "quick"
  threads: 4
  timeout: 5
  rate_limit: 1000
  resolve_timeout: 2
  retry: 0
  verbose: false
  output_dir: "{output_dir}"
profiles:
  quick:
    phases: [subdomain, validation, enrichment, report]
  full:
    phases: [subdomain, validation, enrichment, portscan, fingerprint, github_recon,
             content, api_discovery, jsanalysis, cloud_enum, vulnscan, sensitive,
             screenshot, prioritize, report]
subdomain_enum:
  enabled: true
  subfinder: {{enabled: false}}
subdomain_validation:
  enabled: true
  httpx: {{enabled: false}}
  dnsx: {{enabled: false}}
asset_enrichment:
  enabled: true
  max_hosts: 5
  probe_admin_paths: true
  admin_paths: ["/admin", "/.env", "/server-status"]
port_scanning:
  enabled: true
  naabu: {{enabled: false}}
  nmap: {{enabled: false}}
fingerprinting:
  enabled: true
  whatweb: {{enabled: false}}
  wafw00f: {{enabled: false}}
  webanalyze: {{enabled: false}}
github_recon:
  enabled: true
  search_code: false
  dorks: ["password"]
content_discovery:
  enabled: true
  waybackurls: {{enabled: false}}
  gau: {{enabled: false}}
  katana: {{enabled: false}}
  gospider: {{enabled: false}}
  hakrawler: {{enabled: false}}
  paramspider: {{enabled: false}}
  dirsearch: {{enabled: false}}
  feroxbuster: {{enabled: false}}
  ffuf: {{enabled: false}}
  x8: {{enabled: false}}
api_introspection:
  enabled: true
  max_hosts: 5
js_analysis:
  enabled: true
  linkfinder: {{enabled: false}}
  secretfinder: {{enabled: false}}
  custom_regex:
    enabled: true
    patterns:
      - name: "Test Token"
        regex: "TESTTOKEN_[A-Za-z0-9]{{12,}}"
        severity: "high"
        confidence: "high"
        entropy: false
cloud_enum:
  enabled: true
  aws: true
  azure: false
  gcp: false
  max_candidates: 6
vuln_scanning:
  enabled: true
  nuclei: {{enabled: false}}
  nikto: {{enabled: false}}
  dalfox: {{enabled: false}}
  sqlmap: {{enabled: false}}
  crlfuzz: {{enabled: false}}
  corsy: {{enabled: false}}
sensitive_info:
  enabled: true
  github_dorking: {{enabled: false}}
  google_dorking: {{enabled: true}}
  shodan: {{enabled: false}}
screenshots:
  enabled: true
  gowitness: {{enabled: false}}
  aquatone: {{enabled: false}}
finding_prioritizer:
  enabled: true
  min_severity: "info"
  threat_intel: {{enabled: false}}
  searchsploit: {{enabled: false}}
reporting:
  enabled: true
  html_report: true
  markdown_report: true
notifications:
  enabled: false
"""


@pytest.fixture
def output_dir(tmp_path):
    directory = tmp_path / "output"
    directory.mkdir()
    return str(directory)


@pytest.fixture
def config_path(tmp_path, output_dir):
    path = tmp_path / "config.yaml"
    # YAML double-quoted scalars interpret backslash escapes, so Windows paths
    # must be written with forward slashes (Path handles both everywhere).
    safe_output_dir = str(output_dir).replace("\\", "/")
    path.write_text(MINIMAL_CONFIG.format(output_dir=safe_output_dir))
    return str(path)


@pytest.fixture
def config(config_path):
    return ConfigManager(config_path)


@pytest.fixture
def logger(output_dir):
    return BugHuntLogger(name="SyncHuntTest", output_dir=output_dir, verbose=False)


@pytest.fixture
def runner(logger):
    return ToolRunner(logger=logger, timeout=20, verbose=False)


@pytest.fixture
def ctx(tmp_path, config, logger, runner, output_dir):
    target = "example.com"
    run_dir = os.path.join(output_dir, target, "20260101_000000")
    create_output_structure(run_dir)
    database = DatabaseManager(default_db_path(run_dir))
    scan_id = database.start_scan(target, "test", run_dir)
    context = ScanContext(
        target=target,
        output_dir=run_dir,
        config=config,
        logger=logger,
        runner=runner,
        scope=ScopeManager.from_config(config),
        database=database,
        scan_id=scan_id,
    )
    yield context
    database.close()


# ----------------------------------------------------------------------
# Local test server
# ----------------------------------------------------------------------
OPENAPI_DOC = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0"},
    "paths": {"/users": {"get": {}}, "/users/{id}": {"post": {}}},
}

PAGE = (
    "<html><head><title>Test Server</title></head><body>"
    "<script>var api_key = 'abcdefghijklmnop12345678';</script>"
    "</body></html>"
)


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):  # keep test output clean
        pass

    def _send(self, status, body="", content_type="text/html"):
        payload = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Powered-By", "TestStack/1.0")
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/openapi.json":
            self._send(200, json.dumps(OPENAPI_DOC), "application/json")
        elif path in ("/admin", "/login"):
            self._send(200, "<html>admin</html>")
        elif path == "/graphql":
            self._send(400, "bad request", "application/json")
        elif path == "/health":
            self._send(200, '{"status":"UP"}', "application/json")
        elif path == "/.env":
            self._send(200, "SECRET=value")
        elif path == "/echo":
            # reflects the request headers so tests can prove auth reaches the target
            self._send(200, json.dumps({k: v for k, v in self.headers.items()}),
                       "application/json")
        else:
            self._send(200, PAGE)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        path = self.path.split("?")[0]
        if path == "/graphql" and b"__typename" in body:
            self._send(200, json.dumps({"data": {"__typename": "Query"}}), "application/json")
        elif path == "/graphql" and b"__schema" in body:
            self._send(200, json.dumps({"data": {"__schema": {"types": [{"name": "Query"}]}}}),
                       "application/json")
        else:
            self._send(404, "not found", "application/json")


@pytest.fixture
def local_server():
    """A local HTTP server; yields its base URL."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
