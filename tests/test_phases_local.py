"""
Integration tests: run real phases against a local HTTP server.
No external network access is required or performed.
"""

import glob
import json
import os

from core.net import HttpResult


# ----------------------------------------------------------------------
# Enrichment
# ----------------------------------------------------------------------
def test_enrichment_profiles_a_live_host(ctx, local_server):
    from core.utils import write_file_lines
    from modules.asset_enrichment import AssetEnricher

    write_file_lines(ctx.get_file("live_hosts", ctx.path("dns", "live_hosts.txt")),
                     [local_server])
    write_file_lines(ctx.path("dns", "live_hosts.txt"), [local_server])

    AssetEnricher(ctx).run_all()

    hosts_file = ctx.path("intel", "hosts.json")
    assert os.path.exists(hosts_file)
    records = json.load(open(hosts_file, encoding="utf-8"))
    record = next(r for r in records if r["host"] == "127.0.0.1")
    assert record["status"] == 200
    assert record["server"] or record["powered_by"]
    assert any("/admin" in entry["url"] for entry in record["interesting_paths"])

    interesting = open(ctx.path("intel", "interesting_paths.txt"), encoding="utf-8").read()
    assert "/admin" in interesting

    findings = ctx.database.findings(ctx.scan_id)
    assert any("Content-Security-Policy" in f.title for f in findings)
    # http:// means no HSTS finding (checked only for https)
    assert not any("HSTS" in f.title for f in findings)


def test_enrichment_respects_scope(ctx, local_server, monkeypatch):
    from core.utils import write_file_lines
    from modules.asset_enrichment import AssetEnricher
    from modules.scope_manager import ScopeManager, parse_rule

    ctx.scope = ScopeManager(include=[parse_rule("example.com")])
    write_file_lines(ctx.path("dns", "live_hosts.txt"), [local_server, "http://example.com"])
    AssetEnricher(ctx).run_all()

    assert ctx.scope.dropped, "out-of-scope host should have been dropped"
    assert any("127.0.0.1" in dropped[0] for dropped in ctx.scope.dropped)


# ----------------------------------------------------------------------
# API discovery
# ----------------------------------------------------------------------
def test_api_introspection_finds_spec_and_graphql(ctx, local_server):
    from core.utils import write_file_lines
    from modules.api_introspection import APIIntrospector

    write_file_lines(ctx.path("dns", "live_hosts.txt"), [local_server])
    ctx.set_file("live_hosts", ctx.path("dns", "live_hosts.txt"))
    APIIntrospector(ctx).run_all()

    specs = json.load(open(ctx.path("api_intelligence", "api_specs.json"), encoding="utf-8"))
    assert any(spec["title"] == "Test API" for spec in specs)
    assert any(spec["endpoint_count"] == 2 for spec in specs)

    graphql = json.load(open(ctx.path("api_intelligence", "graphql.json"), encoding="utf-8"))
    assert any(entry["url"].endswith("/graphql") for entry in graphql)

    findings = ctx.database.findings(ctx.scan_id)
    titles = " ".join(f.title for f in findings)
    assert "specification exposed" in titles
    assert "GraphQL introspection" in titles


# ----------------------------------------------------------------------
# Cloud enumeration (probe is mocked: no third-party traffic in CI)
# ----------------------------------------------------------------------
def test_cloud_enum_flags_public_bucket(ctx, monkeypatch):
    from modules import cloud_enum

    def fake_probe(session, url, **kwargs):
        if "example-public" in url:
            return HttpResult(url=url, status=200, text="<ListBucketResult>")
        if "example-private" in url:
            return HttpResult(url=url, status=403, text="AccessDenied")
        return HttpResult(url=url, status=404, text="NoSuchBucket")

    monkeypatch.setattr(cloud_enum, "probe", fake_probe)
    monkeypatch.setattr(
        cloud_enum.CloudEnumerator, "_candidate_names",
        lambda self: ["example-public", "example-private", "example-absent"],
    )

    cloud_enum.CloudEnumerator(ctx).run_all()

    results = json.load(open(ctx.path("cloud_enum", "aws.json"), encoding="utf-8"))
    names = {entry["name"]: entry for entry in results}
    assert names["example-public"]["public"] is True
    assert names["example-private"]["public"] is False
    assert "example-absent" not in names

    public = open(ctx.path("cloud_enum", "public_buckets.txt"), encoding="utf-8").read()
    assert "example-public" in public

    findings = ctx.database.findings(ctx.scan_id)
    assert any(f.severity == "critical" and "Public AWS bucket" in f.title for f in findings)


# ----------------------------------------------------------------------
# Shell-injection regression guard
# ----------------------------------------------------------------------
def test_no_phase_module_uses_a_shell():
    """
    Only core/runner.py may use shell=True (for genuine pipelines), and it
    quotes every argument. Phase modules must pass argv lists.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    offenders = []
    for path in glob.glob(os.path.join(root, "modules", "**", "*.py"), recursive=True):
        with open(path, encoding="utf-8") as fh:
            for number, line in enumerate(fh, start=1):
                if "shell=True" in line:
                    offenders.append(f"{os.path.relpath(path, root)}:{number}")
    assert offenders == [], f"shell=True found in: {offenders}"


def test_sqlmap_command_is_argv_not_shell(ctx, tmp_path):
    """A crafted URL must be passed as data, never parsed by a shell."""
    from core.utils import write_file_lines
    from modules.vuln_scanning import VulnScanner

    marker = tmp_path / "pwned"
    params_file = ctx.path("content_discovery", "params", "all_params.txt")
    write_file_lines(params_file, [f"http://127.0.0.1/?a=$(touch {marker})"])
    write_file_lines(ctx.path("dns", "live_hosts.txt"), ["http://127.0.0.1"])
    ctx.set_file("live_hosts", ctx.path("dns", "live_hosts.txt"))
    ctx.set_file("params", params_file)
    ctx.config.set("vuln_scanning.sqlmap.enabled", True)

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["shell"] = kwargs.get("shell", False)
        return {"stdout": "", "stderr": "", "returncode": 1, "success": False,
                "skipped": False, "duration": 0, "result_count": 0, "tool": "sqlmap"}

    ctx.runner.run = fake_run  # type: ignore
    ctx.runner.is_available = lambda tool: True  # type: ignore

    VulnScanner(ctx).run_sqlmap()

    assert captured["shell"] is False
    assert isinstance(captured["command"], list)
    assert any(str(marker) in str(part) for part in captured["command"])
    assert not marker.exists()


# ----------------------------------------------------------------------
# JS analysis with the shared secret engine
# ----------------------------------------------------------------------
def test_js_analysis_detects_secrets_from_disk(ctx):
    from core.utils import write_file_lines
    from modules.js_analysis import JSAnalyzer

    js_dir = ctx.path("js_analysis", "files")
    os.makedirs(js_dir, exist_ok=True)
    with open(os.path.join(js_dir, "app.js"), "w", encoding="utf-8") as fh:
        fh.write(
            "const key='AKIAIOSFODNN7EXAMPLE';\n"
            "const token='TESTTOKEN_abcdefghijklmnop';\n"
            "fetch('/api/v1/users');\n"
        )
    js_list = ctx.path("content_discovery", "js_files.txt")
    write_file_lines(js_list, ["https://example.com/app.js"])
    ctx.set_file("js_files", js_list)

    JSAnalyzer(ctx).run_all()

    secrets = json.load(open(ctx.path("js_analysis", "secrets", "custom_regex.json"), encoding="utf-8"))
    types = {entry["type"] for entry in secrets}
    assert "AWS Access Key" in types
    assert "Test Token" in types, "custom config patterns must be honoured"
    # values are redacted on disk
    assert all("AKIAIOSFODNN7EXAMPLE" not in entry["value"] for entry in secrets)

    endpoints = open(ctx.path("js_analysis", "endpoints", "all_endpoints.txt"), encoding="utf-8").read()
    assert "/api/v1/users" in endpoints

    findings = ctx.database.findings(ctx.scan_id)
    assert any(f.category == "secrets" for f in findings)


def test_js_analysis_handles_empty_input(ctx):
    from modules.js_analysis import JSAnalyzer

    js_list = ctx.path("content_discovery", "js_files.txt")
    from core.utils import write_file_lines

    write_file_lines(js_list, [])
    ctx.set_file("js_files", js_list)
    assert JSAnalyzer(ctx).run_all().endswith("js_analysis")
