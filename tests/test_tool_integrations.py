"""
Coverage for the tool integrations added for the full bug-bounty stack.

External binaries are never executed: `ToolRunner.run` is monkeypatched and the
tests assert both the argument list (no shell, correct flags) and the parsing
of that tool's real output format.
"""

import json
import os

from core.utils import write_file_lines

TOOL_RESULT = {"stdout": "", "stderr": "", "returncode": 0, "success": True,
               "skipped": False, "duration": 0.0, "result_count": 0, "tool": "test"}


def _install_fake_runner(ctx, outputs=None):
    """Replace runner.run/require; return the list of captured commands."""
    commands = []
    outputs = outputs or {}

    def fake_run(command, **kwargs):
        commands.append(list(command))
        tool = kwargs.get("tool_name", "").split("-")[0] or "test"
        result = dict(TOOL_RESULT)
        result["tool"] = tool
        stdout = outputs.get(tool)
        if callable(stdout):
            stdout = stdout(command)
        if stdout:
            result["stdout"] = stdout
            result["success"] = True
        for path_key, contents in (kwargs.get("_writes") or {}).items():
            pass
        return result

    ctx.runner.run = fake_run  # type: ignore
    ctx.runner.require = lambda tool, *a, **k: False  # type: ignore
    ctx.runner.is_available = lambda tool: True  # type: ignore
    return commands


def _write_output(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# ----------------------------------------------------------------------
# Port scanning: rustscan
# ----------------------------------------------------------------------
def test_rustscan_parses_greppable_output(ctx, tmp_path):
    from modules.port_scanning import PortScanner

    live = ctx.path("dns", "live_hosts.txt")
    write_file_lines(live, ["example.com"])
    ctx.set_file("live_hosts", live)
    ctx.config.set("port_scanning.rustscan.enabled", True)

    scanner = PortScanner(ctx)
    target_file = ctx.path("ports", "scan_targets.txt")
    write_file_lines(target_file, ["example.com"])

    _write_output(ctx.path("ports", "rustscan.txt"),
                  ["example.com -> [22,80,443]"])

    commands = _install_fake_runner(ctx)
    ports = scanner.run_rustscan(target_file)

    assert commands, "rustscan must be invoked"
    assert commands[0][0] == "rustscan"
    assert "--greppable" in commands[0]
    assert set(ports) == {"example.com:22", "example.com:80", "example.com:443"}


# ----------------------------------------------------------------------
# Content discovery: gobuster / arjun
# ----------------------------------------------------------------------
def test_gobuster_output_is_ingested(ctx):
    from modules.content_discovery import ContentDiscovery

    live = ctx.path("dns", "live_hosts.txt")
    write_file_lines(live, ["https://example.com"])
    ctx.set_file("live_hosts", live)
    ctx.config.set("content_discovery.gobuster.enabled", True)
    ctx.config.set("content_discovery.gobuster.wordlist", "/dev/null")

    phase = ContentDiscovery(ctx)
    raw_dir = os.path.join(phase.dirs_dir, "gobuster")
    # gobuster prints absolute URLs in most builds, relative in others: both work
    _write_output(os.path.join(raw_dir, "example.com.txt"),
                  ["https://example.com/admin    (Status: 200) [Size: 512]",
                   "/robots.txt                   (Status: 200) [Size: 12]"])

    commands = _install_fake_runner(ctx)
    phase.run_gobuster()

    assert commands and commands[0][0] == "gobuster"
    assert "dir" in commands[0]
    assert "https://example.com/admin" in phase.all_urls
    assert "https://example.com/robots.txt" in phase.all_urls


def test_arjun_parameter_json_becomes_fuzz_urls(ctx):
    from modules.content_discovery import ContentDiscovery

    live = ctx.path("dns", "live_hosts.txt")
    write_file_lines(live, ["https://example.com"])
    ctx.set_file("live_hosts", live)
    ctx.config.set("content_discovery.arjun.enabled", True)

    phase = ContentDiscovery(ctx)
    raw_dir = os.path.join(phase.params_dir, "arjun")
    os.makedirs(raw_dir, exist_ok=True)
    with open(os.path.join(raw_dir, "example.com.json"), "w", encoding="utf-8") as fh:
        json.dump({"https://example.com/search": ["q", "page"]}, fh)

    commands = _install_fake_runner(ctx)
    phase.run_arjun()

    assert commands and commands[0][0] == "arjun"
    assert any("q=FUZZ" in url and "page=FUZZ" in url for url in phase.all_urls)


# ----------------------------------------------------------------------
# JS analysis: jsluice / trufflehog / gitleaks
# ----------------------------------------------------------------------
def test_jsluice_endpoints_are_collected(ctx):
    from modules.js_analysis import JSAnalyzer

    phase = JSAnalyzer(ctx)
    os.makedirs(phase.files_dir, exist_ok=True)
    with open(os.path.join(phase.files_dir, "app.js"), "w", encoding="utf-8") as fh:
        fh.write("fetch('/api/v1/users')")

    commands = _install_fake_runner(
        ctx, {"jsluice": '{"url": "/api/v1/users"}\n{"url": "/api/v1/orders"}\n'}
    )
    phase.run_jsluice()

    assert commands and commands[0][:2] == ["jsluice", "urls"]
    assert "/api/v1/users" in phase.endpoints
    assert "/api/v1/orders" in phase.endpoints


def test_trufflehog_secrets_are_recorded_and_redacted(ctx):
    from modules.js_analysis import JSAnalyzer

    phase = JSAnalyzer(ctx)
    os.makedirs(phase.files_dir, exist_ok=True)
    with open(os.path.join(phase.files_dir, "app.js"), "w", encoding="utf-8") as fh:
        fh.write("k='AKIAIOSFODNN7EXAMPLE'")

    record = {
        "DetectorName": "AWS",
        "Verified": True,
        "Raw": "AKIAIOSFODNN7EXAMPLE",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "app.js"}}},
    }
    _install_fake_runner(ctx, {"trufflehog": json.dumps(record) + "\n"})
    phase.run_trufflehog()

    assert phase.secrets, "trufflehog output should produce a secret entry"
    entry = phase.secrets[-1]
    assert entry["type"] == "AWS"
    assert entry["verified"] is True
    assert entry["severity"] == "high"
    assert "AKIAIOSFODNN7EXAMPLE" not in entry["value"]  # redacted
    finding = phase.findings[-1]
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.evidence


def test_gitleaks_report_is_parsed(ctx):
    from modules.js_analysis import JSAnalyzer

    phase = JSAnalyzer(ctx)
    os.makedirs(phase.files_dir, exist_ok=True)
    report = os.path.join(phase.output_dir, "secrets", "gitleaks.json")
    os.makedirs(os.path.dirname(report), exist_ok=True)
    with open(report, "w", encoding="utf-8") as fh:
        json.dump([{"RuleID": "generic-api-key", "Secret": "supersecretvalue123",
                    "File": "app.js"}], fh)

    _install_fake_runner(ctx)
    phase.run_gitleaks()

    assert phase.secrets and phase.secrets[-1]["type"] == "generic-api-key"
    assert "supersecretvalue123" not in phase.secrets[-1]["value"]


# ----------------------------------------------------------------------
# Vulnerability scanning: wapiti / ghauri / xsstrike / wpscan
# ----------------------------------------------------------------------
def test_wapiti_json_becomes_findings(ctx):
    from modules.vuln_scanning import VulnScanner

    live = ctx.path("dns", "live_hosts.txt")
    write_file_lines(live, ["https://example.com"])
    ctx.set_file("live_hosts", live)
    ctx.config.set("vuln_scanning.wapiti.enabled", True)
    ctx.config.set("vuln_scanning.wapiti.max_hosts", 1)

    scanner = VulnScanner(ctx)
    report = os.path.join(scanner.output_dir, "wapiti", "example.com.json")
    os.makedirs(os.path.dirname(report), exist_ok=True)
    with open(report, "w", encoding="utf-8") as fh:
        json.dump({
            "vulnerabilities": {
                "SQL Injection": [
                    {"level": 4, "path": "https://example.com/item?id=1",
                     "parameter": "id", "info": "boolean-based"}
                ],
                "Cross Site Scripting": [
                    {"level": 2, "path": "https://example.com/search",
                     "parameter": "q", "info": "reflected"}
                ],
            }
        }, fh)

    commands = _install_fake_runner(ctx)
    scanner.run_wapiti()

    assert commands and commands[0][0] == "wapiti"
    severities = {f.category: f.severity for f in scanner.findings}
    assert severities["sql-injection"] == "critical"
    assert severities["cross-site-scripting"] == "medium"


def test_ghauri_detects_injectable_url(ctx):
    from modules.vuln_scanning import VulnScanner

    live = ctx.path("dns", "live_hosts.txt")
    write_file_lines(live, ["https://example.com"])
    ctx.set_file("live_hosts", live)
    params = ctx.path("content_discovery", "params", "all_params.txt")
    write_file_lines(params, ["https://example.com/item?id=1"])
    ctx.set_file("params", params)
    ctx.config.set("vuln_scanning.ghauri.enabled", True)
    ctx.config.set("vuln_scanning.ghauri.max_urls", 1)

    scanner = VulnScanner(ctx)
    commands = _install_fake_runner(
        ctx, {"ghauri": "Parameter id is injectable (boolean-based blind)"}
    )
    scanner.run_ghauri()

    assert commands and commands[0][0] == "ghauri"
    assert commands[0][1:3] == ["-u", "https://example.com/item?id=1"]
    assert len(scanner.findings) == 1
    assert scanner.findings[0].category == "sqli"
    assert scanner.findings[0].severity == "critical"


def test_wpscan_reports_plugins_and_core_cves(ctx):
    from modules.vuln_scanning import VulnScanner

    live = ctx.path("dns", "live_hosts.txt")
    write_file_lines(live, ["https://blog.example.com"])
    ctx.set_file("live_hosts", live)
    ctx.config.set("vuln_scanning.wpscan.enabled", True)

    scanner = VulnScanner(ctx)
    report = os.path.join(scanner.output_dir, "wpscan", "blog.example.com.json")
    os.makedirs(os.path.dirname(report), exist_ok=True)
    with open(report, "w", encoding="utf-8") as fh:
        json.dump({
            "target_url": "https://blog.example.com/",
            "version": {"number": "6.4.1"},
            "vulnerabilities": [{"title": "WP < 6.4.2 XSS", "cvss": {"score": 6.1}}],
            "plugins": {
                "contact-form-7": {
                    "vulnerabilities": [{"title": "CF7 < 5.8 RCE", "cvss": 9.8}]
                }
            },
        }, fh)

    commands = _install_fake_runner(ctx)
    scanner.run_wpscan()

    assert commands and commands[0][0] == "wpscan"
    titles = {f.title: f.severity for f in scanner.findings}
    assert any("WordPress 6.4.1" in title for title in titles)
    assert any("contact-form-7" in title and severity == "critical"
               for title, severity in titles.items())
    assert any("core vulnerability" in title and severity == "medium"
               for title, severity in titles.items())


def test_no_integration_uses_a_shell(ctx):
    """Guard: every new tool invocation must be an argv list."""
    import subprocess

    source = ""
    for name in ("subdomain_enum", "port_scanning", "content_discovery",
                 "js_analysis", "vuln_scanning", "subdomain_takeover"):
        with open(os.path.join(os.path.dirname(__file__), "..", "modules",
                               f"{name}.py"), encoding="utf-8") as fh:
            source += fh.read()
    assert "shell=True" not in source
    assert subprocess is not None
