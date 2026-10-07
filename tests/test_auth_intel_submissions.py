"""
Coverage for the authenticated-scanning, threat-intelligence and submission
export gaps: headers/cookies reach the session and the tools, CISA KEV + EPSS
enrichment re-ranks CVE findings, and the platform drafts are well formed.
"""

import json
import os

import pytest

from core.utils import write_file_lines

TOOL_RESULT = {"stdout": "", "stderr": "", "returncode": 0, "success": True,
               "skipped": False, "duration": 0.0, "result_count": 0, "tool": "test"}


def _install_fake_runner(ctx, outputs=None):
    commands = []
    outputs = outputs or {}

    def fake_run(command, **kwargs):
        commands.append(list(command))
        tool = kwargs.get("tool_name", "").split("-")[0] or "test"
        result = dict(TOOL_RESULT)
        result["tool"] = tool
        stdout = outputs.get(tool)
        if stdout:
            result["stdout"] = stdout
        return result

    ctx.runner.run = fake_run  # type: ignore
    ctx.runner.require = lambda tool, *a, **k: False  # type: ignore
    ctx.runner.is_available = lambda tool: True  # type: ignore
    return commands


# ----------------------------------------------------------------------
# Header / cookie plumbing
# ----------------------------------------------------------------------
def test_parse_header_accepts_colon_and_equals():
    from core.auth import parse_header

    assert parse_header("Authorization: Bearer abc") == ("Authorization", "Bearer abc")
    assert parse_header("X-Api-Key=secret") == ("X-Api-Key", "secret")
    for bad in ("", "no-separator", "Host: evil.test", "Content-Length: 5"):
        with pytest.raises(ValueError):
            parse_header(bad)


def test_auth_headers_from_config(config):
    from core.auth import auth_headers, summary

    config.set("general.headers", ["X-Bug-Bounty: handle", "Authorization: Bearer eyJ0"])
    config.set("general.cookie", "session=abc123")
    headers = auth_headers(config)

    assert headers["Authorization"] == "Bearer eyJ0"
    assert headers["Cookie"] == "session=abc123"
    # the summary never leaks values
    assert "abc123" not in summary(config) and "eyJ0" not in summary(config)
    assert "Cookie" in summary(config)


def test_session_carries_auth_headers():
    from core.net import build_session

    session = build_session(retries=0, extra_headers={"Cookie": "session=x", "X-Test": "1"})
    assert session.headers["Cookie"] == "session=x"
    assert session.headers["X-Test"] == "1"


def test_auth_headers_reach_the_target(ctx, local_server):
    """End-to-end: config -> ScanContext session -> the actual HTTP request."""
    from core.net import http_request

    ctx.config.set("general.headers", ["Authorization: Bearer tok"])
    ctx.config.set("general.cookie", "session=abc")
    ctx.session = None
    ctx.__post_init__()  # rebuild the session the way a real run does

    result = http_request(ctx.session, "GET", f"{local_server}/echo")
    echoed = json.loads(result.text)

    assert echoed["Authorization"] == "Bearer tok"
    assert echoed["Cookie"] == "session=abc"


def test_tool_argv_receives_headers(ctx):
    from modules.vuln_scanning import VulnScanner

    ctx.config.set("general.headers", ["Authorization: Bearer tok", "X-Bug-Bounty: handle"])
    ctx.config.set("general.cookie", "session=abc")
    live = ctx.path("dns", "live_hosts.txt")
    write_file_lines(live, ["https://example.com"])
    ctx.set_file("live_hosts", live)

    scanner = VulnScanner(ctx)
    commands = _install_fake_runner(ctx)
    scanner.run_nuclei()

    cmd = commands[0]
    assert "-H" in cmd
    assert "Authorization: Bearer tok" in cmd
    assert "Cookie: session=abc" in cmd


def test_sqlmap_args_split_cookie(config):
    from core.auth import sqlmap_args

    config.set("general.headers", ["Authorization: Bearer tok"])
    config.set("general.cookie", "session=abc")
    args = sqlmap_args(config)

    assert "--headers" in args
    assert args[args.index("--cookie") + 1] == "session=abc"


def test_sqlmap_and_wpscan_receive_the_proxy(ctx):
    from modules.vuln_scanning import VulnScanner

    ctx.config.set("general.proxy", "http://127.0.0.1:8080")
    live = ctx.path("dns", "live_hosts.txt")
    write_file_lines(live, ["https://example.com"])
    ctx.set_file("live_hosts", live)
    params = ctx.path("content_discovery", "params", "all_params.txt")
    os.makedirs(os.path.dirname(params), exist_ok=True)
    write_file_lines(params, ["https://example.com/item?id=1"])
    ctx.set_file("params", params)

    scanner = VulnScanner(ctx)
    commands = _install_fake_runner(ctx)
    scanner.run_sqlmap()
    scanner.run_wpscan()

    sqlmap_cmd = next(cmd for cmd in commands if cmd[0] == "sqlmap")
    wpscan_cmd = next(cmd for cmd in commands if cmd[0] == "wpscan")
    assert sqlmap_cmd[sqlmap_cmd.index("--proxy") + 1] == "http://127.0.0.1:8080"
    assert wpscan_cmd[wpscan_cmd.index("--proxy") + 1] == "http://127.0.0.1:8080"


# ----------------------------------------------------------------------
# Threat intelligence: CISA KEV + FIRST EPSS
# ----------------------------------------------------------------------
class _FakeResponse:
    def __init__(self, payload):
        self.payload = payload
        self.status = 200
        self.ok = True
        self.error = ""

    def json(self, default=None):
        return self.payload


def _patch_feeds(monkeypatch, kev=(), epss=()):
    from core import net as net_module

    def fake_request(session, method, url, **kwargs):
        if "known_exploited" in url:
            return _FakeResponse({"vulnerabilities": list(kev)})
        return _FakeResponse({"data": list(epss)})

    monkeypatch.setattr(net_module, "http_request", fake_request)


def test_threat_intel_lookup_merges_kev_and_epss(monkeypatch):
    from core.threatintel import ThreatIntel

    _patch_feeds(
        monkeypatch,
        kev=[{"cveID": "CVE-2021-44228", "vulnerabilityName": "Log4Shell",
              "knownRansomwareCampaignUse": "Known"}],
        epss=[{"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.99"}],
    )
    client = ThreatIntel(session=object(), cache_path="")
    entries = client.lookup(["CVE-2021-44228"])

    entry = entries["CVE-2021-44228"]
    assert entry["kev"] is True and entry["epss"] == 0.97
    assert "name" in entry


def test_threat_intel_bonus_prefers_kev():
    from core.threatintel import bonus_for

    kev_bonus, kev_reasons = bonus_for({"kev": True, "epss": 0.97, "percentile": 0.99})
    epss_bonus, epss_reasons = bonus_for({"epss": 0.6, "percentile": 0.95})
    assert kev_bonus > epss_bonus > 0
    assert "KEV" in kev_reasons[0]
    assert "EPSS" in epss_reasons[0]


def test_prioritiser_enriches_cve_findings(ctx, monkeypatch):
    from core.models import Finding
    from modules.finding_prioritizer import FindingPrioritizer

    _patch_feeds(
        monkeypatch,
        kev=[{"cveID": "CVE-2021-44228", "vulnerabilityName": "Log4Shell"}],
        epss=[{"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.99"}],
    )
    ctx.config.set("finding_prioritizer.threat_intel.enabled", True)
    prioritizer = FindingPrioritizer(ctx)
    finding = Finding(
        category="vulnerability",
        title="Apache Log4j RCE (CVE-2021-44228)",
        severity="critical",
        target="example.com",
        score=9.0,
    )
    prioritizer.findings = [finding]

    prioritizer.enrich_with_threat_intel()

    assert "kev" in finding.tags
    assert finding.score > 9.0
    assert finding.extra["threat_intel"]["CVE-2021-44228"]["kev"] is True
    artifact = os.path.join(prioritizer.output_dir, "threat_intel.json")
    assert os.path.exists(artifact)


def test_prioritiser_threat_intel_is_optional(ctx):
    from core.models import Finding
    from modules.finding_prioritizer import FindingPrioritizer

    ctx.config.set("finding_prioritizer.threat_intel.enabled", False)
    prioritizer = FindingPrioritizer(ctx)
    finding = Finding(category="cms", title="CVE-2020-1234 thing", severity="high")
    prioritizer.findings = [finding]

    prioritizer.enrich_with_threat_intel()  # disabled -> no network, no change

    assert finding.score == 0.0
    assert "kev" not in finding.tags


# ----------------------------------------------------------------------
# Submission exports (HackerOne / Intigriti / Bugcrowd)
# ----------------------------------------------------------------------
def _sample_findings():
    from core.models import Finding

    return [
        Finding(category="sqli", title="SQL injection in /item", severity="critical",
                target="example.com", url="https://example.com/item?id=1",
                evidence="boolean-based blind", source="sqlmap", confidence="high",
                score=12.0, extra={"priority": "P1"}),
        Finding(category="headers", title="Missing HSTS", severity="low",
                target="example.com", url="https://example.com/",
                source="asset_enrichment", confidence="high"),
    ]


def test_submission_exports_are_written(ctx):
    from reports.submission_export import SubmissionExporter

    exporter = SubmissionExporter(ctx.output_dir, ctx.target)
    generated = exporter.export(_sample_findings())

    assert set(generated) == {"hackerone", "intigriti", "bugcrowd"}

    hackerone = json.load(open(generated["hackerone"], encoding="utf-8"))
    report = hackerone["reports"][0]
    assert report["severity"] == "critical"
    assert "SQL injection" in report["title"]
    assert "### Reproduction" in report["vulnerability_information"]

    bugcrowd = open(generated["bugcrowd"], encoding="utf-8").read()
    assert "P1" in bugcrowd and "P4" in bugcrowd
    assert "SQL injection in /item" in bugcrowd


def test_submission_severity_mapping_covers_info():
    from core.models import Finding
    from reports.submission_export import BUGCROWD_PRIORITY, SubmissionExporter

    finding = Finding(category="info", title="Note", severity="info")
    rows = SubmissionExporter("/tmp", "example.com")._rows([finding])
    assert rows[0]["priority"] == BUGCROWD_PRIORITY["info"]
    assert rows[0]["severity"] == "medium" or rows[0]["severity"] in (
        "none", "low", "medium", "high", "critical"
    )
