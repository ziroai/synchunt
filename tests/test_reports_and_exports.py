import json
import os
from datetime import datetime

from core.models import Finding
from reports.data_export import DataExporter
from reports.html_report import HTMLReportGenerator
from reports.markdown_report import MarkdownReportGenerator
from reports.notifier import Notifier

XSS_PAYLOAD = '"><script>alert(document.domain)</script>'


def _seed(ctx, findings):
    ctx.record_findings(findings)
    from core.utils import write_file_lines

    write_file_lines(ctx.path("subdomains", "all_subdomains.txt"),
                     ["www.example.com", f"{XSS_PAYLOAD}.example.com"])
    write_file_lines(ctx.path("dns", "live_hosts.txt"),
                     [f"https://example.com/{XSS_PAYLOAD}"])
    write_file_lines(ctx.path("ports", "all_ports.txt"), ["example.com:443"])
    write_file_lines(ctx.path("content_discovery", "all_urls.txt"),
                     ["https://example.com/?q=1"])
    write_file_lines(ctx.path("cloud_enum", "public_buckets.txt"),
                     ["https://example-assets.s3.amazonaws.com/"])


def test_html_report_escapes_attacker_controlled_content(ctx):
    _seed(ctx, [
        Finding(category="xss", title=f"Reflected XSS {XSS_PAYLOAD}", severity="high",
                url=f"https://example.com/{XSS_PAYLOAD}", evidence=f"payload: {XSS_PAYLOAD}"),
    ])
    path = HTMLReportGenerator(
        ctx.output_dir, ctx.target, datetime.now(), datetime.now(),
        database=ctx.database, scan_id=ctx.scan_id,
    ).generate()

    html = open(path).read()
    assert "<script>alert(document.domain)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "onerror" not in html.replace("&lt;", "")
    # still renders the finding text (escaped)
    assert "Reflected XSS" in html
    assert "example-assets.s3.amazonaws.com" in html


def test_html_report_renders_severity_and_priority_summary(ctx):
    _seed(ctx, [
        Finding(category="secrets", title="AWS key", severity="critical",
                url="https://example.com/app.js", evidence="AKIA***"),
    ])
    from modules.finding_prioritizer import FindingPrioritizer

    FindingPrioritizer(ctx).run_all()
    path = HTMLReportGenerator(
        ctx.output_dir, ctx.target, datetime.now(), datetime.now(),
        database=ctx.database, scan_id=ctx.scan_id,
        findings=ctx.database.findings(ctx.scan_id),
    ).generate()
    html = open(path).read()
    assert "Critical" in html
    assert "AWS key" in html
    assert "P1" in html or "P2" in html


def test_markdown_report_contains_tables_and_details(ctx):
    _seed(ctx, [
        Finding(category="sqli", title="SQL injection", severity="critical",
                url="https://example.com/api?id=1", evidence="injectable"),
    ])
    path = MarkdownReportGenerator(
        ctx.output_dir, ctx.target, datetime.now(), datetime.now(),
        database=ctx.database, scan_id=ctx.scan_id,
    ).generate()
    text = open(path).read()
    assert "SQL injection" in text
    assert "Subdomains" in text
    assert text.count("```") % 2 == 0  # balanced code fences


def test_data_exporter_writes_json_and_csv(ctx):
    findings = [
        Finding(category="xss", title="XSS", severity="high", url="https://example.com/?q=1"),
        Finding(category="cloud", title="Public bucket", severity="critical",
                url="https://b.s3.amazonaws.com/"),
    ]
    exporter = DataExporter(ctx.output_dir, ctx.target)
    paths = exporter.export_findings(findings)
    scan_path = exporter.export_scan_data({"findings": 2})

    assert os.path.exists(paths["findings_json"])
    assert os.path.exists(paths["findings_csv"])
    assert os.path.exists(scan_path)

    with open(paths["findings_json"]) as fh:
        rows = json.load(fh)
    assert len(rows) == 2
    assert {"fingerprint", "severity", "title"} <= set(rows[0])

    header = open(paths["findings_csv"]).readline()
    assert "fingerprint" in header and "severity" in header


def test_notifier_is_silent_when_disabled(ctx):
    notifier = Notifier(ctx.config)
    assert notifier.enabled is False
    assert notifier.notify_all("hello") == {}
    assert notifier.send_critical_finding("boom") is None


def test_notifier_builds_messages_when_enabled(ctx):
    ctx.config.set("notifications.enabled", True)
    sent = []
    notifier = Notifier(ctx.config)
    notifier.send_slack = lambda message: sent.append(message) or True  # type: ignore
    ctx.config.set("notifications.slack.enabled", True)

    notifier.send_scan_summary("example.com", {"subdomains": 5, "vulns": 2},
                              extra={"severity": {"critical": 1}})
    assert sent and "example.com" in sent[0]

    notifier.send_critical_findings([
        Finding(category="rce", title="RCE", severity="critical",
                url="https://example.com", evidence="proof"),
        Finding(category="info", title="noise", severity="info"),
    ])
    assert any("CRITICAL FINDING" in message for message in sent)
    assert len(sent) == 2
