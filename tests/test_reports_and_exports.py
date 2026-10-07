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


def test_data_exporter_respects_format_toggles(tmp_path):
    from core.models import Finding
    from reports.data_export import DataExporter

    exporter = DataExporter(str(tmp_path), "example.com")
    generated = exporter.export_findings(
        [Finding(category="test", title="t", severity="low")],
        json_enabled=False,
        csv_enabled=True,
    )
    assert "findings_json" not in generated
    assert "findings_csv" in generated
    assert os.path.exists(generated["findings_csv"])


# ----------------------------------------------------------------------
# SARIF export
# ----------------------------------------------------------------------
def test_sarif_export_is_valid_and_maps_severities(tmp_path):
    import json as jsonlib

    from core.models import Finding
    from reports.sarif_export import SarifExporter

    findings = [
        Finding(category="api", title="Exposed spec", severity="medium",
                url="https://example.com/openapi.json", evidence="Test API"),
        Finding(category="exposure", title=".env exposed", severity="high",
                url="https://example.com/.env"),
        Finding(category="api", title="GraphQL introspection", severity="high",
                url="https://example.com/graphql", extra={"priority": "P1"}),
    ]
    path = SarifExporter(str(tmp_path), "example.com", findings,
                         tool_version="9.9.9").generate()
    assert os.path.exists(path)
    doc = jsonlib.load(open(path))
    run = doc["runs"][0]

    assert doc["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "SyncHunt"
    assert run["tool"]["driver"]["version"] == "9.9.9"
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "synchunt/api", "synchunt/exposure",
    ]
    assert len(run["results"]) == 3
    levels = {result["properties"]["severity"]: result["level"] for result in run["results"]}
    assert levels["high"] == "error"
    assert levels["medium"] == "warning"
    for result in run["results"]:
        assert result["partialFingerprints"]["synchuntFinding/v1"]
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert any(result["properties"].get("priority") == "P1" for result in run["results"])


# ----------------------------------------------------------------------
# Scan history diff
# ----------------------------------------------------------------------
def test_history_compare_classifies_new_fixed_and_persisting():
    from core.history import compare
    from core.models import Finding

    persisting = Finding(category="api", title="Exposed spec", severity="medium",
                         url="https://x/openapi.json")
    fresh = Finding(category="exposure", title=".env exposed", severity="high",
                    url="https://x/.env")
    previous = [
        {"fingerprint": persisting.fingerprint(), "title": persisting.title,
         "severity": "medium", "score": 3.0},
        {"fingerprint": "gone", "title": "Fixed issue", "severity": "low", "score": 1.0},
    ]
    report = compare([persisting, fresh], previous, previous_run="/tmp/old-run")

    counts = report.counts()
    assert counts["new"] == 1
    assert counts["fixed"] == 1
    assert counts["persisting"] == 1
    assert counts["new_critical_high"] == 1
    assert persisting.extra["history"] == "persisting"
    assert fresh.extra["history"] == "new"
    assert [row["title"] for row in report.fixed] == ["Fixed issue"]
    assert report.to_dict()["counts"]["new"] == 1


def test_history_identity_survives_evidence_changes():
    """A finding whose evidence changed is still the same issue, not new+fixed."""
    from core.history import compare
    from core.models import Finding

    before = Finding(category="exposure", title="Exposed management endpoint: /env",
                     severity="high", url="http://x/env", evidence="HTML body")
    after = Finding(category="exposure", title="Exposed management endpoint: /env",
                    severity="high", url="http://x/env", evidence="{json: true}")
    assert before.fingerprint() != after.fingerprint()

    report = compare([after], [before.to_dict()], previous_run="/tmp/old")
    assert report.counts()["new"] == 0
    assert report.counts()["fixed"] == 0
    assert report.counts()["persisting"] == 1


def test_history_finds_previous_run_and_skips_current(tmp_path):
    import json as jsonlib

    from core.history import find_previous_run, load_findings, target_slug

    base = tmp_path / "out"
    slug_dir = base / target_slug("https://example.com:8443")
    old_run = slug_dir / "20260101_000000"
    (old_run / "findings_prioritized").mkdir(parents=True)
    (old_run / "findings_prioritized" / "findings.json").write_text(
        jsonlib.dumps([{"fingerprint": "abc", "title": "old"}])
    )
    # a dry-run directory without findings must be ignored
    (slug_dir / "20260102_000000").mkdir()
    current = slug_dir / "20260103_000000"
    current.mkdir()

    assert find_previous_run(str(base), "https://example.com:8443", str(current)) == str(old_run)
    assert find_previous_run(str(base), "https://example.com:8443", str(old_run)) is None
    assert load_findings(str(old_run))[0]["title"] == "old"
    assert load_findings(str(current)) == []


def test_reports_render_history_section(tmp_path):
    from core.models import Finding
    from reports.html_report import HTMLReportGenerator
    from reports.markdown_report import MarkdownReportGenerator

    history = {
        "previous_run": "/tmp/out/example.com/20260101_000000",
        "counts": {"new": 1, "fixed": 2, "persisting": 3, "previous_total": 5,
                   "new_critical_high": 1},
        "new": [{"fingerprint": "fp", "title": "Regressed <b>issue</b>",
                 "severity": "high", "url": "https://x/new"}],
        "fixed": [{"fingerprint": "old", "title": "Gone", "severity": "low",
                   "url": "https://x/old"}],
    }
    findings = [Finding(category="api", title="Current", severity="low",
                        url="https://x/current")]

    html_path = HTMLReportGenerator(
        str(tmp_path), "example.com", None, None, findings=findings,
        history=history,
    ).generate()
    html_text = open(html_path).read()
    assert "Since last scan" in html_text
    assert "&lt;b&gt;issue&lt;/b&gt;" in html_text  # history entries are escaped too

    md_path = MarkdownReportGenerator(
        str(tmp_path), "example.com", None, None, findings=findings,
        history=history,
    ).generate()
    markdown = open(md_path).read()
    assert "Since last scan" in markdown
    assert "1 new" in markdown and "2 fixed" in markdown
    assert markdown.count("```") % 2 == 0
