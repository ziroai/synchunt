from core.models import Asset, Finding, PhaseResult


def test_scan_lifecycle_and_summary(tmp_path):
    from core.database_manager import DatabaseManager

    db = DatabaseManager(str(tmp_path / "results.db"))
    scan_id = db.start_scan("example.com", "quick", str(tmp_path))
    db.record_phase(scan_id, PhaseResult("subdomain", "done", 1.5, 12, ""))
    db.finish_scan(scan_id, "finished", {"findings": 0})

    summary = db.scan_summary(scan_id)
    assert summary["target"] == "example.com"
    assert summary["profile"] == "quick"
    assert summary["phases"][0]["phase"] == "subdomain"
    assert db.completed_phases(scan_id) == ["subdomain"]
    db.close()


def test_findings_are_deduplicated_by_fingerprint(tmp_path):
    from core.database_manager import DatabaseManager

    db = DatabaseManager(str(tmp_path / "results.db"))
    scan_id = db.start_scan("example.com")

    finding = Finding(category="xss", title="Reflected XSS", severity="high",
                      url="https://example.com/?q=1", evidence="payload reflected")
    assert db.add_finding(scan_id, finding) is True
    assert db.add_finding(scan_id, finding) is False  # duplicate
    assert db.finding_count(scan_id) == 1

    slightly_different = Finding(category="xss", title="Reflected XSS", severity="high",
                                 url="https://example.com/?q=2", evidence="payload reflected")
    assert db.add_finding(scan_id, slightly_different) is True
    assert db.finding_count(scan_id) == 2
    db.close()


def test_assets_are_deduplicated(tmp_path):
    from core.database_manager import DatabaseManager

    db = DatabaseManager(str(tmp_path / "results.db"))
    scan_id = db.start_scan("example.com")
    asset = Asset(kind="host", value="api.example.com", host="api.example.com")
    assert db.add_asset(scan_id, asset.kind, asset.value, host=asset.host) is True
    assert db.add_asset(scan_id, asset.kind, asset.value, host=asset.host) is False
    assert db.count_assets(scan_id) == 1
    assert db.count_assets(scan_id, "host") == 1
    db.close()


def test_severity_counts_and_filters(tmp_path):
    from core.database_manager import DatabaseManager

    db = DatabaseManager(str(tmp_path / "results.db"))
    scan_id = db.start_scan("example.com")
    findings = [
        ("critical", "https://x/a"),
        ("critical", "https://x/b"),
        ("high", "https://x/c"),
        ("low", "https://x/d"),
        ("info", "https://x/e"),
    ]
    for severity, url in findings:
        db.add_finding(scan_id, Finding(category="test", title=f"finding {url}",
                                        severity=severity, url=url))
    counts = db.severity_counts(scan_id)
    assert counts["critical"] == 2
    assert counts["high"] == 1
    assert len(db.findings(scan_id, min_severity="high")) == 3
    db.close()


def test_scores_are_persisted(tmp_path):
    from core.database_manager import DatabaseManager

    db = DatabaseManager(str(tmp_path / "results.db"))
    scan_id = db.start_scan("example.com")
    finding = Finding(category="secrets", title="AWS key", severity="high")
    db.add_finding(scan_id, finding)
    db.update_score(scan_id, finding.fingerprint(), 9.5)
    stored = db.findings(scan_id)[0]
    assert stored.score == 9.5
    db.close()


# ----------------------------------------------------------------------
# Prioritizer
# ----------------------------------------------------------------------
def test_priority_buckets():
    from modules.finding_prioritizer import FindingPrioritizer

    assert FindingPrioritizer.priority_for(12) == "P1"
    assert FindingPrioritizer.priority_for(7) == "P2"
    assert FindingPrioritizer.priority_for(4) == "P3"
    assert FindingPrioritizer.priority_for(0.5) == "P4"


def test_scoring_prefers_severe_high_confidence_findings(ctx):
    from modules.finding_prioritizer import FindingPrioritizer

    prioritizer = FindingPrioritizer(ctx)
    critical = Finding(category="rce", title="Remote Code Execution in upload",
                       severity="critical", confidence="high", evidence="rce")
    high_conf_medium = Finding(category="misconfiguration", title="Missing CSP",
                               severity="low", confidence="medium")
    low_conf = Finding(category="misconfiguration", title="Missing CSP",
                       severity="low", confidence="low")

    critical_score, reasons = prioritizer.score(critical)
    medium_score, _ = prioritizer.score(high_conf_medium)
    low_score, _ = prioritizer.score(low_conf)

    assert critical_score > medium_score > low_score
    assert any("RCE" in reason for reason in reasons)


def test_production_hosts_score_higher_than_dev(ctx):
    from modules.finding_prioritizer import FindingPrioritizer

    prioritizer = FindingPrioritizer(ctx)
    prod = Finding(category="exposure", title="Debug endpoint exposed", severity="medium",
                   url="https://prod.example.com/debug")
    dev = Finding(category="exposure", title="Debug endpoint exposed", severity="medium",
                  url="https://dev.example.com/debug")
    assert prioritizer.score(prod)[0] > prioritizer.score(dev)[0]


def test_run_all_deduplicates_and_scores(ctx, tmp_path):
    from modules.finding_prioritizer import FindingPrioritizer

    duplicate_a = Finding(category="xss", title="Reflected XSS", severity="high",
                          url="https://example.com/?q=1", evidence="reflected")
    duplicate_b = Finding(category="xss", title="Reflected XSS", severity="high",
                          url="https://example.com/?q=1", evidence="reflected")
    secret = Finding(category="secrets", title="AWS Access Key in JS", severity="critical",
                     url="https://example.com/app.js", evidence="AKIA***MNOP")
    ctx.record_findings([duplicate_a, duplicate_b, secret])

    prioritizer = FindingPrioritizer(ctx)
    prioritizer.run_all()

    titles = [finding.title for finding in prioritizer.findings]
    assert titles.count("Reflected XSS") == 1
    assert prioritizer.findings[0].score >= prioritizer.findings[-1].score
    assert prioritizer.findings[0].extra.get("priority") in {"P1", "P2"}

    import json
    import os

    json_path = os.path.join(ctx.path("findings_prioritized"), "findings.json")
    csv_path = os.path.join(ctx.path("findings_prioritized"), "findings.csv")
    assert os.path.exists(json_path) and os.path.exists(csv_path)
    with open(json_path) as fh:
        rows = json.load(fh)
    assert any(row["priority"] == "P1" for row in rows)
    assert all("score_reasons" in row for row in rows)


def test_files_fallback_collects_from_disk(ctx):
    from core.utils import write_file_lines

    write_file_lines(ctx.path("vulnerabilities", "nuclei", "nuclei.txt"),
                     ["[high] CVE-2024-0001 https://example.com/x"])
    write_file_lines(ctx.path("js_analysis", "secrets", "custom_regex.txt"),
                     ["[AWS Access Key|high] app.js: AKIA***MPLE"])

    from modules.finding_prioritizer import FindingPrioritizer

    # Fresh context without DB findings to force the file fallback
    ctx.database._conn.execute("DELETE FROM findings")
    ctx.database._conn.commit()

    prioritizer = FindingPrioritizer(ctx)
    findings = prioritizer._collect()
    assert findings, "expected findings parsed from files"
    categories = {finding.category for finding in findings}
    assert "secrets" in categories
