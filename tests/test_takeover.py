"""
Subdomain-takeover detection tests.

The DNS layer is monkeypatched: these tests must pass with no network access.
"""

import json

from core.utils import write_file_lines
from modules.subdomain_takeover import FINGERPRINTS, SubdomainTakeover


# ----------------------------------------------------------------------
# Fingerprint matching
# ----------------------------------------------------------------------
def test_match_service_recognises_known_cnames(ctx):
    phase = SubdomainTakeover(ctx)
    assert phase.match_service("mybucket.s3.amazonaws.com")["service"] == "Amazon S3"
    assert phase.match_service("org.github.io")["service"] == "GitHub Pages"
    assert phase.match_service("app.herokudns.com")["service"] == "Heroku"
    assert phase.match_service("something.azurewebsites.net")["service"] == "Azure"
    assert phase.match_service("example.com") is None


def test_every_fingerprint_entry_is_well_formed():
    for entry in FINGERPRINTS:
        assert entry["service"]
        assert entry["cnames"] and all(pattern.startswith(".") for pattern in entry["cnames"])
        assert entry["bodies"]
        assert isinstance(entry["claimable"], bool)
        assert entry["reference"].startswith("http")


def test_match_body_detects_unclaimed_resource(ctx):
    phase = SubdomainTakeover(ctx)
    s3 = phase.match_service("x.s3.amazonaws.com")
    assert phase.match_body("<Error><Code>NoSuchBucket</Code></Error>", s3) == "NoSuchBucket"
    assert phase.match_body("<html>hi</html>", s3) == ""


# ----------------------------------------------------------------------
# check_host
# ----------------------------------------------------------------------
def _serve_body(ctx, local_server, body):
    """Register a live host pointing at the test server."""
    write_file_lines(ctx.path("dns", "live_hosts.txt"), [local_server])
    ctx.set_file("live_hosts", ctx.path("dns", "live_hosts.txt"))


def test_confirmed_takeover_is_critical(ctx, local_server, monkeypatch):
    from modules import subdomain_takeover as module

    phase = SubdomainTakeover(ctx)
    monkeypatch.setattr(
        module, "resolve_cname_chain",
        lambda host, **kwargs: ["abandoned-bucket.s3.amazonaws.com"],
    )
    monkeypatch.setattr(
        module, "http_request",
        lambda *a, **k: type("R", (), {
            "reachable": True, "status": 404,
            "text": "<Error><Code>NoSuchBucket</Code></Error>",
        })(),
    )

    record = phase.check_host("shop.example.com")

    assert record is not None
    assert record["service"] == "Amazon S3"
    assert record["confidence"] == "high"
    assert record["severity"] == "critical"
    finding = phase.findings[-1]
    assert finding.category == "takeover"
    assert finding.severity == "critical"
    assert "NoSuchBucket" in finding.evidence
    assert finding.references


def test_claimable_false_service_is_informational(ctx, monkeypatch):
    from modules import subdomain_takeover as module

    phase = SubdomainTakeover(ctx)
    monkeypatch.setattr(module, "resolve_cname_chain",
                        lambda host, **kwargs: ["old.fastly.net"])
    monkeypatch.setattr(
        module, "http_request",
        lambda *a, **k: type("R", (), {
            "reachable": True, "status": 503,
            "text": "Fastly error: unknown domain: old.fastly.net",
        })(),
    )

    record = phase.check_host("www.example.com")

    assert record["confidence"] == "low"
    assert record["severity"] == "info"
    assert "cannot be claimed" in record["reason"]


def test_cname_without_fingerprint_is_a_medium_lead(ctx, monkeypatch):
    from modules import subdomain_takeover as module

    phase = SubdomainTakeover(ctx)
    monkeypatch.setattr(module, "resolve_cname_chain",
                        lambda host, **kwargs: ["alive.zendesk.com"])
    monkeypatch.setattr(
        module, "http_request",
        lambda *a, **k: type("R", (), {
            "reachable": True, "status": 200, "text": "<html>real support page</html>",
        })(),
    )

    record = phase.check_host("help.example.com")

    assert record["confidence"] == "medium"
    assert record["severity"] == "high"


def test_host_without_cname_is_ignored(ctx, monkeypatch):
    from modules import subdomain_takeover as module

    phase = SubdomainTakeover(ctx)
    monkeypatch.setattr(module, "resolve_cname_chain", lambda host, **kwargs: [])
    assert phase.check_host("plain.example.com") is None
    assert phase.findings == []


# ----------------------------------------------------------------------
# Phase plumbing
# ----------------------------------------------------------------------
def test_run_all_writes_artifacts_and_findings(ctx, monkeypatch):
    from modules import subdomain_takeover as module

    write_file_lines(ctx.path("subdomains", "all_subdomains.txt"),
                     ["shop.example.com", "plain.example.com"])
    monkeypatch.setattr(
        module, "resolve_cname_chain",
        lambda host, **kwargs: (
            ["bucket.s3.amazonaws.com"] if host == "shop.example.com" else []
        ),
    )
    monkeypatch.setattr(
        module, "http_request",
        lambda *a, **k: type("R", (), {
            "reachable": True, "status": 404, "text": "NoSuchBucket",
        })(),
    )
    # no external tools in tests
    ctx.config.set("subdomain_takeover.subjack.enabled", False)

    phase = SubdomainTakeover(ctx)
    phase.run_all()

    candidates = json.load(open(ctx.path("takeover", "candidates.json")))
    summary = json.load(open(ctx.path("takeover", "summary.json")))
    assert len(candidates) == 1
    assert candidates[0]["host"] == "shop.example.com"
    assert summary["confirmed"] == 1
    assert summary["services"] == ["Amazon S3"]
    assert ctx.get_file("takeover_candidates", "").endswith("candidates.json")
    # findings are persisted in the correlation DB
    stored = ctx.database.findings(ctx.scan_id)
    assert any(f.category == "takeover" for f in stored)


def test_run_all_without_subdomains_is_a_noop(ctx, monkeypatch):
    phase = SubdomainTakeover(ctx)
    phase.run_all()
    assert phase.findings == []
    assert json.load(open(ctx.path("takeover", "candidates.json"))) == []


def test_scope_filter_is_enforced(ctx, monkeypatch):
    from core.utils import write_file_lines as _write
    from modules.scope_manager import ScopeManager

    scope_file = ctx.path("scope.txt")
    _write(scope_file, ["example.com"])
    ctx.scope = ScopeManager.from_config(
        ctx.config, extra_scope=["example.com"], out_of_scope_file=None
    )
    _write(ctx.path("subdomains", "all_subdomains.txt"),
           ["shop.example.com", "evil.other-domain.com"])

    phase = SubdomainTakeover(ctx)
    checked = []

    def fake_check(host):
        checked.append(host)
        return None

    monkeypatch.setattr(phase, "check_host", fake_check)
    phase.run_all()

    assert "shop.example.com" in checked
    assert "evil.other-domain.com" not in checked
