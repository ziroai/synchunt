from core.secrets import (
    DEFAULT_PATTERNS,
    compile_patterns,
    redact,
    scan_text,
    shannon_entropy,
)
from modules.scope_manager import ScopeManager, parse_rule


# ----------------------------------------------------------------------
# Scope
# ----------------------------------------------------------------------
def test_parse_rule_kinds():
    assert parse_rule("example.com").kind == "domain"
    assert parse_rule("*.example.com").kind == "wildcard"
    assert parse_rule("10.0.0.0/24").kind == "cidr"
    assert parse_rule("192.168.1.5").kind == "ip"
    assert parse_rule("https://example.com/path").value == "example.com"
    assert parse_rule("") is None
    assert parse_rule("# comment") is None


def test_wildcard_excludes_apex_but_domain_includes_it():
    scope = ScopeManager(include=[parse_rule("*.example.com")])
    assert scope.in_scope("api.example.com")
    assert not scope.in_scope("example.com")

    scope = ScopeManager(include=[parse_rule("example.com")])
    assert scope.in_scope("example.com")
    assert scope.in_scope("deep.api.example.com")


def test_exclusions_win_over_inclusions():
    scope = ScopeManager(
        include=[parse_rule("example.com")],
        exclude=[parse_rule("admin.example.com")],
    )
    assert scope.in_scope("www.example.com")
    assert not scope.in_scope("admin.example.com")

    reason = []
    assert scope.in_scope("admin.example.com", reason) is False
    assert "excluded" in reason[0]


def test_exclude_only_scope_allows_rest():
    scope = ScopeManager(exclude=[parse_rule("internal.example.com")])
    assert scope.in_scope("www.example.com")
    assert not scope.in_scope("internal.example.com")


def test_strict_mode_requires_include_rule():
    strict = ScopeManager(strict=True)
    assert not strict.in_scope("example.com")
    loose = ScopeManager()
    assert loose.in_scope("example.com")


def test_filter_records_drops_and_deduplicates():
    scope = ScopeManager(
        include=[parse_rule("example.com")],
        exclude=[parse_rule("admin.example.com")],
    )
    values = [
        "www.example.com",
        "www.example.com",
        "admin.example.com",
        "other.net",
    ]
    kept = scope.filter(values, record_drops=True)
    assert kept == ["www.example.com"]
    assert len(scope.dropped) == 2
    summary = scope.summary()
    assert summary["dropped_count"] == 2


def test_from_config_reads_files_and_bang_exclusions(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n!admin.example.com\n10.10.0.0/16\n", encoding="utf-8")
    config_file = tmp_path / "config.yaml"
    config_file.write_text("scope:\n  strict: false\n", encoding="utf-8")

    from core.config_manager import ConfigManager

    config = ConfigManager(str(config_file))
    scope = ScopeManager.from_config(config, scope_file=str(scope_file))
    assert scope.in_scope("www.example.com")
    assert not scope.in_scope("admin.example.com")
    assert scope.in_scope("10.10.5.5")
    assert not scope.in_scope("10.11.0.1")


# ----------------------------------------------------------------------
# Secrets
# ----------------------------------------------------------------------
def test_detects_obvious_high_signal_secrets():
    text = (
        "aws_key = 'AKIAIOSFODNN7EXAMPLE'\n"
        "slack = 'xoxb-1234567890-abcdefghijkl'\n"
        "url = 'https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXX'\n"
        # secrets are assembled at runtime so push-protection scanners do not
        # flag these obviously-fake test fixtures
        "stripe = 'sk_" + "live_" + "51H8xQ2LkdIwHu7ixY0BJZq1Kd'\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "token = 'ghp_" + "a" * 36 + "'\n"
    )
    findings = scan_text(text, patterns=compile_patterns())
    names = {finding.name for finding in findings}
    assert "AWS Access Key" in names
    assert "Slack Token" in names
    assert "Private Key Block" in names
    assert "GitHub Token" in names
    assert "Stripe Key" in names


def test_low_entropy_values_are_filtered_out():
    text = "api_key = 'aaaaaaaaaaaaaaaaaaaaaaaa'"
    findings = scan_text(text, patterns=compile_patterns())
    assert findings == []


def test_placeholder_values_are_ignored():
    text = "api_key = 'your_api_key'"
    findings = scan_text(text, patterns=compile_patterns())
    assert findings == []


def test_database_urls_and_jwts_are_detected():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    text = f"mongo = 'mongodb://user:SuperSecret123@db.internal:27017/app'\ntoken={jwt}"
    findings = scan_text(text, patterns=compile_patterns())
    names = {finding.name for finding in findings}
    assert "Database Connection String" in names
    assert "JSON Web Token" in names


def test_matches_are_redacted_in_serialised_output():
    text = "AKIAIOSFODNN7EXAMPLE"
    findings = scan_text(text, patterns=compile_patterns())
    payload = findings[0].to_dict()
    assert "AKIAIOSFODNN7EXAMPLE" not in payload["value"]
    assert payload["value"].endswith("MPLE")
    assert "*" in payload["value"]


def test_redact_handles_short_values():
    assert redact("short") == "*" * 5
    assert redact("a" * 30).startswith("aaaaaa")
    assert "*" in redact("a" * 30)


def test_entropy_maths():
    assert shannon_entropy("aaaaaaaa") < 1.0
    assert shannon_entropy("aB3$xY9!qW2@") > 3.0


def test_custom_patterns_extend_the_library():
    patterns = compile_patterns(
        DEFAULT_PATTERNS + [{"name": "Acme Key", "regex": r"ACME_[A-Za-z0-9]{16}",
                             "severity": "medium", "confidence": "high"}]
    )
    findings = scan_text("key=ACME_abcdefghijklmnop", patterns=patterns)
    assert any(f.name == "Acme Key" for f in findings)


def test_invalid_regex_is_skipped_not_fatal():
    patterns = compile_patterns([{"name": "broken", "regex": "([unclosed"}])
    assert patterns == []
