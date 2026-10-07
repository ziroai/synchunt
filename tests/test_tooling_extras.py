"""
Coverage for the second wave of tool integrations: the offline helper CLI
(anew / unfurl / gf / meg / postman / hashcat preflight), proxy plumbing, and
the extra scanners (theHarvester, Censys, dnsrecon, dnsenum, wfuzz, JoomScan,
Commix, Tplmap, SSRFmap, Hunter.io, CloudBrute, EyeWitness, searchsploit).

External binaries are never executed: ToolRunner.run/require/is_available are
monkeypatched and the tests assert the argv plus the parsing of real output.
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
        if callable(stdout):
            stdout = stdout(command)
        if stdout:
            result["stdout"] = stdout
            result["success"] = True
        return result

    ctx.runner.run = fake_run  # type: ignore
    ctx.runner.require = lambda tool, *a, **k: False  # type: ignore
    ctx.runner.is_available = lambda tool: True  # type: ignore
    return commands


# ----------------------------------------------------------------------
# Hash identification (Hashcat / John preflight)
# ----------------------------------------------------------------------
def test_hash_identification_and_commands():
    from core import hashid

    matches = hashid.identify("5f4dcc3b5aa765d61d8327deb882cf99")
    names = [match.name for match in matches]
    assert "MD5 / NTLM" in names and "MD4" in names

    bcrypt = hashid.suggest_commands("$2y$10$" + "a" * 53)
    assert bcrypt["identified"] is True
    assert any("hashcat -m 3200" in cmd for cmd in bcrypt["hashcat"])
    assert any("john --format=bcrypt" in cmd for cmd in bcrypt["john"])


def test_jwt_is_recognised_and_short_tokens_are_not():
    from core import hashid

    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepart"
    assert [m.name for m in hashid.identify(jwt)] == ["JWT"]
    assert hashid.identify("deadbeef") == []


def test_find_hashes_in_free_text():
    from core import hashid

    blob = "var t = '5f4dcc3b5aa765d61d8327deb882cf99'; var n = 12345;"
    hits = hashid.find_hashes_in_text(blob)
    assert len(hits) == 1
    assert hits[0]["value"] == "5f4dcc3b5aa765d61d8327deb882cf99"


# ----------------------------------------------------------------------
# Helper CLI (anew / unfurl / gf / meg / postman / hash-id)
# ----------------------------------------------------------------------
def test_cli_dedupe_unfurl_gf(tmp_path, capsys):
    import tools_cli

    urls = tmp_path / "urls.txt"
    urls.write_text(
        "https://a.example.com/item?id=7\n"
        "https://a.example.com/item?id=7\n"
        "https://a.example.com/static/logo.png\n"
        "https://a.example.com/next?next=https://evil.example\n"
    )

    assert tools_cli.main(["dedupe", str(urls)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 3

    assert tools_cli.main(["unfurl", str(urls), "--part", "hosts"]) == 0
    assert capsys.readouterr().out.strip() == "a.example.com"

    assert tools_cli.main(["gf", "redirect", str(urls)]) == 0
    assert "evil.example" in capsys.readouterr().out

    assert tools_cli.main(["gf", "nope", str(urls)]) == 2


def test_cli_meg_urls_and_postman(tmp_path, capsys):
    import tools_cli

    hosts = tmp_path / "hosts.txt"
    hosts.write_text("a.example.com\nb.example.com\n")
    paths = tmp_path / "paths.txt"
    paths.write_text("/admin\n/.env\n")

    assert tools_cli.main(["meg-urls", "--hosts", str(hosts), "--paths", str(paths)]) == 0
    urls = capsys.readouterr().out.splitlines()
    assert "https://a.example.com/admin" in urls and len(urls) == 4

    collection = tmp_path / "c.json"
    collection.write_text(json.dumps({
        "variable": [{"key": "base", "value": "https://api.example.com"}],
        "item": [{
            "name": "get user",
            "request": {"method": "GET", "url": "{{base}}/v1/users/1"},
            "item": [{"request": {"url": {"protocol": "https", "host": ["api", "example", "com"],
                                         "path": ["v2", "orders"]}}}],
        }],
    }))
    assert tools_cli.main(["postman", str(collection)]) == 0
    out = capsys.readouterr().out
    assert "https://api.example.com/v1/users/1" in out
    assert "https://api.example.com/v2/orders" in out


def test_cli_hash_id(tmp_path, capsys):
    import tools_cli

    hashes = tmp_path / "h.txt"
    hashes.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n")
    assert tools_cli.main(["hash-id", str(hashes)]) == 0
    assert "hashcat -m 0" in capsys.readouterr().out


def test_builtin_pattern_library_buckets_urls():
    from core.patterns import classify_urls, pattern_names

    assert "ssrf" in pattern_names()
    buckets = classify_urls([
        "https://x.test/api/user?id=5",
        "https://x.test/fetch?url=https://y.test",
        "https://x.test/static/logo.png",
    ])
    assert "idor" in buckets and "ssrf" in buckets
    assert "https://x.test/static/logo.png" not in sum(buckets.values(), [])


# ----------------------------------------------------------------------
# Proxy plumbing (Burp / ZAP / mitmproxy)
# ----------------------------------------------------------------------
def test_proxy_env_applied_and_cleared(monkeypatch):
    from core import proxy

    keys = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
    for key in keys:
        monkeypatch.delenv(key, raising=False)
        monkeypatch.delenv(key.lower(), raising=False)

    assert proxy.apply_proxy_env(None, "") == ""

    used = proxy.apply_proxy_env(None, "http://127.0.0.1:8080")
    assert used == "http://127.0.0.1:8080"
    assert os.environ["HTTPS_PROXY"] == used
    assert "127.0.0.1" in os.environ["NO_PROXY"]

    for key in keys:
        os.environ.pop(key, None)
        os.environ.pop(key.lower(), None)


def test_proxy_prefers_cli_over_config(config):
    from core.proxy import proxy_from_config

    config.set("general.proxy", "http://config:8080")
    assert proxy_from_config(config, "") == "http://config:8080"
    assert proxy_from_config(config, "http://cli:9090") == "http://cli:9090"


# ----------------------------------------------------------------------
# Recon: theHarvester + Censys
# ----------------------------------------------------------------------
def test_theharvester_hosts_and_emails(ctx):
    from modules.subdomain_enum import SubdomainEnumerator

    enumerator = SubdomainEnumerator(ctx)
    base = os.path.join(enumerator.output_dir, "theharvester.json")
    with open(base, "w") as handle:
        json.dump({
            "hosts": ["api.example.com:1.2.3.4", "other.test"],
            "emails": ["security@example.com", "nope"],
        }, handle)

    commands = _install_fake_runner(ctx)
    found = enumerator.run_theharvester()

    assert commands[0][0] in ("theHarvester", "theharvester")
    assert found == ["api.example.com"]
    emails = ctx.path("subdomains", "emails.txt")
    assert "security@example.com" in open(emails).read()


def test_censys_needs_keys_and_parses_hits(ctx, monkeypatch):
    from core import net as net_module
    from modules.subdomain_enum import SubdomainEnumerator

    enumerator = SubdomainEnumerator(ctx)
    assert enumerator.run_censys() == []  # no keys configured -> no request

    class FakeResult:
        ok = True
        status = 200

        def json(self, default=None):
            return {"result": {"hits": [
                {"names": ["shop.example.com", "other.test"]},
                {"names": ["cdn.example.com"]},
            ]}}

    calls = []

    def fake_request(session, method, url, **kwargs):
        calls.append((method, url, kwargs.get("json")))
        return FakeResult()

    monkeypatch.setattr(net_module, "http_request", fake_request)
    monkeypatch.setenv("CENSYS_API_ID", "id")
    monkeypatch.setenv("CENSYS_API_SECRET", "secret")

    found = enumerator.run_censys()
    assert calls and calls[0][1].endswith("/hosts/search")
    assert found == ["cdn.example.com", "shop.example.com"]


# ----------------------------------------------------------------------
# DNS enumeration: dnsrecon / dnsenum
# ----------------------------------------------------------------------
def test_dnsrecon_records_and_zone_transfer(ctx):
    from modules.subdomain_validation import SubdomainValidator

    ctx.config.set("subdomain_validation.dnsrecon.enabled", True)
    validator = SubdomainValidator(ctx)
    with open(os.path.join(validator.output_dir, "dnsrecon.json"), "w") as handle:
        json.dump([
            {"type": "A", "name": "api.example.com", "address": "1.2.3.4"},
            {"type": "NS", "name": "ns1.example.com", "target": "ns1.example.com"},
            {"type": "A", "name": "elsewhere.test", "address": "9.9.9.9"},
        ], handle)

    _install_fake_runner(ctx, {"dnsrecon": "[+] Zone Transfer was successful!!"})
    names = validator.run_dnsrecon()

    assert names == ["api.example.com", "ns1.example.com"]
    assert any(f.category == "dns" and f.severity == "critical" for f in validator.findings)


def test_dnsenum_extracts_names_from_output(ctx):
    from modules.subdomain_validation import SubdomainValidator

    ctx.config.set("subdomain_validation.dnsenum.enabled", True)
    validator = SubdomainValidator(ctx)
    _install_fake_runner(ctx, {"dnsenum": "www.example.com. 300 IN A 1.2.3.4\nmail.example.com. 300 IN MX"})

    names = validator.run_dnsenum()

    assert "www.example.com" in names and "mail.example.com" in names
    assert validator.findings == []  # no AXFR markers -> no finding


# ----------------------------------------------------------------------
# Content discovery: wfuzz + gf classification
# ----------------------------------------------------------------------
def test_wfuzz_ingests_urls(ctx):
    from modules.content_discovery import ContentDiscovery

    live = ctx.path("dns", "live_hosts.txt")
    write_file_lines(live, ["https://example.com"])
    ctx.set_file("live_hosts", live)
    ctx.config.set("content_discovery.wfuzz.enabled", True)
    wordlist = ctx.path("wordlists", "directories.txt")
    write_file_lines(wordlist, ["admin", ".env"])
    ctx.config.set("content_discovery.wfuzz.wordlist", wordlist)

    phase = ContentDiscovery(ctx)
    raw_dir = os.path.join(phase.dirs_dir, "wfuzz")
    os.makedirs(raw_dir, exist_ok=True)
    write_file_lines(os.path.join(raw_dir, "example.com.txt"),
                     ["000000001: 200 10 L 20 W 300 Ch https://example.com/admin"])

    commands = _install_fake_runner(ctx)
    phase.run_wfuzz()

    assert commands and commands[0][0] == "wfuzz"
    assert "https://example.com/admin" in phase.all_urls


def test_gf_classification_writes_buckets(ctx):
    from modules.content_discovery import ContentDiscovery

    phase = ContentDiscovery(ctx)
    phase.all_urls = {
        "https://example.com/user?id=42",
        "https://example.com/next?next=https://evil.test",
        "https://example.com/robots.txt",
    }
    phase.classify_urls()

    pattern_dir = os.path.join(phase.output_dir, "patterns")
    index = json.load(open(os.path.join(pattern_dir, "index.json")))
    assert index["buckets"]["idor"] == 1
    assert index["buckets"]["ssrf"] == 1
    assert "idor.txt" in os.listdir(pattern_dir)


# ----------------------------------------------------------------------
# Vulnerability scanning: JoomScan, Commix, Tplmap, SSRFmap
# ----------------------------------------------------------------------
def _vuln_scanner(ctx, params=("https://example.com/index.php?id=1",)):
    from modules.vuln_scanning import VulnScanner

    live = ctx.path("dns", "live_hosts.txt")
    write_file_lines(live, ["https://example.com"])
    ctx.set_file("live_hosts", live)
    params_file = ctx.path("content_discovery", "params", "all_params.txt")
    os.makedirs(os.path.dirname(params_file), exist_ok=True)
    write_file_lines(params_file, list(params))
    ctx.set_file("params", params_file)
    return VulnScanner(ctx)


def test_joomscan_cve_becomes_finding(ctx):
    ctx.config.set("vuln_scanning.joomscan.enabled", True)
    scanner = _vuln_scanner(ctx)
    _install_fake_runner(ctx, {"joomscan": "Joomla! version 3.9.0\n[+] CVE-2019-10945 detected"})

    scanner.run_joomscan()

    assert any("CVE-2019-10945" in f.title for f in scanner.findings)
    assert any(f.category == "cms" and f.severity == "info" for f in scanner.findings)


def test_commix_injectable_reported(ctx):
    ctx.config.set("vuln_scanning.commix.enabled", True)
    scanner = _vuln_scanner(ctx)
    _install_fake_runner(ctx, {"commix": "The parameter 'id' is vulnerable to command injection"})

    scanner.run_commix()

    assert [f.category for f in scanner.findings] == ["rce"]
    assert scanner.findings[0].severity == "critical"


def test_tplmap_and_ssrfmap_report_candidates(ctx):
    ctx.config.set("vuln_scanning.tplmap.enabled", True)
    ctx.config.set("vuln_scanning.ssrfmap.enabled", True)
    scanner = _vuln_scanner(ctx, params=("https://example.com/page?url=https://x.test",))
    _install_fake_runner(ctx, {
        "tplmap": "The URL is injectable (SSTI: Jinja2)",
        "ssrfmap": "Target is vulnerable to SSRF",
    })

    scanner.run_tplmap()
    scanner.run_ssrfmap()

    categories = sorted(f.category for f in scanner.findings)
    assert categories == ["ssrf", "ssti"]


# ----------------------------------------------------------------------
# OSINT: Hunter.io
# ----------------------------------------------------------------------
def test_hunter_requires_key_and_reports_emails(ctx, monkeypatch):
    from core import net as net_module
    from modules.sensitive_info import SensitiveInfoScanner

    scanner = SensitiveInfoScanner(ctx)
    scanner.run_hunter()  # no key -> no request, no findings
    assert scanner.findings == []

    class FakeResult:
        ok = True
        status = 200

        def json(self, default=None):
            return {"data": {"emails": [
                {"value": "ceo@example.com", "type": "personal", "confidence": 90},
            ]}}

    monkeypatch.setattr(net_module, "http_request",
                        lambda *a, **k: FakeResult())
    monkeypatch.setenv("HUNTER_API_KEY", "key")
    scanner.run_hunter()

    assert [f.category for f in scanner.findings] == ["osint"]
    assert os.path.exists(os.path.join(scanner.output_dir, "hunter", "emails.txt"))


# ----------------------------------------------------------------------
# Cloud: CloudBrute
# ----------------------------------------------------------------------
def test_cloudbrute_hits_become_findings(ctx, monkeypatch):
    from modules import cloud_enum

    monkeypatch.setattr(cloud_enum.CloudEnumerator, "_candidate_names",
                        lambda self: ["example", "example-assets"])
    enumerator = cloud_enum.CloudEnumerator(ctx)
    ctx.config.set("cloud_enum.cloudbrute.enabled", True)
    _install_fake_runner(ctx, {"cloudbrute": "Found https://example-assets.s3.amazonaws.com/"})

    enumerator.run_cloudbrute()

    assert enumerator.results["cloudbrute"][0]["url"] == "https://example-assets.s3.amazonaws.com/"
    assert any(f.severity == "critical" for f in enumerator.findings)
    assert os.path.exists(os.path.join(enumerator.output_dir, "cloudbrute_names.txt"))


# ----------------------------------------------------------------------
# Screenshots: EyeWitness
# ----------------------------------------------------------------------
def test_eyewitness_counts_report_images(ctx):
    from modules.screenshots import ScreenshotCapture

    live = ctx.path("dns", "live_hosts.txt")
    write_file_lines(live, ["https://example.com"])
    ctx.set_file("live_hosts", live)
    ctx.config.set("screenshots.eyewitness.enabled", True)

    phase = ScreenshotCapture(ctx)
    commands = []

    def fake_run(command, **kwargs):
        commands.append(list(command))
        report_dir = command[command.index("-d") + 1]
        os.makedirs(report_dir, exist_ok=True)
        with open(os.path.join(report_dir, "example.com.png"), "wb") as handle:
            handle.write(b"\x89PNG")
        return dict(TOOL_RESULT)

    ctx.runner.run = fake_run  # type: ignore
    ctx.runner.require = lambda tool, *a, **k: False  # type: ignore
    ctx.runner.is_available = lambda tool: True  # type: ignore

    captured = phase.run_eyewitness()

    assert captured == 1
    assert commands[0][0] in ("eyewitness", "EyeWitness", "EyeWitness.py")
    assert "--web" in commands[0]


# ----------------------------------------------------------------------
# Prioritisation: searchsploit enrichment
# ----------------------------------------------------------------------
def test_searchsploit_enriches_cve_findings(ctx):
    from core.models import Finding
    from modules.finding_prioritizer import FindingPrioritizer

    ctx.config.set("finding_prioritizer.searchsploit.enabled", True)
    prioritizer = FindingPrioritizer(ctx)
    finding = Finding(
        category="cms",
        title="WordPress plugin vulnerability CVE-2021-29447",
        severity="high",
        target="example.com",
        source="wpscan",
        score=8.0,
    )
    prioritizer.findings = [finding]

    payload = json.dumps({"RESULTS_EXPLOIT": [
        {"EDB-ID": "50310", "Title": "WordPress - Authenticated XXE", "Path": "webapps/50310.py"},
    ]})
    ctx.runner.is_available = lambda tool: True  # type: ignore
    ctx.runner.run = lambda command, **kwargs: dict(TOOL_RESULT, stdout=payload)  # type: ignore

    prioritizer.enrich_with_searchsploit()

    assert "public-exploit" in finding.tags
    assert finding.extra["exploitdb"]["CVE-2021-29447"][0]["id"] == "50310"
    assert finding.score > 8.0
    assert os.path.exists(os.path.join(prioritizer.output_dir, "exploits.json"))


def test_searchsploit_skips_without_cves(ctx):
    from modules.finding_prioritizer import FindingPrioritizer

    prioritizer = FindingPrioritizer(ctx)
    prioritizer.enrich_with_searchsploit()  # no findings, no crash, no artifact
    assert not os.path.exists(os.path.join(prioritizer.output_dir, "exploits.json"))


@pytest.mark.parametrize("tool", ["dnsrecon", "dnsenum", "wfuzz", "joomscan", "searchsploit"])
def test_new_tools_are_in_the_dependency_registry(tool):
    from core.dependency_checker import DependencyChecker

    assert tool in DependencyChecker.TOOLS
    assert DependencyChecker.TOOLS[tool]["required"] is False
