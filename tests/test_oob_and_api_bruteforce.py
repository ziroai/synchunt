"""
Tests for the OOB (out-of-band) collaborator and API route brute forcing.

No network access: every provider call is monkeypatched.
"""

import json

from core.utils import write_file_lines

# ----------------------------------------------------------------------
# OOB client
# ----------------------------------------------------------------------
def _fake_result(status=200, payload=None, text=""):
    return type("R", (), {
        "status": status,
        "reachable": status > 0,
        "ok": 200 <= status < 300,
        "text": text or json.dumps(payload or {}),
        "headers": {},
        "error": "",
        "json": lambda self=None, default=None: payload if payload is not None else default,
        "header": lambda self=None, name="", default="": default,
    })()


def test_webhook_provider_registers_and_polls(monkeypatch):
    from core import oob as oob_module

    calls = []

    def fake_post(session, url, payload=None, **kwargs):
        calls.append(("post", url, payload))
        if url.endswith("/token") and "webhook" in url:
            return _fake_result(payload={"uuid": "abc-123"})
        return _fake_result(status=404)

    def fake_get(session, method, url, **kwargs):
        calls.append(("get", url))
        if "/requests" in url:
            return _fake_result(payload={"data": [
                {"method": "GET", "url": "/?p=ssrf-deadbeef", "ip": "203.0.113.9",
                 "created_at": "2026-01-01T00:00:00Z", "headers": {"user-agent": "curl"},
                 "query": {"p": "ssrf-deadbeef"}},
            ]})
        return _fake_result(status=404)

    monkeypatch.setattr(oob_module, "post_json", fake_post)
    monkeypatch.setattr(oob_module, "http_request", fake_get)

    client = oob_module.OOBClient(provider="webhook")
    assert client.start() is True
    assert client.callback_url().startswith("https://webhook.site/abc-123")
    probe = client.probe_url("ssrf")
    assert "p=ssrf-" in probe

    interactions = client.poll()
    assert len(interactions) == 1
    assert interactions[0].method == "GET"
    assert interactions[0].source_ip == "203.0.113.9"
    assert "ssrf-" in interactions[0].path
    assert "webhook" in interactions[0].summary()

    client.stop()


def test_webhook_registration_failure_is_reported(monkeypatch):
    from core import oob as oob_module

    monkeypatch.setattr(oob_module, "post_json",
                        lambda *a, **k: _fake_result(status=500))
    client = oob_module.OOBClient(provider="webhook")
    assert client.start() is False
    assert "registration failed" in client.error
    assert client.poll() == []


def test_interactsh_provider_uses_correlation_id(monkeypatch):
    from core import oob as oob_module

    posted = {}

    def fake_post(session, url, payload=None, **kwargs):
        posted["url"] = url
        posted["payload"] = payload
        return _fake_result(status=200)

    monkeypatch.setattr(oob_module, "post_json", fake_post)
    monkeypatch.setattr(
        oob_module, "http_request",
        lambda *a, **k: _fake_result(payload={"data": ["encrypted-payload"]}),
    )

    client = oob_module.OOBClient(provider="interactsh", interactsh_server="oast.pro")
    assert client.start() is True
    assert posted["url"] == "https://oast.pro/register"
    assert len(posted["payload"]["correlation-id"]) == 20
    assert len(posted["payload"]["secret-key"]) == 64

    url = client.callback_url("marker")
    assert url.endswith(".oast.pro")
    assert "marker" in url

    interactions = client.poll()
    assert len(interactions) == 1
    assert interactions[0].raw.get("encrypted") is True  # stdlib has no AES


def test_custom_provider_needs_a_url():
    from core.oob import OOBClient

    assert OOBClient(provider="custom").start() is False
    client = OOBClient(provider="custom", custom_url="https://collector.example")
    assert client.start() is True
    assert client.callback_url("m").startswith("https://collector.example/")


def test_build_client_respects_config(ctx):
    from core.oob import build_client

    assert build_client(ctx.config) is None  # disabled by default
    ctx.config.set("vuln_scanning.oob.enabled", True)
    ctx.config.set("vuln_scanning.oob.provider", "custom")
    ctx.config.set("vuln_scanning.oob.custom_url", "https://collector.example")
    client = build_client(ctx.config, session=ctx.session, limiter=ctx.limiter)
    assert client is not None and client.provider == "custom"


# ----------------------------------------------------------------------
# vuln_scanning wiring
# ----------------------------------------------------------------------
def test_dalfox_uses_oob_blind_xss_when_enabled(ctx, tmp_path):
    from modules.vuln_scanning import VulnScanner

    live = ctx.path("dns", "live_hosts.txt")
    write_file_lines(live, ["https://example.com"])
    ctx.set_file("live_hosts", live)
    params = ctx.path("content_discovery", "params", "all_params.txt")
    write_file_lines(params, ["https://example.com/search?q=1"])
    ctx.set_file("params", params)
    ctx.config.set("vuln_scanning.dalfox.enabled", True)

    scanner = VulnScanner(ctx)

    class DummyOOB:
        def probe_url(self, kind):
            return f"https://webhook.site/token?p={kind}-deadbeef"

        def stop(self):
            pass

        def poll(self):
            return []

    scanner.oob = DummyOOB()
    commands = []

    def fake_run(command, **kwargs):
        commands.append(list(command))
        return {"stdout": "", "stderr": "", "returncode": 0, "success": True,
                "skipped": False, "duration": 0.0, "result_count": 0, "tool": "dalfox"}

    ctx.runner.run = fake_run  # type: ignore
    ctx.runner.require = lambda *a, **k: False  # type: ignore
    scanner.run_dalfox()

    assert commands, "dalfox must run"
    assert "-b" in commands[0]
    assert "blindxss-deadbeef" in commands[0][commands[0].index("-b") + 1]


def test_oob_interactions_become_findings(ctx):
    from core.oob import OOBInteraction
    from modules.vuln_scanning import VulnScanner

    scanner = VulnScanner(ctx)

    class DummyOOB:
        stopped = False

        def poll(self):
            return [OOBInteraction(provider="webhook", method="GET",
                                   path="/?p=ssrf-1", source_ip="203.0.113.7",
                                   time="2026-01-01T00:00:00Z")]

        def stop(self):
            self.stopped = True

    dummy = DummyOOB()
    scanner.oob = dummy
    scanner._collect_oob_findings()

    assert len(scanner.findings) == 1
    finding = scanner.findings[0]
    assert finding.category == "oob"
    assert finding.severity == "high"
    assert "203.0.113.7" in finding.evidence
    assert dummy.stopped is True

    records = json.load(open(ctx.path("vulnerabilities", "oob_interactions.json"), encoding="utf-8"))
    assert records[0]["provider"] == "webhook"


def test_oob_param_probes_are_off_by_default(ctx):
    from modules.vuln_scanning import VulnScanner

    params = ctx.path("content_discovery", "params", "all_params.txt")
    write_file_lines(params, ["https://example.com/?a=1"])
    ctx.set_file("params", params)

    scanner = VulnScanner(ctx)

    class DummyOOB:
        def probe_url(self, kind):
            raise AssertionError("must not be called when probe_params is off")

    scanner.oob = DummyOOB()
    scanner.run_oob_param_probes()  # must be a no-op
    assert scanner.findings == []


def test_callback_injection_replaces_one_parameter():
    from modules.vuln_scanning import _inject_callback

    injected = _inject_callback("https://x/search?q=1&page=2", "https://cb.example/p")
    assert "q=https%3A%2F%2Fcb.example%2Fp" in injected
    assert "page=2" in injected
    assert _inject_callback("https://x/noparams", "https://cb.example/p") == ""


# ----------------------------------------------------------------------
# API route brute forcing
# ----------------------------------------------------------------------
def test_builtin_api_wordlist_is_sane():
    from modules.api_introspection import BRUTEFORCE_PATHS

    assert len(BRUTEFORCE_PATHS) >= 60
    assert "api/v1" in BRUTEFORCE_PATHS
    assert "graphql" in BRUTEFORCE_PATHS
    assert all(not path.startswith("/") for path in BRUTEFORCE_PATHS)
    assert len(set(BRUTEFORCE_PATHS)) == len(BRUTEFORCE_PATHS)


def test_bruteforce_discovers_routes_and_flags_admin(ctx, monkeypatch):
    import modules.api_introspection as api_module

    from modules import api_introspection

    ctx.config.set("api_introspection.bruteforce.enabled", True)
    ctx.config.set("api_introspection.bruteforce.max_paths", 200)

    seen = []

    def fake_probe(session, url, **kwargs):
        seen.append(url)
        if url.endswith("/api/v1"):
            return _fake_result(status=200, text='{"openapi": "3.0.0", "paths": {}}')
        if url.endswith("/admin"):
            return _fake_result(status=401)
        if url.endswith("/internal"):
            return _fake_result(status=200, text="{}")
        return _fake_result(status=404)

    monkeypatch.setattr(api_module, "probe", fake_probe)

    phase = api_introspection.APIIntrospector(ctx)
    phase._bruteforce_host("https://example.com")

    assert any(url.endswith("/api/v1") for url in seen)
    assert any("api/v1" in url for url in phase.bruteforce_hits)
    assert any("admin" in url for url in phase.bruteforce_hits)
    titles = [f.title for f in phase.findings]
    assert any("Sensitive API route" in title for title in titles)
    assert any(f.url.endswith("/admin") and f.severity == "low" for f in phase.findings)
    assert any(f.url.endswith("/internal") and f.severity == "medium"
               for f in phase.findings)


def test_bruteforce_can_be_disabled_and_paths_are_capped(ctx, monkeypatch):
    import modules.api_introspection as api_module

    from modules import api_introspection

    ctx.config.set("api_introspection.bruteforce.enabled", False)
    phase = api_introspection.APIIntrospector(ctx)
    monkeypatch.setattr(api_module, "probe",
                        lambda *a, **k: _fake_result(status=404))
    phase._bruteforce_host("https://example.com")
    assert phase.bruteforce_hits == []

    ctx.config.set("api_introspection.bruteforce.enabled", True)
    ctx.config.set("api_introspection.bruteforce.max_paths", 5)
    phase = api_introspection.APIIntrospector(ctx)
    assert len(phase.bruteforce_paths()) == 5


def test_wordlist_file_supplements_the_builtin_list(ctx, tmp_path):
    from modules.api_introspection import APIIntrospector

    extra = tmp_path / "api.txt"
    extra.write_text("# comment\ncustom/v9\n\napi/v1\n")
    ctx.config.set("api_introspection.bruteforce.wordlist", str(extra))

    phase = APIIntrospector(ctx)
    paths = phase.bruteforce_paths()
    assert "custom/v9" in paths
    assert paths.count("api/v1") == 1          # de-duplicated
    assert "graphql" in paths                  # built-ins preserved
