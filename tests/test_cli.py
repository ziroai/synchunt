"""
CLI behaviour tests, including the documented commands from the README.
"""

import sys

import pytest

import main as cli


def test_check_deps_works_without_a_target(monkeypatch, capsys):
    """Regression: --check-deps used to fail with 'No valid targets specified'."""
    monkeypatch.setattr(sys, "argv", ["synchunt", "--check-deps"])
    code = cli.main()
    output = capsys.readouterr().out
    assert "No valid targets specified" not in output
    assert "Checking Tool Dependencies" in output
    assert code in (0, 1)


def test_doctor_runs_without_a_target(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        sys, "argv",
        ["synchunt", "--doctor", "--config", str(tmp_path / "cfg.yaml")],
    )
    # provide a minimal config so ConfigManager can load something
    (tmp_path / "cfg.yaml").write_text("general:\n  output_dir: " + str(tmp_path / "out") + "\n")
    code = cli.main()
    output = capsys.readouterr().out
    assert "Configuration check" in output
    assert code in (0, 1)


def test_list_phases_documents_every_phase(monkeypatch, tmp_path, capsys):
    config = tmp_path / "cfg.yaml"
    config.write_text("general:\n  output_dir: " + str(tmp_path / "out") + "\n")
    monkeypatch.setattr(sys, "argv", ["synchunt", "--list-phases", "--config", str(config)])
    code = cli.main()
    output = capsys.readouterr().out
    assert code == 0
    for phase in ("subdomain", "validation", "enrichment", "api_discovery",
                  "cloud_enum", "prioritize", "report"):
        assert phase in output


def test_unknown_phase_is_rejected(monkeypatch, tmp_path, capsys):
    config = tmp_path / "cfg.yaml"
    config.write_text("general:\n  output_dir: " + str(tmp_path / "out") + "\n")
    monkeypatch.setattr(
        sys, "argv",
        ["synchunt", "-d", "example.com", "--phase", "not_a_phase",
         "--config", str(config)],
    )
    assert cli.main() == 2
    assert "unknown phase" in capsys.readouterr().out


def test_missing_target_is_a_usage_error(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["synchunt"])
    with pytest.raises(SystemExit):
        cli.parse_arguments()


def test_profile_flag_is_accepted(monkeypatch, tmp_path):
    config = tmp_path / "cfg.yaml"
    config.write_text(
        "general:\n"
        f"  output_dir: {tmp_path / 'out'}\n"
        "profiles:\n"
        "  quick:\n"
        "    phases: [subdomain, report]\n"
    )
    monkeypatch.setattr(
        sys, "argv",
        ["synchunt", "-d", "example.com", "--profile", "quick",
         "--dry-run", "--config", str(config)],
    )
    assert cli.main() == 0


def test_invalid_targets_are_rejected(monkeypatch, tmp_path, capsys):
    config = tmp_path / "cfg.yaml"
    config.write_text("general:\n  output_dir: " + str(tmp_path / "out") + "\n")
    monkeypatch.setattr(
        sys, "argv",
        ["synchunt", "-d", "not a domain", "--config", str(config)],
    )
    assert cli.main() == 3
    assert "No valid targets" in capsys.readouterr().out


def test_phase_selection_always_includes_reporting(config_path, tmp_path):
    args = cli.parse_arguments(["-d", "example.com", "--phase", "subdomain",
                                "--config", config_path])
    app = cli.SyncHunt(args)
    phases = app._select_phases()
    assert phases == ["subdomain", "prioritize", "report"]


def test_phase_selection_uses_profile_order(config_path):
    args = cli.parse_arguments(["-d", "example.com", "--config", config_path])
    app = cli.SyncHunt(args)
    phases = app._select_phases()
    # profile order is honoured, and reporting dependencies are appended
    assert phases[:3] == ["subdomain", "validation", "enrichment"]
    assert phases[-2:] == ["prioritize", "report"]


def test_target_parsing_handles_urls_ips_and_ports(tmp_path, config_path):
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text(
        "https://example.com/path\n"
        "127.0.0.1\n"
        "10.0.0.0/24\n"
        "127.0.0.1:8080\n"
        "not valid\n"
    )
    args = cli.parse_arguments(["-l", str(targets_file), "--config", config_path])
    app = cli.SyncHunt(args)
    targets = app._parse_targets()
    assert "example.com" in targets
    assert "127.0.0.1" in targets
    assert "10.0.0.0/24" in targets
    assert "127.0.0.1:8080" in targets
    assert "not valid" not in targets


def test_result_count_reads_jsonl_artifacts(config_path, ctx):
    """Regression: .jsonl artifacts used to be parsed with the JSON loader."""
    args = cli.parse_arguments(["-d", "example.com", "--config", config_path])
    app = cli.SyncHunt(args)
    jsonl = ctx.path("ports", "naabu.jsonl")
    with open(jsonl, "w") as fh:
        fh.write('{"port": 80, "host": "example.com"}\n')
        fh.write('{"port": 443, "host": "example.com"}\n')
        fh.write("not json\n")
    ctx.set_file("ports", jsonl)
    assert app._result_count(ctx, cli.PHASE_BY_NAME["portscan"]) == 2


def test_end_to_end_run_against_local_server(monkeypatch, tmp_path, local_server):
    """Full CLI run of the deterministic phases against a local test server."""
    config = tmp_path / "cfg.yaml"
    output = tmp_path / "out"
    config.write_text(
        "general:\n"
        f"  output_dir: {output}\n"
        "  rate_limit: 5000\n"
        "  threads: 8\n"
        "  timeout: 5\n"
        "  resolve_timeout: 2\n"
        "  retry: 0\n"
        "  verbose: false\n"
        "asset_enrichment:\n"
        "  enabled: true\n"
        "  max_hosts: 3\n"
        "  probe_admin_paths: true\n"
        "  admin_paths: ['/admin']\n"
        "api_introspection:\n"
        "  enabled: true\n"
        "  max_hosts: 3\n"
        "finding_prioritizer:\n"
        "  enabled: true\n"
        "  min_severity: info\n"
        "reporting:\n"
        "  html_report: true\n"
        "  markdown_report: true\n"
    )
    monkeypatch.setattr(
        sys, "argv",
        ["synchunt", "-d", local_server, "--output-dir", str(output),
         "--phase", "enrichment,api_discovery,prioritize,report",
         "--config", str(config), "--quiet"],
    )
    assert cli.main() == 0

    run_dirs = [
        path for path in output.rglob("report.html")
    ]
    assert run_dirs, "HTML report should exist"
    report = run_dirs[0].read_text()
    assert "SyncHunt Report" in report
    assert "GraphQL introspection" in report or "specification exposed" in report

    assert list(output.rglob("findings.csv")), "CSV export should exist"
    assert list(output.rglob("synchunt_results.db")), "correlation DB should exist"
    assert list(output.rglob("report.md")), "markdown report should exist"


def test_resume_skips_completed_phases(monkeypatch, tmp_path, local_server):
    config = tmp_path / "cfg.yaml"
    output = tmp_path / "out"
    config.write_text(
        "general:\n"
        f"  output_dir: {output}\n"
        "  rate_limit: 5000\n  threads: 8\n  timeout: 5\n  retry: 0\n  verbose: false\n"
        "asset_enrichment:\n  enabled: true\n  max_hosts: 2\n"
        "  probe_admin_paths: false\n  admin_paths: []\n"
    )
    argv = ["synchunt", "-d", local_server, "--output-dir", str(output),
            "--phase", "enrichment,report", "--config", str(config), "--quiet"]

    monkeypatch.setattr(sys, "argv", argv)
    assert cli.main() == 0

    state_files = list(output.rglob("scan_state.json"))
    assert state_files, "state file should be written for resumes"
    import json

    state = json.loads(state_files[0].read_text())
    assert "enrichment" in state["completed_phases"]

    monkeypatch.setattr(sys, "argv", argv + ["--resume"])
    assert cli.main() == 0  # second run resumes instead of failing
