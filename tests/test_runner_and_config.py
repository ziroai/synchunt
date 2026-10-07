import os
import sys

from core.config_manager import ConfigManager


# ----------------------------------------------------------------------
# Runner
# ----------------------------------------------------------------------
def test_runner_executes_argv_without_shell(runner, tmp_path):
    output = str(tmp_path / "out.txt")
    result = runner.run(
        [sys.executable, "-c", "print('hello from tool')"],
        output_file=output, tool_name="python-hello",
    )
    assert result["success"] is True
    assert "hello from tool" in result["stdout"]
    assert open(output, encoding="utf-8").read().strip() == "hello from tool"
    assert result["result_count"] == 1


def test_runner_marks_missing_tools_as_skipped(runner):
    result = runner.run(["definitely-not-installed-tool", "--version"],
                        tool_name="ghost-tool")
    assert result["skipped"] is True
    assert result["success"] is False


def test_require_helper_returns_skip_result_for_missing_binary(runner):
    assert runner.require("definitely-not-installed-tool")["skipped"] is True
    assert runner.require(sys.executable) is None


def test_runner_times_out_and_kills_process(runner):
    result = runner.run(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        timeout=1, tool_name="sleeper",
    )
    assert result["success"] is False
    assert result["duration"] < 15


def test_runner_pipes_stdin(runner):
    result = runner.run_with_stdin(
        [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read().upper())"],
        "hello\nworld\n", tool_name="upper",
    )
    assert "HELLO" in result["stdout"]


def test_runner_never_interpolates_shell_metacharacters(runner, tmp_path):
    """A hostile 'URL' must not become a command (regression test)."""
    marker = tmp_path / "pwned"
    hostile = f"http://x/$(touch {marker})"
    result = runner.run(
        ["echo", "-u", hostile], tool_name="echo-test"
    )
    assert str(marker) in result["stdout"]
    assert not marker.exists()


def test_runner_parallel(runner):
    commands = [
        {"command": [sys.executable, "-c", f"print({index})"], "tool_name": f"job{index}"}
        for index in range(4)
    ]
    results = runner.run_parallel(commands, max_workers=2)
    assert len(results) == 4
    assert sum(1 for r in results if r["success"]) == 4


def test_dependency_checker_never_installs_anything(monkeypatch):
    from core.dependency_checker import DependencyChecker

    checker = DependencyChecker()
    checker.missing_tools = {"nuclei": checker.TOOLS["nuclei"]}
    calls = []
    monkeypatch.setattr(
        "subprocess.run", lambda *a, **k: calls.append((a, k)) or None, raising=False
    )
    checker.auto_install()
    assert calls == [], "auto_install must only print commands"


# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------
def test_config_dot_access_and_defaults(config):
    assert config.get("general.threads") == 4
    assert config.get("does.not.exist", "fallback") == "fallback"
    assert config.get_bool("api_introspection.enabled") is True
    assert config.get_int("general.timeout") == 5
    assert config.get_list("github_recon.dorks") == ["password"]


def test_config_phase_and_tool_gates(config):
    assert config.is_phase_enabled("subdomain_enum") is True
    assert config.is_tool_enabled("subdomain_enum", "subfinder") is False
    assert config.is_tool_enabled("content_discovery", "katana") is False


def test_config_profiles(config):
    quick = config.profile_phases("quick")
    assert quick == ["subdomain", "validation", "enrichment", "report"]
    full = config.profile_phases("full")
    assert "prioritize" in full and "cloud_enum" in full
    assert set(config.available_profiles()) == {"quick", "full"}


def test_config_validate_flags_missing_wordlists(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "profiles:\n"
        "  quick:\n"
        "    phases: [subdomain, bogus_phase]\n"
        "content_discovery:\n"
        "  dirsearch:\n"
        "    wordlist: 'wordlists/missing.txt'\n"
        "general:\n"
        "  rate_limit: 10\n"
    )
    config = ConfigManager(str(path))
    warnings = config.validate(["subdomain", "validation"])
    joined = " ".join(warnings)
    assert "bogus_phase" in joined
    assert "wordlists/missing.txt" in joined


def test_output_dir_and_latest_run(config, output_dir):
    first = config.get_output_dir("example.com", run_id="20260101_000000",
                                  base_dir=output_dir)
    second = config.get_output_dir("example.com", run_id="20260102_000000",
                                   base_dir=output_dir)
    os.makedirs(first)
    os.makedirs(second)
    assert config.latest_output_dir("example.com", base_dir=output_dir) == second
    assert config.latest_output_dir("nothing.com", base_dir=output_dir) is None


def test_config_set_and_reload(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("general:\n  threads: 5\n")
    config = ConfigManager(str(path))
    config.set("general.threads", 99)
    config.set("brand.new.option", True)
    config.save_config()

    reloaded = ConfigManager(str(path))
    assert reloaded.get("general.threads") == 99
    assert reloaded.get("brand.new.option") is True
