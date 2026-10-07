"""
Coverage for the internationalisation catalogue and the platform-compatibility
layer (console encoding, UTF-8 I/O, portable process handling).
"""

import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ----------------------------------------------------------------------
# i18n
# ----------------------------------------------------------------------
def test_every_language_defines_the_english_keys():
    from core import i18n

    english = set(i18n.TRANSLATIONS["en"])
    for code, catalogue in i18n.TRANSLATIONS.items():
        missing = english - set(catalogue)
        assert not missing, f"{code} is missing keys: {sorted(missing)}"


def test_translation_and_fallback():
    from core import i18n

    assert i18n.translate("cli.dry_run", "es").startswith("SIMULACIÓN")
    assert "निष्कर्ष" in i18n.translate("summary.findings", "hi")
    # unknown key -> the key itself, unknown language -> English
    assert i18n.translate("does.not.exist", "es") == "does.not.exist"
    assert i18n.translate("summary.title", "xx") == i18n.TRANSLATIONS["en"]["summary.title"]


def test_language_normalisation_and_configure(monkeypatch):
    from core import i18n

    assert i18n.normalise("en-US") == "en"
    assert i18n.normalise("PT_br") == "pt"
    assert i18n.normalise("klingon") == "en"

    class FakeConfig:
        def get(self, key, default=None):
            return "fr" if key == "general.language" else default

    assert i18n.configure(FakeConfig()) == "fr"
    assert i18n.configure(FakeConfig(), "hi") == "hi"      # CLI wins
    monkeypatch.setenv("SYNCHUNT_LANG", "de")
    assert i18n.configure(None) == "de"
    i18n.set_language("en")


def test_formatting_never_raises_on_missing_fields():
    from core import i18n

    # a template expecting fields, called without them, returns the raw template
    assert "{findings}" in i18n.translate("cli.complete", "de")


def test_list_languages_cli_and_dry_run_language(monkeypatch, tmp_path, capsys):
    import main as cli

    monkeypatch.setattr(sys, "argv", ["synchunt", "--list-languages"])
    assert cli.main() == 0
    out = capsys.readouterr().out
    assert "English" in out and "Español" in out

    config = tmp_path / "c.yaml"
    config.write_text("general:\n  profile: quick\n", encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv",
        ["synchunt", "-d", "example.com", "--dry-run", "--lang", "de",
         "--config", str(config), "--output-dir", str(tmp_path / "out")],
    )
    assert cli.main() == 0
    assert "TESTLAUF" in capsys.readouterr().out


def test_report_headings_follow_the_language(tmp_path):
    from core import i18n
    from reports.markdown_report import MarkdownReportGenerator

    i18n.set_language("es")
    try:
        generator = MarkdownReportGenerator(str(tmp_path), "example.com", None, None)
        content = open(generator.generate(), encoding="utf-8").read()
    finally:
        i18n.set_language("en")

    assert "Resumen del escaneo" in content


# ----------------------------------------------------------------------
# Platform compatibility
# ----------------------------------------------------------------------
def test_platform_helpers_expose_the_running_system():
    from core import platform_compat as pc

    summary = pc.platform_summary()
    assert "python" in summary
    assert isinstance(pc.supports_process_groups(), bool)
    assert pc.IS_WINDOWS == (sys.platform == "win32")


def test_ascii_fallback_degrades_icons():
    from core import platform_compat as pc

    pc.set_ascii_mode(True)
    try:
        assert not pc.console_supports_unicode()
        assert pc.sanitize("✅ done") == "[ ok ] done"
        assert pc.sanitize("═" * 3) == "==="
        assert pc.sanitize("plain").isascii()
    finally:
        pc.set_ascii_mode(False)


def test_child_env_forces_utf8():
    from core.platform_compat import child_env

    env = child_env({"PATH": "/usr/bin"})
    assert env["PYTHONIOENCODING"] == "utf-8"
    assert env["PYTHONUTF8"] == "1"
    assert env["PATH"] == "/usr/bin"


def test_kill_process_tree_terminates_a_real_child():
    from core.platform_compat import kill_process_tree

    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    kill_process_tree(process, grace=0.2)
    deadline = time.time() + 10
    while process.poll() is None and time.time() < deadline:
        time.sleep(0.1)
    assert process.poll() is not None


def test_every_text_file_write_uses_utf8():
    """A regression guard: non-ASCII evidence must survive on any platform."""
    offenders = []
    for root, _dirs, files in os.walk(ROOT):
        if any(part in root for part in (".git", ".check", "__pycache__", "node_modules")):
            continue
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8", errors="replace") as handle:
                for number, line in enumerate(handle, start=1):
                    if "open(" in line and '"r"' not in line and '"rb"' not in line:
                        if '"w"' in line and "encoding=" not in line and "newline=" not in line:
                            offenders.append(f"{os.path.relpath(path, ROOT)}:{number}")
    assert not offenders, f"open() without encoding: {offenders}"


def test_cross_platform_check_script_exists_and_compiles():
    import py_compile

    script = os.path.join(ROOT, "scripts", "check.py")
    assert os.path.exists(script)
    py_compile.compile(script, doraise=True)


def test_ascii_stream_degrades_every_console_path():
    import io

    from core import platform_compat as pc

    buffer = io.StringIO()
    pc.set_ascii_mode(True)
    try:
        pc.AsciiStream(buffer).write("✅ ══ 🚨 ✗ █░")
    finally:
        pc.set_ascii_mode(False)
    assert buffer.getvalue() == "[ ok ] == [ALERT] x #."


def test_log_file_is_utf8_and_not_duplicated(tmp_path):
    from core.logger import BugHuntLogger

    log = BugHuntLogger(output_dir=str(tmp_path))
    log.info("héllo ✅")
    log.found("emoji 🎯")
    log.skip("skipped ✗")

    with open(log.log_file, "rb") as handle:
        data = handle.read()
    assert "héllo ✅".encode("utf-8") in data
    assert data.decode("utf-8").count("[FOUND]") == 1
