"""
SyncHunt - platform compatibility helpers

SyncHunt targets Linux, macOS and Windows from the same code base. Everything
platform-specific lives here:

  * console encoding - the CLI prints icons and box drawing; on a legacy Windows
    code page (cp1252/cp437) that raises UnicodeEncodeError, so stdio is
    reconfigured to UTF-8 and every string can be degraded to pure ASCII
    (`SYNCHUNT_ASCII=1` forces it, useful for CI logs too)
  * child processes - POSIX gets process groups (setsid/killpg), Windows gets
    `taskkill /F /T` so a killed tool does not leave orphans behind
  * environment - UTF-8 is exported to child tools so their output is decoded
    consistently
  * paths - the file helpers in core.utils always open with encoding="utf-8", so
    a scan started on Windows and read on Linux (or vice versa) is identical
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Dict, Optional

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

# Icons used by the logger -> ASCII equivalents for non-UTF-8 consoles.
ASCII_FALLBACK: Dict[str, str] = {
    "🔎": "[scan]",
    "🔍": "[find]",
    "✅": "[ ok ]",
    "⚠️": "[warn]",
    "⚠": "[warn]",
    "❌": "[fail]",
    "✗": "x",
    "✘": "x",
    "🎯": "[hit ]",
    "📍": "[mark]",
    "📌": "[note]",
    "🔥": "[vuln]",
    "🚨": "[ALERT]",
    "⏭️": "[skip]",
    "⏭": "[skip]",
    "📊": "[data]",
    "🚀": "[go  ]",
    "🛡️": "[safe]",
    "🛡": "[safe]",
    "📁": "[dir ]",
    "📂": "[dir ]",
    "📦": "[pkg ]",
    "📋": "[list]",
    "🔧": "[tool]",
    "⏳": "[wait]",
    "•": "*",
    "→": "->",
    "✓": "v",
    "★": "*",
    "█": "#",
    "░": ".",
    "═": "=",
    "║": "|",
    "╔": "+",
    "╗": "+",
    "╚": "+",
    "╝": "+",
    "─": "-",
}

_ASCII_MODE = os.environ.get("SYNCHUNT_ASCII", "").strip().lower() in ("1", "true", "yes", "on")


def ascii_mode() -> bool:
    """True when output must stay inside the ASCII character set."""
    return _ASCII_MODE


def set_ascii_mode(enabled: bool) -> None:
    global _ASCII_MODE
    _ASCII_MODE = bool(enabled)


class AsciiStream:
    """Stream proxy that degrades non-ASCII output to ASCII on the way out."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text):
        return self._stream.write(sanitize(text))

    def __getattr__(self, name):
        return getattr(self._stream, name)


def _wrappable(stream) -> bool:
    """True for real OS-level streams (never for in-memory capture buffers)."""
    try:
        stream.fileno()
    except Exception:
        return False
    return True


def _stream_encodes_unicode(stream) -> bool:
    """Can this stream's encoding represent box-drawing characters?"""
    encoding = (getattr(stream, "encoding", "") or "").strip().lower()
    if not encoding:
        return True  # unknown (capture buffers, StringIO) - assume capable
    try:
        "\u2550".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def configure_stdio() -> bool:
    """
    Make stdout/stderr UTF-8 capable. Returns True when unicode output is safe.

    ASCII mode is enabled only when `SYNCHUNT_ASCII` asks for it or the console
    demonstrably cannot encode box-drawing characters or emoji. In-memory
    streams (test runners, notebooks) are never wrapped, so importing the
    framework can never break a host application's capture machinery.
    """
    safe = True
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:  # pragma: no cover - exotic consoles
                pass
        if not _stream_encodes_unicode(stream):
            safe = False
    if not safe:
        set_ascii_mode(True)
    if ascii_mode():
        # Wrap real streams once: this covers prints, logging handlers, progress
        # bars and any third-party output, not just the framework's own paths.
        for stream_name in ("stdout", "stderr"):
            stream = getattr(sys, stream_name, None)
            if stream is not None and not isinstance(stream, AsciiStream) and _wrappable(stream):
                setattr(sys, stream_name, AsciiStream(stream))
    return safe


def console_supports_unicode() -> bool:
    """Can the active console encode a box-drawing character?"""
    if ascii_mode():
        return False
    encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
    if not encoding:
        return not IS_WINDOWS
    if encoding.replace("-", "") in ("utf8", "utf16", "utf32"):
        return True
    try:
        "═".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def sanitize(text: str) -> str:
    """Degrade a string to ASCII when the console cannot render it."""
    if not text or console_supports_unicode():
        return text
    for unicode_char, replacement in ASCII_FALLBACK.items():
        text = text.replace(unicode_char, replacement)
    return text.encode("ascii", "replace").decode("ascii")


def child_env(base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Environment for external tools: inherit, plus UTF-8 so their output is
    decoded the same way on every platform.
    """
    env = dict(base if base is not None else os.environ)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("LC_ALL", env.get("LC_ALL", "C.UTF-8") if IS_LINUX else env.get("LC_ALL", ""))
    return {key: value for key, value in env.items() if value != ""}


def spawn_kwargs(shell: bool = False) -> Dict[str, object]:
    """Platform-appropriate subprocess kwargs (own process group on POSIX)."""
    kwargs: Dict[str, object] = {}
    if not (IS_WINDOWS or shell):
        kwargs["preexec_fn"] = os.setsid
    return kwargs


def kill_process_tree(process: subprocess.Popen, grace: float = 1.5) -> None:
    """
    Terminate a tool and everything it spawned.

    POSIX: signal the process group (SIGTERM, then SIGKILL).
    Windows: `taskkill /F /T /PID` kills the tree in one call.
    """
    import time

    if process.poll() is not None:
        return
    if IS_WINDOWS:
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True, check=False,
            )
            return
        except Exception:  # pragma: no cover - fall through to kill()
            pass
    else:
        try:
            os.killpg(os.getpgid(process.pid), signal_SIGTERM())
            time.sleep(grace)
            if process.poll() is None:
                os.killpg(os.getpgid(process.pid), signal_SIGKILL())
            return
        except Exception:  # pragma: no cover - fall through to kill()
            pass
    try:
        process.kill()
    except Exception:
        pass


def signal_SIGTERM():
    import signal

    return signal.SIGTERM


def signal_SIGKILL():
    import signal

    return signal.SIGKILL


def platform_summary() -> str:
    """Human-readable platform/runner line for --doctor and the reports."""
    import platform

    bits = [
        platform.system() or sys.platform,
        platform.release(),
        f"python {platform.python_version()}",
        f"{os.cpu_count() or 1} cpu",
    ]
    return " | ".join(part for part in bits if part)


def supports_process_groups() -> bool:
    return not IS_WINDOWS
