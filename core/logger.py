"""
SyncHunt - Logging Framework
Colored terminal output + file logging, plus result/vuln/found helpers.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime
from typing import Optional

from colorama import init, Fore, Style, Back

init(autoreset=True)

LEVEL_STYLES = {
    "DEBUG": (Fore.CYAN, "🔍"),
    "INFO": (Fore.GREEN, "✅"),
    "WARNING": (Fore.YELLOW, "⚠️ "),
    "ERROR": (Fore.RED, "❌"),
    "CRITICAL": (Fore.WHITE + Back.RED, "🚨"),
}


class ColoredFormatter(logging.Formatter):
    """Custom colored formatter for terminal output."""

    def format(self, record: logging.LogRecord) -> str:
        color, icon = LEVEL_STYLES.get(record.levelname, ("", ""))
        timestamp = datetime.now().strftime("%H:%M:%S")
        return (
            f"{Fore.WHITE}[{timestamp}] "
            f"{color}{icon} [{record.levelname:^8}]{Style.RESET_ALL} "
            f"{color}{record.getMessage()}{Style.RESET_ALL}"
        )


class FileFormatter(logging.Formatter):
    """Plain formatter for file logging."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"[{timestamp}] [{record.levelname:^8}] {record.getMessage()}"


class BugHuntLogger:
    """Main logger used across the framework."""

    def __init__(self, name: str = "SyncHunt", output_dir: str = "output",
                 verbose: bool = True):
        self.output_dir = output_dir
        self.verbose = verbose
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.propagate = False
        self.logger.handlers = []

        self.console_handler = logging.StreamHandler(sys.stdout)
        self.console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.console_handler.setFormatter(ColoredFormatter())
        self.logger.addHandler(self.console_handler)

        self.file_handler: Optional[logging.FileHandler] = None
        self.log_file: Optional[str] = None
        self.attach_file(output_dir)

    # ------------------------------------------------------------------
    def attach_file(self, output_dir: str) -> None:
        """Attach (or re-attach) a file handler after the run directory exists."""
        if not output_dir:
            return
        try:
            log_dir = os.path.join(output_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(
                log_dir, f"synchunt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            )
            if self.file_handler is not None:
                self.logger.removeHandler(self.file_handler)
                self.file_handler.close()
            handler = logging.FileHandler(log_file)
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(FileFormatter())
            self.logger.addHandler(handler)
            self.file_handler = handler
            self.log_file = log_file
            self.output_dir = output_dir
        except OSError:  # pragma: no cover - disk problems shouldn't kill a scan
            pass

    # ------------------------------------------------------------------
    def debug(self, msg: str) -> None:
        self.logger.debug(msg)

    def info(self, msg: str) -> None:
        self.logger.info(msg)

    def warning(self, msg: str) -> None:
        self.logger.warning(msg)

    def error(self, msg: str) -> None:
        self.logger.error(msg)

    def critical(self, msg: str) -> None:
        self.logger.critical(msg)

    # ------------------------------------------------------------------
    def banner(self, version: str = "2.0.0") -> None:
        banner_text = f"""
{Fore.RED}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════╗
║   ███████╗██╗   ██╗███╗   ██╗ ██████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
║   ██╔════╝╚██╗ ██╔╝████╗  ██║██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
║   ███████╗ ╚████╔╝ ██╔██╗ ██║██║     ███████║██║   ██║██╔██╗ ██║   ██║
║   ╚════██║  ╚██╔╝  ██║╚██╗██║██║     ██╔══██║██║   ██║██║╚██╗██║   ██║
║   ███████║   ██║   ██║ ╚████║╚██████╗██║  ██║╚██████╔╝██║ ╚████║   ██║
║   ╚══════╝   ╚═╝   ╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
║                                                              ║
║        {Fore.YELLOW}🔎 Automated Recon & Vulnerability Scanning 🔎{Fore.RED}         ║
║            {Fore.CYAN}   v{version} | authorized testing only{Fore.RED}              ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
        print(banner_text)

    def phase_banner(self, phase_name: str, phase_num: Optional[int] = None,
                     extra: str = "") -> None:
        phase_str = f"PHASE {phase_num}: " if phase_num else ""
        width = 62
        msg = f"{phase_str}{phase_name}"
        if extra:
            msg = f"{msg} — {extra}"
        padding = max(0, width - len(msg) - 4)
        left_pad = padding // 2
        right_pad = padding - left_pad
        print(f"\n{Fore.CYAN}{Style.BRIGHT}")
        print("═" * width)
        print(f"║ {' ' * left_pad}{msg}{' ' * right_pad} ║")
        print("═" * width)
        print(f"{Style.RESET_ALL}")

    def result(self, msg: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(
            f"{Fore.WHITE}[{timestamp}] "
            f"{Fore.MAGENTA}📌 [RESULT  ]{Style.RESET_ALL} "
            f"{Fore.MAGENTA}{msg}{Style.RESET_ALL}"
        )
        self.logger.info(f"[RESULT] {msg}")

    def found(self, msg: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(
            f"{Fore.WHITE}[{timestamp}] "
            f"{Fore.GREEN}🎯 [ FOUND  ]{Style.RESET_ALL} "
            f"{Fore.GREEN}{msg}{Style.RESET_ALL}"
        )
        self.logger.info(f"[FOUND] {msg}")

    def vuln(self, msg: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(
            f"{Fore.WHITE}[{timestamp}] "
            f"{Fore.RED}{Style.BRIGHT}🚨 [  VULN  ]{Style.RESET_ALL} "
            f"{Fore.RED}{Style.BRIGHT}{msg}{Style.RESET_ALL}"
        )
        self.logger.critical(f"[VULN] {msg}")

    def skip(self, msg: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(
            f"{Fore.WHITE}[{timestamp}] "
            f"{Fore.YELLOW}⏭️  [ SKIP   ]{Style.RESET_ALL} {msg}"
        )
        self.logger.info(f"[SKIP] {msg}")

    def progress(self, current: int, total: int, tool_name: str = "") -> None:
        total = max(1, int(total))
        percent = (current / total) * 100
        bar_length = 30
        filled = int(bar_length * current // total)
        bar = "█" * filled + "░" * (bar_length - filled)
        sys.stdout.write(
            f"\r{Fore.WHITE}    ⏳ {tool_name} "
            f"[{Fore.CYAN}{bar}{Fore.WHITE}] {percent:.1f}% ({current}/{total})"
        )
        if current >= total:
            sys.stdout.write("\n")
        sys.stdout.flush()
