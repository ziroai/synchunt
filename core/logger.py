"""
BugHuntRecon - Logging Framework
Colored terminal output + file logging
"""

import logging
import os
import sys
from datetime import datetime
from colorama import init, Fore, Style, Back

init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Custom colored formatter for terminal output."""

    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.WHITE + Back.RED,
    }

    ICONS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️ ',
        'ERROR': '❌',
        'CRITICAL': '🚨',
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, '')
        icon = self.ICONS.get(record.levelname, '')
        reset = Style.RESET_ALL

        timestamp = datetime.now().strftime('%H:%M:%S')

        formatted = (
            f"{Fore.WHITE}[{timestamp}] "
            f"{color}{icon}  [{record.levelname:^8}]{reset} "
            f"{color}{record.getMessage()}{reset}"
        )
        return formatted


class FileFormatter(logging.Formatter):
    """Clean formatter for file logging."""

    def format(self, record):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return f"[{timestamp}] [{record.levelname:^8}] {record.getMessage()}"


class BugHuntLogger:
    """Main logger class for BugHuntRecon."""

    def __init__(self, name="BugHuntRecon", output_dir="output", verbose=True):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.handlers = []

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        console_handler.setFormatter(ColoredFormatter())
        self.logger.addHandler(console_handler)

        # File handler
        log_dir = os.path.join(output_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(
            log_dir,
            f"recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(FileFormatter())
        self.logger.addHandler(file_handler)

    def debug(self, msg):
        self.logger.debug(msg)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)

    def critical(self, msg):
        self.logger.critical(msg)

    def banner(self):
        """Print the tool banner."""
        banner_text = f"""
{Fore.RED}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗ ║
║   ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝ ║
║   ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║    ║
║   ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║    ║
║   ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║    ║
║   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ║
║                                                              ║
║          {Fore.YELLOW}🔥 Automated Bug Hunting Recon Framework 🔥{Fore.RED}          ║
║           {Fore.CYAN}       v1.0 | by BugHuntRecon Team{Fore.RED}                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
        print(banner_text)

    def phase_banner(self, phase_name, phase_num=None):
        """Print a phase separator banner."""
        phase_str = f"PHASE {phase_num}: " if phase_num else ""
        width = 60
        msg = f"{phase_str}{phase_name}"
        padding = width - len(msg) - 4
        left_pad = padding // 2
        right_pad = padding - left_pad

        print(f"\n{Fore.CYAN}{Style.BRIGHT}")
        print(f"{'═' * width}")
        print(f"║ {' ' * left_pad}{msg}{' ' * right_pad} ║")
        print(f"{'═' * width}")
        print(f"{Style.RESET_ALL}")

    def result(self, msg):
        """Print a result line."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(
            f"{Fore.WHITE}[{timestamp}] "
            f"{Fore.MAGENTA}📌 [RESULT  ]{Style.RESET_ALL} "
            f"{Fore.MAGENTA}{msg}{Style.RESET_ALL}"
        )
        self.logger.info(f"[RESULT] {msg}")

    def found(self, msg):
        """Print a found item."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(
            f"{Fore.WHITE}[{timestamp}] "
            f"{Fore.GREEN}🎯 [ FOUND  ]{Style.RESET_ALL} "
            f"{Fore.GREEN}{msg}{Style.RESET_ALL}"
        )
        self.logger.info(f"[FOUND] {msg}")

    def vuln(self, msg):
        """Print a vulnerability found."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(
            f"{Fore.WHITE}[{timestamp}] "
            f"{Fore.RED}{Style.BRIGHT}🚨 [  VULN  ]{Style.RESET_ALL} "
            f"{Fore.RED}{Style.BRIGHT}{msg}{Style.RESET_ALL}"
        )
        self.logger.critical(f"[VULN] {msg}")

    def progress(self, current, total, tool_name=""):
        """Print progress bar."""
        percent = (current / total) * 100 if total > 0 else 0
        bar_length = 30
        filled = int(bar_length * current // total) if total > 0 else 0
        bar = '█' * filled + '░' * (bar_length - filled)

        sys.stdout.write(
            f"\r{Fore.WHITE}    ⏳ {tool_name} "
            f"[{Fore.CYAN}{bar}{Fore.WHITE}] "
            f"{percent:.1f}% ({current}/{total})"
        )
        if current == total:
            sys.stdout.write('\n')
        sys.stdout.flush()