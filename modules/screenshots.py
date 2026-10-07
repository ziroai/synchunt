"""
SyncHunt - Visual Recon
Screenshots of live web applications via gowitness (v3 or v2 syntax) or
aquatone, so findings can be verified visually at triage time.
"""

from __future__ import annotations

import os
import time
from typing import List

from core.models import Asset
from core.utils import read_file_lines


class ScreenshotCapture:
    """Capture screenshots of live hosts."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.runner = ctx.runner
        self.logger = ctx.logger
        self.output_dir = ctx.path("screenshots")
        self.live_hosts_file = ctx.resolve_file("live_hosts", "dns", "live_hosts.txt")
        os.makedirs(self.output_dir, exist_ok=True)

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("VISUAL RECON", 14)
        started = time.time()

        hosts = read_file_lines(self.live_hosts_file)
        if not hosts:
            self.logger.warning("No live hosts for screenshots")
            return self.output_dir

        self.logger.info(f"Capturing screenshots for {len(hosts)} host(s)...")
        captured = 0
        if self.config.is_tool_enabled("screenshots", "gowitness"):
            captured += self.run_gowitness()
        if self.config.is_tool_enabled("screenshots", "aquatone") and captured == 0:
            captured += self.run_aquatone()

        if captured == 0:
            self.logger.skip(
                "no screenshot tool available (install gowitness or aquatone)"
            )

        self.logger.result(
            f"Visual Recon Complete: {captured} screenshot(s) in {time.time() - started:.1f}s"
        )
        return self.output_dir

    # ------------------------------------------------------------------
    def _hosts_limited(self) -> List[str]:
        limit = self.config.get_int("screenshots.max_hosts", 100)
        return read_file_lines(self.live_hosts_file)[:limit]

    def _count_images(self, directory: str) -> int:
        if not os.path.isdir(directory):
            return 0
        count = 0
        for root, _dirs, files in os.walk(directory):
            count += sum(1 for name in files if name.lower().endswith((".png", ".jpg", ".jpeg")))
        return count

    def run_gowitness(self) -> int:
        if self.runner.require("gowitness"):
            return 0

        cfg = self.config.get_tool_config("screenshots", "gowitness")
        gowitness_dir = os.path.join(self.output_dir, "gowitness")
        os.makedirs(gowitness_dir, exist_ok=True)
        hosts_file = os.path.join(self.output_dir, "screenshot_targets.txt")
        from core.utils import write_file_lines

        write_file_lines(hosts_file, self._hosts_limited())

        resolution = str(cfg.get("resolution", "1440,900")).split(",")
        res_x = resolution[0] if resolution else "1440"
        res_y = resolution[1] if len(resolution) > 1 else "900"
        common = [
            "--threads", str(cfg.get("threads", 10)),
            "--timeout", str(cfg.get("timeout", 10)),
        ]

        self.logger.info("Running gowitness...")
        # gowitness v3 uses subcommands ("scan file"), v2 used "file".
        attempts = [
            ["gowitness", "scan", "file", "-f", hosts_file,
             "--screenshot-path", gowitness_dir, *common],
            ["gowitness", "file", "-f", hosts_file,
             "--screenshot-path", gowitness_dir,
             "--resolution-x", str(res_x), "--resolution-y", str(res_y), *common],
        ]
        for cmd in attempts:
            result = self.runner.run(cmd, tool_name="gowitness", timeout=3600)
            if result.get("success") or self._count_images(gowitness_dir) > 0:
                break

        captured = self._count_images(gowitness_dir)
        if captured:
            self.logger.found(f"gowitness: {captured} screenshot(s)")
            self.runner.run(
                ["gowitness", "report", "generate", "--screenshot-path", gowitness_dir],
                tool_name="gowitness-report", timeout=120,
            )
            self.ctx.record_assets(
                [
                    Asset(kind="screenshot", value=f"{gowitness_dir}/{name}",
                          source="screenshots")
                    for name in os.listdir(gowitness_dir)
                    if name.lower().endswith((".png", ".jpg", ".jpeg"))
                ]
            )
        return captured

    def run_aquatone(self) -> int:
        if self.runner.require("aquatone"):
            return 0

        cfg = self.config.get_tool_config("screenshots", "aquatone")
        aquatone_dir = os.path.join(self.output_dir, "aquatone")
        os.makedirs(aquatone_dir, exist_ok=True)
        seed = "\n".join(self._hosts_limited()) + "\n"

        self.logger.info("Running aquatone...")
        self.runner.run_with_stdin(
            [
                "aquatone",
                "-threads", str(cfg.get("threads", 5)),
                "-http-timeout", str(cfg.get("timeout", 15000)),
                "-out", aquatone_dir,
            ],
            seed,
            tool_name="aquatone",
            timeout=3600,
        )
        captured = self._count_images(aquatone_dir)
        report = os.path.join(aquatone_dir, "aquatone_report.html")
        if os.path.exists(report):
            self.logger.found(f"aquatone report: {report}")
        if captured:
            self.logger.found(f"aquatone: {captured} screenshot(s)")
        return captured
