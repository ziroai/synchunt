"""
BugHuntRecon - Screenshot & Visual Recon Module
Integrates: Gowitness, Aquatone
"""

import os
import time
from core.utils import read_file_lines


class ScreenshotCapture:
    """Capture screenshots of live web applications."""

    def __init__(self, config, runner, logger, output_dir, live_hosts_file):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = os.path.join(output_dir, "screenshots")
        self.live_hosts_file = live_hosts_file

        os.makedirs(self.output_dir, exist_ok=True)

    def run_all(self):
        """Run all screenshot tools."""
        self.logger.phase_banner("VISUAL RECON / SCREENSHOTS", 9)
        start_time = time.time()

        live_hosts = read_file_lines(self.live_hosts_file)
        if not live_hosts:
            self.logger.warning("No live hosts for screenshots!")
            return None

        self.logger.info(f"Taking screenshots of {len(live_hosts)} hosts...")

        # Gowitness
        if self.config.is_tool_enabled('screenshots', 'gowitness'):
            try:
                self.run_gowitness()
            except Exception as e:
                self.logger.error(f"Gowitness failed: {str(e)}")

        # Aquatone
        if self.config.is_tool_enabled('screenshots', 'aquatone'):
            try:
                self.run_aquatone()
            except Exception as e:
                self.logger.error(f"Aquatone failed: {str(e)}")

        duration = time.time() - start_time
        self.logger.result(f"Screenshots Complete in {duration:.1f}s")

        return self.output_dir

    def run_gowitness(self):
        """Run Gowitness for screenshots."""
        self.logger.info("Running Gowitness...")

        tool_config = self.config.get_tool_config('screenshots', 'gowitness')

        gowitness_dir = os.path.join(self.output_dir, "gowitness")
        os.makedirs(gowitness_dir, exist_ok=True)

        threads = tool_config.get('threads', 10)
        timeout = tool_config.get('timeout', 10)
        resolution = tool_config.get('resolution', '1440,900')

        res_parts = resolution.split(',')
        res_x = res_parts[0] if len(res_parts) > 0 else '1440'
        res_y = res_parts[1] if len(res_parts) > 1 else '900'

        cmd = (
            f"gowitness file -f {self.live_hosts_file} "
            f"--threads {threads} "
            f"--timeout {timeout} "
            f"--resolution-x {res_x} "
            f"--resolution-y {res_y} "
            f"--screenshot-path {gowitness_dir}"
        )

        result = self.runner.run(cmd, tool_name="gowitness", timeout=1800)

        # Count screenshots
        screenshots = [
            f for f in os.listdir(gowitness_dir)
            if f.endswith(('.png', '.jpg', '.jpeg'))
        ]

        self.logger.found(f"Gowitness: {len(screenshots)} screenshots captured")

        # Generate report
        cmd_report = (
            f"gowitness report generate "
            f"--screenshot-path {gowitness_dir}"
        )
        self.runner.run(cmd_report, tool_name="gowitness-report", timeout=60)

    def run_aquatone(self):
        """Run Aquatone for visual recon."""
        self.logger.info("Running Aquatone...")

        tool_config = self.config.get_tool_config('screenshots', 'aquatone')

        aquatone_dir = os.path.join(self.output_dir, "aquatone")
        os.makedirs(aquatone_dir, exist_ok=True)

        threads = tool_config.get('threads', 5)
        timeout = tool_config.get('timeout', 15000)

        cmd = (
            f"cat {self.live_hosts_file} | aquatone "
            f"-threads {threads} "
            f"-http-timeout {timeout} "
            f"-out {aquatone_dir}"
        )

        result = self.runner.run(
            cmd,
            tool_name="aquatone",
            timeout=1800,
            shell=True
        )

        # Check for report
        report_file = os.path.join(aquatone_dir, "aquatone_report.html")
        if os.path.exists(report_file):
            self.logger.found(
                f"Aquatone: Report generated at {report_file}"
            )
        else:
            self.logger.info("Aquatone processing complete")