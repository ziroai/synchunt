"""
BugHuntRecon - Web Technology Fingerprinting Module
Integrates: WhatWeb, wafw00f, webanalyze
"""

import os
import json
import time
from core.utils import read_file_lines, write_file_lines


class Fingerprinter:
    """Web technology fingerprinting and WAF detection."""

    def __init__(self, config, runner, logger, output_dir, live_hosts_file):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = os.path.join(output_dir, "fingerprinting")
        self.live_hosts_file = live_hosts_file
        self.technologies = {}

        os.makedirs(self.output_dir, exist_ok=True)

    def run_all(self):
        """Run all fingerprinting tools."""
        self.logger.phase_banner("WEB FINGERPRINTING", 4)
        start_time = time.time()

        live_hosts = read_file_lines(self.live_hosts_file)
        if not live_hosts:
            self.logger.warning("No live hosts for fingerprinting!")
            return None

        self.logger.info(f"Fingerprinting {len(live_hosts)} live hosts...")

        # WhatWeb
        if self.config.is_tool_enabled('fingerprinting', 'whatweb'):
            try:
                self.run_whatweb()
            except Exception as e:
                self.logger.error(f"WhatWeb failed: {str(e)}")

        # wafw00f
        if self.config.is_tool_enabled('fingerprinting', 'wafw00f'):
            try:
                self.run_wafw00f()
            except Exception as e:
                self.logger.error(f"wafw00f failed: {str(e)}")

        # webanalyze
        if self.config.is_tool_enabled('fingerprinting', 'webanalyze'):
            try:
                self.run_webanalyze()
            except Exception as e:
                self.logger.error(f"webanalyze failed: {str(e)}")

        duration = time.time() - start_time
        self.logger.result(f"Fingerprinting Complete in {duration:.1f}s")

        return self.output_dir

    def run_whatweb(self):
        """Run WhatWeb for technology detection."""
        self.logger.info("Running WhatWeb...")

        tool_config = self.config.get_tool_config('fingerprinting', 'whatweb')
        output_file = os.path.join(self.output_dir, "whatweb_output.txt")
        json_file = os.path.join(self.output_dir, "whatweb_output.json")

        aggression = tool_config.get('aggression', 3)

        hosts = read_file_lines(self.live_hosts_file)

        # WhatWeb can read from file using -i
        cmd = (
            f"whatweb -i {self.live_hosts_file} "
            f"-a {aggression} "
            f"--log-json={json_file} "
            f"--log-verbose={output_file} "
            f"--no-errors"
        )

        result = self.runner.run(cmd, tool_name="whatweb", timeout=900)

        self.logger.found("WhatWeb fingerprinting complete")

    def run_wafw00f(self):
        """Run wafw00f for WAF detection."""
        self.logger.info("Running wafw00f for WAF detection...")

        output_file = os.path.join(self.output_dir, "wafw00f_output.txt")
        json_file = os.path.join(self.output_dir, "wafw00f_output.json")

        cmd = (
            f"wafw00f -i {self.live_hosts_file} "
            f"-o {json_file} -f json"
        )

        result = self.runner.run(
            cmd,
            output_file=output_file,
            tool_name="wafw00f",
            timeout=600
        )

        waf_results = read_file_lines(output_file)
        waf_detected = [l for l in waf_results if 'behind' in l.lower() or 'waf' in l.lower()]

        if waf_detected:
            self.logger.found(f"wafw00f: WAF detected on {len(waf_detected)} hosts")
        else:
            self.logger.info("wafw00f: No WAF detected")

    def run_webanalyze(self):
        """Run webanalyze for technology stack detection."""
        self.logger.info("Running webanalyze...")

        output_file = os.path.join(self.output_dir, "webanalyze_output.json")

        hosts = read_file_lines(self.live_hosts_file)

        # webanalyze processes one host at a time or via crawl
        results = []
        for host in hosts:
            cmd = f"webanalyze -host {host} -output json -silent"

            result = self.runner.run(
                cmd,
                tool_name=f"webanalyze-{host}",
                timeout=30
            )

            if result['success'] and result['stdout']:
                results.append({
                    'host': host,
                    'output': result['stdout']
                })

        # Save combined results
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        self.logger.found(f"webanalyze: Analyzed {len(results)} hosts")