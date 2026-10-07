"""
BugHuntRecon - Subdomain Validation Module
Integrates: httpx, dnsx, massdns
"""

import os
import json
import time
from core.utils import read_file_lines, write_file_lines, get_timestamp


class SubdomainValidator:
    """Validates subdomains for live hosts and DNS resolution."""

    def __init__(self, config, runner, logger, output_dir, subdomains_file):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = os.path.join(output_dir, "dns")
        self.subdomains_file = subdomains_file
        self.live_hosts = []
        self.resolved = []

        os.makedirs(self.output_dir, exist_ok=True)

    def run_all(self):
        """Run all validation tools."""
        self.logger.phase_banner("SUBDOMAIN VALIDATION", 2)
        start_time = time.time()

        subdomains = read_file_lines(self.subdomains_file)
        if not subdomains:
            self.logger.warning("No subdomains to validate!")
            return None

        self.logger.info(f"Validating {len(subdomains)} subdomains...")

        # Run httpx (primary)
        if self.config.is_tool_enabled('subdomain_validation', 'httpx'):
            try:
                self.run_httpx()
            except Exception as e:
                self.logger.error(f"httpx failed: {str(e)}")

        # Run dnsx
        if self.config.is_tool_enabled('subdomain_validation', 'dnsx'):
            try:
                self.run_dnsx()
            except Exception as e:
                self.logger.error(f"dnsx failed: {str(e)}")

        # Run massdns
        if self.config.is_tool_enabled('subdomain_validation', 'massdns'):
            try:
                self.run_massdns()
            except Exception as e:
                self.logger.error(f"massdns failed: {str(e)}")

        duration = time.time() - start_time
        live_count = len(read_file_lines(self.get_live_hosts_file()))
        self.logger.result(
            f"Validation Complete: {live_count} live hosts found in {duration:.1f}s"
        )

        return self.get_live_hosts_file()

    def run_httpx(self):
        """Run httpx to probe for live HTTP/HTTPS hosts."""
        self.logger.info("Running httpx for live host detection...")

        tool_config = self.config.get_tool_config('subdomain_validation', 'httpx')

        output_file = os.path.join(self.output_dir, "httpx_output.txt")
        live_file = self.get_live_hosts_file()
        json_file = os.path.join(self.output_dir, "httpx_detailed.json")

        cmd = f"httpx -l {self.subdomains_file} -silent"

        # Add options
        threads = tool_config.get('threads', 50)
        cmd += f" -threads {threads}"

        timeout = tool_config.get('timeout', 10)
        cmd += f" -timeout {timeout}"

        if tool_config.get('follow_redirects', True):
            cmd += " -follow-redirects"
        if tool_config.get('status_code', True):
            cmd += " -status-code"
        if tool_config.get('title', True):
            cmd += " -title"
        if tool_config.get('tech_detect', True):
            cmd += " -tech-detect"
        if tool_config.get('content_length', True):
            cmd += " -content-length"
        if tool_config.get('web_server', True):
            cmd += " -web-server"

        cmd += f" -o {output_file}"

        # Run with detailed JSON output
        result = self.runner.run(cmd, tool_name="httpx", timeout=900)

        # Also run for just URLs (clean list)
        cmd_clean = (
            f"httpx -l {self.subdomains_file} -silent "
            f"-threads {threads} -timeout {timeout} -no-color"
        )
        if tool_config.get('follow_redirects', True):
            cmd_clean += " -follow-redirects"

        result_clean = self.runner.run(
            cmd_clean,
            output_file=live_file,
            tool_name="httpx-clean",
            timeout=900
        )

        # Also get JSON output for detailed analysis
        cmd_json = (
            f"httpx -l {self.subdomains_file} -silent "
            f"-threads {threads} -timeout {timeout} "
            f"-json -follow-redirects "
            f"-status-code -title -tech-detect -content-length -web-server"
        )

        result_json = self.runner.run(
            cmd_json,
            output_file=json_file,
            tool_name="httpx-json",
            timeout=900
        )

        live_hosts = read_file_lines(live_file)
        self.live_hosts = live_hosts
        self.logger.found(f"httpx: {len(live_hosts)} live hosts detected")

        return live_hosts

    def run_dnsx(self):
        """Run dnsx for DNS resolution."""
        self.logger.info("Running dnsx for DNS resolution...")

        tool_config = self.config.get_tool_config('subdomain_validation', 'dnsx')

        output_file = os.path.join(self.output_dir, "dnsx_output.txt")
        ip_file = os.path.join(self.output_dir, "resolved_ips.txt")

        cmd = f"dnsx -l {self.subdomains_file} -silent"

        threads = tool_config.get('threads', 100)
        cmd += f" -threads {threads}"

        if tool_config.get('resp', True):
            cmd += " -resp"

        cmd += f" -o {output_file}"

        result = self.runner.run(cmd, tool_name="dnsx", timeout=600)

        # Extract IPs
        cmd_ip = (
            f"dnsx -l {self.subdomains_file} -silent "
            f"-threads {threads} -a -resp-only"
        )

        result_ip = self.runner.run(
            cmd_ip,
            output_file=ip_file,
            tool_name="dnsx-ips",
            timeout=600
        )

        resolved = read_file_lines(output_file)
        self.resolved = resolved
        self.logger.found(f"dnsx: {len(resolved)} domains resolved")

        return resolved

    def run_massdns(self):
        """Run massdns for high-performance DNS resolution."""
        self.logger.info("Running massdns for DNS resolution...")

        tool_config = self.config.get_tool_config('subdomain_validation', 'massdns')

        output_file = os.path.join(self.output_dir, "massdns_output.txt")
        resolvers = tool_config.get('resolvers', 'wordlists/resolvers.txt')

        # Create default resolvers file if it doesn't exist
        if not os.path.exists(resolvers):
            self.logger.warning(
                f"Resolvers file not found at {resolvers}, creating default..."
            )
            os.makedirs(os.path.dirname(resolvers) or '.', exist_ok=True)
            default_resolvers = [
                "8.8.8.8", "8.8.4.4",
                "1.1.1.1", "1.0.0.1",
                "9.9.9.9", "149.112.112.112",
                "208.67.222.222", "208.67.220.220",
                "64.6.64.6", "64.6.65.6",
            ]
            write_file_lines(resolvers, default_resolvers)

        rate = tool_config.get('rate', 500)

        cmd = (
            f"massdns -r {resolvers} -t A -o S "
            f"-s {rate} {self.subdomains_file}"
        )

        result = self.runner.run(
            cmd,
            output_file=output_file,
            tool_name="massdns",
            timeout=600
        )

        resolved = read_file_lines(output_file)
        self.logger.found(f"massdns: {len(resolved)} DNS records resolved")

        return resolved

    def get_live_hosts_file(self):
        """Get path to the live hosts file."""
        return os.path.join(self.output_dir, "live_hosts.txt")

    def get_resolved_ips_file(self):
        """Get path to resolved IPs file."""
        return os.path.join(self.output_dir, "resolved_ips.txt")