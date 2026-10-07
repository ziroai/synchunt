"""
BugHuntRecon - Port Scanning Module
Integrates: Naabu, Nmap, Masscan
"""

import os
import json
import time
from core.utils import read_file_lines, write_file_lines, get_timestamp


class PortScanner:
    """Orchestrates port scanning tools."""

    def __init__(self, config, runner, logger, output_dir, targets_file):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = os.path.join(output_dir, "ports")
        self.targets_file = targets_file
        self.open_ports = {}

        os.makedirs(self.output_dir, exist_ok=True)

    def run_all(self):
        """Run all enabled port scanning tools."""
        self.logger.phase_banner("PORT SCANNING", 3)
        start_time = time.time()

        targets = read_file_lines(self.targets_file)
        if not targets:
            self.logger.warning("No targets for port scanning!")
            return None

        # Clean targets (extract hostnames from URLs)
        clean_targets = []
        for t in targets:
            t = t.replace('https://', '').replace('http://', '')
            t = t.split('/')[0].split(':')[0]
            if t:
                clean_targets.append(t)

        clean_targets = list(set(clean_targets))
        clean_file = os.path.join(self.output_dir, "scan_targets.txt")
        write_file_lines(clean_file, clean_targets)

        self.logger.info(f"Scanning ports on {len(clean_targets)} targets...")

        # Run Naabu
        if self.config.is_tool_enabled('port_scanning', 'naabu'):
            try:
                self.run_naabu(clean_file)
            except Exception as e:
                self.logger.error(f"Naabu failed: {str(e)}")

        # Run Nmap (on discovered ports)
        if self.config.is_tool_enabled('port_scanning', 'nmap'):
            try:
                self.run_nmap(clean_file)
            except Exception as e:
                self.logger.error(f"Nmap failed: {str(e)}")

        # Run Masscan
        if self.config.is_tool_enabled('port_scanning', 'masscan'):
            try:
                self.run_masscan(clean_file)
            except Exception as e:
                self.logger.error(f"Masscan failed: {str(e)}")

        duration = time.time() - start_time
        self.logger.result(
            f"Port Scanning Complete in {duration:.1f}s"
        )

        return self.get_output_file()

    def run_naabu(self, targets_file):
        """Run Naabu for fast port scanning."""
        self.logger.info("Running Naabu for port scanning...")

        tool_config = self.config.get_tool_config('port_scanning', 'naabu')

        output_file = os.path.join(self.output_dir, "naabu_output.txt")
        json_file = os.path.join(self.output_dir, "naabu_output.json")

        cmd = f"naabu -list {targets_file} -silent"

        top_ports = tool_config.get('top_ports', 1000)
        cmd += f" -top-ports {top_ports}"

        rate = tool_config.get('rate', 5000)
        cmd += f" -rate {rate}"

        threads = tool_config.get('threads', 25)
        cmd += f" -c {threads}"

        scan_type = tool_config.get('scan_type', 's')
        cmd += f" -scan-type {scan_type}"

        cmd += f" -o {output_file}"

        result = self.runner.run(cmd, tool_name="naabu", timeout=1200)

        # Also get JSON output
        cmd_json = cmd.replace(f"-o {output_file}", f"-json -o {json_file}")
        self.runner.run(cmd_json, tool_name="naabu-json", timeout=1200)

        ports = read_file_lines(output_file)
        self.logger.found(f"Naabu: {len(ports)} host:port combinations found")

        # Parse and save structured data
        for line in ports:
            if ':' in line:
                host, port = line.rsplit(':', 1)
                if host not in self.open_ports:
                    self.open_ports[host] = []
                self.open_ports[host].append(port)

        return ports

    def run_nmap(self, targets_file):
        """Run Nmap for service/version detection."""
        self.logger.info("Running Nmap for service detection...")

        tool_config = self.config.get_tool_config('port_scanning', 'nmap')

        output_dir = os.path.join(self.output_dir, "nmap")
        os.makedirs(output_dir, exist_ok=True)

        scan_type = tool_config.get('scan_type', '-sV -sC')
        timing = tool_config.get('timing', 'T4')
        top_ports = tool_config.get('top_ports', 100)

        # If we have naabu results, use those ports
        naabu_file = os.path.join(self.output_dir, "naabu_output.txt")
        targets = read_file_lines(targets_file)

        if os.path.exists(naabu_file) and self.open_ports:
            # Scan specific ports per host
            for host, ports in self.open_ports.items():
                if not ports:
                    continue
                port_str = ','.join(ports)
                output_file = os.path.join(
                    output_dir,
                    f"nmap_{host.replace('.', '_')}"
                )

                cmd = (
                    f"nmap {scan_type} -{timing} -p {port_str} "
                    f"-oA {output_file} {host}"
                )

                self.runner.run(
                    cmd,
                    tool_name=f"nmap-{host}",
                    timeout=600
                )
        else:
            # Scan top ports on all targets
            output_file = os.path.join(output_dir, "nmap_scan")
            cmd = (
                f"nmap {scan_type} -{timing} --top-ports {top_ports} "
                f"-iL {targets_file} -oA {output_file}"
            )

            self.runner.run(cmd, tool_name="nmap", timeout=1800)

        self.logger.found("Nmap service detection complete")

    def run_masscan(self, targets_file):
        """Run Masscan for ultra-fast port scanning."""
        self.logger.info("Running Masscan for port scanning...")

        tool_config = self.config.get_tool_config('port_scanning', 'masscan')

        output_file = os.path.join(self.output_dir, "masscan_output.txt")
        json_file = os.path.join(self.output_dir, "masscan_output.json")

        rate = tool_config.get('rate', 10000)
        ports = tool_config.get('ports', '1-65535')

        cmd = (
            f"sudo masscan -iL {targets_file} -p {ports} "
            f"--rate {rate} -oJ {json_file} "
            f"--open-only"
        )

        result = self.runner.run(cmd, tool_name="masscan", timeout=3600)

        self.logger.found("Masscan scanning complete")

    def get_output_file(self):
        """Get path to the combined port scan output."""
        output_file = os.path.join(self.output_dir, "all_ports.txt")

        # Combine results
        all_lines = []
        for f in ['naabu_output.txt']:
            filepath = os.path.join(self.output_dir, f)
            if os.path.exists(filepath):
                all_lines.extend(read_file_lines(filepath))

        write_file_lines(output_file, all_lines)
        return output_file