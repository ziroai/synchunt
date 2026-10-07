"""
BugHuntRecon - Vulnerability Scanning Module
Integrates: Nuclei, Nikto, Dalfox, SQLMap, CRLFuzz, Corsy
"""

import os
import json
import time
from core.utils import read_file_lines, write_file_lines


class VulnScanner:
    """Orchestrates vulnerability scanning tools."""

    def __init__(self, config, runner, logger, output_dir,
                 live_hosts_file, urls_file, params_file):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = os.path.join(output_dir, "vulnerabilities")
        self.live_hosts_file = live_hosts_file
        self.urls_file = urls_file
        self.params_file = params_file
        self.vulns = []

        os.makedirs(self.output_dir, exist_ok=True)

    def run_all(self):
        """Run all vulnerability scanning tools."""
        self.logger.phase_banner("VULNERABILITY SCANNING", 7)
        start_time = time.time()

        live_hosts = read_file_lines(self.live_hosts_file)
        if not live_hosts:
            self.logger.warning("No targets for vulnerability scanning!")
            return None

        self.logger.info(f"Scanning {len(live_hosts)} targets for vulnerabilities...")

        # Nuclei - Primary scanner
        if self.config.is_tool_enabled('vuln_scanning', 'nuclei'):
            try:
                self.run_nuclei()
            except Exception as e:
                self.logger.error(f"Nuclei failed: {str(e)}")

        # Nikto
        if self.config.is_tool_enabled('vuln_scanning', 'nikto'):
            try:
                self.run_nikto()
            except Exception as e:
                self.logger.error(f"Nikto failed: {str(e)}")

        # Dalfox - XSS Scanner
        if self.config.is_tool_enabled('vuln_scanning', 'dalfox'):
            try:
                self.run_dalfox()
            except Exception as e:
                self.logger.error(f"Dalfox failed: {str(e)}")

        # SQLMap
        if self.config.is_tool_enabled('vuln_scanning', 'sqlmap'):
            try:
                self.run_sqlmap()
            except Exception as e:
                self.logger.error(f"SQLMap failed: {str(e)}")

        # CRLFuzz
        if self.config.is_tool_enabled('vuln_scanning', 'crlfuzz'):
            try:
                self.run_crlfuzz()
            except Exception as e:
                self.logger.error(f"CRLFuzz failed: {str(e)}")

        # Corsy - CORS
        if self.config.is_tool_enabled('vuln_scanning', 'corsy'):
            try:
                self.run_corsy()
            except Exception as e:
                self.logger.error(f"Corsy failed: {str(e)}")

        # Open Redirect Check
        self._check_open_redirects()

        duration = time.time() - start_time
        self.logger.result(
            f"Vulnerability Scanning Complete: {len(self.vulns)} potential "
            f"vulnerabilities found in {duration:.1f}s"
        )

        return self.output_dir

    def run_nuclei(self):
        """Run Nuclei template-based vulnerability scanner."""
        self.logger.info("Running Nuclei vulnerability scanner...")

        tool_config = self.config.get_tool_config('vuln_scanning', 'nuclei')

        nuclei_dir = os.path.join(self.output_dir, "nuclei")
        os.makedirs(nuclei_dir, exist_ok=True)

        output_file = os.path.join(nuclei_dir, "nuclei_output.txt")
        json_file = os.path.join(nuclei_dir, "nuclei_output.json")

        cmd = f"nuclei -l {self.live_hosts_file} -silent"

        # Severity
        severity = tool_config.get('severity', 'critical,high,medium,low,info')
        cmd += f" -severity {severity}"

        # Rate limiting
        rate_limit = tool_config.get('rate_limit', 150)
        cmd += f" -rl {rate_limit}"

        # Concurrency
        bulk_size = tool_config.get('bulk_size', 25)
        cmd += f" -bs {bulk_size}"

        concurrency = tool_config.get('concurrency', 25)
        cmd += f" -c {concurrency}"

        # Templates
        templates = tool_config.get('templates', '')
        if templates:
            cmd += f" -t {templates}"

        # New templates
        if tool_config.get('new_templates', True):
            cmd += " -nt"

        # Automatic scan
        if tool_config.get('automatic_scan', True):
            cmd += " -as"

        # Headless
        if tool_config.get('headless', False):
            cmd += " -headless"

        cmd += f" -o {output_file}"
        cmd += f" -je {json_file}"

        result = self.runner.run(cmd, tool_name="nuclei", timeout=3600)

        # Parse results
        findings = read_file_lines(output_file)
        for finding in findings:
            self.vulns.append(finding)
            if any(sev in finding.lower() for sev in ['critical', 'high']):
                self.logger.vuln(finding)
            else:
                self.logger.found(finding)

        self.logger.found(f"Nuclei: {len(findings)} findings")

    def run_nikto(self):
        """Run Nikto web server scanner."""
        self.logger.info("Running Nikto web server scanner...")

        nikto_dir = os.path.join(self.output_dir, "nikto")
        os.makedirs(nikto_dir, exist_ok=True)

        tool_config = self.config.get_tool_config('vuln_scanning', 'nikto')
        tuning = tool_config.get('tuning', '1234567890')

        live_hosts = read_file_lines(self.live_hosts_file)

        for host in live_hosts[:10]:  # Limit to 10 hosts
            safe_host = host.replace('https://', '').replace('http://', '')
            safe_host = safe_host.replace('/', '_').replace(':', '_')
            output_file = os.path.join(nikto_dir, f"nikto_{safe_host}.txt")

            cmd = (
                f"nikto -h {host} "
                f"-Tuning {tuning} "
                f"-output {output_file} "
                f"-Format txt -nointeractive"
            )

            self.runner.run(
                cmd,
                tool_name=f"nikto-{safe_host[:30]}",
                timeout=600
            )

        self.logger.found("Nikto scanning complete")

    def run_dalfox(self):
        """Run Dalfox XSS scanner."""
        self.logger.info("Running Dalfox XSS scanner...")

        xss_dir = os.path.join(self.output_dir, "xss")
        os.makedirs(xss_dir, exist_ok=True)

        tool_config = self.config.get_tool_config('vuln_scanning', 'dalfox')
        output_file = os.path.join(xss_dir, "dalfox_output.txt")
        json_file = os.path.join(xss_dir, "dalfox_output.json")

        # Use parameterized URLs if available
        scan_file = self.params_file if os.path.exists(self.params_file or '') else self.urls_file

        if not scan_file or not os.path.exists(scan_file):
            self.logger.warning("No URLs available for XSS scanning")
            return

        threads = tool_config.get('threads', 10)
        blind_xss = tool_config.get('blind_xss', '')

        cmd = (
            f"dalfox file {scan_file} "
            f"-w {threads} "
            f"--silence "
            f"-o {output_file}"
        )

        if blind_xss:
            cmd += f" -b {blind_xss}"

        result = self.runner.run(cmd, tool_name="dalfox", timeout=1800)

        xss_results = read_file_lines(output_file)
        for xss in xss_results:
            self.vulns.append(f"[XSS] {xss}")
            self.logger.vuln(f"XSS Found: {xss}")

        self.logger.found(f"Dalfox: {len(xss_results)} potential XSS found")

    def run_sqlmap(self):
        """Run SQLMap for SQL injection detection."""
        self.logger.info("Running SQLMap for SQL injection detection...")

        sqli_dir = os.path.join(self.output_dir, "sqli")
        os.makedirs(sqli_dir, exist_ok=True)

        tool_config = self.config.get_tool_config('vuln_scanning', 'sqlmap')

        # Use parameterized URLs
        if not self.params_file or not os.path.exists(self.params_file):
            self.logger.warning("No parameterized URLs for SQLMap")
            return

        params_urls = read_file_lines(self.params_file)
        level = tool_config.get('level', 1)
        risk = tool_config.get('risk', 1)

        for url in params_urls[:20]:  # Limit heavily
            safe_name = url.replace('https://', '').replace('http://', '')
            safe_name = safe_name[:50].replace('/', '_').replace('?', '_')
            output_dir_sqli = os.path.join(sqli_dir, safe_name)

            cmd = (
                f"sqlmap -u \"{url}\" "
                f"--level {level} --risk {risk} "
                f"--batch --random-agent "
                f"--output-dir={output_dir_sqli} "
                f"--threads 5"
            )

            result = self.runner.run(
                cmd,
                tool_name=f"sqlmap",
                timeout=300,
                shell=True
            )

            if result['success'] and 'injectable' in result['stdout'].lower():
                self.vulns.append(f"[SQLi] {url}")
                self.logger.vuln(f"SQL Injection Found: {url}")

    def run_crlfuzz(self):
        """Run CRLFuzz for CRLF injection scanning."""
        self.logger.info("Running CRLFuzz...")

        crlf_dir = os.path.join(self.output_dir, "crlf")
        os.makedirs(crlf_dir, exist_ok=True)

        output_file = os.path.join(crlf_dir, "crlfuzz_output.txt")

        tool_config = self.config.get_tool_config('vuln_scanning', 'crlfuzz')
        concurrency = tool_config.get('concurrency', 25)

        cmd = (
            f"crlfuzz -l {self.live_hosts_file} "
            f"-c {concurrency} "
            f"-s "
            f"-o {output_file}"
        )

        result = self.runner.run(cmd, tool_name="crlfuzz", timeout=600)

        crlf_results = read_file_lines(output_file)
        for crlf in crlf_results:
            self.vulns.append(f"[CRLF] {crlf}")
            self.logger.vuln(f"CRLF Injection: {crlf}")

        self.logger.found(f"CRLFuzz: {len(crlf_results)} potential CRLF injections")

    def run_corsy(self):
        """Run Corsy for CORS misconfiguration scanning."""
        self.logger.info("Running Corsy for CORS misconfiguration...")

        cors_dir = os.path.join(self.output_dir, "cors")
        os.makedirs(cors_dir, exist_ok=True)

        output_file = os.path.join(cors_dir, "corsy_output.json")

        tool_config = self.config.get_tool_config('vuln_scanning', 'corsy')
        threads = tool_config.get('threads', 20)

        cmd = (
            f"corsy -i {self.live_hosts_file} "
            f"-t {threads} "
            f"-o {output_file}"
        )

        result = self.runner.run(cmd, tool_name="corsy", timeout=600)

        self.logger.found("Corsy: CORS scanning complete")

    def _check_open_redirects(self):
        """Check for open redirect vulnerabilities using patterns."""
        self.logger.info("Checking for open redirects...")

        redirect_dir = os.path.join(self.output_dir, "open_redirect")
        os.makedirs(redirect_dir, exist_ok=True)

        if not self.urls_file or not os.path.exists(self.urls_file):
            return

        all_urls = read_file_lines(self.urls_file)

        # Common redirect parameter patterns
        redirect_params = [
            'redirect', 'url', 'next', 'dest', 'destination',
            'redir', 'redirect_url', 'redirect_uri', 'return',
            'return_url', 'returnTo', 'go', 'goto', 'out',
            'view', 'to', 'ref', 'referrer', 'continue',
            'forward', 'target', 'link', 'callback'
        ]

        suspicious_urls = []
        for url in all_urls:
            url_lower = url.lower()
            for param in redirect_params:
                if f'{param}=' in url_lower:
                    suspicious_urls.append(url)
                    break

        output_file = os.path.join(redirect_dir, "potential_redirects.txt")
        write_file_lines(output_file, suspicious_urls)

        self.logger.found(
            f"Open Redirect: {len(suspicious_urls)} potentially "
            f"vulnerable URLs found"
        )