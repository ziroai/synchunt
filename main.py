#!/usr/bin/env python3
"""
Synchunt - Enhanced Main Entry Point with Advanced Recon Pipeline
Orchestrates all modules with parallel execution, state tracking, and result correlation.
"""

import os
import sys
import time
import signal
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.logger import BugHuntLogger
from core.config_manager import ConfigManager
from core.runner import ToolRunner
from core.dependency_checker import DependencyChecker
from core.database_manager import DatabaseManager
from core.utils import (
    create_output_structure, read_file_lines,
    is_valid_domain, format_duration, save_json, get_file_count
)

# Original modules
from modules.subdomain_enum import SubdomainEnumerator
from modules.subdomain_validation import SubdomainValidator
from modules.port_scanning import PortScanner
from modules.fingerprinting import Fingerprinter
from modules.content_discovery import ContentDiscovery
from modules.js_analysis import JSAnalyzer
from modules.vuln_scanning import VulnScanner
from modules.sensitive_info import SensitiveInfoScanner
from modules.screenshots import ScreenshotCapture

# Advanced modules
from modules.asset_enrichment import AssetEnrichment
from modules.github_recon import GitHubRecon
from modules.api_introspection import APIIntrospection
from modules.cloud_enum import CloudEnumeration
from modules.finding_prioritizer import FindingPrioritizer
from modules.scope_manager import ScopeManager

# Reporting
from reports.html_report import HTMLReportGenerator
from reports.markdown_report import MarkdownReportGenerator
from reports.notifier import Notifier


class SynchuntAutoRecon:
    """Main orchestrator class for automated bug hunting reconnaissance."""

    PHASES = [
        'subdomain',
        'validation',
        'enrichment',
        'portscan',
        'fingerprint',
        'github_recon',
        'content',
        'api_discovery',
        'jsanalysis',
        'cloud_enum',
        'vulnscan',
        'sensitive',
        'screenshot',
        'prioritize',
        'report'
    ]

    def __init__(self, args):
        self.args = args
        self.scan_start = datetime.now()
        self.scan_end = None

        # Initialize config
        self.config = ConfigManager(args.config)

        # Initialize logger
        base_output = self.config.get('general.output_dir', 'output')
        os.makedirs(base_output, exist_ok=True)
        verbose = args.verbose or self.config.get('general.verbose', True)
        self.logger = BugHuntLogger(
            output_dir=base_output,
            verbose=verbose
        )

        # Initialize runner
        timeout = self.config.get_timeout()
        self.runner = ToolRunner(
            logger=self.logger,
            timeout=timeout,
            verbose=verbose
        )

        # Initialize notifier
        self.notifier = Notifier(self.config, self.logger)

        # State tracking
        self.output_dir = None
        self.targets = []
        self.results = {}
        self.db_manager = None

        # Handle graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        try:
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (OSError, AttributeError):
            pass

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.logger.warning("\nReceived interrupt signal. Cleaning up...")
        self.runner.cleanup()
        self._generate_reports()
        self.logger.info("Cleanup complete. Exiting.")
        sys.exit(0)

    def run(self):
        """Main execution method."""
        self.logger.banner()

        # Parse targets
        self.targets = self._parse_targets()
        if not self.targets:
            self.logger.error("No valid targets specified!")
            sys.exit(1)

        # Check dependencies
        if self.args.check_deps:
            checker = DependencyChecker(self.logger)
            result = checker.check_all()
            if self.args.install_deps:
                checker.auto_install()
            sys.exit(0 if result['ready'] else 1)

        # Run recon on each target
        for target in self.targets:
            self.logger.info(f"\n{'=' * 70}")
            self.logger.info(f"🎯 STARTING COMPREHENSIVE RECON ON: {target}")
            self.logger.info(f"{'=' * 70}\n")

            try:
                self._run_target(target)
            except Exception as e:
                self.logger.error(f"Fatal error on target {target}: {str(e)}")
                import traceback
                self.logger.debug(traceback.format_exc())

        self.scan_end = datetime.now()
        duration = (self.scan_end - self.scan_start).total_seconds()
        self.logger.info(f"\n{'=' * 70}")
        self.logger.result(f"🏁 ALL SCANS COMPLETE! Total time: {format_duration(duration)}")
        self.logger.info(f"{'=' * 70}")

    def _parse_targets(self):
        """Parse and validate targets."""
        targets = []

        if self.args.domain:
            domain = self.args.domain.strip()
            domain = domain.replace('https://', '').replace('http://', '')
            domain = domain.rstrip('/')
            if is_valid_domain(domain):
                targets.append(domain)
            else:
                self.logger.error(f"Invalid domain: {domain}")

        if self.args.list:
            if os.path.exists(self.args.list):
                domains = read_file_lines(self.args.list)
                for d in domains:
                    d = d.replace('https://', '').replace('http://', '').rstrip('/')
                    if is_valid_domain(d):
                        targets.append(d)
                    else:
                        self.logger.warning(f"Skipping invalid domain: {d}")
            else:
                self.logger.error(f"Target list file not found: {self.args.list}")

        return list(dict.fromkeys(targets))

    def _run_target(self, target):
        """Run the complete recon pipeline on a single target."""
        # Create output directory
        self.output_dir = self.config.get_output_dir(target)
        create_output_structure(self.output_dir)
        self.logger.info(f"Output directory: {self.output_dir}")

        # Initialize database manager
        self.db_manager = DatabaseManager(self.output_dir)

        target_start = time.time()

        # Determine which phases to run
        phases_to_run = self._get_phases_to_run()

        # Track file paths between phases
        subdomains_file = None
        live_hosts_file = None
        ports_file = None
        urls_file = None
        js_files_file = None
        params_file = None

        # =====================
        # PHASE 1: Subdomain Enumeration
        # =====================
        if 'subdomain' in phases_to_run and self.config.is_phase_enabled('subdomain_enum'):
            self.logger.phase_banner("PHASE 1: SUBDOMAIN ENUMERATION", 1)
            enumerator = SubdomainEnumerator(
                self.config, self.runner, self.logger,
                self.output_dir, target
            )
            subdomains_file = enumerator.run_all()

        if not subdomains_file:
            subdomains_file = os.path.join(self.output_dir, "subdomains", "all_subdomains.txt")

        # =====================
        # PHASE 2: Subdomain Validation
        # =====================
        if 'validation' in phases_to_run and self.config.is_phase_enabled('subdomain_validation'):
            self.logger.phase_banner("PHASE 2: SUBDOMAIN VALIDATION", 2)
            if os.path.exists(subdomains_file) and get_file_count(subdomains_file) > 0:
                validator = SubdomainValidator(
                    self.config, self.runner, self.logger,
                    self.output_dir, subdomains_file
                )
                live_hosts_file = validator.run_all()
            else:
                self.logger.warning("No subdomains file found, skipping validation")

        if not live_hosts_file:
            live_hosts_file = os.path.join(self.output_dir, "dns", "live_hosts.txt")

        # =====================
        # PHASE 3: Asset Enrichment (NEW)
        # =====================
        if 'enrichment' in phases_to_run and os.path.exists(live_hosts_file) and get_file_count(live_hosts_file) > 0:
            self.logger.phase_banner("PHASE 3: ASSET ENRICHMENT & INTELLIGENCE", 3)
            enrichment = AssetEnrichment(
                self.config, self.runner, self.logger,
                self.output_dir, live_hosts_file, target
            )
            try:
                enrichment.run_all()
            except Exception as e:
                self.logger.error(f"Asset enrichment failed: {e}")

        # =====================
        # PHASE 4: Port Scanning
        # =====================
        if 'portscan' in phases_to_run and self.config.is_phase_enabled('port_scanning'):
            self.logger.phase_banner("PHASE 4: PORT SCANNING & SERVICE DETECTION", 4)
            if os.path.exists(live_hosts_file) and get_file_count(live_hosts_file) > 0:
                scanner = PortScanner(
                    self.config, self.runner, self.logger,
                    self.output_dir, live_hosts_file
                )
                ports_file = scanner.run_all()

        # =====================
        # PHASE 5: Fingerprinting
        # =====================
        if 'fingerprint' in phases_to_run and self.config.is_phase_enabled('fingerprinting'):
            self.logger.phase_banner("PHASE 5: WEB FINGERPRINTING & TECH DETECTION", 5)
            if os.path.exists(live_hosts_file) and get_file_count(live_hosts_file) > 0:
                fingerprinter = Fingerprinter(
                    self.config, self.runner, self.logger,
                    self.output_dir, live_hosts_file
                )
                fingerprinter.run_all()

        # =====================
        # PHASE 6: GitHub Reconnaissance (NEW - PARALLEL)
        # =====================
        github_recon_future = None
        if 'github_recon' in phases_to_run:
            self.logger.phase_banner("PHASE 6: GITHUB RECONNAISSANCE (PARALLEL)", 6)
            github_recon = GitHubRecon(
                self.config, self.runner, self.logger,
                self.output_dir, target
            )
            try:
                github_recon.run_all()
            except Exception as e:
                self.logger.error(f"GitHub recon failed: {e}")

        # =====================
        # PHASE 7: Content Discovery
        # =====================
        if 'content' in phases_to_run and self.config.is_phase_enabled('content_discovery'):
            self.logger.phase_banner("PHASE 7: CONTENT DISCOVERY & CRAWLING", 7)
            if os.path.exists(live_hosts_file) and get_file_count(live_hosts_file) > 0:
                discovery = ContentDiscovery(
                    self.config, self.runner, self.logger,
                    self.output_dir, live_hosts_file, target
                )
                urls_file = discovery.run_all()
                js_files_file = discovery.get_js_files()
                params_file = discovery.get_params_file()

        if not urls_file:
            urls_file = os.path.join(self.output_dir, "content_discovery", "all_urls.txt")
        if not js_files_file:
            js_files_file = os.path.join(self.output_dir, "content_discovery", "js_files.txt")
        if not params_file:
            params_file = os.path.join(self.output_dir, "content_discovery", "params", "all_params.txt")

        # =====================
        # PHASE 8: API Introspection (NEW)
        # =====================
        if 'api_discovery' in phases_to_run:
            self.logger.phase_banner("PHASE 8: API INTROSPECTION & DISCOVERY", 8)
            if os.path.exists(live_hosts_file) and get_file_count(live_hosts_file) > 0:
                api_probe = APIIntrospection(
                    self.config, self.runner, self.logger,
                    self.output_dir, live_hosts_file
                )
                try:
                    api_probe.run_all()
                except Exception as e:
                    self.logger.error(f"API introspection failed: {e}")

        # =====================
        # PHASE 9: JavaScript Analysis
        # =====================
        if 'jsanalysis' in phases_to_run and self.config.is_phase_enabled('js_analysis'):
            self.logger.phase_banner("PHASE 9: JAVASCRIPT DEEP ANALYSIS", 9)
            if os.path.exists(js_files_file) and get_file_count(js_files_file) > 0:
                analyzer = JSAnalyzer(
                    self.config, self.runner, self.logger,
                    self.output_dir, js_files_file
                )
                analyzer.run_all()

        # =====================
        # PHASE 10: Cloud Enumeration (NEW)
        # =====================
        if 'cloud_enum' in phases_to_run:
            self.logger.phase_banner("PHASE 10: CLOUD ASSET ENUMERATION", 10)
            cloud_enum = CloudEnumeration(
                self.config, self.runner, self.logger,
                self.output_dir, target
            )
            try:
                cloud_enum.run_all()
            except Exception as e:
                self.logger.error(f"Cloud enumeration failed: {e}")

        # =====================
        # PHASE 11: Vulnerability Scanning
        # =====================
        if 'vulnscan' in phases_to_run and self.config.is_phase_enabled('vuln_scanning'):
            self.logger.phase_banner("PHASE 11: VULNERABILITY SCANNING", 11)
            if os.path.exists(live_hosts_file) and get_file_count(live_hosts_file) > 0:
                vuln_scanner = VulnScanner(
                    self.config, self.runner, self.logger,
                    self.output_dir, live_hosts_file,
                    urls_file, params_file
                )
                vuln_scanner.run_all()

        # =====================
        # PHASE 12: Sensitive Information
        # =====================
        if 'sensitive' in phases_to_run and self.config.is_phase_enabled('sensitive_info'):
            self.logger.phase_banner("PHASE 12: SENSITIVE INFO & SECRETS DISCOVERY", 12)
            sensitive_scanner = SensitiveInfoScanner(
                self.config, self.runner, self.logger,
                self.output_dir, target
            )
            sensitive_scanner.run_all()

        # =====================
        # PHASE 13: Screenshots
        # =====================
        if 'screenshot' in phases_to_run and self.config.is_phase_enabled('screenshots'):
            self.logger.phase_banner("PHASE 13: VISUAL VERIFICATION & SCREENSHOTS", 13)
            if os.path.exists(live_hosts_file) and get_file_count(live_hosts_file) > 0:
                screenshotter = ScreenshotCapture(
                    self.config, self.runner, self.logger,
                    self.output_dir, live_hosts_file
                )
                screenshotter.run_all()

        # =====================
        # PHASE 14: Finding Prioritization (NEW)
        # =====================
        if 'prioritize' in phases_to_run:
            self.logger.phase_banner("PHASE 14: FINDING PRIORITIZATION & TRIAGE", 14)
            prioritizer = FindingPrioritizer(
                self.config, self.runner, self.logger,
                self.output_dir
            )
            try:
                prioritizer.run_all()
            except Exception as e:
                self.logger.error(f"Finding prioritization failed: {e}")

        # =====================
        # PHASE 15: Reporting
        # =====================
        if 'report' in phases_to_run:
            self.logger.phase_banner("PHASE 15: COMPREHENSIVE REPORTING", 15)
            self._generate_reports(target)

        # Scan summary
        target_duration = time.time() - target_start
        self._print_summary(target, target_duration)

        # Send notification
        self._send_notification(target)

    def _get_phases_to_run(self):
        """Determine which phases to run based on CLI args."""
        if self.args.full:
            return self.PHASES

        if self.args.phase:
            phases = [p.strip().lower() for p in self.args.phase.split(',')]
            if 'report' not in phases:
                phases.append('report')
            return phases

        return self.PHASES

    def _generate_reports(self, target):
        """Generate all reports with enhanced intelligence."""
        self.logger.phase_banner("GENERATING REPORTS", 15)
        self.scan_end = datetime.now()

        if not self.output_dir:
            return

        # HTML Report
        if self.config.get('reporting.html_report', True):
            try:
                html_gen = HTMLReportGenerator(
                    self.output_dir, target,
                    self.scan_start, self.scan_end
                )
                report_path = html_gen.generate()
                self.logger.found(f"HTML Report: {report_path}")
            except Exception as e:
                self.logger.error(f"HTML report generation failed: {e}")

        # Markdown Report
        if self.config.get('reporting.markdown_report', True):
            try:
                md_gen = MarkdownReportGenerator(
                    self.output_dir, target,
                    self.scan_start, self.scan_end
                )
                report_path = md_gen.generate()
                self.logger.found(f"Markdown Report: {report_path}")
            except Exception as e:
                self.logger.error(f"Markdown report generation failed: {e}")

        # JSON export
        if self.config.get('reporting.json_export', True):
            try:
                json_data = {
                    'target': target,
                    'scan_start': str(self.scan_start),
                    'scan_end': str(self.scan_end),
                    'output_dir': self.output_dir,
                }
                json_path = os.path.join(self.output_dir, "reports", "scan_data.json")
                save_json(json_data, json_path)
                self.logger.found(f"JSON Export: {json_path}")
            except Exception as e:
                self.logger.error(f"JSON export failed: {e}")

    def _print_summary(self, target, duration):
        """Print comprehensive scan summary."""
        self.logger.phase_banner("SCAN SUMMARY")

        stats = {}

        counts = {
            'Subdomains': os.path.join(self.output_dir, "subdomains", "all_subdomains.txt"),
            'Live Hosts': os.path.join(self.output_dir, "dns", "live_hosts.txt"),
            'Open Ports': os.path.join(self.output_dir, "ports", "all_ports.txt"),
            'URLs': os.path.join(self.output_dir, "content_discovery", "all_urls.txt"),
            'JS Files': os.path.join(self.output_dir, "content_discovery", "js_files.txt"),
            'Parameters': os.path.join(self.output_dir, "content_discovery", "params", "all_params.txt"),
        }

        from colorama import Fore, Style

        print(f"\n  {Fore.CYAN}{'─' * 70}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}🎯 Target: {Fore.GREEN}{target}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}⏱️  Duration: {Fore.GREEN}{format_duration(duration)}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}📁 Output: {Fore.GREEN}{self.output_dir}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}{'─' * 70}{Style.RESET_ALL}")

        for label, filepath in counts.items():
            count = get_file_count(filepath) if os.path.exists(filepath) else 0
            stats[label.lower().replace(' ', '_')] = count
            color = Fore.GREEN if count > 0 else Fore.RED
            print(f"  {Fore.WHITE}  📊 {label}: {color}{count}{Style.RESET_ALL}")

        # Count vulns
        vuln_count = 0
        vuln_dir = os.path.join(self.output_dir, "vulnerabilities")
        if os.path.exists(vuln_dir):
            for root, dirs, files in os.walk(vuln_dir):
                for f in files:
                    if f.endswith('.txt'):
                        vuln_count += get_file_count(os.path.join(root, f))

        stats['vulns'] = vuln_count
        color = Fore.RED if vuln_count > 0 else Fore.GREEN
        print(f"  {Fore.WHITE}  🚨 Vulnerabilities: {color}{vuln_count}{Style.RESET_ALL}")

        # Count secrets
        secret_count = 0
        secrets_dir = os.path.join(self.output_dir, "js_analysis", "secrets")
        if os.path.exists(secrets_dir):
            for f in os.listdir(secrets_dir):
                if f.endswith('.txt'):
                    secret_count += get_file_count(os.path.join(secrets_dir, f))

        stats['secrets'] = secret_count
        color = Fore.RED if secret_count > 0 else Fore.GREEN
        print(f"  {Fore.WHITE}  🔑 Secrets Found: {color}{secret_count}{Style.RESET_ALL}")

        # API endpoints
        api_count = 0
        api_dir = os.path.join(self.output_dir, "api_intelligence")
        if os.path.exists(api_dir):
            api_file = os.path.join(api_dir, "apis_discovered.txt")
            if os.path.exists(api_file):
                api_count = get_file_count(api_file)

        stats['apis'] = api_count
        color = Fore.GREEN if api_count > 0 else Fore.YELLOW
        print(f"  {Fore.WHITE}  🔌 APIs Discovered: {color}{api_count}{Style.RESET_ALL}")

        # GitHub findings
        github_count = 0
        github_dir = os.path.join(self.output_dir, "github_recon")
        if os.path.exists(github_dir):
            for f in ['repositories.txt', 'issues.txt', 'secrets_exposed.txt']:
                fpath = os.path.join(github_dir, f)
                if os.path.exists(fpath):
                    github_count += get_file_count(fpath)

        stats['github_findings'] = github_count
        color = Fore.YELLOW if github_count > 0 else Fore.GREEN
        print(f"  {Fore.WHITE}  🐙 GitHub Findings: {color}{github_count}{Style.RESET_ALL}")

        print(f"  {Fore.CYAN}{'─' * 70}{Style.RESET_ALL}\n")

        self.results = stats

    def _send_notification(self, target):
        """Send scan completion notification."""
        try:
            self.notifier.send_scan_summary(target, self.results)
        except Exception as e:
            self.logger.debug(f"Notification failed: {e}")


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='🔥 SYNCHUNT v2026 - Advanced Automated Bug Hunting Reconnaissance Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d target.com --full
  %(prog)s -d target.com --phase subdomain,validation,github_recon,vulnscan
  %(prog)s -l targets.txt --full
  %(prog)s -d target.com --config custom_config.yaml
  %(prog)s --check-deps
  %(prog)s --check-deps --install-deps
        """
    )

    # Target options
    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument(
        '-d', '--domain',
        help='Target domain (e.g., example.com)'
    )
    target_group.add_argument(
        '-l', '--list',
        help='File containing list of target domains'
    )

    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument(
        '--full',
        action='store_true',
        help='Run full advanced recon pipeline (all phases)'
    )
    scan_group.add_argument(
        '--phase',
        help=(
            'Comma-separated phases to run: '
            'subdomain,validation,enrichment,portscan,fingerprint,'
            'github_recon,content,api_discovery,jsanalysis,cloud_enum,'
            'vulnscan,sensitive,screenshot,prioritize,report'
        )
    )
    scan_group.add_argument(
        '--resume',
        action='store_true',
        help='Resume previous scan (skip completed phases)'
    )

    # Configuration
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument(
        '--config',
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )
    config_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    # Dependency management
    dep_group = parser.add_argument_group('Dependencies')
    dep_group.add_argument(
        '--check-deps',
        action='store_true',
        help='Check tool dependencies and exit'
    )
    dep_group.add_argument(
        '--install-deps',
        action='store_true',
        help='Attempt to install missing dependencies'
    )

    args = parser.parse_args()

    # Validate: need at least a target or --check-deps
    if not args.domain and not args.list and not args.check_deps:
        parser.error("Please specify a target with -d/--domain or -l/--list")

    # Default to full scan if no phase specified
    if args.domain or args.list:
        if not args.full and not args.phase:
            args.full = True

    return args


def main():
    """Main entry point."""
    args = parse_arguments()

    try:
        recon = SynchuntAutoRecon(args)
        recon.run()
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        print("Make sure config.yaml exists or specify with --config")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
