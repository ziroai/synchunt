#!/usr/bin/env python3
"""
SyncHunt - Automated Recon & Vulnerability Scanning Framework

Entry point and phase orchestrator: subdomain discovery, validation,
enrichment, port scanning, fingerprinting, GitHub recon, content discovery,
API introspection, JS analysis, cloud enumeration, vulnerability scanning,
sensitive-info OSINT, screenshots, prioritisation and reporting.

Authorised testing only. See README.md (Security & Legal).
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from colorama import Fore, Style

from core import __version__, history as scan_history
from core.config_manager import ConfigManager
from core.context import ScanContext
from core.database_manager import DatabaseManager, default_db_path
from core.dependency_checker import DependencyChecker
from core.logger import BugHuntLogger
from core.runner import ToolRunner
from core.utils import (
    create_output_structure,
    ensure_dir,
    format_duration,
    get_file_count,
    is_valid_target,
    load_json,
    read_file_lines,
    read_json_lines,
    save_json,
    strip_scheme,
)

from modules.api_introspection import APIIntrospector
from modules.asset_enrichment import AssetEnricher
from modules.cloud_enum import CloudEnumerator
from modules.content_discovery import ContentDiscovery
from modules.finding_prioritizer import FindingPrioritizer
from modules.fingerprinting import Fingerprinter
from modules.github_recon import GitHubRecon
from modules.js_analysis import JSAnalyzer
from modules.port_scanning import PortScanner
from modules.screenshots import ScreenshotCapture
from modules.scope_manager import ScopeManager
from modules.sensitive_info import SensitiveInfoScanner
from modules.subdomain_enum import SubdomainEnumerator
from modules.subdomain_validation import SubdomainValidator
from modules.vuln_scanning import VulnScanner
from reports.data_export import DataExporter
from reports.html_report import HTMLReportGenerator
from reports.markdown_report import MarkdownReportGenerator
from reports.notifier import Notifier
from reports.sarif_export import SarifExporter

STATE_FILE = "scan_state.json"


class UsageError(Exception):
    """Raised for invalid CLI combinations (no stack trace needed)."""


@dataclass
class Phase:
    """One pipeline phase."""

    name: str
    section: str
    banner: int
    build: Optional[Callable[[ScanContext], object]]
    requires: List[str] = field(default_factory=list)
    produces: List[str] = field(default_factory=list)
    description: str = ""


PHASES: List[Phase] = [
    Phase("subdomain", "subdomain_enum", 1, lambda ctx: SubdomainEnumerator(ctx),
          produces=["subdomains"],
          description="subfinder/amass/crt.sh/puredns subdomain discovery"),
    Phase("validation", "subdomain_validation", 2, lambda ctx: SubdomainValidator(ctx),
          requires=["subdomains"], produces=["live_hosts", "live_hosts_details"],
          description="live host detection (httpx or built-in prober)"),
    Phase("enrichment", "asset_enrichment", 3, lambda ctx: AssetEnricher(ctx),
          requires=[], produces=["intel_hosts", "interesting_paths"],
          description="DNS/TLS/header/CDN enrichment and exposure checks"),
    Phase("portscan", "port_scanning", 4, lambda ctx: PortScanner(ctx),
          requires=["live_hosts"], produces=["ports"],
          description="naabu/nmap/masscan port and service discovery"),
    Phase("fingerprint", "fingerprinting", 5, lambda ctx: Fingerprinter(ctx),
          requires=["live_hosts"], produces=["fingerprint"],
          description="whatweb/wafw00f/webanalyze tech and WAF detection"),
    Phase("github_recon", "github_recon", 6, lambda ctx: GitHubRecon(ctx),
          produces=["github_repos"],
          description="GitHub repositories, issues and leaked secrets"),
    Phase("content", "content_discovery", 7, lambda ctx: ContentDiscovery(ctx),
          requires=["live_hosts"], produces=["urls", "js_files", "params"],
          description="URL crawling, parameter and directory discovery"),
    Phase("api_discovery", "api_introspection", 8, lambda ctx: APIIntrospector(ctx),
          produces=["api_specs", "api_endpoints"],
          description="OpenAPI/Swagger/GraphQL/actuator discovery"),
    Phase("jsanalysis", "js_analysis", 9, lambda ctx: JSAnalyzer(ctx),
          requires=["js_files"], produces=["js_endpoints"],
          description="JS endpoint extraction and secret scanning"),
    Phase("cloud_enum", "cloud_enum", 10, lambda ctx: CloudEnumerator(ctx),
          produces=["cloud_public_buckets"],
          description="S3/Azure/GCP bucket enumeration"),
    Phase("vulnscan", "vuln_scanning", 11, lambda ctx: VulnScanner(ctx),
          requires=["live_hosts"], produces=["vulnerabilities"],
          description="nuclei/nikto/dalfox/sqlmap/crlfuzz/corsy scanning"),
    Phase("sensitive", "sensitive_info", 12, lambda ctx: SensitiveInfoScanner(ctx),
          description="GitHub dorks, Google dorks, optional Shodan"),
    Phase("screenshot", "screenshots", 13, lambda ctx: ScreenshotCapture(ctx),
          requires=["live_hosts"], description="gowitness/aquatone visual recon"),
    Phase("prioritize", "finding_prioritizer", 14, lambda ctx: FindingPrioritizer(ctx),
          produces=["findings_json", "findings_csv", "prioritized_md"],
          description="de-duplicate, score and rank every finding"),
    Phase("report", "reporting", 15, None,
          description="HTML/Markdown reports and JSON/CSV exports"),
]

PHASE_BY_NAME = {phase.name: phase for phase in PHASES}
PHASE_ORDER = [phase.name for phase in PHASES]

# Default artifact locations, used to pick up files from previous runs (resume)
DEFAULT_FILES: Dict[str, List[str]] = {
    "subdomains": ["subdomains", "all_subdomains.txt"],
    "live_hosts": ["dns", "live_hosts.txt"],
    "live_hosts_details": ["dns", "httpx_details.json"],
    "ports": ["ports", "all_ports.txt"],
    "urls": ["content_discovery", "all_urls.txt"],
    "js_files": ["content_discovery", "js_files.txt"],
    "params": ["content_discovery", "params", "all_params.txt"],
    "js_endpoints": ["js_analysis", "endpoints", "all_endpoints.txt"],
    "intel_hosts": ["intel", "hosts.json"],
    "interesting_paths": ["intel", "interesting_paths.txt"],
    "api_specs": ["api_intelligence", "api_specs.json"],
    "api_endpoints": ["api_intelligence", "endpoints.txt"],
    "fingerprint": ["fingerprinting", "technologies.json"],
    "cloud_public_buckets": ["cloud_enum", "public_buckets.txt"],
    "vulnerabilities": ["vulnerabilities", "findings.json"],
    "findings_json": ["findings_prioritized", "findings.json"],
    "findings_csv": ["findings_prioritized", "findings.csv"],
    "prioritized_md": ["findings_prioritized", "prioritized.md"],
    "github_repos": ["github_recon", "repos.json"],
}


class SyncHunt:
    """Main orchestrator."""

    def __init__(self, args):
        self.args = args
        self.scan_start = datetime.now()
        self.scan_end: Optional[datetime] = None
        # Read-only commands work without a config file (e.g. a pipx install
        # outside a checkout); scanning still requires a real one.
        diagnostics = bool(
            getattr(args, "list_phases", False) or getattr(args, "check_deps", False)
            or getattr(args, "install_deps", False) or getattr(args, "doctor", False)
        )
        self.config = ConfigManager(args.config, allow_missing=diagnostics)
        self.base_output = args.output_dir or self.config.get("general.output_dir", "output")
        if not diagnostics:
            # read-only commands must not litter the filesystem
            os.makedirs(self.base_output, exist_ok=True)

        verbose = args.verbose or self.config.get_bool("general.verbose", True)
        if args.quiet:
            verbose = False
        # The file handler is attached per-run in _run_target so logs land
        # inside the run directory rather than the base output directory.
        self.logger = BugHuntLogger(output_dir="", verbose=verbose)
        self.runner = ToolRunner(
            logger=self.logger,
            timeout=args.timeout or self.config.get_timeout(),
            verbose=verbose,
        )
        self.notifier = Notifier(self.config, self.logger)
        self.scope: Optional[ScopeManager] = None
        self.selected_phases: List[str] = []
        # Filled in as targets are scanned; consumed by --json-report
        self.run_reports: List[Dict[str, Any]] = []
        self.json_targets: List[str] = []
        self._json_report_written = False
        self.last_artifacts: Dict[str, str] = {}
        self.last_history = None
        self._interrupted = False

        signal.signal(signal.SIGINT, self._signal_handler)
        try:
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (OSError, AttributeError):  # pragma: no cover - Windows
            pass

    # ------------------------------------------------------------------
    # Signals
    # ------------------------------------------------------------------
    def _signal_handler(self, signum, frame):  # pragma: no cover - interactive only
        if self._interrupted:
            os._exit(130)
        self._interrupted = True
        self.logger.warning("Interrupt received - finishing the current phase and cleaning up...")
        self.runner.cleanup()

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------
    def _parse_targets(self) -> List[str]:
        targets: List[str] = []
        if self.args.domain:
            for raw in self.args.domain.split(","):
                self._add_target(raw, targets)

        if self.args.list:
            if not os.path.exists(self.args.list):
                self.logger.error(f"target list not found: {self.args.list}")
            else:
                for raw in read_file_lines(self.args.list):
                    self._add_target(raw, targets)

        return list(dict.fromkeys(targets))

    def _add_target(self, raw: str, targets: List[str]) -> None:
        value = strip_scheme(raw)
        if not value:
            return
        if is_valid_target(value):
            targets.append(value)
        else:
            self.logger.warning(f"skipping invalid target: {raw}")

    # ------------------------------------------------------------------
    # Phase selection
    # ------------------------------------------------------------------
    def _select_phases(self) -> List[str]:
        if self.args.phase:
            requested = [p.strip().lower() for p in self.args.phase.split(",") if p.strip()]
            unknown = [p for p in requested if p not in PHASE_BY_NAME]
            if unknown:
                raise UsageError(
                    f"unknown phase(s): {', '.join(unknown)}\n"
                    f"available phases: {', '.join(PHASE_ORDER)}"
                )
            selected = requested
        elif self.args.full:
            selected = list(PHASE_ORDER)
        else:
            profile = self.args.profile or self.config.profile
            configured = self.config.profile_phases(profile)
            if configured:
                unknown = [p for p in configured if p not in PHASE_BY_NAME]
                if unknown:
                    self.logger.warning(
                        f"profile '{profile}' references unknown phase(s): "
                        f"{', '.join(unknown)} - ignored"
                    )
                selected = [p for p in configured if p in PHASE_BY_NAME]
                self.logger.info(f"Using profile '{profile}' ({len(selected)} phases)")
            else:
                selected = list(PHASE_ORDER)

        # Reporting always runs, and it is only useful with prioritised
        # findings, so the two phases stay paired.
        if "report" not in selected:
            selected.append("report")
        if "prioritize" not in selected:
            selected.insert(selected.index("report"), "prioritize")

        ordered = [name for name in PHASE_ORDER if name in set(selected)]
        return ordered

    # ------------------------------------------------------------------
    # Main entry
    # ------------------------------------------------------------------
    def run(self) -> int:
        """Run the CLI, always emitting --json-report when one was requested."""
        started = time.time()
        exit_code = 1
        try:
            exit_code = self._execute()
            return exit_code
        finally:
            if not self._json_report_written:
                self._write_json_report(
                    exit_code, self.json_targets, time.time() - started
                )

    def _execute(self) -> int:
        self.logger.banner(__version__)

        if self.args.list_phases:
            self._print_phases()
            return 0

        checker = DependencyChecker(self.logger)

        if self.args.check_deps or self.args.install_deps:
            result = checker.check_all()
            if self.args.install_deps:
                checker.auto_install()
            return 0 if result["ready"] else 1

        if self.args.doctor:
            return self._doctor(checker)

        # Validate phase selection up-front so a typo fails before any traffic.
        self.selected_phases = self._select_phases()

        targets = self._parse_targets()
        if not targets:
            self.logger.error("No valid targets specified")
            return 3

        self.logger.info(
            f"Targets: {', '.join(targets)} | "
            f"output: {os.path.abspath(self.base_output)}"
        )

        # Pre-flight: tell the user what is missing, but keep going - every
        # phase degrades gracefully and reports honestly what it skipped.
        preflight = checker.check_all() if self.args.check_deps else None
        if preflight is None:
            missing = [
                name for name in ("subfinder", "httpx", "nuclei")
                if not checker.is_available(name)
            ]
            if missing:
                self.logger.warning(
                    f"missing core tools: {', '.join(missing)} "
                    f"(run `synchunt --doctor` for install commands)"
                )

        exit_code = 0
        for target in targets:
            if self._interrupted:
                break
            try:
                self._run_target(target)
            except SystemExit:
                raise
            except Exception as exc:  # pragma: no cover - top-level guard
                import traceback

                self.logger.error(f"fatal error on {target}: {exc}")
                self.logger.debug(traceback.format_exc())
                exit_code = 1

        self.scan_end = datetime.now()
        duration = (self.scan_end - self.scan_start).total_seconds()
        if self.args.json_report:
            self.json_targets = targets
            self._write_json_report(exit_code, targets, duration)
        self.logger.info("=" * 62)
        self.logger.result(
            f"🏁 All scans complete in {format_duration(duration)}"
            + (" (interrupted)" if self._interrupted else "")
        )
        self.logger.info("=" * 62)
        return exit_code

    # ------------------------------------------------------------------
    # Per-target pipeline
    # ------------------------------------------------------------------
    def _run_target(self, target: str) -> None:
        run_id = None
        resume_dir = None
        if self.args.resume:
            resume_dir = self.config.latest_output_dir(target, self.base_output)
            if resume_dir:
                run_id = os.path.basename(resume_dir)
                self.logger.info(f"Resuming previous run: {resume_dir}")
            else:
                self.logger.info("No previous run found for this target - starting fresh")

        output_dir = resume_dir or self.config.get_output_dir(
            target, run_id=run_id, base_dir=self.base_output
        )
        create_output_structure(output_dir)
        self.logger.attach_file(output_dir)

        scope = ScopeManager.from_config(
            self.config,
            scope_file=self.args.scope_file,
            out_of_scope_file=self.args.out_of_scope_file,
            extra_scope=[target] if is_valid_target(target) else None,
            logger=self.logger,
        )
        self.scope = scope

        db_path = default_db_path(output_dir)
        database = DatabaseManager(db_path)
        scan_id = database.start_scan(target, self.config.profile, output_dir)

        ctx = ScanContext(
            target=target,
            output_dir=output_dir,
            config=self.config,
            logger=self.logger,
            runner=self.runner,
            scope=scope,
            database=database,
            scan_id=scan_id,
            profile=self.args.profile or self.config.profile,
        )
        self._sync_files(ctx)

        phases = self.selected_phases or self._select_phases()
        completed = set()
        if self.args.resume:
            completed = set(database.completed_phases(scan_id))
            if not completed:
                state = load_json(os.path.join(output_dir, STATE_FILE), {})
                completed = set(state.get("completed_phases", []))

        self.logger.phase_banner(
            f"TARGET: {target}",
            extra=f"{len(phases)} phases | scope: {scope.describe()}",
        )
        self.logger.info(f"Output directory: {output_dir}")
        self.logger.info(f"Correlation DB:   {db_path}")

        if self.args.dry_run:
            self._print_dry_run(ctx, phases)
            self.run_reports.append({
                "target": target,
                "status": "dry-run",
                "output_dir": output_dir,
                "database": db_path,
                "profile": ctx.profile,
                "phases": list(phases),
                "findings": 0,
                "severity": {},
                "categories": {},
                "top_findings": [],
                "artifacts": {},
                "history": {},
            })
            database.finish_scan(scan_id, "dry-run")
            database.close()
            return

        applied_scope = False
        for phase in PHASES:
            if phase.name not in phases:
                continue
            if self._interrupted:
                break
            if phase.name in completed:
                self.logger.skip(f"{phase.name} already completed (resume)")
                self._sync_files(ctx)
                continue

            if phase.name == "report":
                self._generate_reports(ctx)
                database.record_phase(scan_id, _phase_result("report", "done"))
                continue

            started = time.time()
            status = "done"
            notes = ""
            result_count = 0

            if not self.config.is_phase_enabled(phase.section, True):
                self.logger.skip(f"{phase.name} disabled in config")
                database.record_phase(
                    scan_id, _phase_result(phase.name, "skipped", notes="disabled in config")
                )
                continue

            missing_inputs = [
                key for key in phase.requires if not os.path.exists(ctx.get_file(key, ""))
            ]
            if missing_inputs:
                self.logger.skip(
                    f"{phase.name}: missing input(s) {', '.join(missing_inputs)}"
                )
                database.record_phase(
                    scan_id,
                    _phase_result(phase.name, "skipped",
                                  notes=f"missing inputs: {missing_inputs}"),
                )
                continue

            try:
                instance = phase.build(ctx) if phase.build else None
                if instance is not None:
                    outcome = instance.run_all()
                    if isinstance(outcome, str):
                        notes = outcome
                    result_count = self._result_count(ctx, phase)
            except KeyboardInterrupt:  # pragma: no cover - interactive only
                self._interrupted = True
                status = "failed"
                notes = "interrupted"
            except Exception as exc:
                status = "failed"
                notes = str(exc)
                import traceback

                self.logger.error(f"{phase.name} failed: {exc}")
                self.logger.debug(traceback.format_exc())

            duration = time.time() - started
            database.record_phase(
                scan_id,
                _phase_result(phase.name, status, duration=duration,
                              result_count=result_count, notes=notes),
            )
            self._save_state(ctx, database, scan_id)

            # Scope enforcement happens as soon as we have a host list.
            if phase.name in ("subdomain", "validation") and not applied_scope:
                applied_scope = self._apply_scope(ctx)
            self._sync_files(ctx)

        summary = database.scan_summary(scan_id)
        self._print_summary(target, summary, phases)
        self._send_notifications(ctx, summary)

        top_findings = [
            {
                "title": finding.title,
                "severity": finding.severity,
                "category": finding.category,
                "url": finding.url,
                "score": finding.score,
                "priority": finding.extra.get("priority", ""),
            }
            for finding in database.top_findings(scan_id, limit=10)
        ]
        self.run_reports.append({
            "target": target,
            "status": "interrupted" if self._interrupted else "finished",
            "output_dir": output_dir,
            "database": db_path,
            "profile": ctx.profile,
            "phases": [name for name in phases],
            "findings": summary.get("findings", 0),
            "severity": summary.get("severity", {}),
            "categories": summary.get("categories", {}),
            "top_findings": top_findings,
            "artifacts": dict(self.last_artifacts),
            "history": self.last_history.counts() if self.last_history else {},
        })

        database.finish_scan(scan_id, "finished", stats={
            "severity": summary.get("severity", {}),
            "findings": summary.get("findings", 0),
        })
        database.close()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _sync_files(self, ctx: ScanContext) -> None:
        """Point ctx.files at existing artifacts (fresh or from a prior run)."""
        for key, parts in DEFAULT_FILES.items():
            path = ctx.path(*parts)
            if os.path.exists(path):
                ctx.set_file(key, path)
        state_path = os.path.join(ctx.output_dir, STATE_FILE)
        state = load_json(state_path, {})
        for key, value in (state.get("files") or {}).items():
            if value and os.path.exists(value):
                ctx.set_file(key, value)

    def _save_state(self, ctx: ScanContext, database: DatabaseManager, scan_id: int) -> None:
        save_json(
            {
                "target": ctx.target,
                "scan_id": scan_id,
                "profile": ctx.profile,
                "updated_at": datetime.now().isoformat(),
                "completed_phases": database.completed_phases(scan_id),
                "files": {k: v for k, v in ctx.files.items() if v and os.path.exists(v)},
            },
            os.path.join(ctx.output_dir, STATE_FILE),
        )

    def _apply_scope(self, ctx: ScanContext) -> bool:
        """Filter subdomains and live hosts down to the authorised scope."""
        if ctx.scope is None or not ctx.scope.has_rules:
            return True
        subdomains_file = ctx.get_file("subdomains")
        live_hosts_file = ctx.get_file("live_hosts")
        dropped_total = 0

        for path in (subdomains_file, live_hosts_file):
            if not path or not os.path.exists(path):
                continue
            before = read_file_lines(path)
            after = ctx.scope.filter(before, record_drops=True)
            dropped = len(before) - len(after)
            if dropped > 0:
                dropped_total += dropped
            from core.utils import write_file_lines

            write_file_lines(path, after)

        if dropped_total:
            self.logger.warning(
                f"Scope filter removed {dropped_total} out-of-scope entr(ies)"
            )
            save_json(
                ctx.scope.summary(),
                ctx.path("reports", "scope.json"),
            )
        return True

    def _result_count(self, ctx: ScanContext, phase: Phase) -> int:
        for key in phase.produces:
            path = ctx.get_file(key)
            if not path and key in DEFAULT_FILES:
                candidate = ctx.path(*DEFAULT_FILES[key])
                path = candidate if os.path.exists(candidate) else ""
            if path and os.path.exists(path):
                if path.endswith(".jsonl"):
                    return len(read_json_lines(path))
                if path.endswith(".json"):
                    data = load_json(path, [])
                    return len(data) if isinstance(data, list) else 1
                return get_file_count(path)
        return 0

    def _write_json_report(self, exit_code: int, targets: List[str],
                           duration: float) -> None:
        """Write a machine-readable run summary for CI/pipelines (--json-report)."""
        path = getattr(self.args, "json_report", None)
        if not path:
            return
        payload = {
            "tool": "SyncHunt",
            "version": __version__,
            "generated_at": datetime.now().isoformat(),
            "duration_seconds": round(duration, 2),
            "exit_code": exit_code,
            "targets_requested": targets,
            "targets": self.run_reports,
        }
        try:
            ensure_dir(os.path.dirname(os.path.abspath(path)))
            save_json(payload, path)
            self._json_report_written = True
            self.logger.info(f"JSON report: {os.path.abspath(path)}")
        except OSError as exc:
            self.logger.error(f"could not write JSON report: {exc}")

    def _generate_reports(self, ctx: ScanContext) -> None:
        self.logger.phase_banner("REPORT GENERATION", 15)
        self.scan_end = datetime.now()

        findings = []
        if ctx.database is not None and ctx.scan_id is not None:
            findings = ctx.database.findings(ctx.scan_id)

        history_data: Dict[str, Any] = {}
        self.last_history = None
        if findings and self.config.get_bool("reporting.track_history", True):
            previous = scan_history.find_previous_run(
                self.base_output, ctx.target, ctx.output_dir
            )
            if previous:
                report = scan_history.compare(
                    findings,
                    scan_history.load_findings(previous),
                    previous_run=previous,
                )
                self.last_history = report
                history_data = report.to_dict()
                save_json(history_data, ctx.path("reports", "history.json"))
                counts = report.counts()
                self.logger.found(
                    f"History vs {os.path.basename(previous)}: {counts['new']} new, "
                    f"{counts['fixed']} fixed, {counts['persisting']} persisting"
                )

        generated: Dict[str, str] = {}
        self.last_artifacts = generated
        if self.config.get_bool("reporting.html_report", True):
            try:
                path = HTMLReportGenerator(
                    ctx.output_dir, ctx.target, self.scan_start, self.scan_end,
                    database=ctx.database, scan_id=ctx.scan_id, findings=findings,
                    history=history_data or None,
                ).generate()
                generated["html"] = path
                self.logger.found(f"HTML report: {path}")
            except Exception as exc:
                self.logger.error(f"HTML report failed: {exc}")

        if self.config.get_bool("reporting.markdown_report", True):
            try:
                path = MarkdownReportGenerator(
                    ctx.output_dir, ctx.target, self.scan_start, self.scan_end,
                    database=ctx.database, scan_id=ctx.scan_id, findings=findings,
                    history=history_data or None,
                ).generate()
                generated["markdown"] = path
                self.logger.found(f"Markdown report: {path}")
            except Exception as exc:
                self.logger.error(f"Markdown report failed: {exc}")

        if self.config.get_bool("reporting.sarif_export", True):
            try:
                path = SarifExporter(
                    ctx.output_dir, ctx.target, findings,
                    tool_version=__version__,
                ).generate()
                generated["sarif"] = path
                self.logger.found(f"SARIF export: {path}")
            except Exception as exc:
                self.logger.error(f"SARIF export failed: {exc}")

        exporter = DataExporter(ctx.output_dir, ctx.target)
        try:
            generated.update(exporter.export_findings(
                findings,
                json_enabled=self.config.get_bool("reporting.json_export", True),
                csv_enabled=self.config.get_bool("reporting.csv_export", True),
            ))
            if ctx.database is not None and ctx.scan_id is not None:
                scan_data = ctx.database.scan_summary(ctx.scan_id)
                if history_data:
                    scan_data["history"] = history_data
                generated["scan_data"] = exporter.export_scan_data(scan_data)
        except Exception as exc:
            self.logger.error(f"data export failed: {exc}")

        if generated:
            self.logger.info(
                "Artefacts: " + ", ".join(os.path.basename(p) for p in generated.values())
            )

    def _send_notifications(self, ctx: ScanContext, summary: Dict) -> None:
        if not self.notifier.enabled:
            return
        stats = {
            "subdomains": len(read_file_lines(ctx.get_file("subdomains", ""))),
            "live_hosts": len(read_file_lines(ctx.get_file("live_hosts", ""))),
            "open_ports": len(read_file_lines(ctx.get_file("ports", ""))),
            "urls": len(read_file_lines(ctx.get_file("urls", ""))),
            "vulnerabilities": summary.get("findings", 0),
            "secrets": (summary.get("categories") or {}).get("secrets", 0),
        }
        try:
            self.notifier.send_scan_summary(ctx.target, stats, extra=summary)
            if ctx.database is not None and ctx.scan_id is not None:
                critical = [
                    f for f in ctx.database.findings(ctx.scan_id, min_severity="high")
                ]
                self.notifier.send_critical_findings(critical[:5])
        except Exception as exc:  # pragma: no cover - network dependent
            self.logger.debug(f"notification failed: {exc}")

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    def _print_phases(self) -> None:
        print(f"\n{Fore.CYAN}Available phases ({len(PHASES)}){Style.RESET_ALL}\n")
        for phase in PHASES:
            print(
                f"  {phase.banner:>2}. {Fore.GREEN}{phase.name:<14}{Style.RESET_ALL} "
                f"{phase.description}"
            )
        print(f"\nProfiles: {', '.join(self.config.available_profiles())}\n")

    def _print_dry_run(self, ctx: ScanContext, phases: List[str]) -> None:
        checker = DependencyChecker(self.logger)
        print(f"\n{Fore.CYAN}{Style.BRIGHT}DRY RUN{Style.RESET_ALL} - no traffic will be sent\n")
        print(f"  Target : {ctx.target}")
        print(f"  Output : {ctx.output_dir}")
        print(f"  Scope  : {ctx.scope.describe() if ctx.scope else 'n/a'}")
        print("\n  Phases:")
        for name in phases:
            phase = PHASE_BY_NAME[name]
            print(f"    • {name:<14} {phase.description}")
        print("\n  Tool availability:")
        for tool in ("subfinder", "httpx", "nuclei", "naabu", "katana", "gowitness"):
            mark = f"{Fore.GREEN}ok" if checker.is_available(tool) else f"{Fore.RED}missing"
            print(f"    • {tool:<12} {mark}{Style.RESET_ALL}")
        print()

    def _print_summary(self, target: str, summary: Dict, phases: List[str]) -> None:
        severity = summary.get("severity", {})
        categories = summary.get("categories", {})
        phases_done = [
            row for row in summary.get("phases", []) if row.get("status") in ("done", "failed")
        ]
        del phases  # selected list is echoed in the banner already

        print(f"\n  {Fore.CYAN}{'─' * 58}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}🎯 Target: {Fore.GREEN}{target}{Style.RESET_ALL}")
        print(
            f"  {Fore.WHITE}🧩 Phases executed: "
            f"{Fore.GREEN}{len(phases_done)}{Style.RESET_ALL}"
        )
        print(
            f"  {Fore.WHITE}📁 Findings: {Fore.GREEN}{summary.get('findings', 0)}"
            f"{Style.RESET_ALL}   "
            f"{Fore.RED}critical {severity.get('critical', 0)}{Style.RESET_ALL} · "
            f"{Fore.LIGHTRED_EX}high {severity.get('high', 0)}{Style.RESET_ALL} · "
            f"{Fore.YELLOW}medium {severity.get('medium', 0)}{Style.RESET_ALL} · "
            f"{Fore.GREEN}low {severity.get('low', 0)}{Style.RESET_ALL} · "
            f"info {severity.get('info', 0)}"
        )
        if categories:
            top = ", ".join(f"{k}={v}" for k, v in list(categories.items())[:6])
            print(f"  {Fore.WHITE}🗂️  Categories: {top}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}{'─' * 58}{Style.RESET_ALL}\n")

    # ------------------------------------------------------------------
    def _doctor(self, checker: DependencyChecker) -> int:
        """Dependency + configuration sanity check."""
        result = checker.check_all()

        print(f"\n{Fore.CYAN}{Style.BRIGHT}📋 Configuration check{Style.RESET_ALL}\n")
        warnings = self.config.validate(PHASE_ORDER)
        if warnings:
            for warning in warnings:
                print(f"  {Fore.YELLOW}⚠️  {warning}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✅ configuration looks consistent{Style.RESET_ALL}")

        from modules.github_recon import github_token_present

        print(f"\n{Fore.CYAN}🔑 Optional integrations{Style.RESET_ALL}")
        print(
            f"  GitHub token : "
            f"{'set' if github_token_present(self.config) else 'not set (code search disabled)'}"
        )
        print(
            f"  Shodan key   : "
            f"{'set' if (self.config.get('sensitive_info.shodan.api_key') or os.environ.get('SHODAN_API_KEY')) else 'not set (optional)'}"
        )
        print(f"  Notifications: {'enabled' if self.notifier.enabled else 'disabled'}\n")

        return 0 if result["ready"] else 1


def _phase_result(name: str, status: str, duration: float = 0.0,
                  result_count: int = 0, notes: str = ""):
    from core.models import PhaseResult

    return PhaseResult(name=name, status=status, duration=duration,
                       result_count=result_count, notes=notes)


# Backwards-compatible alias (earlier versions used this class name)
BugHuntRecon = SyncHunt


def parse_arguments(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="synchunt",
        description="🔎 SyncHunt - automated recon & vulnerability scanning (authorised testing only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  synchunt -d example.com                      # run the configured profile
  synchunt -d example.com --profile quick      # 5-phase fast pass
  synchunt -d example.com --full               # all 15 phases
  synchunt -d example.com --phase subdomain,validation,report
  synchunt -l targets.txt --profile balanced --resume
  synchunt -d example.com --scope-file scope.txt --out-of-scope-file oos.txt
  synchunt -d example.com --dry-run            # show the plan, send no traffic
  synchunt -d example.com --full --json-report summary.json   # CI-friendly summary
  synchunt --doctor                            # dependencies + config check
  synchunt --list-phases
        """,
    )

    target_group = parser.add_argument_group("Targets")
    target_group.add_argument("-d", "--domain", help="target domain/IP (comma-separated)")
    target_group.add_argument("-l", "--list", help="file with one target per line")

    scan_group = parser.add_argument_group("Scanning")
    scan_group.add_argument("--profile", help="config profile: quick|balanced|full|deep")
    scan_group.add_argument("--phase", help="comma-separated phases to run")
    scan_group.add_argument("--full", action="store_true", help="run all 15 phases")
    scan_group.add_argument("--resume", action="store_true",
                            help="continue the latest run for this target")
    scan_group.add_argument("--dry-run", action="store_true",
                            help="print the plan without sending traffic")
    scan_group.add_argument("--output-dir", help="base output directory (default: output)")
    scan_group.add_argument("--threads", type=int, help="worker threads")
    scan_group.add_argument("--timeout", type=int, help="per-tool timeout in seconds")
    scan_group.add_argument("--rate-limit", type=float, help="HTTP requests per second")
    scan_group.add_argument("--json-report", metavar="PATH",
                            help="write a machine-readable JSON summary for CI")

    scope_group = parser.add_argument_group("Scope")
    scope_group.add_argument("--scope-file", help="file with in-scope entries")
    scope_group.add_argument("--out-of-scope-file", help="file with excluded entries")

    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument("--config", default="config.yaml", help="config file path")
    config_group.add_argument("-v", "--verbose", action="store_true")
    config_group.add_argument("-q", "--quiet", action="store_true")

    diag_group = parser.add_argument_group("Diagnostics")
    diag_group.add_argument("--check-deps", action="store_true",
                            help="check tool dependencies and exit")
    diag_group.add_argument("--install-deps", action="store_true",
                            help="print install commands for missing tools "
                                 "(exits 1 while anything is missing)")
    diag_group.add_argument("--doctor", action="store_true",
                            help="dependency + configuration health check")
    diag_group.add_argument("--list-phases", action="store_true", help="list phases and exit")
    diag_group.add_argument("--version", action="version", version=f"SyncHunt {__version__}")

    args = parser.parse_args(argv)

    diagnostic = (
        args.check_deps or args.install_deps or args.doctor or args.list_phases
    )
    if not args.domain and not args.list and not diagnostic:
        parser.error("specify a target with -d/--domain or -l/--list (or use --doctor)")

    return args


def main() -> int:
    args = parse_arguments()
    try:
        app = SyncHunt(args)
    except FileNotFoundError as exc:
        print(f"\n❌ {exc}")
        print(
            "Create config.yaml in the working directory, point at one with "
            "--config PATH,\nor copy the fully commented example from the repository."
        )
        return 2
    except ValueError as exc:
        print(f"\n❌ invalid configuration: {exc}")
        return 2

    # CLI values override config file values
    if getattr(args, "threads", None):
        app.config.set("general.threads", args.threads)
    if getattr(args, "rate_limit", None):
        app.config.set("general.rate_limit", args.rate_limit)
    if getattr(args, "timeout", None):
        app.config.set("general.timeout", args.timeout)

    try:
        return app.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  interrupted by user")
        return 130
    except UsageError as exc:
        print(f"\n❌ {exc}")
        return 2
    except SystemExit as exc:  # argparse
        return exc.code if isinstance(exc.code, int) else 2
    except Exception as exc:  # pragma: no cover - top-level guard
        import traceback

        print(f"\n❌ fatal error: {exc}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
