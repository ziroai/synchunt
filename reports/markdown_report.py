"""
SyncHunt - Markdown Report Generator
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Dict, List, Optional

from core.models import Finding
from core.utils import fenced_block, format_duration, load_json, read_file_lines


class MarkdownReportGenerator:
    """Generate a Markdown report suitable for tickets and PR comments."""

    def __init__(self, output_dir, target, scan_start, scan_end,
                 database=None, scan_id=None, findings: Optional[List[Finding]] = None):
        self.output_dir = output_dir
        self.target = target
        self.scan_start = scan_start
        self.scan_end = scan_end
        self.database = database
        self.scan_id = scan_id
        self._findings = findings
        self.report_dir = os.path.join(output_dir, "reports")
        os.makedirs(self.report_dir, exist_ok=True)

    # ------------------------------------------------------------------
    def _findings_list(self) -> List[Dict]:
        if self._findings:
            return [
                f.to_dict() | {"priority": f.extra.get("priority", "")}
                for f in self._findings
            ]
        if self.database is not None and self.scan_id is not None:
            try:
                rows = self.database.findings(self.scan_id)
                if rows:
                    return [
                        f.to_dict() | {"priority": f.extra.get("priority", "")}
                        for f in rows
                    ]
            except Exception:  # pragma: no cover - defensive
                pass
        data = load_json(
            os.path.join(self.output_dir, "findings_prioritized", "findings.json"), []
        )
        return data if isinstance(data, list) else []

    def generate(self) -> str:
        report_path = os.path.join(self.report_dir, "report.md")
        findings = self._findings_list()

        duration = "N/A"
        if self.scan_end and self.scan_start:
            duration = format_duration((self.scan_end - self.scan_start).total_seconds())

        lines: List[str] = [
            "# 🔎 SyncHunt Report",
            "",
            f"**Target:** `{self.target}`  ",
            f"**Scan start:** {self.scan_start}  ",
            f"**Duration:** {duration}  ",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "> Findings are heuristic and require manual verification. "
            "Only test systems you are authorised to test.",
            "",
            "## 📊 Summary",
            "",
        ]

        severity_counts: Dict[str, int] = {}
        priority_counts: Dict[str, int] = {}
        for finding in findings:
            key = (finding.get("severity") or "info").lower()
            severity_counts[key] = severity_counts.get(key, 0) + 1
            prio = finding.get("priority") or "—"
            priority_counts[prio] = priority_counts.get(prio, 0) + 1

        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Total findings | {len(findings)} |")
        for level in ("critical", "high", "medium", "low", "info"):
            lines.append(f"| {level.title()} | {severity_counts.get(level, 0)} |")
        for prio in ("P1", "P2", "P3", "P4"):
            lines.append(f"| Priority {prio} | {priority_counts.get(prio, 0)} |")
        lines.append("")

        for label, path in (
            ("Subdomains", ("subdomains", "all_subdomains.txt")),
            ("Live hosts", ("dns", "live_hosts.txt")),
            ("Open ports", ("ports", "all_ports.txt")),
            ("URLs", ("content_discovery", "all_urls.txt")),
            ("JS files", ("content_discovery", "js_files.txt")),
            ("API endpoints", ("api_intelligence", "endpoints.txt")),
            ("Public buckets", ("cloud_enum", "public_buckets.txt")),
            ("Interesting paths", ("intel", "interesting_paths.txt")),
        ):
            full = os.path.join(self.output_dir, *path)
            count = len(read_file_lines(full)) if os.path.exists(full) else 0
            lines.append(f"| {label} | {count} |")
        lines.append("")

        if findings:
            lines += [
                "## 🎯 Prioritised findings",
                "",
                "| Priority | Score | Severity | Category | Title | Location |",
                "|----------|-------|----------|----------|-------|----------|",
            ]
            for finding in findings[:120]:
                title = str(finding.get("title") or "").replace("|", "\\|")[:90]
                location = str(finding.get("url") or finding.get("target") or "")
                location = location.replace("|", "\\|")[:70]
                try:
                    score = f"{float(finding.get('score') or 0):.2f}"
                except (TypeError, ValueError):
                    score = "0.00"
                lines.append(
                    f"| {finding.get('priority') or '—'} | {score} | "
                    f"{finding.get('severity') or 'info'} | {finding.get('category') or ''} | "
                    f"{title} | {location} |"
                )
            lines.append("")

            lines.append("## 🔍 Finding detail")
            lines.append("")
            for finding in findings[:20]:
                lines.append(f"### {finding.get('title') or 'finding'}")
                lines.append("")
                lines.append(f"- **Severity / priority:** {finding.get('severity')} "
                             f"({finding.get('priority') or '—'}, score {finding.get('score')})")
                lines.append(f"- **Category:** {finding.get('category')}")
                if finding.get("url"):
                    lines.append(f"- **Location:** {finding.get('url')}")
                if finding.get("source"):
                    lines.append(f"- **Source phase:** {finding.get('source')}")
                if finding.get("score_reasons"):
                    lines.append(f"- **Why this score:** {finding.get('score_reasons')}")
                if finding.get("evidence"):
                    lines.append("")
                    lines.append(fenced_block(str(finding["evidence"])[:800]))
                lines.append("")

        for title, rel in (
            ("🌐 Subdomains", ("subdomains", "all_subdomains.txt")),
            ("✅ Live hosts", ("dns", "live_hosts.txt")),
            ("🔓 Open ports", ("ports", "all_ports.txt")),
        ):
            full = os.path.join(self.output_dir, *rel)
            items = read_file_lines(full) if os.path.exists(full) else []
            lines.append(f"## {title} ({len(items)})")
            lines.append("")
            if items:
                lines.append("<details><summary>Click to expand</summary>")
                lines.append("")
                lines.append(fenced_block("\n".join(items[:300])))
                lines.append("")
                lines.append("</details>")
            else:
                lines.append("_none_")
            lines.append("")

        lines.append("---")
        lines.append(
            f"*Generated by SyncHunt at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        )
        lines.append("")

        with open(report_path, "w") as fh:
            fh.write("\n".join(lines))
        return report_path
