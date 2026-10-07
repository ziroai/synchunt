"""
SyncHunt - HTML Report Generator

Every value that comes from scan output (URLs, titles, evidence) is escaped
before it is embedded: findings are attacker-influenced data, and a report
that executes injected script is itself a vulnerability.
"""

from __future__ import annotations

import html
import os
from datetime import datetime
from typing import Dict, List, Optional

from core.i18n import t
from core.models import Finding
from core.utils import (
    format_duration,
    load_json,
    read_file_lines,
    truncate,
)


class HTMLReportGenerator:
    """Generate a self-contained HTML report."""

    def __init__(self, output_dir, target, scan_start, scan_end,
                 database=None, scan_id=None, findings: Optional[List[Finding]] = None,
                 history: Optional[Dict] = None):
        self.output_dir = output_dir
        self.target = target
        self.scan_start = scan_start
        self.scan_end = scan_end
        self.database = database
        self.scan_id = scan_id
        self._findings = findings
        self.history = history or {}
        self.report_dir = os.path.join(output_dir, "reports")
        os.makedirs(self.report_dir, exist_ok=True)

    # ------------------------------------------------------------------
    def generate(self) -> str:
        report_path = os.path.join(self.report_dir, "report.html")
        data = self._gather_data()
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(self._build_html(data))
        return report_path

    # ------------------------------------------------------------------
    def _findings_list(self) -> List[Dict]:
        if self._findings:
            return [f.to_dict() | {"priority": f.extra.get("priority", "")} for f in self._findings]
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
        path = os.path.join(self.output_dir, "findings_prioritized", "findings.json")
        data = load_json(path, [])
        return data if isinstance(data, list) else []

    def _gather_data(self) -> Dict:
        findings = self._findings_list()
        severity_counts: Dict[str, int] = {level: 0 for level in
                                          ("critical", "high", "medium", "low", "info")}
        priority_counts: Dict[str, int] = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for finding in findings:
            severity = (finding.get("severity") or "info").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            priority = finding.get("priority") or ""
            if priority in priority_counts:
                priority_counts[priority] += 1

        duration = "N/A"
        if self.scan_end and self.scan_start:
            duration = format_duration((self.scan_end - self.scan_start).total_seconds())

        def _lines(*parts) -> List[str]:
            path = os.path.join(self.output_dir, *parts)
            return read_file_lines(path) if os.path.exists(path) else []

        data = {
            "target": self.target,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "duration": duration,
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "findings": findings,
            "severity": severity_counts,
            "priority": priority_counts,
            "finding_count": len(findings),
            "history": self.history,
            "subdomains": _lines("subdomains", "all_subdomains.txt"),
            "live_hosts": _lines("dns", "live_hosts.txt"),
            "open_ports": _lines("ports", "all_ports.txt"),
            "urls": _lines("content_discovery", "all_urls.txt"),
            "js_files": _lines("content_discovery", "js_files.txt"),
            "api_endpoints": _lines("api_intelligence", "endpoints.txt"),
            "public_buckets": _lines("cloud_enum", "public_buckets.txt"),
            "interesting_paths": _lines("intel", "interesting_paths.txt"),
            "secrets": _lines("js_analysis", "secrets", "custom_regex.txt")
            + _lines("js_analysis", "secrets", "secretfinder.txt"),
        }
        data["url_count"] = len(data["urls"])
        return data

    # ------------------------------------------------------------------
    def _build_html(self, data: Dict) -> str:
        e = html.escape

        def _stat(number, label, css_class: str = "") -> str:
            return (
                f'<div class="stat-card {css_class}">'
                f'<div class="number">{e(str(number))}</div>'
                f'<div class="label">{e(label)}</div></div>'
            )

        def _list(items, limit=500, links=False, empty="nothing found") -> str:
            items = items[:limit]
            if not items:
                return f'<div class="item muted">{e(empty)}</div>'
            chunks = []
            for item in items:
                safe = e(str(item))
                if links and str(item).startswith(("http://", "https://")):
                    chunks.append(
                        f'<div class="item"><a href="{safe}" rel="noopener noreferrer" '
                        f'target="_blank">{safe}</a></div>'
                    )
                else:
                    chunks.append(f'<div class="item">{safe}</div>')
            return "".join(chunks)

        def _findings_rows(findings, limit=200) -> str:
            if not findings:
                return '<div class="item muted">no findings</div>'
            rows = []
            for finding in findings[:limit]:
                severity = str(finding.get("severity") or "info").lower()
                priority = str(finding.get("priority") or "")
                reasons = finding.get("score_reasons") or ""
                if isinstance(reasons, list):
                    reasons = ", ".join(str(r) for r in reasons)
                try:
                    score = round(float(finding.get("score") or 0), 2)
                except (TypeError, ValueError):
                    score = 0.0

                parts = [
                    f'<div class="vuln-item vuln-{e(severity)}">',
                    '<div class="vuln-head">',
                    f'<span class="badge">{e(severity.upper())}</span>',
                ]
                if priority:
                    parts.append(f'<span class="badge prio">{e(priority)}</span>')
                parts.append(f'<span class="score">{score}</span>')
                parts.append(f'<span class="vuln-title">{e(str(finding.get("title") or ""))}</span>')
                parts.append("</div>")

                meta = [e(str(finding.get("category") or ""))]
                if finding.get("url"):
                    meta.append(e(str(finding["url"])))
                if finding.get("source"):
                    meta.append("source: " + e(str(finding["source"])))
                parts.append('<div class="vuln-meta">' + " · ".join(meta) + "</div>")

                if reasons:
                    parts.append(f'<div class="vuln-why">why: {e(str(reasons))}</div>')
                if finding.get("evidence"):
                    evidence = truncate(str(finding["evidence"]), 600)
                    parts.append(f'<pre class="evidence">{e(evidence)}</pre>')
                parts.append("</div>")
                rows.append("".join(parts))
            return "".join(rows)

        def _history_section(history: Dict) -> str:
            if not history or not history.get("previous_run"):
                return ""
            counts = history.get("counts") or {}
            rows = history.get("new") or []
            if rows:
                items = []
                for row in rows[:30]:
                    severity = str(row.get("severity") or "info").lower()
                    items.append(
                        f'<div class="vuln-item vuln-{e(severity)}"><div class="vuln-head">'
                        f'<span class="badge">{e(severity.upper())}</span>'
                        f'<span class="vuln-title">{e(str(row.get("title") or ""))}</span>'
                        f'</div><div class="vuln-meta">{e(str(row.get("url") or ""))}</div></div>'
                    )
                new_block = "".join(items)
            else:
                new_block = '<div class="item muted">nothing new</div>'
            return (
                f'<div class="section">'
                f'<h2>🕓 Since last scan ({e(os.path.basename(str(history["previous_run"])))})</h2>'
                f'<div class="stats-grid" style="margin-bottom:14px">'
                f'{_stat(counts.get("new", 0), "New", "high")}'
                f'{_stat(counts.get("fixed", 0), "Fixed")}'
                f'{_stat(counts.get("persisting", 0), "Persisting")}'
                f'</div>'
                f'<div class="data-list" style="max-height:420px">{new_block}</div>'
                f'</div>'
            )

        severity = data["severity"]
        priority = data["priority"]

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
<title>SyncHunt Report - {e(str(data['target']))}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', Tahoma, Verdana, sans-serif; background: #0a0a0f;
         color: #e6e6f0; line-height: 1.55; }}
  .container {{ max-width: 1280px; margin: 0 auto; padding: 24px; }}
  .header {{ background: linear-gradient(135deg, #14142b, #0f1b2d); padding: 32px;
             border-radius: 14px; margin-bottom: 24px; border: 1px solid #26264a;
             text-align: center; }}
  .header h1 {{ color: #4ade80; font-size: 2.1em; margin-bottom: 8px; }}
  .header .target {{ color: #f87171; font-size: 1.35em; word-break: break-all; }}
  .header .meta {{ color: #8b8ba7; margin-top: 12px; font-size: .92em; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                 gap: 14px; margin-bottom: 24px; }}
  .stat-card {{ background: #14142b; padding: 18px 12px; border-radius: 10px;
                text-align: center; border: 1px solid #26264a; }}
  .stat-card .number {{ font-size: 1.9em; font-weight: 700; color: #4ade80; }}
  .stat-card .label {{ color: #8b8ba7; font-size: .82em; margin-top: 4px;
                       text-transform: uppercase; letter-spacing: .04em; }}
  .stat-card.critical .number {{ color: #ef4444; }}
  .stat-card.high .number {{ color: #f97316; }}
  .stat-card.medium .number {{ color: #eab308; }}
  .stat-card.warning .number {{ color: #f59e0b; }}
  .section {{ background: #12122a; padding: 22px; border-radius: 12px;
              margin-bottom: 18px; border: 1px solid #26264a; }}
  .section h2 {{ color: #4ade80; font-size: 1.15em; margin-bottom: 14px;
                 padding-bottom: 8px; border-bottom: 1px solid #26264a; }}
  .data-list {{ max-height: 380px; overflow-y: auto; background: #0a0a0f;
                padding: 12px; border-radius: 8px; font-family: ui-monospace, Menlo, monospace;
                font-size: .84em; }}
  .data-list .item {{ padding: 4px 8px; border-bottom: 1px solid #1c1c30;
                      word-break: break-all; }}
  .data-list a {{ color: #6ee7b7; text-decoration: none; }}
  .muted {{ color: #6b6b85; }}
  .vuln-item {{ padding: 10px 12px; margin: 6px 0; border-radius: 8px;
                border-left: 4px solid #6b7280; background: #16162e; }}
  .vuln-head {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
  .badge {{ font-size: .68em; padding: 2px 7px; border-radius: 999px;
            background: #26264a; color: #cbd5f5; letter-spacing: .03em; }}
  .badge.prio {{ background: #3b2f63; color: #e9d5ff; }}
  .score {{ font-family: ui-monospace, monospace; color: #93c5fd; font-size: .8em; }}
  .vuln-title {{ font-weight: 600; }}
  .vuln-meta {{ color: #8b8ba7; font-size: .8em; margin-top: 3px; word-break: break-all; }}
  .vuln-why {{ color: #a5b4fc; font-size: .78em; margin-top: 3px; }}
  .evidence {{ background: #0a0a0f; padding: 8px; border-radius: 6px; margin-top: 6px;
               font-size: .78em; color: #c9d1d9; white-space: pre-wrap;
               word-break: break-all; max-height: 180px; overflow: auto; }}
  .vuln-critical {{ border-color: #ef4444; }}
  .vuln-high {{ border-color: #f97316; }}
  .vuln-medium {{ border-color: #eab308; }}
  .vuln-low {{ border-color: #4ade80; }}
  .vuln-info {{ border-color: #38bdf8; }}
  .search-box {{ width: 100%; padding: 10px; background: #0a0a0f; border: 1px solid #26264a;
                 color: #e6e6f0; border-radius: 8px; margin-bottom: 12px; }}
  .footer {{ text-align: center; padding: 18px; color: #55556e; font-size: .85em; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🔎 SyncHunt - {e(t('report.title'))}</h1>
    <div class="target">{e(str(data['target']))}</div>
    <div class="meta">
      Scan start: {e(str(data['scan_start']))} · Duration: {e(data['duration'])}<br>
      Generated {e(data['generated'])} · Authorised testing only
    </div>
  </div>

  <div class="stats-grid">
    {_stat(data['finding_count'], 'Total findings', 'critical')}
    {_stat(severity.get('critical', 0), 'Critical', 'critical')}
    {_stat(severity.get('high', 0), 'High', 'high')}
    {_stat(severity.get('medium', 0), 'Medium', 'medium')}
    {_stat(priority.get('P1', 0), 'Priority 1', 'warning')}
    {_stat(len(data['subdomains']), 'Subdomains')}
    {_stat(len(data['live_hosts']), 'Live hosts')}
    {_stat(len(data['open_ports']), 'Open ports')}
    {_stat(data['url_count'], 'URLs')}
    {_stat(len(data['api_endpoints']), 'API endpoints')}
    {_stat(len(data['public_buckets']), 'Public buckets', 'critical')}
    {_stat(len(data['secrets']), 'Secrets', 'warning')}
  </div>

  {_history_section(data.get('history') or {})}

  <div class="section">
    <h2>🎯 Prioritised findings ({data['finding_count']})</h2>
    <input type="text" class="search-box" placeholder="Filter findings..."
           onkeyup="filterList(this, 'findings-list')">
    <div id="findings-list" class="data-list" style="max-height:640px">
      {_findings_rows(data['findings'])}
    </div>
  </div>

  <div class="section">
    <h2>🛰️ Exposed management / interesting paths ({len(data['interesting_paths'])})</h2>
    <div class="data-list">{_list(data['interesting_paths'], 200, links=True)}</div>
  </div>

  <div class="section">
    <h2>🔌 API endpoints ({len(data['api_endpoints'])})</h2>
    <div class="data-list">{_list(data['api_endpoints'], 400, links=True)}</div>
  </div>

  <div class="section">
    <h2>☁️ Public cloud buckets ({len(data['public_buckets'])})</h2>
    <div class="data-list">{_list(data['public_buckets'], 100, links=True)}</div>
  </div>

  <div class="section">
    <h2>🌐 Subdomains ({len(data['subdomains'])})</h2>
    <input type="text" class="search-box" placeholder="Filter subdomains..."
           onkeyup="filterList(this, 'subdomain-list')">
    <div class="data-list" id="subdomain-list">{_list(data['subdomains'], 1000)}</div>
  </div>

  <div class="section">
    <h2>✅ Live hosts ({len(data['live_hosts'])})</h2>
    <div class="data-list">{_list(data['live_hosts'], 500, links=True)}</div>
  </div>

  <div class="section">
    <h2>🔓 Open ports ({len(data['open_ports'])})</h2>
    <div class="data-list">{_list(data['open_ports'], 500)}</div>
  </div>

  <div class="section">
    <h2>📜 JavaScript files ({len(data['js_files'])})</h2>
    <div class="data-list">{_list(data['js_files'], 300, links=True)}</div>
  </div>

  <div class="footer">
    Generated by SyncHunt · findings are heuristic and require manual verification
  </div>
</div>
<script>
function filterList(input, listId) {{
  const filter = (input.value || '').toLowerCase();
  const list = document.getElementById(listId);
  if (!list) return;
  const items = list.getElementsByClassName('item');
  for (let i = 0; i < items.length; i++) {{
    const text = (items[i].textContent || '').toLowerCase();
    items[i].style.display = text.includes(filter) ? '' : 'none';
  }}
}}
</script>
</body>
</html>"""
