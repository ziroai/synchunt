"""
BugHuntRecon - HTML Report Generator
Generates a comprehensive HTML report of all findings.
"""

import os
from datetime import datetime
from core.utils import read_file_lines, get_file_count, load_json


class HTMLReportGenerator:
    """Generate beautiful HTML reports."""

    def __init__(self, output_dir, target, scan_start, scan_end):
        self.output_dir = output_dir
        self.target = target
        self.scan_start = scan_start
        self.scan_end = scan_end
        self.report_dir = os.path.join(output_dir, "reports")
        os.makedirs(self.report_dir, exist_ok=True)

    def generate(self):
        """Generate the full HTML report."""
        report_path = os.path.join(self.report_dir, "report.html")

        # Gather all data
        data = self._gather_data()

        # Generate HTML
        html = self._build_html(data)

        with open(report_path, 'w') as f:
            f.write(html)

        return report_path

    def _gather_data(self):
        """Gather all scan data for the report."""
        data = {
            'target': self.target,
            'scan_start': self.scan_start,
            'scan_end': self.scan_end,
            'duration': str(self.scan_end - self.scan_start) if self.scan_end and self.scan_start else 'N/A',
        }

        # Subdomains
        sub_file = os.path.join(self.output_dir, "subdomains", "all_subdomains.txt")
        data['subdomains'] = read_file_lines(sub_file) if os.path.exists(sub_file) else []
        data['subdomain_count'] = len(data['subdomains'])

        # Live hosts
        live_file = os.path.join(self.output_dir, "dns", "live_hosts.txt")
        data['live_hosts'] = read_file_lines(live_file) if os.path.exists(live_file) else []
        data['live_host_count'] = len(data['live_hosts'])

        # Ports
        ports_file = os.path.join(self.output_dir, "ports", "all_ports.txt")
        data['open_ports'] = read_file_lines(ports_file) if os.path.exists(ports_file) else []
        data['port_count'] = len(data['open_ports'])

        # URLs
        urls_file = os.path.join(self.output_dir, "content_discovery", "all_urls.txt")
        data['urls'] = read_file_lines(urls_file) if os.path.exists(urls_file) else []
        data['url_count'] = len(data['urls'])

        # JS files
        js_file = os.path.join(self.output_dir, "content_discovery", "js_files.txt")
        data['js_files'] = read_file_lines(js_file) if os.path.exists(js_file) else []
        data['js_count'] = len(data['js_files'])

        # Vulnerabilities
        vuln_dir = os.path.join(self.output_dir, "vulnerabilities")
        data['vulnerabilities'] = []
        if os.path.exists(vuln_dir):
            for root, dirs, files in os.walk(vuln_dir):
                for f in files:
                    if f.endswith('.txt'):
                        vulns = read_file_lines(os.path.join(root, f))
                        data['vulnerabilities'].extend(vulns)
        data['vuln_count'] = len(data['vulnerabilities'])

        # JS Secrets
        secrets_dir = os.path.join(self.output_dir, "js_analysis", "secrets")
        data['secrets'] = []
        if os.path.exists(secrets_dir):
            for f in os.listdir(secrets_dir):
                if f.endswith('.txt'):
                    data['secrets'].extend(
                        read_file_lines(os.path.join(secrets_dir, f))
                    )
        data['secret_count'] = len(data['secrets'])

        return data

    def _build_html(self, data):
        """Build the HTML report string."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugHuntRecon Report - {data['target']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0a0a;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            padding: 40px;
            border-radius: 15px;
            margin-bottom: 30px;
            border: 1px solid #333;
            text-align: center;
        }}
        .header h1 {{
            color: #00ff88;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header .target {{
            color: #ff6b6b;
            font-size: 1.5em;
        }}
        .header .meta {{
            color: #888;
            margin-top: 15px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: #1a1a2e;
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid #333;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #00ff88;
        }}
        .stat-card .label {{
            color: #888;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .stat-card.critical .number {{ color: #ff4444; }}
        .stat-card.warning .number {{ color: #ffaa00; }}
        .section {{
            background: #1a1a2e;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid #333;
        }}
        .section h2 {{
            color: #00ff88;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #333;
        }}
        .data-list {{
            max-height: 400px;
            overflow-y: auto;
            background: #0a0a0a;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
        }}
        .data-list .item {{
            padding: 5px 10px;
            border-bottom: 1px solid #222;
            word-break: break-all;
        }}
        .data-list .item:hover {{
            background: #1a1a2e;
        }}
        .vuln-item {{
            padding: 10px 15px;
            margin: 5px 0;
            border-radius: 6px;
            border-left: 4px solid;
        }}
        .vuln-critical {{
            background: rgba(255, 0, 0, 0.1);
            border-color: #ff0000;
        }}
        .vuln-high {{
            background: rgba(255, 68, 68, 0.1);
            border-color: #ff4444;
        }}
        .vuln-medium {{
            background: rgba(255, 170, 0, 0.1);
            border-color: #ffaa00;
        }}
        .vuln-low {{
            background: rgba(0, 255, 136, 0.1);
            border-color: #00ff88;
        }}
        .vuln-info {{
            background: rgba(0, 136, 255, 0.1);
            border-color: #0088ff;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #555;
        }}
        ::-webkit-scrollbar {{ width: 8px; }}
        ::-webkit-scrollbar-track {{ background: #0a0a0a; }}
        ::-webkit-scrollbar-thumb {{ background: #333; border-radius: 4px; }}
        .search-box {{
            width: 100%;
            padding: 12px;
            background: #0a0a0a;
            border: 1px solid #333;
            color: #e0e0e0;
            border-radius: 8px;
            margin-bottom: 15px;
            font-size: 1em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 BugHuntRecon Report</h1>
            <div class="target">Target: {data['target']}</div>
            <div class="meta">
                Scan Start: {data['scan_start']} |
                Duration: {data['duration']}
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">{data['subdomain_count']}</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="number">{data['live_host_count']}</div>
                <div class="label">Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="number">{data['port_count']}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="number">{data['url_count']}</div>
                <div class="label">URLs Discovered</div>
            </div>
            <div class="stat-card">
                <div class="number">{data['js_count']}</div>
                <div class="label">JS Files</div>
            </div>
            <div class="stat-card critical">
                <div class="number">{data['vuln_count']}</div>
                <div class="label">Vulnerabilities</div>
            </div>
            <div class="stat-card warning">
                <div class="number">{data['secret_count']}</div>
                <div class="label">Secrets Found</div>
            </div>
        </div>

        <!-- Vulnerabilities Section -->
        <div class="section">
            <h2>🚨 Vulnerabilities ({data['vuln_count']})</h2>
            <div class="data-list">
                {''.join(f'<div class="vuln-item {self._get_vuln_class(v)}">{v}</div>' for v in data['vulnerabilities'][:200]) or '<div class="item">No vulnerabilities found</div>'}
            </div>
        </div>

        <!-- Secrets Section -->
        <div class="section">
            <h2>🔑 Secrets & Sensitive Data ({data['secret_count']})</h2>
            <div class="data-list">
                {''.join(f'<div class="vuln-item vuln-high">{s}</div>' for s in data['secrets'][:100]) or '<div class="item">No secrets found</div>'}
            </div>
        </div>

        <!-- Subdomains Section -->
        <div class="section">
            <h2>🌐 Subdomains ({data['subdomain_count']})</h2>
            <input type="text" class="search-box" placeholder="Search subdomains..." onkeyup="filterList(this, 'subdomain-list')">
            <div class="data-list" id="subdomain-list">
                {''.join(f'<div class="item">{s}</div>' for s in data['subdomains'][:500])}
            </div>
        </div>

        <!-- Live Hosts Section -->
        <div class="section">
            <h2>✅ Live Hosts ({data['live_host_count']})</h2>
            <div class="data-list">
                {''.join(f'<div class="item"><a href="{h}" target="_blank" style="color: #00ff88; text-decoration: none;">{h}</a></div>' for h in data['live_hosts'][:500])}
            </div>
        </div>

        <!-- Open Ports Section -->
        <div class="section">
            <h2>🔓 Open Ports ({data['port_count']})</h2>
            <div class="data-list">
                {''.join(f'<div class="item">{p}</div>' for p in data['open_ports'][:500])}
            </div>
        </div>

        <div class="footer">
            <p>Generated by BugHuntRecon | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>

    <script>
        function filterList(input, listId) {{
            const filter = input.value.toLowerCase();
            const list = document.getElementById(listId);
            const items = list.getElementsByClassName('item');
            for (let i = 0; i < items.length; i++) {{
                const text = items[i].textContent.toLowerCase();
                items[i].style.display = text.includes(filter) ? '' : 'none';
            }}
        }}
    </script>
</body>
</html>"""
        return html

    def _get_vuln_class(self, vuln_text):
        """Determine CSS class based on vulnerability severity."""
        vuln_lower = vuln_text.lower()
        if 'critical' in vuln_lower:
            return 'vuln-critical'
        elif 'high' in vuln_lower:
            return 'vuln-high'
        elif 'medium' in vuln_lower:
            return 'vuln-medium'
        elif 'low' in vuln_lower:
            return 'vuln-low'
        else:
            return 'vuln-info'