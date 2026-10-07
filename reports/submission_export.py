"""
SyncHunt - bug-bounty submission exports

Findings already come out as HTML/Markdown/JSON/CSV/SARIF. This module adds the
platform formats you actually paste into a report:

  * `submission_hackerone.json` - HackerOne-shaped report objects
    (title, severity, vulnerability_information, impact, weakness)
  * `submission_intigriti.json` - Intigriti-shaped submissions
  * `submission_bugcrowd.csv`   - Bugcrowd's P1-P5 triage grid

Nothing is uploaded anywhere: the files are local drafts for the human to
review, evidence-check and submit by hand.
"""

from __future__ import annotations

import os
from typing import Dict, Iterable, List

from core.models import Finding
from core.utils import save_csv, save_json

HACKERONE_SEVERITIES = ("none", "low", "medium", "high", "critical")

BUGCROWD_PRIORITY = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
    "info": "P5",
}

SUBMISSION_TEMPLATE = """### Summary
{title}

### Affected asset
{url}

### Category
{category} (detected by {source}, severity: {severity}, confidence: {confidence})

### Evidence
{evidence}

### Reproduction
1. Re-run the phase that produced this finding (see the scan's HTML report for the exact command).
2. Confirm manually before submitting - automated findings are leads, not proof.

### Suggested remediation
{remediation}
"""

REMEDIATION_HINTS = {
    "cms": "Update the CMS core/plugins and remove unused components.",
    "sqli": "Use parameterised queries and validate input server-side.",
    "xss": "Encode output contextually and apply a strict Content-Security-Policy.",
    "rce": "Never pass user input to a shell; use allow-lists and argument arrays.",
    "ssrf": "Allow-list outbound destinations and block link-local/metadata ranges.",
    "ssti": "Do not build templates from user input; use sandboxed renderers.",
    "cloud": "Remove public access from the bucket and audit its contents for data exposure.",
    "takeover": "Claim or delete the dangling DNS record, or remove the CNAME.",
    "secrets": "Rotate the credential immediately and purge it from history.",
    "dns": "Restrict zone transfers to authorised secondary name servers.",
    "headers": "Set the missing security headers at the edge.",
    "exposure": "Require authentication and restrict network access to the service.",
    "api": "Require authentication/authorisation on the endpoint and document it.",
}


class SubmissionExporter:
    """Write platform-shaped submission drafts next to the other reports."""

    def __init__(self, output_dir: str, target: str):
        self.output_dir = output_dir
        self.target = target
        self.reports_dir = os.path.join(output_dir, "reports")
        os.makedirs(self.reports_dir, exist_ok=True)

    # ------------------------------------------------------------------
    def _rows(self, findings: Iterable[Finding]) -> List[Dict]:
        rows: List[Dict] = []
        for finding in findings:
            rows.append(
                {
                    "title": finding.title,
                    "severity": finding.severity if finding.severity in HACKERONE_SEVERITIES else "medium",
                    "url": finding.url or finding.target or self.target,
                    "category": finding.category,
                    "source": finding.source,
                    "confidence": finding.confidence,
                    "evidence": finding.evidence,
                    "references": list(finding.references),
                    "priority": finding.extra.get("priority") or BUGCROWD_PRIORITY.get(finding.severity, "P5"),
                    "cve": sorted({
                        tag.upper() for tag in finding.tags if tag.upper().startswith("CVE-")
                    }),
                    "remediation": REMEDIATION_HINTS.get(finding.category, "Review and remediate the underlying issue."),
                    "score": finding.score,
                }
            )
        return rows

    # ------------------------------------------------------------------
    def export(self, findings: Iterable[Finding]) -> Dict[str, str]:
        rows = self._rows(findings)
        generated: Dict[str, str] = {}

        hackerone = [
            {
                "title": row["title"],
                "severity": row["severity"],
                "vulnerability_information": SUBMISSION_TEMPLATE.format(**row),
                "impact": (
                    f"{row['category']} finding on {row['url']} "
                    f"({row['severity']}, confidence {row['confidence']})."
                ),
                "weakness": row["category"],
                "asset": row["url"],
                "references": row["references"],
                "cve": row["cve"],
            }
            for row in rows
        ]
        hackerone_path = os.path.join(self.reports_dir, "submission_hackerone.json")
        save_json({"target": self.target, "reports": hackerone}, hackerone_path)
        generated["hackerone"] = hackerone_path

        intigriti = [
            {
                "title": row["title"],
                "severity": row["severity"],
                "endpoint": row["url"],
                "description": SUBMISSION_TEMPLATE.format(**row),
                "type": row["category"],
                "cvss_vector": "",
                "cve": row["cve"],
            }
            for row in rows
        ]
        intigriti_path = os.path.join(self.reports_dir, "submission_intigriti.json")
        save_json({"target": self.target, "submissions": intigriti}, intigriti_path)
        generated["intigriti"] = intigriti_path

        bugcrowd_rows = [
            {
                "Title": row["title"],
                "Severity": row["priority"],
                "Target": row["url"],
                "Category": row["category"],
                "Description": SUBMISSION_TEMPLATE.format(**row),
                "CVE": ", ".join(row["cve"]),
            }
            for row in rows
        ]
        bugcrowd_path = os.path.join(self.reports_dir, "submission_bugcrowd.csv")
        save_csv(
            bugcrowd_rows,
            bugcrowd_path,
            fieldnames=["Title", "Severity", "Target", "Category", "Description", "CVE"],
        )
        generated["bugcrowd"] = bugcrowd_path
        return generated
