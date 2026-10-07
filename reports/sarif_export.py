"""
SyncHunt - SARIF 2.1.0 export

SARIF (Static Analysis Results Interchange Format) is what GitHub code
scanning, GitLab and most CI security dashboards ingest. Exporting it makes
every SyncHunt scan usable as a CI artefact instead of a directory of files
somebody has to read by hand.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

from core.models import Finding
from core.utils import ensure_dir, save_json

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/ziroai/synchunt"

# SARIF understands error/warning/note/none. Finding severities map like this.
LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


class SarifExporter:
    """Build a SARIF log for one scan."""

    def __init__(self, output_dir: str, target: str,
                 findings: Iterable[Finding], tool_version: str = ""):
        self.output_dir = output_dir
        self.target = target
        self.findings: List[Finding] = [f for f in findings if f is not None]
        self.tool_version = tool_version

    # ------------------------------------------------------------------
    @staticmethod
    def rule_id(finding: Finding) -> str:
        category = str(finding.category or "unknown").strip().lower().replace(" ", "-")
        return f"synchunt/{category or 'unknown'}"

    @staticmethod
    def level(finding: Finding) -> str:
        return LEVEL_BY_SEVERITY.get(
            str(finding.severity or "info").lower(), "warning"
        )

    def _rules(self) -> List[Dict[str, Any]]:
        rules: Dict[str, Dict[str, Any]] = {}
        max_rank: Dict[str, int] = {}
        for finding in self.findings:
            rule_id = self.rule_id(finding)
            rank = finding.severity_rank
            if rule_id not in rules:
                category = str(finding.category or "unknown")
                rules[rule_id] = {
                    "id": rule_id,
                    "name": category.title().replace(" ", ""),
                    "shortDescription": {"text": f"SyncHunt {category} finding"},
                    "fullDescription": {
                        "text": (
                            f"Findings produced by the SyncHunt '{category}' checks. "
                            "Findings are heuristic and require manual verification."
                        )
                    },
                    "defaultConfiguration": {"level": self.level(finding)},
                    "properties": {"tags": ["security"]},
                }
                max_rank[rule_id] = rank
            elif rank > max_rank[rule_id]:
                # keep the most severe default level seen for this rule
                max_rank[rule_id] = rank
                rules[rule_id]["defaultConfiguration"]["level"] = self.level(finding)
        return sorted(rules.values(), key=lambda item: item["id"])

    def _results(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        rule_index = {rule["id"]: index for index, rule in enumerate(rules)}
        results: List[Dict[str, Any]] = []
        ordered = sorted(self.findings, key=lambda f: -f.severity_rank)
        for finding in ordered:
            rule_id = self.rule_id(finding)
            message = str(finding.title or "finding")
            if finding.evidence:
                message = f"{message} — {finding.evidence}"
            location = finding.url or finding.target or self.target
            properties: Dict[str, Any] = {
                "severity": finding.severity,
                "confidence": finding.confidence,
                "category": finding.category,
                "source": finding.source,
                "score": finding.score,
            }
            priority = finding.extra.get("priority")
            if priority:
                properties["priority"] = priority
            if finding.tags:
                properties["tags"] = list(finding.tags)

            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_index.get(rule_id, 0),
                "level": self.level(finding),
                "message": {"text": message[:4000]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(location)},
                    },
                    "logicalLocations": [{"fullyQualifiedName": str(finding.target or self.target)}],
                }],
                "partialFingerprints": {"synchuntFinding/v1": finding.fingerprint()},
                "properties": properties,
            })
        return results

    # ------------------------------------------------------------------
    def build(self) -> Dict[str, Any]:
        rules = self._rules()
        driver: Dict[str, Any] = {
            "name": "SyncHunt",
            "informationUri": INFORMATION_URI,
            "rules": rules,
        }
        if self.tool_version:
            driver["version"] = self.tool_version
        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [{
                "tool": {"driver": driver},
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:%SZ"),
                }],
                "results": self._results(rules),
            }],
        }

    def generate(self) -> str:
        report_dir = os.path.join(self.output_dir, "reports")
        ensure_dir(report_dir)
        path = os.path.join(report_dir, "results.sarif")
        save_json(self.build(), path)
        return path
