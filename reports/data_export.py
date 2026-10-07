"""
SyncHunt - Machine-readable exports
JSON / CSV artefacts that downstream tooling (dashboards, trackers, CI jobs)
can consume. One small module keeps export formats consistent everywhere.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List

from core.models import Finding
from core.utils import ensure_dir, get_timestamp, save_csv, save_json

FINDING_FIELDS = [
    "fingerprint", "priority", "score", "severity", "confidence", "category",
    "title", "url", "target", "evidence", "source", "tags", "score_reasons",
]


class DataExporter:
    """Writes scan results in machine-readable formats."""

    def __init__(self, output_dir: str, target: str):
        self.output_dir = output_dir
        self.target = target
        self.export_dir = os.path.join(output_dir, "reports")
        ensure_dir(self.export_dir)

    # ------------------------------------------------------------------
    def export_findings(self, findings: Iterable[Finding]) -> Dict[str, str]:
        rows: List[Dict[str, Any]] = []
        for finding in findings:
            row = finding.to_dict()
            row["priority"] = finding.extra.get("priority", "")
            reasons = finding.extra.get("score_reasons") or []
            row["score_reasons"] = "; ".join(reasons) if isinstance(reasons, list) else str(reasons)
            row["tags"] = ",".join(row.get("tags") or [])
            rows.append(row)

        json_path = os.path.join(self.export_dir, "findings.json")
        csv_path = os.path.join(self.export_dir, "findings.csv")
        save_json(rows, json_path)
        save_csv(rows, csv_path, fieldnames=FINDING_FIELDS)
        return {"findings_json": json_path, "findings_csv": csv_path}

    # ------------------------------------------------------------------
    def export_scan_data(self, data: Dict[str, Any]) -> str:
        payload = {
            "target": self.target,
            "exported_at": get_timestamp(),
            **data,
        }
        path = os.path.join(self.export_dir, "scan_data.json")
        save_json(payload, path)
        return path

    def export_assets(self, assets: Iterable[Dict[str, Any]]) -> Dict[str, str]:
        rows = list(assets)
        json_path = os.path.join(self.export_dir, "assets.json")
        csv_path = os.path.join(self.export_dir, "assets.csv")
        save_json(rows, json_path)
        save_csv(rows, csv_path)
        return {"assets_json": json_path, "assets_csv": csv_path}
