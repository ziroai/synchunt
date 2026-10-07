"""
SyncHunt - Finding Prioritisation
Normalises, de-duplicates, scores and ranks findings from every phase so a
tester can triage the noise in minutes instead of hours.

Scoring is a transparent weighted heuristic (severity x confidence x exposure
x context keywords), not a black box: every finding carries the reasons that
produced its score, so results stay explainable in a report.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Dict, Iterable, List, Tuple

from core.models import Finding

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
from core.utils import (
    ensure_dir,
    get_timestamp,
    load_json,
    read_file_lines,
    save_csv,
    save_json,
    severity_rank,
    write_file_lines,
)

SEVERITY_WEIGHT = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 1.0,
}

CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.8, "low": 0.6}

CATEGORY_FACTOR = {
    "secrets": 1.25,
    "credentials": 1.25,
    "vulnerability": 1.2,
    "vuln": 1.2,
    "rce": 1.3,
    "sqli": 1.25,
    "xss": 1.1,
    "cloud": 1.1,
    "exposure": 1.1,
    "api": 1.05,
    "github": 0.95,
    "misconfiguration": 0.95,
    "tls": 0.9,
    "headers": 0.9,
    "info": 0.8,
}

# keyword -> (bonus, reason)
CONTEXT_BOOSTS: List[Tuple[str, float, str]] = [
    ("remote code execution", 3.0, "RCE-class impact"),
    ("rce", 2.5, "RCE-class impact"),
    ("deserialization", 2.0, "deserialization impact"),
    ("sql injection", 2.5, "SQL injection impact"),
    ("sqli", 2.2, "SQL injection impact"),
    ("ssrf", 2.0, "SSRF impact"),
    ("authentication bypass", 2.2, "auth bypass impact"),
    ("auth bypass", 2.0, "auth bypass impact"),
    ("subdomain takeover", 2.0, "takeover potential"),
    ("open redirect", 0.8, "redirect abuse potential"),
    ("idor", 1.5, "access-control impact"),
    ("xss", 1.2, "client-side impact"),
    ("private key", 1.6, "high-value secret"),
    ("aws", 1.4, "cloud credential exposure"),
    ("admin", 0.6, "administrative surface"),
    ("swagger", 0.5, "API surface"),
    ("openapi", 0.5, "API surface"),
    ("graphql", 0.5, "API surface"),
    ("actuator", 1.2, "management endpoint"),
    ("public", 1.0, "publicly reachable"),
    ("heapdump", 1.5, "memory disclosure"),
    ("password", 1.0, "credential material"),
]

ENV_FACTOR = [
    ("prod", 1.15, "production host"),
    ("live", 1.1, "production host"),
    ("staging", 0.95, "staging host"),
    ("stage", 0.95, "staging host"),
    ("dev", 0.9, "development host"),
    ("test", 0.9, "test host"),
    ("internal", 0.9, "internal-looking host"),
]


class FindingPrioritizer:
    """Collect, de-duplicate, score and export findings."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.logger = ctx.logger
        self.output_dir = ctx.path("findings_prioritized")
        ensure_dir(self.output_dir)
        self.weights = self.config.get("finding_prioritizer", {}) or {}
        self.min_severity = self.config.get("finding_prioritizer.min_severity", "info")
        self.findings: List[Finding] = []

    # ------------------------------------------------------------------
    # Collection
    # ------------------------------------------------------------------
    def _from_database(self) -> List[Finding]:
        if self.ctx.database is None or self.ctx.scan_id is None:
            return []
        try:
            return list(self.ctx.database.findings(self.ctx.scan_id))
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.debug(f"could not read findings from DB: {exc}")
            return []

    def _from_files(self) -> List[Finding]:
        """Fallback: rebuild findings from on-disk phase output."""
        findings: List[Finding] = []

        vuln_dir = self.ctx.path("vulnerabilities")
        if os.path.isdir(vuln_dir):
            for root, _dirs, files in os.walk(vuln_dir):
                for name in files:
                    if not name.endswith((".txt", ".json")):
                        continue
                    path = os.path.join(root, name)
                    rel = os.path.relpath(path, self.ctx.output_dir)
                    if name.endswith(".txt"):
                        for line in read_file_lines(path):
                            findings.append(
                                Finding(
                                    category=_category_from_text(line),
                                    title=line[:200],
                                    severity=_severity_from_text(line),
                                    target=self.ctx.target,
                                    evidence=line,
                                    source=rel,
                                    confidence="medium",
                                )
                            )
                    else:
                        data = load_json(path, [])
                        if isinstance(data, list):
                            for item in data[:200]:
                                if isinstance(item, dict):
                                    info = item.get("info") or {}
                                    findings.append(
                                        Finding(
                                            category="vulnerability",
                                            title=str(info.get("name") or item.get("template-id") or name),
                                            severity=str(info.get("severity", "medium")),
                                            target=self.ctx.target,
                                            url=str(item.get("matched-at") or item.get("host") or ""),
                                            evidence=str(item.get("matched-at") or "")[:400],
                                            source=rel,
                                            confidence="high",
                                        )
                                    )

        secrets_dir = self.ctx.path("js_analysis", "secrets")
        if os.path.isdir(secrets_dir):
            for name in sorted(os.listdir(secrets_dir)):
                if not name.endswith(".txt"):
                    continue
                for line in read_file_lines(os.path.join(secrets_dir, name)):
                    findings.append(
                        Finding(
                            category="secrets",
                            title=line.split("]", 1)[0].strip("[ ") or "Secret",
                            severity="high",
                            target=self.ctx.target,
                            evidence=line,
                            source=f"js_analysis/{name}",
                            confidence="medium",
                        )
                    )

        for subdir, category in (
            ("cloud_enum", "cloud"),
            ("github_recon", "github"),
            ("api_intelligence", "api"),
            ("sensitive_info", "exposure"),
        ):
            path = self.ctx.path(subdir)
            if not os.path.isdir(path):
                continue
            for name in sorted(os.listdir(path)):
                if not name.endswith(".json"):
                    continue
                data = load_json(os.path.join(path, name), [])
                if not isinstance(data, list):
                    continue
                for item in data[:200]:
                    if isinstance(item, dict) and item.get("public"):
                        findings.append(
                            Finding(
                                category=category,
                                title=f"Public {item.get('provider', 'cloud')} bucket: {item.get('name', '')}",
                                severity="critical",
                                target=self.ctx.target,
                                url=str(item.get("url", "")),
                                evidence=str(item)[:400],
                                source=f"{subdir}/{name}",
                                confidence="high",
                            )
                        )
        return findings

    def _collect(self) -> List[Finding]:
        findings = self._from_database()
        origin = "database"
        if not findings:
            findings = self._from_files()
            origin = "files"
        self.logger.info(f"Collected {len(findings)} finding(s) from {origin}")
        return findings

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------
    def score(self, finding: Finding) -> Tuple[float, List[str]]:
        """Return (score, reasons) for one finding."""
        reasons: List[str] = []
        severity = finding.severity
        base = SEVERITY_WEIGHT.get(severity, 1.0)
        reasons.append(f"{severity} base {base:g}")

        confidence = (finding.confidence or "medium").lower()
        factor = CONFIDENCE_FACTOR.get(confidence, 0.8)
        reasons.append(f"{confidence} confidence x{factor:g}")

        category = (finding.category or "").lower()
        cat_factor = CATEGORY_FACTOR.get(category, 1.0)
        if cat_factor != 1.0:
            reasons.append(f"category {category} x{cat_factor:g}")

        haystack = " ".join(
            [finding.title, finding.evidence, finding.url, finding.category]
        ).lower()

        boost = 0.0
        for keyword, bonus, reason in CONTEXT_BOOSTS:
            if keyword in haystack:
                boost += bonus
                reasons.append(f"+{bonus:g} {reason}")
                if boost >= 6:
                    break

        env_multiplier = 1.0
        for keyword, mult, reason in ENV_FACTOR:
            if keyword and keyword in (finding.url + finding.title).lower():
                env_multiplier = mult
                reasons.append(f"x{mult:g} {reason}")
                break

        score = (base * factor * cat_factor + boost) * env_multiplier

        if finding.url and not finding.url.startswith("http"):
            score *= 0.98 if "path" in finding.url.lower() else 1.0

        return round(score, 2), reasons

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("FINDING PRIORITISATION", 15)
        started = time.time()

        collected = self._collect()
        if not collected:
            self.logger.warning("No findings to prioritise")
            self._write_outputs([])
            return self.output_dir

        # De-duplicate across phases
        unique: Dict[str, Finding] = {}
        for finding in collected:
            key = finding.fingerprint()
            if key in unique:
                existing = unique[key]
                if severity_rank(finding.severity) > severity_rank(existing.severity):
                    unique[key] = finding
                continue
            unique[key] = finding

        scored: List[Finding] = []
        for finding in unique.values():
            score, reasons = self.score(finding)
            finding.score = score
            finding.extra.setdefault("score_reasons", reasons)
            finding.extra["priority"] = self.priority_for(score)
            scored.append(finding)

        scored.sort(key=lambda f: (-f.score, -f.severity_rank))
        threshold = severity_rank(self.min_severity)
        self.findings = [f for f in scored if f.severity_rank >= threshold]

        self.enrich_with_searchsploit()

        self._update_database()
        self._write_outputs(self.findings)

        duration = time.time() - started
        counts = _priority_counts(self.findings)
        self.logger.result(
            f"Prioritisation Complete: {len(self.findings)} finding(s) "
            f"(P1={counts.get('P1', 0)}, P2={counts.get('P2', 0)}, "
            f"P3={counts.get('P3', 0)}, P4={counts.get('P4', 0)}) "
            f"in {duration:.1f}s"
        )
        return self.output_dir

    @staticmethod
    def priority_for(score: float) -> str:
        if score >= 9:
            return "P1"
        if score >= 6:
            return "P2"
        if score >= 3.5:
            return "P3"
        return "P4"

    # ------------------------------------------------------------------
    def _update_database(self) -> None:
        if self.ctx.database is None or self.ctx.scan_id is None:
            return
        for finding in self.findings:
            self.ctx.database.update_score(
                self.ctx.scan_id,
                finding.fingerprint(),
                finding.score,
                priority=finding.extra.get("priority"),
                reasons=finding.extra.get("score_reasons"),
            )

    # ------------------------------------------------------------------
    # Exploit intelligence (searchsploit / Exploit-DB)
    # ------------------------------------------------------------------
    def enrich_with_searchsploit(self) -> None:
        """Attach local Exploit-DB entries to findings that reference a CVE."""
        if not self.config.get_bool("finding_prioritizer.searchsploit.enabled", True):
            return
        runner = getattr(self.ctx, "runner", None)
        if runner is None or not runner.is_available("searchsploit"):
            self.logger.debug("searchsploit is not installed - skipping exploit enrichment")
            return

        def cves_for(finding: Finding) -> List[str]:
            haystack = " ".join([
                finding.title, finding.evidence,
                " ".join(finding.tags), " ".join(finding.references),
            ])
            return [match.upper() for match in CVE_RE.findall(haystack)]

        wanted = sorted({cve for finding in self.findings for cve in cves_for(finding)})
        if not wanted:
            return
        max_cves = self.config.get_int("finding_prioritizer.searchsploit.max_cves", 25)
        mapping: Dict[str, List[Dict]] = {}
        for cve in wanted[:max_cves]:
            result = runner.run(
                ["searchsploit", "--cve", cve, "--json"],
                tool_name=f"searchsploit-{cve}", timeout=90,
            )
            try:
                payload = json.loads(result.get("stdout") or "{}")
            except (TypeError, ValueError):
                payload = {}
            entries = []
            for item in (payload.get("RESULTS_EXPLOIT") or []):
                if not isinstance(item, dict):
                    continue
                entries.append({
                    "id": item.get("EDB-ID"),
                    "title": item.get("Title"),
                    "path": item.get("Path"),
                })
            if entries:
                mapping[cve] = entries

        if not mapping:
            return
        exploit_file = os.path.join(self.output_dir, "exploits.json")
        save_json(mapping, exploit_file)
        self.ctx.set_file("exploits_json", exploit_file)

        enriched = 0
        for finding in self.findings:
            hits = sorted(set(cves_for(finding)) & set(mapping))
            if not hits:
                continue
            finding.extra["exploitdb"] = {cve: mapping[cve] for cve in hits}
            if "public-exploit" not in finding.tags:
                finding.tags.append("public-exploit")
            finding.score = round(finding.score + min(3.0, float(len(hits))), 2)
            reasons = finding.extra.setdefault("score_reasons", [])
            if "public exploit available (Exploit-DB)" not in reasons:
                reasons.append("public exploit available (Exploit-DB)")
            finding.extra["priority"] = self.priority_for(finding.score)
            enriched += 1

        self.findings.sort(key=lambda item: (-item.score, -item.severity_rank))
        self.logger.found(
            f"searchsploit: public exploit data for {enriched} finding(s) "
            f"across {len(mapping)} CVE(s)"
        )

    def _write_outputs(self, findings: List[Finding]) -> None:
        rows = []
        for finding in findings:
            row = finding.to_dict()
            row["priority"] = finding.extra.get("priority", "P4")
            row["score_reasons"] = "; ".join(finding.extra.get("score_reasons", []))
            rows.append(row)

        json_file = os.path.join(self.output_dir, "findings.json")
        save_json(rows, json_file)
        self.ctx.set_file("findings_json", json_file)

        csv_file = os.path.join(self.output_dir, "findings.csv")
        save_csv(
            rows,
            csv_file,
            fieldnames=[
                "priority", "score", "severity", "confidence", "category", "title",
                "url", "target", "evidence", "source", "score_reasons",
            ],
        )
        self.ctx.set_file("findings_csv", csv_file)

        summary_file = os.path.join(self.output_dir, "summary.json")
        save_json(
            {
                "target": self.ctx.target,
                "timestamp": get_timestamp(),
                "total": len(findings),
                "by_severity": _count_by(findings, "severity"),
                "by_priority": _priority_counts(findings),
                "by_category": _count_by(findings, "category"),
                "top_10": [
                    {
                        "score": f.score,
                        "priority": f.extra.get("priority"),
                        "severity": f.severity,
                        "title": f.title,
                        "url": f.url,
                    }
                    for f in findings[:10]
                ],
            },
            summary_file,
        )

        write_file_lines(
            os.path.join(self.output_dir, "top_findings.txt"),
            [
                f"[{f.extra.get('priority')}|{f.score:>6.2f}|{f.severity:^8}] "
                f"{f.title} {('- ' + f.url) if f.url else ''}"
                for f in findings[:100]
            ],
        )

        markdown = self._render_markdown(findings)
        md_file = os.path.join(self.output_dir, "prioritized.md")
        with open(md_file, "w") as fh:
            fh.write(markdown)
        self.ctx.set_file("prioritized_md", md_file)

    def _render_markdown(self, findings: List[Finding]) -> str:
        lines = [
            "# 🎯 Prioritised Findings",
            "",
            f"**Target:** `{self.ctx.target}`  ",
            f"**Generated:** {get_timestamp()}  ",
            f"**Total:** {len(findings)}",
            "",
            "Scoring = severity base × confidence × category factor + context boosts × environment factor.",
            "",
            "| Priority | Score | Severity | Category | Title | URL |",
            "|----------|-------|----------|----------|-------|-----|",
        ]
        for finding in findings[:150]:
            title = finding.title.replace("|", "\\|")[:90]
            url = (finding.url or "").replace("|", "\\|")[:70]
            lines.append(
                f"| {finding.extra.get('priority', 'P4')} | {finding.score:.2f} | "
                f"{finding.severity} | {finding.category} | {title} | {url} |"
            )
        lines.append("")
        if findings:
            lines.append("## Top findings in detail")
            lines.append("")
        for finding in findings[:15]:
            lines.append(f"### [{finding.extra.get('priority')}] {finding.title}")
            lines.append("")
            lines.append(f"- **Severity:** {finding.severity} (score {finding.score:.2f})")
            lines.append(f"- **Category:** {finding.category}")
            if finding.url:
                lines.append(f"- **Location:** {finding.url}")
            lines.append(f"- **Source:** {finding.source}")
            reasons = finding.extra.get("score_reasons") or []
            if reasons:
                lines.append(f"- **Why:** {', '.join(reasons)}")
            if finding.evidence:
                lines.append("")
                lines.append("```")
                lines.append(finding.evidence[:800])
                lines.append("```")
            lines.append("")
        return "\n".join(lines)


def _severity_from_text(line: str) -> str:
    lowered = line.lower()
    for level in ("critical", "high", "medium", "low", "info"):
        if f"[{level}]" in lowered or f"severity: {level}" in lowered:
            return level
    if any(word in lowered for word in ("rce", "sqli", "sql injection", "public")):
        return "high"
    return "medium"


def _category_from_text(line: str) -> str:
    lowered = line.lower()
    for tag, category in (
        ("[xss]", "xss"),
        ("[sqli]", "sqli"),
        ("[crlf]", "crlf"),
        ("[cors]", "cors"),
        ("[ssrf]", "ssrf"),
        ("[s3]", "cloud"),
        ("[github]", "github"),
        ("[shodan]", "exposure"),
        ("[tls]", "tls"),
    ):
        if tag in lowered:
            return category
    return "vulnerability"


def _count_by(findings: Iterable[Finding], attribute: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        value = getattr(finding, attribute, "") or "unknown"
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: -item[1]))


def _priority_counts(findings: Iterable[Finding]) -> Dict[str, int]:
    counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for finding in findings:
        key = finding.extra.get("priority", "P4")
        counts[key] = counts.get(key, 0) + 1
    return counts


def priority_label(score: float) -> str:
    """Public helper (also used by tests)."""
    return FindingPrioritizer.priority_for(score)
