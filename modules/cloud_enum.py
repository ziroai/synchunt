"""
SyncHunt - Cloud Storage Enumeration
Checks for publicly reachable / misconfigured cloud storage buckets whose
names are derived from the target (AWS S3, Azure Blob Storage, GCP Storage).

How existence is decided
------------------------
Each provider answers differently for "does not exist" vs "exists but private":

  AWS S3    404 NoSuchBucket (absent) | 403 AccessDenied (exists, private)
            | 200 (public list/get allowed)
  Azure     404 ResourceNotFound (absent) | 403/409/400 (exists)
  GCP       404 (absent) | 401/403 (exists, not public) | 200 (public)

Only a handful of read-only requests per candidate name are made, all rate
limited, and only names derived from the target are ever probed.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from core.models import Asset, Finding
from core.net import probe
from core.utils import ensure_dir, read_file_lines, save_json, write_file_lines

AWS_URL = "https://{name}.s3.amazonaws.com/?list-type=2&max-keys=1"
AZURE_URL = "https://{name}.blob.core.windows.net/?comp=list&maxresults=1"
GCP_URL = "https://storage.googleapis.com/storage/v1/b/{name}/o?maxResults=1"

KEYWORDS = (
    "", "-assets", "-backup", "-backups", "-data", "-dev", "-development",
    "-staging", "-stage", "-prod", "-production", "-test", "-testing",
    "-uploads", "-media", "-static", "-files", "-private", "-public",
    "-internal", "-cdn", "-logs", "-db", "-database", "-config", "-api",
    "-app", "-web", "-images", "-docs", "-documents", "-archive",
    "-terraform", "-tfstate", "-backup-prod", "-prod-backup",
)


class CloudEnumerator:
    """Enumerate cloud storage buckets derived from the target name."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.logger = ctx.logger
        self.output_dir = ctx.path("cloud_enum")
        ensure_dir(self.output_dir)

        self.providers = {
            "aws": self.config.get_bool("cloud_enum.aws", True),
            "azure": self.config.get_bool("cloud_enum.azure", True),
            "gcp": self.config.get_bool("cloud_enum.gcp", True),
        }
        self.max_candidates = self.config.get_int("cloud_enum.max_candidates", 120)
        self.timeout = max(3, min(self.config.get_int("general.timeout", 10), 12))
        self.results: Dict[str, List[Dict]] = {"aws": [], "azure": [], "gcp": []}
        self.findings: List[Finding] = []

    # ------------------------------------------------------------------
    def _candidate_names(self) -> List[str]:
        from core.utils import get_root_domain

        host = self.ctx.target
        root = get_root_domain(host) or host
        bases = {root, root.replace(".", "-"), root.split(".")[0], host}
        bases.update(
            line
            for line in read_file_lines(self.ctx.get_file("subdomains"))[:40]
            if "." in line
        )

        names = set()
        for base in bases:
            stem = base.split(".")[0]
            if len(stem) < 3:
                continue
            for keyword in KEYWORDS:
                names.add(f"{stem}{keyword}".lower())
                if keyword:
                    names.add(f"{keyword.lstrip('-')}-{stem}".lower())
        cleaned = sorted(
            name for name in names if 3 <= len(name) <= 63 and _valid_bucket_name(name)
        )
        return cleaned[: self.max_candidates]

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("CLOUD ENUMERATION", 10)
        started = time.time()

        if not any(self.providers.values()):
            self.logger.skip("all cloud providers disabled")
            return self.output_dir

        candidates = self._candidate_names()
        if not candidates:
            self.logger.warning("No candidate bucket names could be derived")
            return self.output_dir

        enabled = [name for name, on in self.providers.items() if on]
        self.logger.info(
            f"Checking {len(candidates)} candidate name(s) across "
            f"{', '.join(enabled)}..."
        )

        tasks = [
            (provider, name)
            for provider in enabled
            for name in candidates
        ]
        workers = max(1, min(self.ctx.threads(), 24))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._check, provider, name): (provider, name)
                for provider, name in tasks
            }
            for index, future in enumerate(as_completed(futures), start=1):
                provider, name = futures[future]
                try:
                    entry = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    self.logger.debug(f"cloud check failed for {provider}:{name}: {exc}")
                    continue
                if entry:
                    self.results[provider].append(entry)
                if index % 25 == 0 or index == len(tasks):
                    self.logger.progress(index, len(tasks), "cloud-enum")

        self._write_outputs()
        self._record()

        duration = time.time() - started
        public = sum(1 for provider in self.results for e in self.results[provider]
                     if e.get("public"))
        self.logger.result(
            f"Cloud Enumeration Complete: {sum(len(v) for v in self.results.values())} "
            f"existing bucket(s), {public} public in {duration:.1f}s"
        )
        return self.output_dir

    # ------------------------------------------------------------------
    def _check(self, provider: str, name: str) -> Optional[Dict]:
        if provider == "aws":
            return self._check_aws(name)
        if provider == "azure":
            return self._check_azure(name)
        return self._check_gcp(name)

    def _check_aws(self, name: str) -> Optional[Dict]:
        url = AWS_URL.format(name=name)
        result = probe(self.ctx.session, url, limiter=self.ctx.limiter,
                       timeout=self.timeout, max_bytes=8192)
        # 404 => bucket absent (AWS also returns NoSuchBucket in the body).
        if result.status == 404:
            return None
        public = result.status == 200
        if not public and result.status != 403:
            return None
        entry = {
            "provider": "aws",
            "name": name,
            "url": f"https://{name}.s3.amazonaws.com/",
            "status": result.status,
            "public": public,
            "exists": True,
        }
        self._finding(entry)
        return entry

    def _check_azure(self, name: str) -> Optional[Dict]:
        url = AZURE_URL.format(name=name)
        result = probe(self.ctx.session, url, limiter=self.ctx.limiter,
                       timeout=self.timeout, max_bytes=8192)
        exists = result.status in (200, 400, 403, 409)
        if not exists:
            return None
        entry = {
            "provider": "azure",
            "name": name,
            "url": f"https://{name}.blob.core.windows.net/",
            "status": result.status,
            "public": result.status == 200,
            "exists": True,
        }
        self._finding(entry)
        return entry

    def _check_gcp(self, name: str) -> Optional[Dict]:
        url = GCP_URL.format(name=name)
        result = probe(self.ctx.session, url, limiter=self.ctx.limiter,
                       timeout=self.timeout, max_bytes=8192)
        exists = result.status in (200, 401, 403)
        if not exists:
            return None
        entry = {
            "provider": "gcp",
            "name": name,
            "url": f"https://storage.googleapis.com/{name}/",
            "status": result.status,
            "public": result.status == 200,
            "exists": True,
        }
        self._finding(entry)
        return entry

    def _finding(self, entry: Dict) -> None:
        public = entry["public"]
        severity = "critical" if public else "info"
        title = (
            f"Public {entry['provider'].upper()} bucket: {entry['name']}"
            if public
            else f"{entry['provider'].upper()} bucket exists: {entry['name']}"
        )
        finding = Finding(
            category="cloud",
            title=title,
            severity=severity,
            target=self.ctx.target,
            url=entry["url"],
            evidence=f"HTTP {entry['status']} - {'publicly listable' if public else 'not publicly listable'}",
            source="cloud_enum",
            confidence="high",
            tags=["cloud", entry["provider"]] + (["public"] if public else []),
        )
        self.findings.append(finding)
        if public:
            self.logger.vuln(f"Public {entry['provider'].upper()} bucket: {entry['url']}")
        else:
            self.logger.debug(f"Existing bucket (private): {entry['url']}")

    # ------------------------------------------------------------------
    def _write_outputs(self) -> None:
        for provider, entries in self.results.items():
            save_json(entries, os.path.join(self.output_dir, f"{provider}.json"))

        public_urls = [
            entry["url"] for info in self.results.values() for entry in info
            if entry.get("public")
        ]
        write_file_lines(os.path.join(self.output_dir, "public_buckets.txt"), public_urls)

        save_json(
            {
                "target": self.ctx.target,
                "candidates_checked": self.max_candidates,
                "aws": len(self.results["aws"]),
                "azure": len(self.results["azure"]),
                "gcp": len(self.results["gcp"]),
                "public": len(public_urls),
            },
            os.path.join(self.output_dir, "summary.json"),
        )
        self.ctx.set_file("cloud_public_buckets",
                          os.path.join(self.output_dir, "public_buckets.txt"))

    def _record(self) -> None:
        assets: List[Asset] = []
        for provider, entries in self.results.items():
            for entry in entries:
                assets.append(
                    Asset(
                        kind="cloud_bucket",
                        value=entry["url"],
                        host=f"{entry['name']}.{provider}",
                        source="cloud_enum",
                        meta={"public": entry["public"], "status": entry["status"]},
                    )
                )
        self.ctx.record_assets(assets)
        self.ctx.record_findings(self.findings)


def _valid_bucket_name(name: str) -> bool:
    """S3-style naming rules (applies closely enough to Azure/GCP too)."""
    if not name or name.startswith("-") or name.endswith("-"):
        return False
    if ".." in name or "." in name and name.count(".") > 1:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    return all(char in allowed for char in name)
