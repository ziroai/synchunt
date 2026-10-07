"""
SyncHunt - GitHub Reconnaissance
Public-intel gathering on GitHub: repositories tied to the target, issue/PR
mentions, leaked secrets in searchable content and organisation metadata.

Authentication
--------------
Code search requires a token (`GITHUB_TOKEN` env var or `github_recon.token`).
Without one, SyncHunt falls back to the unauthenticated repository/issue search
endpoints and clearly reports the reduced coverage instead of failing.

Only the official GitHub REST API is used - no scraping, no credential reuse.
"""

from __future__ import annotations

import os
import time
from typing import Dict, List, Optional

from core.models import Asset, Finding
from core.secrets import build_patterns, scan_text
from core.utils import (
    ensure_dir,
    get_timestamp,
    read_file_lines,
    save_json,
    truncate,
)

API = "https://api.github.com"
SENSITIVE_FILE_HINTS = (
    ".env", "config", "credentials", "secret", "settings", "docker-compose",
    "id_rsa", ".npmrc", ".pypirc", "terraform.tfvars",
)


class GitHubRecon:
    """Correlate a target with public GitHub data."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.logger = ctx.logger
        self.output_dir = ctx.path("github_recon")
        ensure_dir(self.output_dir)

        self.token = (
            os.environ.get("GITHUB_TOKEN", "")
            or self.config.get("github_recon.token", "")
            or self.config.get("sensitive_info.github_dorking.token", "")
        )
        self.org = self.config.get("github_recon.org", "")
        self.max_repos = self.config.get_int("github_recon.max_repos", 10)
        self.max_issues = self.config.get_int("github_recon.max_issues", 10)
        self.max_pages = self.config.get_int("github_recon.max_pages", 2)
        self.search_code = self.config.get_bool("github_recon.search_code", True)
        self.dorks = self.config.get_list(
            "github_recon.dorks",
            [
                "password",
                "secret",
                "api_key",
                "apikey",
                "access_token",
                "auth_token",
                "credentials",
                "db_password",
                "private_key",
                "BEGIN RSA PRIVATE KEY",
            ],
        )
        self.patterns = build_patterns(
            self.config.get("js_analysis.custom_regex.patterns", [])
        )
        self.http = ctx.session
        self.limiter = ctx.limiter
        self.repos: List[Dict] = []
        self.issues: List[Dict] = []
        self.secrets: List[Dict] = []
        self.findings: List[Finding] = []

    # ------------------------------------------------------------------
    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _get(self, path: str, params: Optional[Dict] = None) -> Dict:
        """GET a GitHub API endpoint with rate-limit awareness."""
        from core.net import http_request

        url = path if path.startswith("http") else f"{API}{path}"
        result = http_request(
            self.http,
            "GET",
            url,
            limiter=self.limiter,
            timeout=20,
            max_bytes=1024 * 1024,
            headers=self._headers(),
        )
        if result.status == 403 and "rate limit" in (result.text or "").lower():
            reset = result.header("X-RateLimit-Reset")
            self.logger.warning(
                "GitHub API rate limit hit"
                + (f" (resets at epoch {reset})" if reset else "")
                + " - consider setting GITHUB_TOKEN"
            )
            return {"_error": "rate_limited"}
        if result.status == 401:
            self.logger.warning("GitHub token rejected (401) - continuing unauthenticated")
            self.token = ""
            return {"_error": "unauthorized"}
        if result.status >= 400:
            self.logger.debug(f"GitHub API {result.status} for {url}")
            return {"_error": f"http_{result.status}"}
        data = result.json(default={})
        return data if isinstance(data, dict) else {"items": data}

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("GITHUB RECON", 7)
        started = time.time()

        if not self.config.get_bool("github_recon.enabled", True):
            self.logger.skip("github_recon disabled in config")
            return self.output_dir

        if not self.token:
            self.logger.warning(
                "No GITHUB_TOKEN set - code search disabled, "
                "repository/issue search only (heavily rate limited)"
            )

        self._search_repos()
        self._search_issues()
        if self.search_code:
            self._search_code()

        self._write_outputs()
        self._record()

        duration = time.time() - started
        self.logger.result(
            f"GitHub Recon Complete: {len(self.repos)} repo(s), "
            f"{len(self.issues)} issue/PR hit(s), {len(self.secrets)} secret(s) "
            f"in {duration:.1f}s"
        )
        return self.output_dir

    # ------------------------------------------------------------------
    def _target_keywords(self) -> List[str]:
        """Search terms derived from the target domain."""
        from core.utils import get_root_domain

        host = self.ctx.target
        root = get_root_domain(host) or host
        keywords = {root, root.split(".")[0]}
        if self.org:
            keywords.add(self.org)
        # read subdomains to catch org-specific names
        sub_file = self.ctx.get_file("subdomains")
        for line in read_file_lines(sub_file)[:50]:
            part = line.split(".")[0]
            if len(part) > 3 and part not in ("www", "api", "dev", "test"):
                keywords.add(part)
        return sorted(k for k in keywords if k)

    def _search_repos(self) -> None:
        for keyword in self._target_keywords()[:4]:
            data = self._get(
                "/search/repositories",
                {"q": f'"{keyword}"', "sort": "updated", "per_page": self.max_repos},
            )
            for item in (data.get("items") or [])[: self.max_repos]:
                repo = {
                    "name": item.get("full_name", ""),
                    "url": item.get("html_url", ""),
                    "description": truncate(item.get("description") or "", 300),
                    "stars": item.get("stargazers_count", 0),
                    "language": item.get("language") or "",
                    "updated_at": item.get("updated_at", ""),
                    "private": item.get("private", False),
                    "keyword": keyword,
                    "default_branch": item.get("default_branch", "main"),
                }
                if repo["name"] and repo["name"] not in {r["name"] for r in self.repos}:
                    self.repos.append(repo)
            if data.get("_error"):
                break

        for repo in self.repos[: self.max_repos]:
            self._inspect_repo(repo)

    def _inspect_repo(self, repo: Dict) -> None:
        """Look for sensitive file names inside the repository tree."""
        owner_repo = repo.get("name")
        branch = repo.get("default_branch") or "main"
        if not owner_repo:
            return
        tree = self._get(f"/repos/{owner_repo}/git/trees/{branch}?recursive=1")
        if tree.get("_error"):
            return
        hits = []
        for entry in tree.get("tree", []) or []:
            path = entry.get("path", "")
            lower = path.lower()
            if any(hint in lower for hint in SENSITIVE_FILE_HINTS):
                hits.append(path)
        if hits:
            repo["sensitive_paths"] = hits[:25]
            self.findings.append(
                Finding(
                    category="github",
                    title="Potentially sensitive files in public repository",
                    severity="low",
                    target=self.ctx.target,
                    url=repo.get("url", ""),
                    evidence=", ".join(hits[:10]),
                    source="github_recon",
                    confidence="low",
                    tags=["github", "exposure"],
                    extra={"repo": owner_repo, "paths": hits[:25]},
                )
            )

    def _search_issues(self) -> None:
        for keyword in self._target_keywords()[:4]:
            data = self._get(
                "/search/issues",
                {"q": f'"{keyword}"', "sort": "updated", "per_page": self.max_issues},
            )
            for item in (data.get("items") or [])[: self.max_issues]:
                entry = {
                    "title": truncate(item.get("title") or "", 250),
                    "url": item.get("html_url", ""),
                    "state": item.get("state", ""),
                    "repo": (item.get("repository_url") or "").replace(f"{API}/repos/", ""),
                    "created_at": item.get("created_at", ""),
                    "keyword": keyword,
                }
                self.issues.append(entry)
                body = item.get("body") or ""
                for match in scan_text(
                    f"{entry['title']}\n{body}",
                    patterns=self.patterns,
                    source="github_issue",
                    location=entry["url"],
                ):
                    self._add_secret(match)
            if data.get("_error"):
                break

    def _search_code(self) -> None:
        if not self.token:
            self.logger.info(
                "Skipping GitHub code search (needs a token) - "
                "set GITHUB_TOKEN for leaked-secret hunting"
            )
            return
        for dork in self.dorks[:12]:
            query = f'"{self.ctx.target}" {dork}'
            data = self._get("/search/code", {"q": query, "per_page": 10})
            if data.get("_error"):
                break
            total = data.get("total_count", 0)
            if total:
                self.logger.found(f"GitHub code search '{dork}': {total} hit(s)")
            for item in (data.get("items") or [])[:10]:
                entry = {
                    "repo": (item.get("repository") or {}).get("full_name", ""),
                    "path": item.get("path", ""),
                    "url": item.get("html_url", ""),
                    "dork": dork,
                }
                self.issues.append({"title": f"code hit: {dork}", **entry})
                if any(hint in entry["path"].lower() for hint in ("env", "config", "secret", "key")):
                    self.findings.append(
                        Finding(
                            category="github",
                            title=f"Credential-like file matched dork '{dork}'",
                            severity="medium",
                            target=self.ctx.target,
                            url=entry["url"],
                            evidence=f"{entry['repo']}/{entry['path']}",
                            source="github_recon",
                            confidence="low",
                            tags=["github", "secrets"],
                        )
                    )

    # ------------------------------------------------------------------
    def _add_secret(self, match) -> None:
        payload = match.to_dict()
        if payload["value"] and payload not in self.secrets:
            self.secrets.append(payload)
            self.findings.append(
                Finding(
                    category="secrets",
                    title=f"Secret in GitHub content: {match.name}",
                    severity=match.severity,
                    target=self.ctx.target,
                    url=match.location,
                    evidence=f"{match.name} -> {payload['value']}",
                    source="github_recon",
                    confidence=match.confidence,
                    tags=["secrets", "github"],
                )
            )
            self.logger.vuln(f"Secret in GitHub content: {match.name} ({payload['value']})")

    # ------------------------------------------------------------------
    def _write_outputs(self) -> None:
        repos_file = os.path.join(self.output_dir, "repos.json")
        save_json(self.repos, repos_file)
        self.ctx.set_file("github_repos", repos_file)

        issues_file = os.path.join(self.output_dir, "issues.json")
        save_json(self.issues, issues_file)

        secrets_file = os.path.join(self.output_dir, "secrets.json")
        save_json(self.secrets, secrets_file)

        save_json(
            {
                "target": self.ctx.target,
                "timestamp": get_timestamp(),
                "authenticated": bool(self.token),
                "repos": len(self.repos),
                "issues": len(self.issues),
                "secrets": len(self.secrets),
                "keywords": self._target_keywords(),
            },
            os.path.join(self.output_dir, "summary.json"),
        )

    def _record(self) -> None:
        assets: List[Asset] = []
        for repo in self.repos:
            assets.append(
                Asset(kind="github_repo", value=repo["url"], host="github.com",
                      source="github_recon", meta={"stars": repo.get("stars", 0)})
            )
        self.ctx.record_assets(assets)
        self.ctx.record_findings(self.findings)


def github_token_present(config) -> bool:
    """Utility used by --doctor to report GitHub coverage."""
    return bool(
        os.environ.get("GITHUB_TOKEN")
        or config.get("github_recon.token", "")
        or config.get("sensitive_info.github_dorking.token", "")
    )
