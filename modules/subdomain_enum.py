"""
SyncHunt - Subdomain Enumeration
Wraps subfinder, amass, assetfinder, findomain, crt.sh, sublist3r plus
puredns/gotator permutation bruteforcing.
"""

from __future__ import annotations

import base64
import os
import time
from typing import Dict, List

from core.models import Asset
from core.utils import (
    get_timestamp,
    host_from_url,
    is_valid_domain,
    load_json,
    read_file_lines,
    save_json,
    write_file_lines,
)


CENSYS_SEARCH_URL = "https://search.censys.io/api/v2/hosts/search"


class SubdomainEnumerator:
    """Orchestrates passive and active subdomain discovery."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.runner = ctx.runner
        self.logger = ctx.logger
        self.output_dir = ctx.path("subdomains")
        self.target = host_from_url(ctx.target)
        os.makedirs(self.output_dir, exist_ok=True)
        self.results: Dict[str, List[str]] = {}
        self.all_subdomains: set = set()

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("SUBDOMAIN ENUMERATION", 1)

        if not is_valid_domain(self.target):
            self.logger.skip(
                f"target '{self.target}' is not a domain - passive enumeration skipped"
            )
            return self._merge_results()

        started = time.time()
        tools = [
            ("subfinder", self.run_subfinder),
            ("amass", self.run_amass),
            ("assetfinder", self.run_assetfinder),
            ("findomain", self.run_findomain),
            ("crtsh", self.run_crtsh),
            ("chaos", self.run_chaos),
            ("securitytrails", self.run_securitytrails),
            ("shodan", self.run_shodan_dns),
            ("sublist3r", self.run_sublist3r),
            ("puredns", self.run_puredns),
            ("gotator", self.run_gotator),
            ("theharvester", self.run_theharvester),
            ("censys", self.run_censys),
        ]

        executed = 0
        for tool_name, tool_func in tools:
            if not self.config.is_tool_enabled("subdomain_enum", tool_name):
                self.logger.debug(f"{tool_name} disabled in config")
                continue
            executed += 1
            try:
                found = tool_func() or []
                if found:
                    self.results[tool_name] = found
                    self.logger.found(f"{tool_name}: {len(found)} subdomain(s)")
            except Exception as exc:
                self.logger.error(f"{tool_name} failed: {exc}")

        output_file = self._merge_results()
        count = len(read_file_lines(output_file))
        self.logger.result(
            f"Subdomain Enumeration Complete: {count} unique subdomain(s) "
            f"from {executed} tool(s) in {time.time() - started:.1f}s"
        )
        self._record()
        return output_file

    # ------------------------------------------------------------------
    def _output(self, name: str) -> str:
        return os.path.join(self.output_dir, name)

    def run_subfinder(self) -> List[str]:
        output_file = self._output("subfinder.txt")
        skipped = self.runner.require("subfinder", output_file)
        if skipped:
            return []
        self.logger.info("Running subfinder...")
        cfg = self.config.get_tool_config("subdomain_enum", "subfinder")
        cmd = ["subfinder", "-d", self.target, "-silent", "-all", "-o", output_file]
        if cfg.get("threads"):
            cmd += ["-t", str(cfg["threads"])]
        if cfg.get("timeout"):
            cmd += ["-timeout", str(cfg["timeout"])]
        if cfg.get("config"):
            cmd += ["-provider-config", str(cfg["config"])]
        self.runner.run(cmd, tool_name="subfinder", timeout=900)
        return self._collect(output_file)

    def run_amass(self) -> List[str]:
        output_file = self._output("amass.txt")
        skipped = self.runner.require("amass", output_file)
        if skipped:
            return []
        self.logger.info("Running amass (passive)...")
        cfg = self.config.get_tool_config("subdomain_enum", "amass")
        cmd = ["amass", "enum", "-d", self.target, "-o", output_file]
        if cfg.get("passive", True):
            cmd.append("-passive")
        if cfg.get("timeout"):
            cmd += ["-timeout", str(cfg["timeout"])]
        if cfg.get("config"):
            cmd += ["-config", str(cfg["config"])]
        self.runner.run(cmd, tool_name="amass", timeout=1800)
        return self._collect(output_file)

    def run_assetfinder(self) -> List[str]:
        output_file = self._output("assetfinder.txt")
        skipped = self.runner.require("assetfinder", output_file)
        if skipped:
            return []
        self.logger.info("Running assetfinder...")
        cfg = self.config.get_tool_config("subdomain_enum", "assetfinder")
        cmd = ["assetfinder"]
        if cfg.get("subs_only", True):
            cmd.append("--subs-only")
        cmd.append(self.target)
        result = self.runner.run(cmd, tool_name="assetfinder", timeout=300)
        found = [
            line.strip()
            for line in (result.get("stdout") or "").splitlines()
            if line.strip().endswith(self.target)
        ]
        write_file_lines(output_file, found)
        return self._collect(output_file)

    def run_findomain(self) -> List[str]:
        output_file = self._output("findomain.txt")
        skipped = self.runner.require("findomain", output_file)
        if skipped:
            return []
        self.logger.info("Running findomain...")
        cmd = ["findomain", "-t", self.target, "-u", output_file, "-q"]
        self.runner.run(cmd, tool_name="findomain", timeout=600)
        return self._collect(output_file)

    def run_crtsh(self) -> List[str]:
        """Certificate transparency lookup (no external binary needed)."""
        output_file = self._output("crtsh.txt")
        self.logger.info("Querying crt.sh (certificate transparency)...")
        from core.net import http_request

        found = set()
        url = f"https://crt.sh/?q=%25.{self.target}&output=json"
        result = http_request(
            self.ctx.session, "GET", url, limiter=self.ctx.limiter,
            timeout=45, max_bytes=8 * 1024 * 1024,
        )
        if not result.reachable:
            self.logger.warning(f"crt.sh unreachable ({result.error or result.status})")
            return []
        data = result.json(default=[])
        if not isinstance(data, list):
            self.logger.warning("crt.sh returned an unexpected payload")
            return []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for name in str(entry.get("name_value", "")).split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and is_valid_domain(name) and name.endswith(self.target):
                    found.add(name)
        write_file_lines(output_file, sorted(found))
        self.logger.info(f"crt.sh returned {len(found)} unique name(s)")
        return self._collect(output_file)

    def run_chaos(self) -> List[str]:
        """ProjectDiscovery chaos dataset (needs a CHAOS_KEY)."""
        output_file = self._output("chaos.txt")
        if self.runner.require("chaos", output_file):
            return []
        self.logger.info("Querying chaos...")
        cmd = ["chaos", "-d", self.target, "-silent", "-o", output_file]
        env_key = os.environ.get("CHAOS_KEY") or self.config.get(
            "subdomain_enum.chaos.api_key", ""
        )
        if env_key:
            cmd += ["-key", str(env_key)]
        self.runner.run(cmd, tool_name="chaos", timeout=600)
        return self._collect(output_file)

    def run_securitytrails(self) -> List[str]:
        """SecurityTrails API (needs a key: config or SECURITYTRAILS_API_KEY)."""
        output_file = self._output("securitytrails.txt")
        api_key = (
            os.environ.get("SECURITYTRAILS_API_KEY")
            or self.config.get("subdomain_enum.securitytrails.api_key", "")
        )
        if not api_key:
            self.logger.debug("securitytrails skipped (no API key)")
            return []
        from core.net import http_request

        url = f"https://api.securitytrails.com/v1/domain/{self.target}/subdomains"
        result = http_request(
            self.ctx.session, "GET", url, limiter=self.ctx.limiter, timeout=30,
            headers={"APIKEY": str(api_key)},
        )
        if not result.ok:
            self.logger.warning(f"securitytrails returned {result.status}")
            return []
        payload = result.json(default={}) or {}
        found = {
            f"{name}.{self.target}".lower()
            for name in payload.get("subdomains", []) or []
            if name
        }
        if not found:
            return []
        write_file_lines(output_file, sorted(found))
        return self._collect(output_file)

    def run_shodan_dns(self) -> List[str]:
        """Shodan DNS domain API (needs a key: config or SHODAN_API_KEY)."""
        output_file = self._output("shodan_dns.txt")
        api_key = (
            os.environ.get("SHODAN_API_KEY")
            or self.config.get("sensitive_info.shodan.api_key", "")
        )
        if not api_key:
            self.logger.debug("shodan DNS skipped (no API key)")
            return []
        from core.net import http_request

        url = f"https://api.shodan.io/dns/domain/{self.target}?key={api_key}"
        result = http_request(
            self.ctx.session, "GET", url, limiter=self.ctx.limiter, timeout=30
        )
        if not result.ok:
            self.logger.warning(f"shodan DNS returned {result.status}")
            return []
        payload = result.json(default={}) or {}
        found = set()
        for record in payload.get("data", []) or []:
            sub = record.get("subdomain")
            if sub:
                found.add(f"{sub}.{self.target}".lower())
        if not found:
            return []
        write_file_lines(output_file, sorted(found))
        return self._collect(output_file)

    def run_sublist3r(self) -> List[str]:
        output_file = self._output("sublist3r.txt")
        skipped = self.runner.require("sublist3r", output_file)
        if skipped:
            return []
        self.logger.info("Running sublist3r...")
        cfg = self.config.get_tool_config("subdomain_enum", "sublist3r")
        cmd = ["sublist3r", "-d", self.target, "-o", output_file]
        if cfg.get("threads"):
            cmd += ["-t", str(cfg["threads"])]
        self.runner.run(cmd, tool_name="sublist3r", timeout=900)
        return self._collect(output_file)

    def run_puredns(self) -> List[str]:
        """Active bruteforcing with a real wordlist (resolvers are separate)."""
        output_file = self._output("puredns.txt")
        skipped = self.runner.require("puredns", output_file)
        if skipped:
            return []
        cfg = self.config.get_tool_config("subdomain_enum", "puredns")
        wordlist = cfg.get("wordlist", "wordlists/subdomains.txt")
        resolvers = cfg.get("resolvers", "wordlists/resolvers.txt")
        if not os.path.exists(wordlist):
            self.logger.skip(
                f"puredns wordlist missing ({wordlist}) - "
                "run scripts/fetch_wordlists.sh to enable active bruteforcing"
            )
            return []
        if not os.path.exists(resolvers):
            self.logger.skip(f"puredns resolvers file missing ({resolvers})")
            return []
        self.logger.info("Running puredns bruteforce...")
        cmd = [
            "puredns", "bruteforce", wordlist, self.target,
            "-r", resolvers, "-w", output_file, "-q",
        ]
        self.runner.run(cmd, tool_name="puredns", timeout=3600)
        return self._collect(output_file)

    def run_gotator(self) -> List[str]:
        """Permutation generation (gotator) piped into puredns resolution."""
        output_file = self._output("gotator.txt")
        skipped = self.runner.require("gotator", output_file)
        if skipped:
            return []
        if not self.all_subdomains:
            self.logger.skip("no subdomains available to permute yet")
            return []
        cfg = self.config.get_tool_config("subdomain_enum", "gotator")
        permutations = cfg.get("permutations", "wordlists/permutations.txt")
        resolvers = self.config.get_tool_config("subdomain_enum", "puredns").get(
            "resolvers", "wordlists/resolvers.txt"
        )
        if not os.path.exists(permutations):
            self.logger.skip(f"permutation wordlist missing ({permutations})")
            return []
        if not self.runner.is_available("puredns"):
            self.logger.skip("puredns needed to resolve gotator permutations")
            return []

        seed_file = self._output("permutation_seed.txt")
        write_file_lines(seed_file, sorted(self.all_subdomains))
        self.logger.info("Running gotator permutations + puredns resolution...")
        self.runner.pipe_commands(
            [
                [
                    "gotator", "-sub", seed_file, "-perm", permutations,
                    "-depth", str(cfg.get("depth", 1)), "-silent",
                ],
                ["puredns", "resolve", "-r", resolvers, "-w", output_file, "-q"],
            ],
            tool_name="gotator|puredns",
            timeout=3600,
        )
        return self._collect(output_file)

    # ------------------------------------------------------------------
    def _collect(self, output_file: str) -> List[str]:
        found = [
            line.strip().lower()
            for line in read_file_lines(output_file)
            if line.strip() and is_valid_domain(line.strip().lower().lstrip("*."))
        ]
        self.all_subdomains.update(found)
        return found

    def _merge_results(self) -> str:
        """Merge every per-tool file into all_subdomains.txt."""
        merged = set(self.all_subdomains)
        for name in os.listdir(self.output_dir):
            if not name.endswith(".txt") or name == "all_subdomains.txt":
                continue
            merged.update(self._collect(os.path.join(self.output_dir, name)))

        valid = sorted(
            name for name in merged
            if name and name.endswith(self.target) and is_valid_domain(name)
        )
        output_file = os.path.join(self.output_dir, "all_subdomains.txt")
        write_file_lines(output_file, valid)

        save_json(
            {
                "target": self.target,
                "timestamp": get_timestamp(),
                "total_unique": len(valid),
                "per_tool": {tool: len(subs) for tool, subs in self.results.items()},
            },
            os.path.join(self.output_dir, "summary.json"),
        )
        return output_file

    def _record(self) -> None:
        assets = [
            Asset(kind="subdomain", value=name, host=name, source="subdomain_enum")
            for name in read_file_lines(os.path.join(self.output_dir, "all_subdomains.txt"))
        ]
        self.ctx.record_assets(assets)

    def get_output_file(self) -> str:
        return os.path.join(self.output_dir, "all_subdomains.txt")

    def get_subdomains(self) -> List[str]:
        return sorted(self.all_subdomains)


# Backwards-compatible alias used by older imports
    def run_theharvester(self) -> List[str]:
        """theHarvester: passive hosts plus email addresses (OSINT)."""
        output_file = self._output("theharvester.txt")
        binary = next(
            (name for name in ("theHarvester", "theharvester")
             if self.runner.is_available(name)),
            "",
        )
        if not binary:
            self.logger.debug("theHarvester is not installed - skipping")
            return []
        cfg = self.config.get_tool_config("subdomain_enum", "theharvester")
        base = os.path.join(self.output_dir, "theharvester")
        cmd = [
            binary, "-d", self.target,
            "-b", str(cfg.get("sources", "duckduckgo,bing,crtsh,otx,urlscan")),
            "-l", str(cfg.get("limit", 200)),
            "-f", base,
        ]
        self.logger.info("Running theHarvester...")
        self.runner.run(cmd, tool_name="theharvester", timeout=900)

        data = load_json(base + ".json", {}) or {}
        if not isinstance(data, dict):
            data = {}
        found = set()
        for host in data.get("hosts", []) or []:
            name = str(host).split(":")[0].strip().lower().rstrip(".")
            if name.endswith(self.target):
                found.add(name)
        emails = sorted({
            str(email).strip().lower()
            for email in (data.get("emails") or [])
            if "@" in str(email)
        })
        if emails:
            write_file_lines(os.path.join(self.output_dir, "emails.txt"), emails)
            self.logger.found(f"theHarvester: {len(emails)} email address(es)")
        if not found:
            return []
        write_file_lines(output_file, sorted(found))
        return self._collect(output_file)

    def run_censys(self) -> List[str]:
        """Censys host search (needs CENSYS_API_ID / CENSYS_API_SECRET)."""
        output_file = self._output("censys.txt")
        api_id = (
            os.environ.get("CENSYS_API_ID")
            or self.config.get("subdomain_enum.censys.api_id", "")
        )
        api_secret = (
            os.environ.get("CENSYS_API_SECRET")
            or self.config.get("subdomain_enum.censys.api_secret", "")
        )
        if not (api_id and api_secret):
            self.logger.debug("censys skipped (no API credentials configured)")
            return []

        from core.net import http_request

        auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        result = http_request(
            self.ctx.session, "POST", CENSYS_SEARCH_URL,
            limiter=self.ctx.limiter, timeout=30,
            headers={"Authorization": f"Basic {auth}",
                     "Content-Type": "application/json",
                     "Accept": "application/json"},
            json={"q": f"names: {self.target}", "per_page": 100},
        )
        if not result.ok:
            self.logger.warning(f"censys search returned {result.status or result.error}")
            return []
        payload = result.json(default={}) or {}
        found = set()
        for hit in ((payload.get("result") or {}).get("hits") or []):
            if not isinstance(hit, dict):
                continue
            for name in hit.get("names", []) or []:
                candidate = str(name).strip().lower().rstrip(".")
                if candidate.endswith(self.target):
                    found.add(candidate)
        if not found:
            return []
        write_file_lines(output_file, sorted(found))
        return self._collect(output_file)

def run_all(ctx) -> str:  # pragma: no cover - convenience helper
    return SubdomainEnumerator(ctx).run_all()
