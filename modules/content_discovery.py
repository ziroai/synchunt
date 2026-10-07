"""
SyncHunt - Content Discovery
URL gathering (waybackurls, gau, katana, gospider, hakrawler), parameter
discovery (paramspider, x8) and directory brute-forcing (dirsearch,
feroxbuster, ffuf).

All external invocations use argv lists or stdin piping - never string
interpolation into a shell.
"""

from __future__ import annotations

import os
import time
from typing import List

from core.models import Asset
from core.utils import (
    extract_js_urls,
    extract_params_from_urls,
    load_json,
    merge_files,
    read_file_lines,
    save_json,
    write_file_lines,
)


class ContentDiscovery:
    """Gather URLs, parameters and directories for in-scope hosts."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.runner = ctx.runner
        self.logger = ctx.logger
        self.output_dir = ctx.path("content_discovery")
        self.urls_dir = os.path.join(self.output_dir, "urls")
        self.params_dir = os.path.join(self.output_dir, "params")
        self.dirs_dir = os.path.join(self.output_dir, "directories")
        self.live_hosts_file = ctx.resolve_file("live_hosts", "dns", "live_hosts.txt")
        self.target = ctx.target
        self.all_urls: set = set()

        for directory in (self.output_dir, self.urls_dir, self.params_dir, self.dirs_dir):
            os.makedirs(directory, exist_ok=True)

    # ------------------------------------------------------------------
    def get_all_urls_file(self) -> str:
        return os.path.join(self.output_dir, "all_urls.txt")

    def get_js_files(self) -> str:
        return os.path.join(self.output_dir, "js_files.txt")

    def get_params_file(self) -> str:
        return os.path.join(self.params_dir, "all_params.txt")

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("CONTENT DISCOVERY", 7)
        started = time.time()

        hosts = read_file_lines(self.live_hosts_file)
        if not hosts:
            self.logger.warning("No live hosts for content discovery")
            write_file_lines(self.get_all_urls_file(), [])
            return self.get_all_urls_file()

        self.logger.info(f"Discovering content on {len(hosts)} host(s)...")
        seed = "\n".join(hosts) + "\n"

        for tool_name, method in (
            ("waybackurls", self.run_waybackurls),
            ("gau", self.run_gau),
            ("katana", self.run_katana),
            ("gospider", self.run_gospider),
            ("hakrawler", self.run_hakrawler),
        ):
            if not self.config.is_tool_enabled("content_discovery", tool_name):
                continue
            try:
                method(seed)
            except Exception as exc:
                self.logger.error(f"{tool_name} failed: {exc}")

        if self.config.is_tool_enabled("content_discovery", "paramspider"):
            self.run_paramspider()

        for tool_name, method in (
            ("dirsearch", self.run_dirsearch),
            ("feroxbuster", self.run_feroxbuster),
            ("ffuf", self.run_ffuf),
            ("x8", self.run_x8),
        ):
            if not self.config.is_tool_enabled("content_discovery", tool_name):
                continue
            try:
                method()
            except Exception as exc:
                self.logger.error(f"{tool_name} failed: {exc}")

        self._merge_and_categorize()
        total = len(read_file_lines(self.get_all_urls_file()))
        self.logger.result(
            f"Content Discovery Complete: {total} unique URL(s) in "
            f"{time.time() - started:.1f}s"
        )
        self._record()
        return self.get_all_urls_file()

    # ------------------------------------------------------------------
    def run_waybackurls(self, seed: str) -> List[str]:
        output_file = os.path.join(self.urls_dir, "waybackurls.txt")
        if self.runner.require("waybackurls", output_file):
            return []
        self.logger.info("Running waybackurls...")
        self.runner.run_with_stdin(
            ["waybackurls"], seed, output_file=output_file,
            tool_name="waybackurls", timeout=900,
        )
        return self._ingest(output_file, "waybackurls")

    def run_gau(self, seed: str) -> List[str]:
        output_file = os.path.join(self.urls_dir, "gau.txt")
        if self.runner.require("gau", output_file):
            return []
        cfg = self.config.get_tool_config("content_discovery", "gau")
        cmd = ["gau", "--threads", str(cfg.get("threads", 5))]
        providers = cfg.get("providers", "")
        if providers:
            cmd += ["--providers", str(providers)]
        self.logger.info("Running gau...")
        self.runner.run_with_stdin(cmd, seed, output_file=output_file,
                                   tool_name="gau", timeout=900)
        return self._ingest(output_file, "gau")

    def run_katana(self, _seed: str) -> List[str]:
        output_file = os.path.join(self.urls_dir, "katana.txt")
        if self.runner.require("katana", output_file):
            return []
        cfg = self.config.get_tool_config("content_discovery", "katana")
        cmd = [
            "katana", "-list", self.live_hosts_file, "-silent",
            "-d", str(cfg.get("depth", 3)),
            "-c", str(cfg.get("threads", 20)),
            "-o", output_file,
        ]
        if cfg.get("js_crawl", True):
            cmd.append("-jc")
        self.logger.info("Running katana crawler...")
        self.runner.run(cmd, tool_name="katana", timeout=1800)
        return self._ingest(output_file, "katana")

    def run_gospider(self, _seed: str) -> List[str]:
        output_file = os.path.join(self.urls_dir, "gospider.txt")
        if self.runner.require("gospider", output_file):
            return []
        cfg = self.config.get_tool_config("content_discovery", "gospider")
        raw_dir = os.path.join(self.urls_dir, "gospider_output")
        os.makedirs(raw_dir, exist_ok=True)
        cmd = [
            "gospider", "-S", self.live_hosts_file,
            "-d", str(cfg.get("depth", 3)),
            "-t", str(cfg.get("threads", 10)),
            "--other-source", "--include-subs",
            "-o", raw_dir,
        ]
        self.logger.info("Running gospider...")
        self.runner.run(cmd, tool_name="gospider", timeout=1800)

        urls: List[str] = []
        for name in sorted(os.listdir(raw_dir)):
            path = os.path.join(raw_dir, name)
            if not os.path.isfile(path):
                continue
            for line in read_file_lines(path):
                urls.append(line.split(" - ", 1)[-1].strip() if " - " in line else line)
        write_file_lines(output_file, urls)
        return self._ingest(output_file, "gospider")

    def run_hakrawler(self, seed: str) -> List[str]:
        output_file = os.path.join(self.urls_dir, "hakrawler.txt")
        if self.runner.require("hakrawler", output_file):
            return []
        cfg = self.config.get_tool_config("content_discovery", "hakrawler")
        self.logger.info("Running hakrawler...")
        self.runner.run_with_stdin(
            ["hakrawler", "-d", str(cfg.get("depth", 3)), "-subs"],
            seed, output_file=output_file, tool_name="hakrawler", timeout=900,
        )
        return self._ingest(output_file, "hakrawler")

    def run_paramspider(self) -> List[str]:
        output_file = os.path.join(self.params_dir, "paramspider.txt")
        if self.runner.require("paramspider", output_file):
            return []
        self.logger.info("Running paramspider...")
        # ParamSpider writes its own files; capture its stdout too.
        self.runner.run(
            ["paramspider", "-d", self.target, "--output", output_file],
            tool_name="paramspider", timeout=900,
        )
        params = read_file_lines(output_file)
        if not params:
            result = self.runner.run(
                ["paramspider", "-d", self.target], tool_name="paramspider-stdout", timeout=900
            )
            params = [line.strip() for line in (result.get("stdout") or "").splitlines() if line.strip()]
            write_file_lines(output_file, params)
        self.logger.found(f"paramspider: {len(params)} parameterised URL(s)")
        return params

    # ------------------------------------------------------------------
    def run_dirsearch(self) -> None:
        if self.runner.require("dirsearch"):
            return
        cfg = self.config.get_tool_config("content_discovery", "dirsearch")
        wordlist = cfg.get("wordlist", "wordlists/common.txt")
        extensions = cfg.get("extensions", "php,html,js,json,txt")
        raw_dir = os.path.join(self.dirs_dir, "dirsearch")
        os.makedirs(raw_dir, exist_ok=True)
        if not os.path.exists(wordlist):
            self.logger.skip(f"dirsearch wordlist missing ({wordlist})")
            return

        self.logger.info("Running dirsearch...")
        for host in read_file_lines(self.live_hosts_file)[:20]:
            safe = host.replace("https://", "").replace("http://", "")
            safe = safe.replace("/", "_").replace(":", "_")
            output_file = os.path.join(raw_dir, f"{safe}.txt")
            cmd = [
                "dirsearch", "-u", host, "-t", str(cfg.get("threads", 30)),
                "-e", str(extensions), "-w", wordlist,
                "--format", "plain", "-o", output_file, "--quiet",
            ]
            self.runner.run(cmd, tool_name=f"dirsearch-{safe[:30]}", timeout=600)

        self._ingest_directory_findings(raw_dir, ".txt")

    def run_feroxbuster(self) -> None:
        if self.runner.require("feroxbuster"):
            return
        cfg = self.config.get_tool_config("content_discovery", "feroxbuster")
        wordlist = cfg.get("wordlist", "wordlists/directories.txt")
        raw_dir = os.path.join(self.dirs_dir, "feroxbuster")
        os.makedirs(raw_dir, exist_ok=True)
        if not os.path.exists(wordlist):
            self.logger.skip(f"feroxbuster wordlist missing ({wordlist})")
            return

        self.logger.info("Running feroxbuster...")
        for host in read_file_lines(self.live_hosts_file)[:10]:
            safe = host.replace("https://", "").replace("http://", "")
            safe = safe.replace("/", "_").replace(":", "_")
            output_file = os.path.join(raw_dir, f"{safe}.txt")
            cmd = [
                "feroxbuster", "-u", host, "-w", wordlist,
                "-t", str(cfg.get("threads", 50)),
                "-d", str(cfg.get("depth", 2)),
                "--silent", "-o", output_file,
            ]
            self.runner.run(cmd, tool_name=f"feroxbuster-{safe[:30]}", timeout=900)

        self._ingest_directory_findings(raw_dir, ".txt")

    def run_ffuf(self) -> None:
        if self.runner.require("ffuf"):
            return
        cfg = self.config.get_tool_config("content_discovery", "ffuf")
        wordlist = cfg.get("wordlist", "wordlists/directories.txt")
        raw_dir = os.path.join(self.dirs_dir, "ffuf")
        os.makedirs(raw_dir, exist_ok=True)
        if not os.path.exists(wordlist):
            self.logger.skip(f"ffuf wordlist missing ({wordlist})")
            return

        extensions = str(cfg.get("extensions", "php,html,js,json,txt"))
        self.logger.info("Running ffuf...")
        for host in read_file_lines(self.live_hosts_file)[:10]:
            safe = host.replace("https://", "").replace("http://", "")
            safe = safe.replace("/", "_").replace(":", "_")
            output_file = os.path.join(raw_dir, f"{safe}.json")
            cmd = [
                "ffuf", "-u", f"{host.rstrip('/')}/FUZZ", "-w", wordlist,
                "-t", str(cfg.get("threads", 40)),
                "-e", f".{extensions.replace(',', ',.')}",
                "-o", output_file, "-of", "json", "-s",
            ]
            self.runner.run(cmd, tool_name=f"ffuf-{safe[:30]}", timeout=900)

        for name in sorted(os.listdir(raw_dir)):
            if not name.endswith(".json"):
                continue
            data = load_json(os.path.join(raw_dir, name), {})
            for entry in (data or {}).get("results", []) or []:
                url = entry.get("url")
                if url:
                    self.all_urls.add(url)

    def run_x8(self) -> None:
        if self.runner.require("x8"):
            return
        cfg = self.config.get_tool_config("content_discovery", "x8")
        wordlist = cfg.get("wordlist", "wordlists/parameters.txt")
        raw_dir = os.path.join(self.params_dir, "x8")
        os.makedirs(raw_dir, exist_ok=True)
        if not os.path.exists(wordlist):
            self.logger.skip(f"x8 wordlist missing ({wordlist})")
            return

        self.logger.info("Running x8 parameter discovery...")
        for host in read_file_lines(self.live_hosts_file)[:10]:
            safe = host.replace("https://", "").replace("http://", "")
            safe = safe.replace("/", "_").replace(":", "_")
            output_file = os.path.join(raw_dir, f"{safe}.txt")
            cmd = [
                "x8", "-u", host, "-w", wordlist,
                "-c", str(cfg.get("threads", 20)), "-O", "json",
                "-o", output_file,
            ]
            self.runner.run(cmd, tool_name=f"x8-{safe[:30]}", timeout=900)

        for name in sorted(os.listdir(raw_dir)):
            if not name.endswith(".txt"):
                continue
            for line in read_file_lines(os.path.join(raw_dir, name)):
                if "http" in line:
                    self.all_urls.add(line)

    # ------------------------------------------------------------------
    def _ingest(self, output_file: str, tool: str) -> List[str]:
        urls = read_file_lines(output_file)
        self.all_urls.update(urls)
        if urls:
            self.logger.found(f"{tool}: {len(urls)} URL(s)")
        return urls

    def _ingest_directory_findings(self, raw_dir: str, suffix: str) -> None:
        for name in sorted(os.listdir(raw_dir)):
            if not name.endswith(suffix):
                continue
            for line in read_file_lines(os.path.join(raw_dir, name)):
                candidate = line.split()[-1] if line.startswith("[") else line
                if candidate.startswith("http"):
                    self.all_urls.add(candidate)

    def _merge_and_categorize(self) -> None:
        url_files = [
            os.path.join(self.urls_dir, name)
            for name in sorted(os.listdir(self.urls_dir))
            if name.endswith(".txt") and os.path.isfile(os.path.join(self.urls_dir, name))
        ]
        total = merge_files(url_files, self.get_all_urls_file(), deduplicate=True)
        self.all_urls.update(read_file_lines(self.get_all_urls_file()))
        self.logger.info(f"Merged URL corpus: {total} unique URL(s)")

        all_urls = sorted(self.all_urls)
        js_urls = extract_js_urls(all_urls)
        write_file_lines(self.get_js_files(), js_urls)
        self.logger.info(f"JavaScript files: {len(js_urls)}")

        param_urls = extract_params_from_urls(all_urls)
        write_file_lines(self.get_params_file(), sorted(set(param_urls)))
        self.logger.info(f"Parameterised URLs: {len(param_urls)}")

        save_json(
            {
                "urls": total,
                "js_files": len(js_urls),
                "parameterised": len(param_urls),
            },
            os.path.join(self.output_dir, "summary.json"),
        )
        self.ctx.set_file("urls", self.get_all_urls_file())
        self.ctx.set_file("js_files", self.get_js_files())
        self.ctx.set_file("params", self.get_params_file())

    def _record(self) -> None:
        self.ctx.record_assets(
            [
                Asset(kind="url", value=url, host=url.split("/")[2] if "//" in url else "",
                      source="content_discovery")
                for url in read_file_lines(self.get_js_files())[:500]
            ]
        )
