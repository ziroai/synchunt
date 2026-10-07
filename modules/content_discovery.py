"""
BugHuntRecon - Content Discovery Module
Integrates: waybackurls, gau, katana, gospider, hakrawler, paramspider,
            dirsearch, feroxbuster
"""

import os
import time
from core.utils import (
    read_file_lines, write_file_lines, merge_files,
    extract_js_urls, extract_params_from_urls
)


class ContentDiscovery:
    """URL gathering, crawling, and directory brute-forcing."""

    def __init__(self, config, runner, logger, output_dir,
                 live_hosts_file, target):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = os.path.join(output_dir, "content_discovery")
        self.urls_dir = os.path.join(self.output_dir, "urls")
        self.params_dir = os.path.join(self.output_dir, "params")
        self.dirs_dir = os.path.join(self.output_dir, "directories")
        self.live_hosts_file = live_hosts_file
        self.target = target
        self.all_urls = set()

        for d in [self.output_dir, self.urls_dir, self.params_dir, self.dirs_dir]:
            os.makedirs(d, exist_ok=True)

    def run_all(self):
        """Run all content discovery tools."""
        self.logger.phase_banner("CONTENT DISCOVERY", 5)
        start_time = time.time()

        live_hosts = read_file_lines(self.live_hosts_file)
        if not live_hosts:
            self.logger.warning("No live hosts for content discovery!")
            return None

        self.logger.info(f"Discovering content on {len(live_hosts)} hosts...")

        # URL Gathering tools
        url_tools = [
            ('waybackurls', self.run_waybackurls),
            ('gau', self.run_gau),
            ('katana', self.run_katana),
            ('gospider', self.run_gospider),
            ('hakrawler', self.run_hakrawler),
        ]

        for tool_name, tool_func in url_tools:
            if self.config.is_tool_enabled('content_discovery', tool_name):
                try:
                    tool_func()
                except Exception as e:
                    self.logger.error(f"{tool_name} failed: {str(e)}")

        # Parameter discovery
        if self.config.is_tool_enabled('content_discovery', 'paramspider'):
            try:
                self.run_paramspider()
            except Exception as e:
                self.logger.error(f"paramspider failed: {str(e)}")

        # Directory brute-forcing
        dir_tools = [
            ('dirsearch', self.run_dirsearch),
            ('feroxbuster', self.run_feroxbuster),
        ]

        for tool_name, tool_func in dir_tools:
            if self.config.is_tool_enabled('content_discovery', tool_name):
                try:
                    tool_func()
                except Exception as e:
                    self.logger.error(f"{tool_name} failed: {str(e)}")

        # Merge and categorize all URLs
        self._merge_and_categorize()

        duration = time.time() - start_time
        total_urls = len(read_file_lines(self.get_all_urls_file()))
        self.logger.result(
            f"Content Discovery Complete: {total_urls} unique URLs "
            f"found in {duration:.1f}s"
        )

        return self.get_all_urls_file()

    def run_waybackurls(self):
        """Fetch URLs from Wayback Machine."""
        self.logger.info("Running waybackurls...")

        output_file = os.path.join(self.urls_dir, "waybackurls.txt")

        # Pipe target domain into waybackurls
        cmd = f"echo {self.target} | waybackurls"

        result = self.runner.run(
            cmd,
            output_file=output_file,
            tool_name="waybackurls",
            timeout=600,
            shell=True
        )

        urls = read_file_lines(output_file)
        self.all_urls.update(urls)
        self.logger.found(f"waybackurls: {len(urls)} URLs fetched")
        return urls

    def run_gau(self):
        """Fetch URLs from multiple sources using gau."""
        self.logger.info("Running gau (GetAllURLs)...")

        tool_config = self.config.get_tool_config('content_discovery', 'gau')
        output_file = os.path.join(self.urls_dir, "gau.txt")

        cmd = f"echo {self.target} | gau"

        threads = tool_config.get('threads', 5)
        cmd += f" --threads {threads}"

        providers = tool_config.get('providers', '')
        if providers:
            cmd += f" --providers {providers}"

        result = self.runner.run(
            cmd,
            output_file=output_file,
            tool_name="gau",
            timeout=600,
            shell=True
        )

        urls = read_file_lines(output_file)
        self.all_urls.update(urls)
        self.logger.found(f"gau: {len(urls)} URLs fetched")
        return urls

    def run_katana(self):
        """Run Katana web crawler."""
        self.logger.info("Running Katana crawler...")

        tool_config = self.config.get_tool_config('content_discovery', 'katana')
        output_file = os.path.join(self.urls_dir, "katana.txt")

        cmd = f"katana -list {self.live_hosts_file} -silent"

        depth = tool_config.get('depth', 3)
        cmd += f" -d {depth}"

        threads = tool_config.get('threads', 20)
        cmd += f" -c {threads}"

        if tool_config.get('js_crawl', True):
            cmd += " -jc"

        cmd += f" -o {output_file}"

        result = self.runner.run(cmd, tool_name="katana", timeout=900)

        urls = read_file_lines(output_file)
        self.all_urls.update(urls)
        self.logger.found(f"Katana: {len(urls)} URLs crawled")
        return urls

    def run_gospider(self):
        """Run GoSpider web crawler."""
        self.logger.info("Running GoSpider...")

        tool_config = self.config.get_tool_config('content_discovery', 'gospider')
        output_dir = os.path.join(self.urls_dir, "gospider_output")
        output_file = os.path.join(self.urls_dir, "gospider.txt")
        os.makedirs(output_dir, exist_ok=True)

        depth = tool_config.get('depth', 3)
        threads = tool_config.get('threads', 10)

        cmd = (
            f"gospider -S {self.live_hosts_file} "
            f"-d {depth} -t {threads} "
            f"--other-source --include-subs "
            f"-o {output_dir}"
        )

        result = self.runner.run(cmd, tool_name="gospider", timeout=900)

        # Merge GoSpider output files
        urls = []
        if os.path.exists(output_dir):
            for f in os.listdir(output_dir):
                filepath = os.path.join(output_dir, f)
                lines = read_file_lines(filepath)
                for line in lines:
                    # GoSpider format: [source] - url
                    if ' - ' in line:
                        url = line.split(' - ', 1)[-1].strip()
                        urls.append(url)
                    else:
                        urls.append(line)

        write_file_lines(output_file, urls)
        self.all_urls.update(urls)
        self.logger.found(f"GoSpider: {len(urls)} URLs crawled")
        return urls

    def run_hakrawler(self):
        """Run Hakrawler web crawler."""
        self.logger.info("Running Hakrawler...")

        tool_config = self.config.get_tool_config('content_discovery', 'hakrawler')
        output_file = os.path.join(self.urls_dir, "hakrawler.txt")

        depth = tool_config.get('depth', 3)

        cmd = f"cat {self.live_hosts_file} | hakrawler -d {depth} -subs"

        result = self.runner.run(
            cmd,
            output_file=output_file,
            tool_name="hakrawler",
            timeout=600,
            shell=True
        )

        urls = read_file_lines(output_file)
        self.all_urls.update(urls)
        self.logger.found(f"Hakrawler: {len(urls)} URLs crawled")
        return urls

    def run_paramspider(self):
        """Run ParamSpider for parameter discovery."""
        self.logger.info("Running ParamSpider...")

        output_file = os.path.join(self.params_dir, "paramspider.txt")

        cmd = f"paramspider -d {self.target} --output {output_file}"

        result = self.runner.run(cmd, tool_name="paramspider", timeout=600)

        params = read_file_lines(output_file)
        self.logger.found(f"ParamSpider: {len(params)} parameterized URLs found")
        return params

    def run_dirsearch(self):
        """Run dirsearch for directory brute-forcing."""
        self.logger.info("Running dirsearch...")

        tool_config = self.config.get_tool_config('content_discovery', 'dirsearch')
        output_dir_path = os.path.join(self.dirs_dir, "dirsearch")
        os.makedirs(output_dir_path, exist_ok=True)

        wordlist = tool_config.get('wordlist', 'wordlists/common.txt')
        threads = tool_config.get('threads', 30)
        extensions = tool_config.get('extensions', 'php,asp,aspx,jsp,html,js,json,txt')

        live_hosts = read_file_lines(self.live_hosts_file)

        for host in live_hosts[:20]:  # Limit to top 20 to avoid being too slow
            safe_host = host.replace('https://', '').replace('http://', '')
            safe_host = safe_host.replace('/', '_').replace(':', '_')
            output_file = os.path.join(output_dir_path, f"{safe_host}.txt")

            cmd = (
                f"dirsearch -u {host} "
                f"-t {threads} "
                f"-e {extensions} "
                f"--format plain "
                f"-o {output_file} "
                f"--quiet"
            )

            if os.path.exists(wordlist):
                cmd += f" -w {wordlist}"

            self.runner.run(
                cmd,
                tool_name=f"dirsearch-{safe_host[:30]}",
                timeout=300
            )

        self.logger.found("dirsearch: Directory brute-forcing complete")

    def run_feroxbuster(self):
        """Run feroxbuster for directory discovery."""
        self.logger.info("Running feroxbuster...")

        tool_config = self.config.get_tool_config('content_discovery', 'feroxbuster')
        output_dir_path = os.path.join(self.dirs_dir, "feroxbuster")
        os.makedirs(output_dir_path, exist_ok=True)

        wordlist = tool_config.get('wordlist', 'wordlists/raft-medium-directories.txt')
        threads = tool_config.get('threads', 50)
        depth = tool_config.get('depth', 2)

        if not os.path.exists(wordlist):
            self.logger.warning(f"Wordlist not found: {wordlist}, skipping feroxbuster")
            return

        live_hosts = read_file_lines(self.live_hosts_file)

        for host in live_hosts[:10]:  # Limit
            safe_host = host.replace('https://', '').replace('http://', '')
            safe_host = safe_host.replace('/', '_').replace(':', '_')
            output_file = os.path.join(output_dir_path, f"{safe_host}.txt")

            cmd = (
                f"feroxbuster -u {host} "
                f"-w {wordlist} "
                f"-t {threads} "
                f"-d {depth} "
                f"--silent "
                f"-o {output_file}"
            )

            self.runner.run(
                cmd,
                tool_name=f"feroxbuster-{safe_host[:30]}",
                timeout=600
            )

        self.logger.found("feroxbuster: Directory discovery complete")

    def _merge_and_categorize(self):
        """Merge all URLs and categorize them."""
        self.logger.info("Merging and categorizing URLs...")

        # Merge all URL files
        url_files = []
        for f in os.listdir(self.urls_dir):
            filepath = os.path.join(self.urls_dir, f)
            if f.endswith('.txt') and os.path.isfile(filepath):
                url_files.append(filepath)

        all_urls_file = self.get_all_urls_file()
        total = merge_files(url_files, all_urls_file, deduplicate=True)
        self.logger.info(f"Total unique URLs: {total}")

        # Extract JS files
        all_urls = read_file_lines(all_urls_file)
        js_urls = extract_js_urls(all_urls)
        js_file = os.path.join(self.output_dir, "js_files.txt")
        write_file_lines(js_file, js_urls)
        self.logger.info(f"JavaScript files found: {len(js_urls)}")

        # Extract parameterized URLs
        param_urls = extract_params_from_urls(all_urls)
        param_file = os.path.join(self.params_dir, "all_params.txt")
        write_file_lines(param_file, param_urls)
        self.logger.info(f"Parameterized URLs found: {len(param_urls)}")

    def get_all_urls_file(self):
        """Get path to merged URLs file."""
        return os.path.join(self.output_dir, "all_urls.txt")

    def get_js_files(self):
        """Get path to JS files list."""
        return os.path.join(self.output_dir, "js_files.txt")

    def get_params_file(self):
        """Get path to parameterized URLs."""
        return os.path.join(self.params_dir, "all_params.txt")