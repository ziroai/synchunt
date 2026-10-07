"""
BugHuntRecon - Subdomain Enumeration Module
Integrates: Subfinder, Amass, Assetfinder, Findomain, crt.sh, Sublist3r
"""

import os
import json
import requests
import time
from core.utils import (
    read_file_lines, write_file_lines, merge_files,
    is_valid_domain, get_timestamp
)


class SubdomainEnumerator:
    """Orchestrates multiple subdomain enumeration tools."""

    def __init__(self, config, runner, logger, output_dir, target):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = os.path.join(output_dir, "subdomains")
        self.target = target
        self.results = {}
        self.all_subdomains = set()

        os.makedirs(self.output_dir, exist_ok=True)

    def run_all(self):
        """Run all enabled subdomain enumeration tools."""
        self.logger.phase_banner("SUBDOMAIN ENUMERATION", 1)
        start_time = time.time()

        tools = [
            ('subfinder', self.run_subfinder),
            ('amass', self.run_amass),
            ('assetfinder', self.run_assetfinder),
            ('findomain', self.run_findomain),
            ('crtsh', self.run_crtsh),
            ('sublist3r', self.run_sublist3r),
            ('puredns', self.run_puredns),
            ('gotator', self.run_gotator),
        ]

        for tool_name, tool_func in tools:
            if self.config.is_tool_enabled('subdomain_enum', tool_name):
                try:
                    result = tool_func()
                    if result:
                        self.results[tool_name] = result
                        self.logger.found(
                            f"{tool_name}: Found {len(result)} subdomains"
                        )
                except Exception as e:
                    self.logger.error(f"{tool_name} failed: {str(e)}")
            else:
                self.logger.debug(f"{tool_name} is disabled, skipping")

        # Merge and deduplicate all results
        final_count = self._merge_results()

        duration = time.time() - start_time
        self.logger.result(
            f"Subdomain Enumeration Complete: {final_count} unique subdomains "
            f"found in {duration:.1f}s"
        )

        return self.get_output_file()

    def run_subfinder(self):
        """Run Subfinder for passive subdomain discovery."""
        self.logger.info("Running Subfinder...")
        output_file = os.path.join(self.output_dir, "subfinder.txt")

        cmd = f"subfinder -d {self.target} -silent -all"

        # Add config options
        tool_config = self.config.get_tool_config('subdomain_enum', 'subfinder')
        if tool_config.get('threads'):
            cmd += f" -t {tool_config['threads']}"
        if tool_config.get('timeout'):
            cmd += f" -timeout {tool_config['timeout']}"
        if tool_config.get('config'):
            cmd += f" -provider-config {tool_config['config']}"

        cmd += f" -o {output_file}"

        result = self.runner.run(
            cmd,
            output_file=None,  # subfinder writes its own output
            tool_name="subfinder",
            timeout=600
        )

        subdomains = read_file_lines(output_file)
        self.all_subdomains.update(subdomains)
        return subdomains

    def run_amass(self):
        """Run OWASP Amass for subdomain enumeration."""
        self.logger.info("Running Amass...")
        output_file = os.path.join(self.output_dir, "amass.txt")

        tool_config = self.config.get_tool_config('subdomain_enum', 'amass')

        cmd = f"amass enum -d {self.target}"

        if tool_config.get('passive', True):
            cmd += " -passive"
        if tool_config.get('timeout'):
            cmd += f" -timeout {tool_config['timeout']}"
        if tool_config.get('config'):
            cmd += f" -config {tool_config['config']}"

        cmd += f" -o {output_file}"

        result = self.runner.run(
            cmd,
            tool_name="amass",
            timeout=1800  # Amass can be slow
        )

        subdomains = read_file_lines(output_file)
        self.all_subdomains.update(subdomains)
        return subdomains

    def run_assetfinder(self):
        """Run Assetfinder for quick subdomain finding."""
        self.logger.info("Running Assetfinder...")
        output_file = os.path.join(self.output_dir, "assetfinder.txt")

        tool_config = self.config.get_tool_config('subdomain_enum', 'assetfinder')

        cmd = f"assetfinder"
        if tool_config.get('subs_only', True):
            cmd += " --subs-only"
        cmd += f" {self.target}"

        result = self.runner.run(
            cmd,
            output_file=output_file,
            tool_name="assetfinder",
            timeout=300
        )

        subdomains = read_file_lines(output_file)
        # Filter to only include subdomains of target
        subdomains = [s for s in subdomains if s.endswith(self.target)]
        write_file_lines(output_file, subdomains)
        self.all_subdomains.update(subdomains)
        return subdomains

    def run_findomain(self):
        """Run Findomain for fast subdomain enumeration."""
        self.logger.info("Running Findomain...")
        output_file = os.path.join(self.output_dir, "findomain.txt")

        cmd = f"findomain -t {self.target} -u {output_file} -q"

        result = self.runner.run(
            cmd,
            tool_name="findomain",
            timeout=300
        )

        subdomains = read_file_lines(output_file)
        self.all_subdomains.update(subdomains)
        return subdomains

    def run_crtsh(self):
        """Query crt.sh Certificate Transparency logs."""
        self.logger.info("Querying crt.sh...")
        output_file = os.path.join(self.output_dir, "crtsh.txt")

        subdomains = set()

        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        # Remove wildcard prefix
                        if name.startswith('*.'):
                            name = name[2:]
                        if name and is_valid_domain(name) and name.endswith(self.target):
                            subdomains.add(name)

                write_file_lines(output_file, list(subdomains))
                self.logger.info(f"crt.sh returned {len(subdomains)} unique subdomains")
            else:
                self.logger.warning(f"crt.sh returned status {response.status_code}")

        except requests.exceptions.Timeout:
            self.logger.warning("crt.sh request timed out")
        except requests.exceptions.JSONDecodeError:
            self.logger.warning("crt.sh returned invalid JSON")
        except Exception as e:
            self.logger.error(f"crt.sh query failed: {str(e)}")

        self.all_subdomains.update(subdomains)
        return list(subdomains)

    def run_sublist3r(self):
        """Run Sublist3r for subdomain enumeration."""
        self.logger.info("Running Sublist3r...")
        output_file = os.path.join(self.output_dir, "sublist3r.txt")

        tool_config = self.config.get_tool_config('subdomain_enum', 'sublist3r')

        cmd = f"sublist3r -d {self.target} -o {output_file}"

        if tool_config.get('threads'):
            cmd += f" -t {tool_config['threads']}"

        result = self.runner.run(
            cmd,
            tool_name="sublist3r",
            timeout=600
        )

        subdomains = read_file_lines(output_file)
        self.all_subdomains.update(subdomains)
        return subdomains

    def run_puredns(self):
        """Run puredns for active subdomain bruteforcing."""
        self.logger.info("Running puredns (Active Bruteforcing)...")
        output_file = os.path.join(self.output_dir, "puredns.txt")
        
        tool_config = self.config.get_tool_config('subdomain_enum', 'puredns')
        wordlist = tool_config.get('wordlist', 'wordlists/resolvers.txt')
        resolvers = tool_config.get('resolvers', 'wordlists/resolvers.txt')

        if not os.path.exists(wordlist):
            self.logger.warning(f"puredns wordlist not found: {wordlist}")
            return []

        cmd = f"puredns bruteforce {wordlist} {self.target} -r {resolvers} -w {output_file}"
        
        result = self.runner.run(
            cmd,
            tool_name="puredns",
            timeout=1800
        )

        subdomains = read_file_lines(output_file)
        self.all_subdomains.update(subdomains)
        return subdomains

    def run_gotator(self):
        """Run gotator for subdomain permutations."""
        self.logger.info("Running gotator (Permutations)...")
        output_file = os.path.join(self.output_dir, "gotator.txt")
        
        tool_config = self.config.get_tool_config('subdomain_enum', 'gotator')
        permutations = tool_config.get('permutations', 'wordlists/permutations.txt')
        
        # We need existing subdomains to permute
        if not self.all_subdomains:
            self.logger.warning("No subdomains found to permute.")
            return []

        # Save current subdomains to a temp file
        temp_subs = os.path.join(self.output_dir, "temp_subs_for_gotator.txt")
        write_file_lines(temp_subs, list(self.all_subdomains))

        cmd = f"gotator -sub {temp_subs} -perm {permutations} -depth {tool_config.get('depth', 1)} -silent"
        
        # gotator generates to stdout, we capture it and pipe to puredns for resolution
        resolvers = self.config.get_tool_config('subdomain_enum', 'puredns').get('resolvers', 'wordlists/resolvers.txt')
        
        pipe_cmds = [
            cmd,
            f"puredns resolve -r {resolvers} -w {output_file}"
        ]

        result = self.runner.pipe_commands(
            pipe_cmds,
            tool_name="gotator",
        )

        # Cleanup temp file
        if os.path.exists(temp_subs):
            os.remove(temp_subs)

        subdomains = read_file_lines(output_file)
        self.all_subdomains.update(subdomains)
        return subdomains

    def _merge_results(self):
        """Merge all results and deduplicate."""
        self.logger.info("Merging and deduplicating subdomain results...")

        # Collect all files
        result_files = []
        for f in os.listdir(self.output_dir):
            filepath = os.path.join(self.output_dir, f)
            if f.endswith('.txt') and f != 'all_subdomains.txt':
                result_files.append(filepath)

        # Merge
        output_file = self.get_output_file()
        all_subs = set()

        for filepath in result_files:
            subs = read_file_lines(filepath)
            all_subs.update(subs)

        # Also include any collected during run
        all_subs.update(self.all_subdomains)

        # Filter valid subdomains
        valid_subs = sorted([
            s.lower().strip() for s in all_subs
            if s and is_valid_domain(s.lower().strip())
        ])

        # Deduplicate
        valid_subs = list(dict.fromkeys(valid_subs))

        count = write_file_lines(output_file, valid_subs)

        # Save summary
        summary = {
            'target': self.target,
            'timestamp': get_timestamp(),
            'total_unique': count,
            'per_tool': {
                tool: len(subs) for tool, subs in self.results.items()
            }
        }

        summary_file = os.path.join(self.output_dir, "summary.json")
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        return count

    def get_output_file(self):
        """Get path to the merged output file."""
        return os.path.join(self.output_dir, "all_subdomains.txt")

    def get_subdomains(self):
        """Get list of all discovered subdomains."""
        return sorted(list(self.all_subdomains))