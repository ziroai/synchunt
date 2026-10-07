"""
SyncHunt - Dependency Checker
Verifies that external tools and Python packages are installed and usable.

Each entry may declare a `verify` substring: some binary names are shared with
unrelated tools (notably `httpx`, which is also a popular Python HTTP client),
so a tool only counts as present when its version output identifies it.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
from typing import Dict, List, Optional

from colorama import Fore, Style


class DependencyChecker:
    """Check and report on tool dependencies."""

    TOOLS = {
        # ---------------- Subdomain enumeration ----------------
        "subfinder": {
            "check": ["subfinder", "-version"],
            "verify": "subfinder",
            "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "required": True,
            "category": "Subdomain Enumeration",
        },
        "amass": {
            "check": ["amass", "-version"],
            "verify": "amass",
            "install": "go install -v github.com/owasp-amass/amass/v4/...@master",
            "required": False,
            "category": "Subdomain Enumeration",
        },
        "assetfinder": {
            "check": ["assetfinder", "-h"],
            "install": "go install -v github.com/tomnomnom/assetfinder@latest",
            "required": False,
            "category": "Subdomain Enumeration",
        },
        "findomain": {
            "check": ["findomain", "--version"],
            "install": "Download from https://github.com/Findomain/Findomain/releases",
            "required": False,
            "category": "Subdomain Enumeration",
        },
        "puredns": {
            "check": ["puredns", "--version"],
            "install": "go install github.com/d3mondev/puredns/v2@latest",
            "required": False,
            "category": "Subdomain Enumeration",
        },
        "chaos": {
            "check": ["chaos", "-version"],
            "verify": "chaos",
            "install": "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
            "required": False,
            "category": "Subdomain Enumeration",
        },
        "gotator": {
            "check": ["gotator", "-h"],
            "install": "go install github.com/Josue87/gotator@latest",
            "required": False,
            "category": "Subdomain Enumeration",
        },
        # ---------------- Validation / probing ----------------
        "httpx": {
            "check": ["httpx", "-version"],
            "verify": "projectdiscovery",
            "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "required": True,
            "category": "Validation",
            "note": "the Python 'httpx' CLI shares this name; SyncHunt verifies the output",
        },
        "dnsx": {
            "check": ["dnsx", "-version"],
            "verify": "projectdiscovery",
            "install": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "required": False,
            "category": "Validation",
        },
        "massdns": {
            "check": ["massdns", "--help"],
            "install": "sudo apt install massdns -y",
            "required": False,
            "category": "Validation",
        },
        # ---------------- Port scanning ----------------
        "naabu": {
            "check": ["naabu", "-version"],
            "verify": "projectdiscovery",
            "install": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "required": False,
            "category": "Port Scanning",
        },
        "nmap": {
            "check": ["nmap", "--version"],
            "verify": "nmap",
            "install": "sudo apt install nmap -y",
            "required": False,
            "category": "Port Scanning",
        },
        "masscan": {
            "check": ["masscan", "--version"],
            "verify": "masscan",
            "install": "sudo apt install masscan -y",
            "required": False,
            "category": "Port Scanning",
        },
        # ---------------- Fingerprinting ----------------
        "rustscan": {
            "check": ["rustscan", "--version"],
            "install": "docker pull rustscan/rustscan:latest  (or cargo install rustscan)",
            "required": False,
            "category": "Port Scanning",
        },
        "whatweb": {
            "check": ["whatweb", "--version"],
            "install": "sudo apt install whatweb -y",
            "required": False,
            "category": "Fingerprinting",
        },
        "wafw00f": {
            "check": ["wafw00f", "-h"],
            "install": "pip install wafw00f",
            "required": False,
            "category": "Fingerprinting",
        },
        "webanalyze": {
            "check": ["webanalyze", "-h"],
            "install": "go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest",
            "required": False,
            "category": "Fingerprinting",
        },
        # ---------------- Content discovery ----------------
        "waybackurls": {
            "check": ["waybackurls", "-h"],
            "install": "go install -v github.com/tomnomnom/waybackurls@latest",
            "required": False,
            "category": "Content Discovery",
        },
        "gau": {
            "check": ["gau", "-version"],
            "install": "go install -v github.com/lc/gau/v2/cmd/gau@latest",
            "required": False,
            "category": "Content Discovery",
        },
        "katana": {
            "check": ["katana", "-version"],
            "verify": "projectdiscovery",
            "install": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
            "required": False,
            "category": "Content Discovery",
        },
        "gospider": {
            "check": ["gospider", "-v"],
            "install": "go install -v github.com/jaeles-project/gospider@latest",
            "required": False,
            "category": "Content Discovery",
        },
        "hakrawler": {
            "check": ["hakrawler", "-h"],
            "install": "go install -v github.com/hakluke/hakrawler@latest",
            "required": False,
            "category": "Content Discovery",
        },
        "paramspider": {
            "check": ["paramspider", "-h"],
            "install": "pip install paramspider",
            "required": False,
            "category": "Content Discovery",
        },
        "dirsearch": {
            "check": ["dirsearch", "-h"],
            "install": "pip install dirsearch",
            "required": False,
            "category": "Content Discovery",
        },
        "feroxbuster": {
            "check": ["feroxbuster", "--version"],
            "install": "cargo install feroxbuster  (or a release binary)",
            "required": False,
            "category": "Content Discovery",
        },
        "ffuf": {
            "check": ["ffuf", "-V"],
            "install": "go install github.com/ffuf/ffuf/v2@latest",
            "required": False,
            "category": "Content Discovery",
        },
        "x8": {
            "check": ["x8", "--version"],
            "install": "cargo install x8",
            "required": False,
            "category": "Content Discovery",
        },
        "gobuster": {
            "check": ["gobuster", "version"],
            "install": "go install github.com/OJ/gobuster/v3@latest",
            "required": False,
            "category": "Content Discovery",
        },
        "waymore": {
            "check": ["waymore", "--version"],
            "install": "pip install waymore",
            "required": False,
            "category": "Content Discovery",
        },
        "arjun": {
            "check": ["arjun", "--help"],
            "install": "pip install arjun",
            "required": False,
            "category": "Content Discovery",
        },
        # ---------------- JS analysis ----------------
        "linkfinder": {
            "check": ["linkfinder", "-h"],
            "install": "pip install linkfinder",
            "required": False,
            "category": "JS Analysis",
        },
        "secretfinder": {
            "check": ["secretfinder", "-h"],
            "install": "pip install secretfinder",
            "required": False,
            "category": "JS Analysis",
        },
        "jsluice": {
            "check": ["jsluice", "-h"],
            "install": "go install github.com/BishopFox/jsluice/cmd/jsluice@latest",
            "required": False,
            "category": "JS Analysis",
        },
        "trufflehog": {
            "check": ["trufflehog", "--version"],
            "install": "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
            "required": False,
            "category": "JS Analysis",
        },
        "gitleaks": {
            "check": ["gitleaks", "version"],
            "install": "go install github.com/gitleaks/gitleaks/v8@latest",
            "required": False,
            "category": "JS Analysis",
        },
        # ---------------- Vulnerability scanning ----------------
        "nuclei": {
            "check": ["nuclei", "-version"],
            "verify": "projectdiscovery",
            "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "required": True,
            "category": "Vulnerability Scanning",
        },
        "nikto": {
            "check": ["nikto", "-Version"],
            "install": "sudo apt install nikto -y",
            "required": False,
            "category": "Vulnerability Scanning",
        },
        "dalfox": {
            "check": ["dalfox", "version"],
            "install": "go install -v github.com/hahwul/dalfox/v2@latest",
            "required": False,
            "category": "Vulnerability Scanning",
        },
        "sqlmap": {
            "check": ["sqlmap", "--version"],
            "install": "sudo apt install sqlmap -y",
            "required": False,
            "category": "Vulnerability Scanning",
        },
        "crlfuzz": {
            "check": ["crlfuzz", "-version"],
            "install": "go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
            "required": False,
            "category": "Vulnerability Scanning",
        },
        "corsy": {
            "check": ["corsy", "-h"],
            "install": "pip install corsy",
            "required": False,
            "category": "Vulnerability Scanning",
        },
        "wapiti": {
            "check": ["wapiti", "--version"],
            "install": "pip install wapiti3",
            "required": False,
            "category": "Vulnerability Scanning",
        },
        "ghauri": {
            "check": ["ghauri", "--version"],
            "install": "pip install ghauri",
            "required": False,
            "category": "Vulnerability Scanning",
        },
        "xsstrike": {
            "check": ["xsstrike", "--help"],
            "install": "pip install xsstrike  (or clone github.com/s0md3v/XSStrike)",
            "required": False,
            "category": "Vulnerability Scanning",
        },
        "wpscan": {
            "check": ["wpscan", "--version"],
            "install": "gem install wpscan",
            "required": False,
            "category": "Vulnerability Scanning",
        },
        # ---------------- Screenshots ----------------
        "gowitness": {
            "check": ["gowitness", "-h"],
            "install": "go install -v github.com/sensepost/gowitness@latest",
            "required": False,
            "category": "Screenshots",
        },
        "aquatone": {
            "check": ["aquatone", "-h"],
            "install": "Download from https://github.com/michenriksen/aquatone/releases",
            "required": False,
            "category": "Screenshots",
        },
        "subjack": {
            "check": ["subjack", "-h"],
            "install": "go install github.com/haccer/subjack@latest",
            "required": False,
            "category": "Subdomain Takeover",
        },
        # ---------------- Cloud / sensitive info ----------------
        "s3scanner": {
            "check": ["s3scanner", "--version"],
            "install": "pip install s3scanner",
            "required": False,
            "category": "Sensitive Information",
        },
        # ---------------- DNS record enumeration ----------------
        "dnsrecon": {
            "check": ["dnsrecon", "-h"],
            "install": "pip install dnsrecon",
            "required": False,
            "category": "Validation",
            "note": "adds record enumeration and a real AXFR attempt to phase 2",
        },
        "dnsenum": {
            "check": ["dnsenum", "--help"],
            "install": "sudo apt install dnsenum -y",
            "required": False,
            "category": "Validation",
        },
        # ---------------- OSINT ----------------
        "theHarvester": {
            "check": ["theHarvester", "-h"],
            "install": "pipx install theHarvester  (binary may also be 'theharvester')",
            "required": False,
            "category": "Subdomain Enumeration",
            "note": "passive hosts plus email addresses",
        },
        # ---------------- Content discovery ----------------
        "wfuzz": {
            "check": ["wfuzz", "--help"],
            "install": "pip install wfuzz",
            "required": False,
            "category": "Content Discovery",
        },
        # ---------------- Vulnerability scanning ----------------
        "joomscan": {
            "check": ["joomscan", "--help"],
            "install": "git clone https://github.com/OWASP/joomscan (needs perl)",
            "required": False,
            "category": "Vulnerability Scanning",
        },
        "commix": {
            "check": ["commix", "--version"],
            "install": "git clone https://github.com/commixproject/commix",
            "required": False,
            "category": "Vulnerability Scanning",
            "note": "off by default - command injection is opt-in",
        },
        "tplmap.py": {
            "check": ["tplmap.py", "-h"],
            "install": "git clone https://github.com/epinna/tplmap",
            "required": False,
            "category": "Vulnerability Scanning",
            "note": "off by default - SSTI probing is opt-in",
        },
        "ssrfmap.py": {
            "check": ["ssrfmap.py", "-h"],
            "install": "git clone https://github.com/swisskyrepo/SSRFmap",
            "required": False,
            "category": "Vulnerability Scanning",
            "note": "off by default - SSRF probing is opt-in",
        },
        # ---------------- Screenshots ----------------
        "eyewitness": {
            "check": ["eyewitness", "--help"],
            "install": "pipx install EyeWitness",
            "required": False,
            "category": "Screenshots",
        },
        # ---------------- Cloud ----------------
        "cloudbrute": {
            "check": ["cloudbrute", "-h"],
            "install": "download a release: https://github.com/0xsha/CloudBrute/releases",
            "required": False,
            "category": "Cloud",
            "note": "off by default - wordlist driven, covers 7 providers",
        },
        # ---------------- Prioritisation ----------------
        "searchsploit": {
            "check": ["searchsploit", "--version"],
            "install": "sudo apt install exploitdb -y",
            "required": False,
            "category": "Prioritisation",
            "note": "attaches local Exploit-DB entries to CVE findings (no network)",
        },
        # ---------------- Interactive companions (not automated) ----------------
        "mitmproxy": {
            "check": ["mitmproxy", "--version"],
            "install": "pipx install mitmproxy",
            "required": False,
            "category": "Interception",
            "note": "use with --proxy; SyncHunt routes traffic through it instead of driving it",
        },
    }

    # Python packages required for the framework itself to run.
    PYTHON_PACKAGES = {
        "yaml": "pyyaml",
        "requests": "requests",
        "colorama": "colorama",
    }

    PYTHON_PACKAGES_OPTIONAL = {
        "dns": "dnspython",
        "shodan": "shodan",
        "tldextract": "tldextract",
    }

    def __init__(self, logger=None, runner=None):
        self.logger = logger
        self.runner = runner
        self.available_tools: Dict[str, str] = {}
        self.missing_tools: Dict[str, Dict] = {}
        self.suspect_tools: Dict[str, str] = {}

    # ------------------------------------------------------------------
    def check_tool(self, tool_name: str) -> bool:
        """Check whether a single tool is available and actually the right one."""
        spec = self.TOOLS.get(tool_name)
        if not spec:
            return False

        binary = tool_name
        path = shutil.which(binary)
        if not path:
            self.missing_tools[tool_name] = spec
            return False

        verify = spec.get("verify")
        if verify:
            output = self._run_check(spec["check"])
            if output is not None and verify.lower() not in output.lower():
                self.suspect_tools[tool_name] = path
                self.missing_tools[tool_name] = spec
                return False

        self.available_tools[tool_name] = path
        return True

    def _run_check(self, argv: List[str]) -> Optional[str]:
        try:
            result = subprocess.run(
                argv, capture_output=True, text=True, timeout=15
            )
            return f"{result.stdout}\n{result.stderr}"
        except Exception:
            return None

    def check_python_packages(self) -> Dict[str, bool]:
        """Verify the Python dependencies SyncHunt itself needs."""
        status = {}
        for module, package in self.PYTHON_PACKAGES.items():
            status[package] = importlib.util.find_spec(module) is not None
        return status

    def optional_python_packages(self) -> Dict[str, bool]:
        status = {}
        for module, package in self.PYTHON_PACKAGES_OPTIONAL.items():
            status[package] = importlib.util.find_spec(module) is not None
        return status

    # ------------------------------------------------------------------
    def check_all(self) -> Dict:
        """Check all tools and print a status report."""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═' * 62}")
        print("  🔧 Checking Tool Dependencies")
        print(f"{'═' * 62}{Style.RESET_ALL}\n")

        packages = self.check_python_packages()
        print(f"  {Fore.YELLOW}{Style.BRIGHT}📦 Python packages{Style.RESET_ALL}")
        missing_packages = []
        for package, present in sorted(packages.items()):
            if present:
                print(f"    {Fore.GREEN}✅ FOUND    {Fore.WHITE}{package}")
            else:
                print(f"    {Fore.RED}❌ MISSING  {Fore.WHITE}{package}")
                missing_packages.append(package)
        print()

        categories: Dict[str, List[str]] = {}
        for tool_name, info in self.TOOLS.items():
            categories.setdefault(info["category"], []).append(tool_name)

        available = 0
        missing_required: List[str] = []
        for category in sorted(categories):
            print(f"  {Fore.YELLOW}{Style.BRIGHT}📂 {category}{Style.RESET_ALL}")
            for tool_name in sorted(categories[category]):
                spec = self.TOOLS[tool_name]
                present = self.check_tool(tool_name)
                tag = f"{Fore.RED}[REQUIRED]" if spec["required"] else f"{Fore.WHITE}[OPTIONAL]"
                if present:
                    available += 1
                    print(f"    {Fore.GREEN}✅ FOUND    {Fore.WHITE}{tool_name:<18} {tag}")
                else:
                    suffix = ""
                    if tool_name in self.suspect_tools:
                        suffix = f" {Fore.YELLOW}(wrong binary: {self.suspect_tools[tool_name]})"
                    print(f"    {Fore.RED}❌ MISSING  {Fore.WHITE}{tool_name:<18} {tag}{suffix}")
                    if spec["required"]:
                        missing_required.append(tool_name)
            print()

        total = len(self.TOOLS)
        print(f"  {Fore.CYAN}{'─' * 52}")
        print(
            f"  {Fore.WHITE}📊 Tools: {Fore.GREEN}{available}{Fore.WHITE}/{total} available"
        )
        if missing_required:
            print(
                f"  {Fore.RED}⚠️  Missing REQUIRED tools: {', '.join(missing_required)}"
                f"{Style.RESET_ALL}"
            )

        if self.missing_tools:
            print(f"\n  {Fore.YELLOW}📋 Install missing tools:{Style.RESET_ALL}")
            for tool_name in sorted(self.missing_tools):
                info = self.missing_tools[tool_name]
                print(f"    {Fore.WHITE}• {tool_name:<18} {Fore.CYAN}{info['install']}")
        print(f"\n{Fore.CYAN}{'═' * 62}{Style.RESET_ALL}\n")

        return {
            "available": dict(self.available_tools),
            "missing": dict(self.missing_tools),
            "missing_required": missing_required,
            "missing_packages": missing_packages,
            "suspect": dict(self.suspect_tools),
            "total": total,
            "available_count": available,
            "ready": not missing_required,
        }

    def is_available(self, tool_name: str) -> bool:
        if tool_name in self.available_tools:
            return True
        return self.check_tool(tool_name)

    def get_install_commands(self) -> List[Dict[str, str]]:
        return [
            {
                "tool": name,
                "command": info["install"],
                "category": info["category"],
            }
            for name, info in sorted(self.missing_tools.items())
        ]

    def auto_install(self, tool_name: Optional[str] = None) -> Dict[str, bool]:
        """
        Print install commands for missing tools.

        SyncHunt deliberately does not execute package-manager commands on the
        user's behalf: silently running `sudo apt install` / `pip install` from
        a scanner is a supply-chain risk and often hangs on a password prompt.
        """
        targets = (
            {tool_name: self.missing_tools.get(tool_name, {})}
            if tool_name
            else self.missing_tools
        )
        results = {}
        for name, info in targets.items():
            command = (info or {}).get("install")
            if not command:
                results[name] = False
                continue
            print(
                f"  {Fore.YELLOW}→ install {name}: {Fore.CYAN}{command}{Style.RESET_ALL}"
            )
            results[name] = False
        if results:
            print(
                f"\n  {Fore.WHITE}Run the commands above, then re-run "
                f"`synchunt --doctor`.{Style.RESET_ALL}"
            )
        return results
