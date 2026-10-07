"""
BugHuntRecon - Dependency Checker
Verifies all required tools are installed and accessible.
"""

import shutil
import subprocess
import sys
from colorama import Fore, Style


class DependencyChecker:
    """Check and report on tool dependencies."""

    # Tool definitions: (name, check_command, install_hint, required)
    TOOLS = {
        # Go-based tools
        'subfinder': {
            'check': 'subfinder -version',
            'install': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'required': True,
            'category': 'Subdomain Enumeration'
        },
        'amass': {
            'check': 'amass -version',
            'install': 'go install -v github.com/owasp-amass/amass/v4/...@master',
            'required': False,
            'category': 'Subdomain Enumeration'
        },
        'assetfinder': {
            'check': 'assetfinder -h',
            'install': 'go install -v github.com/tomnomnom/assetfinder@latest',
            'required': False,
            'category': 'Subdomain Enumeration'
        },
        'findomain': {
            'check': 'findomain --version',
            'install': 'Download from https://github.com/Findomain/Findomain/releases',
            'required': False,
            'category': 'Subdomain Enumeration'
        },
        'httpx': {
            'check': 'httpx -version',
            'install': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'required': True,
            'category': 'Validation'
        },
        'puredns': {
            'check': 'puredns --version',
            'install': 'go install github.com/d3mondev/puredns/v2@latest',
            'required': False,
            'category': 'Subdomain Enumeration'
        },
        'gotator': {
            'check': 'gotator -h',
            'install': 'go install github.com/Josue87/gotator@latest',
            'required': False,
            'category': 'Subdomain Enumeration'
        },
        'dnsx': {
            'check': 'dnsx -version',
            'install': 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
            'required': False,
            'category': 'Validation'
        },
        'naabu': {
            'check': 'naabu -version',
            'install': 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
            'required': False,
            'category': 'Port Scanning'
        },
        'nuclei': {
            'check': 'nuclei -version',
            'install': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'required': True,
            'category': 'Vulnerability Scanning'
        },
        'katana': {
            'check': 'katana -version',
            'install': 'go install -v github.com/projectdiscovery/katana/cmd/katana@latest',
            'required': False,
            'category': 'Content Discovery'
        },
        'gospider': {
            'check': 'gospider -v',
            'install': 'go install -v github.com/jaeles-project/gospider@latest',
            'required': False,
            'category': 'Content Discovery'
        },
        'gau': {
            'check': 'gau -version',
            'install': 'go install -v github.com/lc/gau/v2/cmd/gau@latest',
            'required': False,
            'category': 'Content Discovery'
        },
        'hakrawler': {
            'check': 'hakrawler -h',
            'install': 'go install -v github.com/hakluke/hakrawler@latest',
            'required': False,
            'category': 'Content Discovery'
        },
        'waybackurls': {
            'check': 'waybackurls -h',
            'install': 'go install -v github.com/tomnomnom/waybackurls@latest',
            'required': False,
            'category': 'Content Discovery'
        },
        'dalfox': {
            'check': 'dalfox version',
            'install': 'go install -v github.com/hahwul/dalfox/v2@latest',
            'required': False,
            'category': 'Vulnerability Scanning'
        },
        'crlfuzz': {
            'check': 'crlfuzz -version',
            'install': 'go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest',
            'required': False,
            'category': 'Vulnerability Scanning'
        },
        'gowitness': {
            'check': 'gowitness -h',
            'install': 'go install -v github.com/sensepost/gowitness@latest',
            'required': False,
            'category': 'Screenshots'
        },
        'ffuf': {
            'check': 'ffuf -V',
            'install': 'go install github.com/ffuf/ffuf@latest',
            'required': False,
            'category': 'Content Discovery'
        },
        'x8': {
            'check': 'x8 --version',
            'install': 'cargo install x8',
            'required': False,
            'category': 'Content Discovery'
        },

        # System tools
        'nmap': {
            'check': 'nmap --version',
            'install': 'sudo apt install nmap -y',
            'required': False,
            'category': 'Port Scanning'
        },
        'masscan': {
            'check': 'masscan --version',
            'install': 'sudo apt install masscan -y',
            'required': False,
            'category': 'Port Scanning'
        },
        'massdns': {
            'check': 'massdns --help',
            'install': 'sudo apt install massdns -y',
            'required': False,
            'category': 'Validation'
        },
        'whatweb': {
            'check': 'whatweb --version',
            'install': 'sudo apt install whatweb -y',
            'required': False,
            'category': 'Fingerprinting'
        },
        'wafw00f': {
            'check': 'wafw00f -h',
            'install': 'pip install wafw00f',
            'required': False,
            'category': 'Fingerprinting'
        },
        'nikto': {
            'check': 'nikto -Version',
            'install': 'sudo apt install nikto -y',
            'required': False,
            'category': 'Vulnerability Scanning'
        },

        # Python tools
        'sqlmap': {
            'check': 'sqlmap --version',
            'install': 'pip install sqlmap',
            'required': False,
            'category': 'Vulnerability Scanning'
        },
        'dirsearch': {
            'check': 'dirsearch -h',
            'install': 'pip install dirsearch',
            'required': False,
            'category': 'Content Discovery'
        },
        'paramspider': {
            'check': 'paramspider -h',
            'install': 'pip install paramspider',
            'required': False,
            'category': 'Content Discovery'
        },
    }

    def __init__(self, logger=None):
        self.logger = logger
        self.available_tools = {}
        self.missing_tools = {}

    def check_tool(self, tool_name):
        """Check if a single tool is available."""
        if tool_name not in self.TOOLS:
            return False

        binary = tool_name
        path = shutil.which(binary)

        if path:
            self.available_tools[tool_name] = path
            return True
        else:
            # Try running the check command
            try:
                result = subprocess.run(
                    self.TOOLS[tool_name]['check'].split(),
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0 or result.stdout or result.stderr:
                    self.available_tools[tool_name] = tool_name
                    return True
            except Exception:
                pass

            self.missing_tools[tool_name] = self.TOOLS[tool_name]
            return False

    def check_all(self):
        """Check all tools and return status report."""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═' * 60}")
        print(f"  🔧 Checking Tool Dependencies")
        print(f"{'═' * 60}{Style.RESET_ALL}\n")

        categories = {}
        for tool_name, tool_info in self.TOOLS.items():
            cat = tool_info['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(tool_name)

        total = len(self.TOOLS)
        available = 0
        missing_required = []

        for category, tools in sorted(categories.items()):
            print(f"  {Fore.YELLOW}{Style.BRIGHT}📂 {category}{Style.RESET_ALL}")

            for tool_name in tools:
                is_available = self.check_tool(tool_name)
                required = self.TOOLS[tool_name]['required']
                req_tag = f"{Fore.RED}[REQUIRED]" if required else f"{Fore.WHITE}[OPTIONAL]"

                if is_available:
                    available += 1
                    status = f"{Fore.GREEN}✅ FOUND"
                    path = self.available_tools.get(tool_name, '')
                    print(f"    {status}  {Fore.WHITE}{tool_name:<20} {req_tag}{Style.RESET_ALL}")
                else:
                    status = f"{Fore.RED}❌ MISSING"
                    print(f"    {status} {Fore.WHITE}{tool_name:<20} {req_tag}{Style.RESET_ALL}")
                    if required:
                        missing_required.append(tool_name)

            print()

        # Summary
        print(f"  {Fore.CYAN}{'─' * 50}")
        print(
            f"  {Fore.WHITE}📊 Summary: "
            f"{Fore.GREEN}{available}{Fore.WHITE}/{total} tools available"
        )

        if missing_required:
            print(
                f"  {Fore.RED}⚠️  Missing REQUIRED tools: "
                f"{', '.join(missing_required)}{Style.RESET_ALL}"
            )

        if self.missing_tools:
            print(f"\n  {Fore.YELLOW}📋 Install missing tools:{Style.RESET_ALL}")
            for tool_name, info in self.missing_tools.items():
                print(f"    {Fore.WHITE}• {tool_name}: {Fore.CYAN}{info['install']}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")

        return {
            'available': self.available_tools,
            'missing': self.missing_tools,
            'missing_required': missing_required,
            'total': total,
            'available_count': available,
            'ready': len(missing_required) == 0
        }

    def is_available(self, tool_name):
        """Quick check if a tool is available."""
        if tool_name in self.available_tools:
            return True
        return self.check_tool(tool_name)

    def get_install_commands(self):
        """Get all install commands for missing tools."""
        commands = []
        for tool_name, info in self.missing_tools.items():
            commands.append({
                'tool': tool_name,
                'command': info['install'],
                'category': info['category']
            })
        return commands

    def auto_install(self, tool_name=None):
        """Attempt to automatically install missing tools."""
        tools_to_install = {}
        if tool_name:
            if tool_name in self.missing_tools:
                tools_to_install[tool_name] = self.missing_tools[tool_name]
        else:
            tools_to_install = self.missing_tools.copy()

        results = {}
        for name, info in tools_to_install.items():
            install_cmd = info['install']
            print(f"  {Fore.YELLOW}Installing {name}...{Style.RESET_ALL}")

            try:
                result = subprocess.run(
                    install_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                if result.returncode == 0:
                    print(f"  {Fore.GREEN}✅ {name} installed successfully{Style.RESET_ALL}")
                    results[name] = True
                else:
                    print(f"  {Fore.RED}❌ {name} installation failed{Style.RESET_ALL}")
                    results[name] = False
            except Exception as e:
                print(f"  {Fore.RED}❌ {name} installation error: {e}{Style.RESET_ALL}")
                results[name] = False

        return results