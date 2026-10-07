"""
BugHuntRecon - Utility Functions
Helper functions used across the framework.
"""

import os
import re
import json
import hashlib
import subprocess
from datetime import datetime
from urllib.parse import urlparse


def create_output_structure(base_dir):
    """Create the organized output directory structure."""
    directories = [
        "subdomains",
        "dns",
        "ports",
        "fingerprinting",
        "content_discovery",
        "content_discovery/urls",
        "content_discovery/params",
        "content_discovery/directories",
        "js_analysis",
        "js_analysis/files",
        "js_analysis/endpoints",
        "js_analysis/secrets",
        "vulnerabilities",
        "vulnerabilities/nuclei",
        "vulnerabilities/xss",
        "vulnerabilities/sqli",
        "vulnerabilities/cors",
        "vulnerabilities/crlf",
        "vulnerabilities/open_redirect",
        "sensitive_info",
        "sensitive_info/s3",
        "sensitive_info/github",
        "sensitive_info/shodan",
        "sensitive_info/google_dorks",
        "screenshots",
        "reports",
        "logs",
    ]

    for dir_name in directories:
        dir_path = os.path.join(base_dir, dir_name)
        os.makedirs(dir_path, exist_ok=True)

    return base_dir


def read_file_lines(filepath):
    """Read file and return non-empty, stripped lines."""
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', errors='ignore') as f:
        return [line.strip() for line in f.readlines() if line.strip()]


def write_file_lines(filepath, lines, deduplicate=True):
    """Write lines to file, optionally deduplicated."""
    if deduplicate:
        lines = list(dict.fromkeys(lines))  # preserve order, remove dupes
    with open(filepath, 'w') as f:
        f.write('\n'.join(lines) + '\n' if lines else '')
    return len(lines)


def append_file_lines(filepath, lines):
    """Append lines to file."""
    with open(filepath, 'a') as f:
        for line in lines:
            f.write(line.strip() + '\n')


def merge_files(file_list, output_file, deduplicate=True):
    """Merge multiple files into one."""
    all_lines = []
    for filepath in file_list:
        all_lines.extend(read_file_lines(filepath))

    count = write_file_lines(output_file, all_lines, deduplicate)
    return count


def is_valid_domain(domain):
    """Validate if string is a valid domain."""
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}$'
    )
    return bool(pattern.match(domain))


def is_valid_url(url):
    """Validate if string is a valid URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def extract_domain(url):
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    except Exception:
        return url


def get_root_domain(domain):
    """Get root domain from subdomain."""
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def is_in_scope(domain, scope_domains):
    """Check if a domain is in scope."""
    if not scope_domains:
        return True
    root = get_root_domain(domain)
    for scope in scope_domains:
        if domain.endswith(scope) or root == get_root_domain(scope):
            return True
    return False


def filter_urls_by_extension(urls, extensions):
    """Filter URLs by file extension."""
    filtered = []
    for url in urls:
        parsed = urlparse(url)
        path = parsed.path.lower()
        for ext in extensions:
            if path.endswith(f'.{ext.lower()}'):
                filtered.append(url)
                break
    return filtered


def extract_js_urls(urls):
    """Extract JavaScript file URLs."""
    return filter_urls_by_extension(urls, ['js', 'mjs', 'jsx'])


def extract_params_from_urls(urls):
    """Extract URLs that contain parameters."""
    return [url for url in urls if '?' in url and '=' in url]


def calculate_file_hash(filepath):
    """Calculate MD5 hash of a file for comparison."""
    if not os.path.exists(filepath):
        return None
    hasher = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def save_json(data, filepath):
    """Save data as JSON file."""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)


def load_json(filepath):
    """Load data from JSON file."""
    if not os.path.exists(filepath):
        return {}
    with open(filepath, 'r') as f:
        return json.load(f)


def get_timestamp():
    """Get current timestamp string."""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def get_file_count(filepath):
    """Get number of non-empty lines in a file."""
    return len(read_file_lines(filepath))


def format_duration(seconds):
    """Format seconds into human-readable duration."""
    hours, remainder = divmod(int(seconds), 3600)
    minutes, secs = divmod(remainder, 60)
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    elif minutes > 0:
        return f"{minutes}m {secs}s"
    else:
        return f"{secs}s"


def sanitize_filename(name):
    """Sanitize a string for use as filename."""
    return re.sub(r'[^\w\-.]', '_', name)


def check_command_exists(command):
    """Check if a command exists in PATH."""
    import shutil
    return shutil.which(command) is not None


def run_command(command, timeout=300, shell=False):
    """Run a shell command and return output."""
    try:
        if isinstance(command, str) and not shell:
            command = command.split()

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell
        )
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'success': result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            'stdout': '',
            'stderr': f'Command timed out after {timeout}s',
            'returncode': -1,
            'success': False
        }
    except Exception as e:
        return {
            'stdout': '',
            'stderr': str(e),
            'returncode': -1,
            'success': False
        }


def count_results(output_dir):
    """Count total results across all output files."""
    total = 0
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            if file.endswith('.txt'):
                total += get_file_count(os.path.join(root, file))
    return total