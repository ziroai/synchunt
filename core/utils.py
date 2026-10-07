"""
BugHuntRecon - Utility Functions
Helper functions used across the framework.
"""

import json
import os
import re
import subprocess
from datetime import datetime
from urllib.parse import urlparse


def normalize_domain(domain):
    """Normalize a domain string for consistent processing."""
    if not domain:
        return ''
    value = domain.strip().lower().rstrip('/')
    if '://' in value:
        value = urlparse(value).netloc or value
    return value


def normalize_url(url):
    """Normalize a URL, ensuring it has scheme."""
    if not url:
        return ''
    value = url.strip()
    if not value.startswith(('http://', 'https://')):
        value = 'https://' + value
    return value.rstrip('/')


def create_output_structure(base_dir):
    """Create the organized output directory structure."""
    directories = [
        'subdomains',
        'dns',
        'ports',
        'fingerprinting',
        'content_discovery',
        'content_discovery/urls',
        'content_discovery/params',
        'content_discovery/directories',
        'js_analysis',
        'js_analysis/files',
        'js_analysis/endpoints',
        'js_analysis/secrets',
        'vulnerabilities',
        'vulnerabilities/nuclei',
        'vulnerabilities/xss',
        'vulnerabilities/sqli',
        'vulnerabilities/cors',
        'vulnerabilities/crlf',
        'vulnerabilities/open_redirect',
        'sensitive_info',
        'sensitive_info/s3',
        'sensitive_info/github',
        'sensitive_info/shodan',
        'sensitive_info/google_dorks',
        'screenshots',
        'reports',
        'logs',
        'intel',
        'api_intelligence',
        'github_recon',
        'cloud_enum',
        'scope',
        'findings_prioritized',
    ]

    for dir_name in directories:
        os.makedirs(os.path.join(base_dir, dir_name), exist_ok=True)

    return base_dir


def read_file_lines(filepath):
    """Read file and return non-empty stripped lines."""
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
        return [line.strip() for line in f.readlines() if line.strip()]


def write_file_lines(filepath, lines, deduplicate=True):
    """Write lines to a file, optionally deduplicated."""
    if deduplicate:
        lines = list(dict.fromkeys(lines))
    os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + ('\n' if lines else ''))
    return len(lines)


def append_file_lines(filepath, lines):
    """Append lines to file."""
    os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
    with open(filepath, 'a', encoding='utf-8') as f:
        for line in lines:
            f.write(str(line).strip() + '\n')


def merge_files(file_list, output_file, deduplicate=True):
    """Merge multiple text files into a single output."""
    all_lines = []
    for filepath in file_list:
        if os.path.exists(filepath):
            all_lines.extend(read_file_lines(filepath))
    count = write_file_lines(output_file, all_lines, deduplicate=deduplicate)
    return count


def dedupe_list(items):
    """Remove duplicates while preserving order."""
    return list(dict.fromkeys(item for item in items if item))


def is_valid_domain(domain):
    """Validate domain format."""
    domain = normalize_domain(domain)
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,}$'
    )
    return bool(pattern.match(domain))


def is_valid_url(url):
    try:
        result = urlparse(url)
        return bool(result.scheme and result.netloc)
    except Exception:
        return False


def extract_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    except Exception:
        return url


def get_root_domain(domain):
    parts = normalize_domain(domain).split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def is_in_scope(domain, scope_domains):
    if not scope_domains:
        return True
    target = normalize_domain(domain)
    root = get_root_domain(target)
    for scope in scope_domains:
        scope_norm = normalize_domain(scope)
        if target.endswith(scope_norm) or root == get_root_domain(scope_norm):
            return True
    return False


def filter_urls_by_extension(urls, extensions):
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
    return filter_urls_by_extension(urls, ['js', 'mjs', 'jsx'])


def extract_params_from_urls(urls):
    return [url for url in urls if '?' in url and '=' in url]


def calculate_file_hash(filepath):
    if not os.path.exists(filepath):
        return None
    import hashlib
    hasher = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def save_json(data, filepath):
    os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)


def load_json(filepath):
    if not os.path.exists(filepath):
        return {}
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def get_file_count(filepath):
    return len(read_file_lines(filepath))


def format_duration(seconds):
    hours, remainder = divmod(int(seconds), 3600)
    minutes, secs = divmod(remainder, 60)
    if hours > 0:
        return f'{hours}h {minutes}m {secs}s'
    if minutes > 0:
        return f'{minutes}m {secs}s'
    return f'{secs}s'


def sanitize_filename(name):
    return re.sub(r'[^\w\-.]', '_', name)


def check_command_exists(command):
    import shutil
    return shutil.which(command) is not None


def run_command(command, timeout=300, shell=False):
    try:
        if isinstance(command, str) and not shell:
            command = command.split()
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, shell=shell)
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'success': result.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        return {'stdout': '', 'stderr': f'Command timed out after {timeout}s', 'returncode': -1, 'success': False}
    except Exception as exc:
        return {'stdout': '', 'stderr': str(exc), 'returncode': -1, 'success': False}


def count_results(output_dir):
    total = 0
    for root, _, files in os.walk(output_dir):
        for file in files:
            if file.endswith('.txt'):
                total += get_file_count(os.path.join(root, file))
    return total
