"""
SyncHunt - Utility Functions
Helper functions used across the framework.
"""

import ipaddress
import json
import os
import re
import shlex
import socket
import hashlib
import subprocess
from datetime import datetime
from urllib.parse import urlparse, urlunparse

# Multi-label public suffixes we handle without a full PSL dependency.
# If `tldextract` is installed it is used instead (much more accurate).
_COMMON_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "net.uk",
    "sch.uk", "nhs.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "gov.in", "ac.in",
    "co.za", "org.za", "net.za", "gov.za", "ac.za",
    "com.mx", "net.mx", "org.mx", "gob.mx",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk",
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw",
    "co.kr", "or.kr", "ne.kr", "go.kr", "re.kr",
    "com.ar", "com.co", "com.pe", "com.ve", "com.ec", "com.uy", "com.py",
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    "com.sa", "com.ae", "com.eg", "com.ng", "com.pk", "com.bd", "com.my",
    "com.ph", "com.vn", "co.th", "co.id", "com.ua", "com.pl", "com.ru",
    "co.at", "or.at", "ac.at", "co.hu", "com.ro", "com.gr", "com.pt",
    "com.es", "com.it", "com.fr", "com.de", "com.nl", "com.be", "com.ch",
    "com.se", "com.no", "com.dk", "com.fi", "com.ie",
}

try:  # pragma: no cover - optional dependency
    import tldextract as _tldextract

    _TLD_EXTRACT = _tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)
except Exception:  # pragma: no cover
    _TLD_EXTRACT = None


# --------------------------------------------------------------------------
# Filesystem helpers
# --------------------------------------------------------------------------

OUTPUT_SUBDIRS = (
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
    "vulnerabilities/nikto",
    "sensitive_info",
    "sensitive_info/s3",
    "sensitive_info/github",
    "sensitive_info/shodan",
    "sensitive_info/google_dorks",
    "intel",
    "api_intelligence",
    "github_recon",
    "cloud_enum",
    "findings_prioritized",
    "screenshots",
    "reports",
    "logs",
)


def create_output_structure(base_dir):
    """Create the organized output directory structure."""
    for dir_name in OUTPUT_SUBDIRS:
        os.makedirs(os.path.join(base_dir, dir_name), exist_ok=True)
    return base_dir


def target_slug(target):
    """Filesystem-safe directory name for a target (matches the output tree)."""
    value = str(target or "").strip()
    value = value.replace("https://", "").replace("http://", "")
    return value.replace("/", "_").replace(":", "_").replace("*", "_")


def ensure_dir(path):
    """os.makedirs with empty-dirname safety; returns the directory."""
    if path:
        os.makedirs(path, exist_ok=True)
    return path


def read_file_lines(filepath):
    """Read file and return non-empty, stripped lines."""
    if not filepath or not os.path.exists(filepath):
        return []
    with open(filepath, "r", errors="ignore", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def write_file_lines(filepath, lines, deduplicate=True):
    """Write lines to file, optionally deduplicated. Returns number written."""
    ensure_dir(os.path.dirname(filepath))
    if deduplicate:
        lines = list(dict.fromkeys(lines))
    with open(filepath, "w", encoding="utf-8") as f:
        if lines:
            f.write("\n".join(lines) + "\n")
    return len(lines)


def append_file_lines(filepath, lines):
    """Append lines to file. Returns number written."""
    ensure_dir(os.path.dirname(filepath))
    count = 0
    with open(filepath, "a", encoding="utf-8") as f:
        for line in lines:
            line = line.strip()
            if line:
                f.write(line + "\n")
                count += 1
    return count


def merge_files(file_list, output_file, deduplicate=True):
    """Merge multiple files into one. Returns the merged line count."""
    seen = set()
    merged = []
    for filepath in file_list:
        for line in read_file_lines(filepath):
            if not line:
                continue
            if deduplicate:
                if line in seen:
                    continue
                seen.add(line)
            merged.append(line)
    return write_file_lines(output_file, merged, deduplicate=False)


def get_file_count(filepath):
    """Count non-empty lines without materialising the whole file."""
    if not filepath or not os.path.exists(filepath):
        return 0
    count = 0
    with open(filepath, "r", errors="ignore", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def read_json_lines(filepath):
    """Read newline-delimited JSON (jsonl) into a list of dicts, skipping junk."""
    records = []
    if not filepath or not os.path.exists(filepath):
        return records
    with open(filepath, "r", errors="ignore", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line[0] not in "{[":
                continue
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                records.append(parsed)
    return records


def save_json(data, filepath):
    """Save data as JSON file."""
    ensure_dir(os.path.dirname(filepath))
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    return filepath


def load_json(filepath, default=None):
    """Load data from JSON file, returning `default` on any failure."""
    if not filepath or not os.path.exists(filepath):
        return {} if default is None else default
    try:
        with open(filepath, "r", errors="ignore", encoding="utf-8") as f:
            return json.load(f)
    except ValueError:
        return {} if default is None else default


def save_csv(rows, filepath, fieldnames=None):
    """Write a list of dicts to CSV. Returns number of rows written."""
    import csv

    rows = list(rows or [])
    ensure_dir(os.path.dirname(filepath))
    if not fieldnames:
        fieldnames = []
        for row in rows:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return len(rows)


# --------------------------------------------------------------------------
# Domain / URL / IP helpers
# --------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def is_valid_domain(domain):
    """Validate if a string looks like a DNS domain name."""
    if not domain or len(domain) > 253:
        return False
    return bool(_DOMAIN_RE.match(domain.strip().rstrip(".")))


def is_ip(value):
    """True when `value` is an IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def is_cidr(value):
    """True when `value` is a valid CIDR network (an address alone is not)."""
    value = str(value).strip()
    if "/" not in value:
        return False
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def split_host_port(value):
    """
    Split 'host:port' while leaving bare IPv6 addresses intact.

    Returns (host, port or None).
    """
    value = strip_scheme(value)
    if value.startswith("["):  # [::1]:8080
        host, _, rest = value.partition("]")
        host = host.lstrip("[")
        rest = rest.lstrip(":")
        return host, int(rest) if rest.isdigit() else None
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        if port.isdigit():
            return host, int(port)
    return value, None


def is_valid_target(value):
    """Targets may be domains, IPs, CIDR ranges or host:port pairs."""
    value = (value or "").strip()
    if is_valid_domain(value) or is_ip(value) or is_cidr(value):
        return True
    host, port = split_host_port(value)
    if port is None or not 0 < port <= 65535:
        return False
    return is_valid_domain(host) or is_ip(host)


def is_valid_url(url):
    """Validate if a string is a valid absolute URL."""
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)
    except (ValueError, AttributeError):
        return False


def strip_scheme(value):
    """
    Remove scheme/path noise from a target-like string.

    CIDR ranges keep their prefix length, and `host:port` keeps its port.
    """
    value = (value or "").strip()
    if "://" in value:
        value = urlparse(value).netloc or value.split("://", 1)[1]
    value = value.split("?", 1)[0].strip()
    if is_cidr(value):
        return value
    return value.split("/", 1)[0].strip().rstrip(".")


def host_from_url(url_or_host):
    """Return just the hostname (no scheme, no port, no path)."""
    value = (url_or_host or "").strip()
    if "://" in value:
        value = urlparse(value).netloc
    else:
        value = value.split("/", 1)[0]
    if value.startswith("["):  # IPv6 literal
        return value.split("]", 1)[0].lstrip("[")
    return value.split(":", 1)[0]


def port_from_url(url_or_host):
    """Return the explicit port from a URL/host string, if any."""
    value = (url_or_host or "").strip()
    netloc = urlparse(value).netloc if "://" in value else value.split("/", 1)[0]
    if netloc.startswith("[") and "]" in netloc:
        rest = netloc.split("]", 1)[1]
        return int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
    if ":" in netloc:
        _, _, port = netloc.rpartition(":")
        if port.isdigit():
            return int(port)
    return None


def normalize_url(target, scheme="https"):
    """Ensure a target string is an absolute URL."""
    target = (target or "").strip()
    if not target:
        return ""
    if "://" not in target:
        target = f"{scheme}://{target}"
    return target


def extract_domain(url):
    """Extract domain from URL."""
    return host_from_url(url) or url


def get_root_domain(domain, include_suffix=False):
    """
    Get the registrable root domain from a (sub)domain.

    'shop.example.co.uk' -> 'example.co.uk'
    'a.b.example.com'    -> 'example.com'
    """
    value = strip_scheme(domain).lower().strip()
    if not value or is_ip(value):
        return value
    if _TLD_EXTRACT is not None:  # pragma: no cover - optional dependency
        extracted = _TLD_EXTRACT(value)
        if extracted.registered_domain:
            return extracted.registered_domain
    parts = value.split(".")
    if len(parts) <= 2:
        return value
    last_two = ".".join(parts[-2:])
    if last_two in _COMMON_MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def host_matches_domain(host, domain):
    """
    Boundary-correct suffix match: 'api.example.com' matches 'example.com',
    'notexample.com' and 'example.com.evil.net' do NOT.
    """
    host = (host or "").lower().strip().rstrip(".")
    domain = (domain or "").lower().strip().rstrip(".")
    if not host or not domain:
        return False
    return host == domain or host.endswith("." + domain)


def is_in_scope(domain, scope_domains):
    """
    Check whether a host belongs to any scope entry.

    Scope entries may be domains, subdomains, wildcards, IPs or CIDRs.
    An empty scope means "everything in scope" (backwards-compatible default).
    """
    if not scope_domains:
        return True
    host = host_from_url(domain)
    if not host:
        return False
    if is_ip(host):
        for rule in scope_domains:
            rule = str(rule).strip()
            try:
                if is_cidr(rule) and ipaddress.ip_address(host) in ipaddress.ip_network(rule, strict=False):
                    return True
            except ValueError:
                continue
            if rule == host:
                return True
        return False
    for rule in scope_domains:
        rule = str(rule).strip().lower().lstrip("*.").rstrip(".")
        if not rule:
            continue
        if host_matches_domain(host, rule):
            return True
    return False


def filter_urls_by_extension(urls, extensions):
    """Filter URLs by file extension."""
    extensions = {e.lower().lstrip(".") for e in extensions}
    filtered = []
    for url in urls:
        path = urlparse(url).path.lower()
        suffix = path.rsplit("/", 1)[-1]
        if "." in suffix and suffix.rsplit(".", 1)[1] in extensions:
            filtered.append(url)
    return filtered


def extract_js_urls(urls):
    """Extract JavaScript file URLs."""
    return filter_urls_by_extension(urls, ["js", "mjs", "jsx"])


def extract_params_from_urls(urls):
    """Extract URLs that contain parameters."""
    return [url for url in urls if "?" in url and "=" in url]


def urls_without_query(urls):
    """Return URLs stripped of their query string (deduplicated)."""
    out = []
    seen = set()
    for url in urls:
        parsed = urlparse(url)
        clean = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        if clean not in seen:
            seen.add(clean)
            out.append(clean)
    return out


# --------------------------------------------------------------------------
# Hashing / misc
# --------------------------------------------------------------------------

def calculate_file_hash(filepath, algorithm="md5"):
    """Calculate a file hash for comparison."""
    if not filepath or not os.path.exists(filepath):
        return None
    hasher = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def short_hash(*parts, length=12):
    """Stable short hash of arbitrary parts (used for finding fingerprints)."""
    joined = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8", "ignore")).hexdigest()[:length]


def fenced_block(text, language=""):
    """Wrap text in a Markdown code fence, neutralising embedded fences."""
    fence = "`" * 3
    body = str(text or "").replace(fence, "` ` `")
    return f"{fence}{language}\n{body}\n{fence}"


def get_timestamp():
    """Get current timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def timestamp_slug():
    """Filesystem-safe timestamp."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def format_duration(seconds):
    """Format seconds into human-readable duration."""
    seconds = int(seconds or 0)
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def sanitize_filename(name, max_length=120):
    """Sanitize a string for use as filename."""
    cleaned = re.sub(r"[^\w\-.]+", "_", str(name or "")).strip("._")
    return cleaned[:max_length] or "unnamed"


def truncate(text, limit=200, suffix="..."):
    """Truncate a string for display/logging."""
    text = "" if text is None else str(text)
    if len(text) <= limit:
        return text
    return text[: max(0, limit - len(suffix))] + suffix


def human_bytes(num):
    """Format a byte count."""
    num = float(num or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}"
        num /= 1024.0
    return f"{num:.1f}PB"


SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
    "unknown": 0,
}


def normalize_severity(value, default="info"):
    """Normalise arbitrary severity strings to one of the canonical levels."""
    if not value:
        return default
    value = str(value).strip().lower()
    aliases = {
        "crit": "critical",
        "severe": "critical",
        "important": "high",
        "moderate": "medium",
        "med": "medium",
        "informational": "info",
        "information": "info",
        "none": "info",
    }
    value = aliases.get(value, value)
    return value if value in SEVERITY_ORDER else default


def severity_rank(value):
    """Numeric rank for a severity string (higher = worse)."""
    return SEVERITY_ORDER.get(normalize_severity(value), 0)


# --------------------------------------------------------------------------
# Process helpers
# --------------------------------------------------------------------------

def check_command_exists(command):
    """Check if a command exists in PATH."""
    import shutil

    return shutil.which(command) is not None


def quote_args(args):
    """
    Quote a list of arguments for safe use in a shell string.

    Used wherever a real shell pipeline is unavoidable; never interpolate
    untrusted data into a shell string without going through this.
    """
    return " ".join(shlex.quote(str(a)) for a in args)


def runner_command(args):
    """
    Ensure a command is a list of arguments (the safe default for subprocess).

    Strings are parsed with shlex so that no shell is involved.
    """
    if isinstance(args, str):
        return shlex.split(args)
    return [str(a) for a in args]


def run_command(args, timeout=300, shell=False):
    """Run a command and capture output (no shell unless explicitly requested)."""
    try:
        command = args if shell else runner_command(args)
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s",
            "returncode": -1,
            "success": False,
        }
    except Exception as exc:
        return {
            "stdout": "",
            "stderr": str(exc),
            "returncode": -1,
            "success": False,
        }


def count_results(output_dir):
    """Count total results across all .txt output files."""
    total = 0
    for root, _dirs, files in os.walk(output_dir):
        for name in files:
            if name.endswith(".txt"):
                total += get_file_count(os.path.join(root, name))
    return total


SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


def normalize_security_headers(headers) -> dict:
    """
    Map security header names to a presence flag.

    `headers` may be a requests CaseInsensitiveDict, a plain dict or a list of
    (key, value) pairs; all are normalised to lowercase keys.
    """
    items = headers.items() if hasattr(headers, "items") else (headers or [])
    lowered = {str(key).lower(): value for key, value in items}
    return {name: name in lowered for name in SECURITY_HEADERS}


def resolve_host(host, timeout=5):
    """Resolve a hostname to a deduplicated list of IP strings (stdlib only)."""
    host = host_from_url(host)
    if not host:
        return []
    if is_ip(host):
        return [host]
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({info[4][0] for info in infos})
    except (socket.gaierror, UnicodeError, OSError):
        return []
    finally:
        socket.setdefaulttimeout(old_timeout)
