"""
SyncHunt - Network Helpers
Shared HTTP session (retries + rate limiting), DNS and TLS helpers.

Everything that talks to a target goes through here so that timeouts,
user-agent, rate limits and error handling stay consistent and testable.
"""

import socket
import ssl
import threading
import time
import json as _json
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter

try:  # urllib3 v2
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
)

DEFAULT_TIMEOUT = 10
MAX_BODY_BYTES = 512 * 1024


class RateLimiter:
    """Thread-safe token-bucket rate limiter shared across worker threads."""

    def __init__(self, rate_per_second: float, burst: Optional[float] = None):
        self.rate = max(0.1, float(rate_per_second or 1))
        self.capacity = float(burst) if burst else max(1.0, self.rate)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> None:
        """Block until `tokens` are available."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                wait = (tokens - self._tokens) / self.rate
            time.sleep(min(max(wait, 0.005), 5.0))


@dataclass
class HttpResult:
    """Normalised result of an HTTP request (never raises on network errors)."""

    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    text: str = ""
    content_length: int = 0
    elapsed: float = 0.0
    final_url: str = ""
    error: Optional[str] = None
    content_type: str = ""

    @property
    def ok(self) -> bool:
        return self.status == 200

    @property
    def reachable(self) -> bool:
        return self.status > 0

    def json(self, default=None):
        try:
            return _json.loads(self.text)
        except Exception:
            return default

    def header(self, name, default=""):
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default


def build_session(
    user_agent: str = DEFAULT_USER_AGENT,
    retries: int = 2,
    backoff: float = 0.4,
    pool_size: int = 32,
) -> requests.Session:
    """Build a requests session with retries and a bounded connection pool."""
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": user_agent or DEFAULT_USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
    )
    retry = Retry(
        total=max(0, int(retries)),
        connect=max(0, int(retries)),
        read=max(0, int(retries)),
        backoff_factor=backoff,
        status_forcelist=(429, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD", "POST", "OPTIONS"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=pool_size, pool_maxsize=pool_size)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def http_request(
    session: requests.Session,
    method: str,
    url: str,
    limiter: Optional[RateLimiter] = None,
    timeout: float = DEFAULT_TIMEOUT,
    allow_redirects: bool = True,
    max_bytes: int = MAX_BODY_BYTES,
    headers: Optional[Dict[str, str]] = None,
    data=None,
    json=None,
    verify: bool = True,
) -> HttpResult:
    """Perform an HTTP request, returning a result object instead of raising."""
    result = HttpResult(url=url, final_url=url)
    if limiter is not None:
        limiter.acquire()
    started = time.time()
    try:
        response = session.request(
            method.upper(),
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            headers=headers,
            data=data,
            json=json,
            verify=verify,
            stream=True,
        )
        result.status = response.status_code
        result.headers = {k: v for k, v in response.headers.items()}
        result.final_url = response.url
        result.content_type = response.headers.get("Content-Type", "")
        chunks = []
        total = 0
        for chunk in response.iter_content(chunk_size=16384, decode_unicode=False):
            if not chunk:
                continue
            total += len(chunk)
            chunks.append(chunk)
            if total >= max_bytes:
                break
        raw = b"".join(chunks)
        result.content_length = total
        encoding = response.encoding or "utf-8"
        result.text = raw.decode(encoding, errors="ignore")
        response.close()
    except requests.exceptions.SSLError as exc:
        result.error = f"TLS error: {exc.__class__.__name__}"
    except requests.exceptions.ConnectTimeout:
        result.error = "connect timeout"
    except requests.exceptions.ReadTimeout:
        result.error = "read timeout"
    except requests.exceptions.TooManyRedirects:
        result.error = "too many redirects"
    except requests.exceptions.RequestException as exc:
        result.error = f"{exc.__class__.__name__}"
    except Exception as exc:  # pragma: no cover - defensive
        result.error = str(exc)
    result.elapsed = time.time() - started
    return result


def probe(
    session: requests.Session,
    url: str,
    limiter: Optional[RateLimiter] = None,
    method: str = "GET",
    timeout: float = DEFAULT_TIMEOUT,
    allow_redirects: bool = False,
    max_bytes: int = 65536,
    verify: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> HttpResult:
    """Convenience wrapper used by the probing modules."""
    return http_request(
        session,
        method,
        url,
        limiter=limiter,
        timeout=timeout,
        allow_redirects=allow_redirects,
        max_bytes=max_bytes,
        verify=verify,
        headers=headers,
    )


def post_json(
    session: requests.Session,
    url: str,
    payload: Dict,
    limiter: Optional[RateLimiter] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = MAX_BODY_BYTES,
    headers: Optional[Dict[str, str]] = None,
) -> HttpResult:
    """POST a JSON body (used for GraphQL probes) and return a normalised result."""
    merged_headers = {"Content-Type": "application/json"}
    if headers:
        merged_headers.update(headers)
    return http_request(
        session,
        "POST",
        url,
        limiter=limiter,
        timeout=timeout,
        allow_redirects=False,
        max_bytes=max_bytes,
        json=payload,
        headers=merged_headers,
    )


def resolve_ips(host: str, timeout: float = 5) -> List[str]:
    """Resolve a hostname to a sorted list of unique IPs (never raises)."""
    from core.utils import host_from_url, is_ip

    host = host_from_url(host)
    if not host:
        return []
    if is_ip(host):
        return [host]
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({info[4][0] for info in infos})
    except (socket.gaierror, UnicodeError, OSError):
        return []
    finally:
        socket.setdefaulttimeout(previous)


def reverse_dns(ip: str, timeout: float = 5) -> Optional[str]:
    """Reverse DNS lookup (PTR), returning None when unavailable."""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError, UnicodeError):
        return None
    finally:
        socket.setdefaulttimeout(previous)


def tls_peer_info(host: str, port: int = 443, timeout: float = 6) -> Dict:
    """
    Fetch the TLS certificate presented by a host.

    Returns a dict with subject/issuer/validity/SANs, or {'error': ...}.
    """
    from core.utils import host_from_url, is_ip
    import datetime as _dt

    host = host_from_url(host)
    info: Dict = {"host": host, "port": port, "error": None}
    if not host:
        info["error"] = "empty host"
        return info
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw_sock = None
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        with context.wrap_socket(raw_sock, server_hostname=None if is_ip(host) else host) as tls:
            cert = tls.getpeercert() or {}
            info["version"] = tls.version()
            info["cipher"] = (tls.cipher() or ("",))[0]
            info["subject"] = _flatten_name(cert.get("subject", ()))
            info["issuer"] = _flatten_name(cert.get("issuer", ()))
            san = cert.get("subjectAltName", ())
            info["san"] = sorted({value for kind, value in san if kind in ("DNS", "IP Address")})
            not_after = cert.get("notAfter")
            if not_after:
                expires = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                info["not_after"] = expires.isoformat()
                info["days_until_expiry"] = (expires - _dt.datetime.utcnow()).days
            info["expired"] = bool(cert) is False
    except ssl.SSLError as exc:
        info["error"] = f"TLS error: {exc}"
    except (socket.timeout, OSError) as exc:
        info["error"] = f"connection error: {exc}"
    except Exception as exc:  # pragma: no cover - defensive
        info["error"] = str(exc)
    return info


def _flatten_name(name) -> str:
    """Flatten an ssl certificate name tuple into a readable string."""
    parts = []
    for rdn in name or ():
        for key, value in rdn:
            if key in ("commonName", "organizationName", "organizationalUnitName"):
                parts.append(f"{key}={value}")
    return ", ".join(parts)


def find_scheme(
    session: requests.Session,
    host: str,
    limiter: Optional[RateLimiter] = None,
    timeout: float = 6,
) -> Optional[str]:
    """
    Determine whether a host speaks HTTPS or HTTP.

    Returns the working base URL ('https://host' or 'http://host') or None.
    """
    base = (host or "").strip().rstrip("/")
    if not base:
        return None
    if "://" in base:
        return base
    for scheme in ("https", "http"):
        result = probe(session, f"{scheme}://{base}", limiter=limiter, timeout=timeout)
        if result.reachable:
            return f"{scheme}://{base}"
    return None
