"""util.py - URL normalization, scope checks, logging, and the scoped HTTP client."""
from __future__ import annotations

import logging
from urllib.parse import urldefrag, urljoin, urlparse, urlunparse

import requests

from rate import RateLimiter

BANNER = "For educational use on authorized local targets only."
ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1"})
ALLOWED_SCHEMES = frozenset({"http", "https"})
USER_AGENT = "reconlite/1.0 (educational; authorized local targets only)"

log = logging.getLogger("reconlite")


class ScopeError(Exception):
    """Raised when a URL falls outside the allowlist."""


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def normalize_url(url: str) -> str:
    """Return a clean absolute URL: scheme added, lowercase host, no fragment,
    no user:password@ part, and '/' for an empty path."""
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    url, _ = urldefrag(url)
    p = urlparse(url)
    host = (p.hostname or "").lower()
    try:
        port = p.port
    except ValueError as exc:
        raise ScopeError(f"invalid port in URL: {url}") from exc
    netloc = host + (f":{port}" if port else "")
    return urlunparse((p.scheme.lower(), netloc, p.path or "/", "", p.query, ""))


def in_scope(url: str) -> bool:
    """True only for http(s) URLs whose host is on the allowlist."""
    try:
        p = urlparse(url)
        return p.scheme.lower() in ALLOWED_SCHEMES and (p.hostname or "").lower() in ALLOWED_HOSTS
    except ValueError:
        return False


def require_in_scope(url: str) -> None:
    if not in_scope(url):
        raise ScopeError(
            f"{url} is out of scope; allowed hosts are: {', '.join(sorted(ALLOWED_HOSTS))}"
        )


def _origin(url: str) -> tuple[str, str, int]:
    p = urlparse(url)
    default_port = 443 if p.scheme == "https" else 80
    return p.scheme, (p.hostname or "").lower(), p.port or default_port


def same_origin(a: str, b: str) -> bool:
    return _origin(a) == _origin(b)


def join_url(base: str, path: str) -> str:
    return normalize_url(urljoin(base, path))


class SafeClient:
    """HTTP client that checks scope and applies the rate limiter on every
    request. Redirects are never followed automatically, so a redirect can't
    pull the tool off the allowlisted host."""

    def __init__(self, limiter: RateLimiter, timeout: float = 5.0):
        self.limiter = limiter
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.session.trust_env = False  # ignore system proxy settings; traffic stays local

    def get(self, url: str) -> requests.Response:
        require_in_scope(url)
        self.limiter.acquire()
        n, cap = self.limiter.count, self.limiter.max_requests
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as exc:
            log.warning("GET %s -> failed: %s (%d/%d)", url, exc.__class__.__name__, n, cap)
            raise
        log.info("GET %s -> %d, %d bytes (%d/%d)", url, resp.status_code, len(resp.content), n, cap)
        return resp
