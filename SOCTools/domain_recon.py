#!/usr/bin/env python3
"""
domain_recon.py — passive OSINT reconnaissance for a single domain.

Aggregates publicly available information about a target domain:

  * WHOIS / RDAP registration records
  * DNS records (A, AAAA, CNAME, MX, NS, SOA, TXT, CAA, SRV, DNSKEY) plus
    SPF / DMARC / DKIM / CAA mail-security analysis
  * Subdomains from certificate transparency logs, passive DNS aggregators
    and web archives
  * Email addresses from registration contacts, the DNS SOA record and the
    target's own published pages

Output is a structured JSON file or a formatted PDF report (or both).
No port scanning, no brute forcing, no zone transfers, no exploitation.

INSTALL
    pip install requests dnspython reportlab
    (reportlab is only needed for PDF output; python-whois is an optional
     fallback for TLDs that do not serve RDAP)

USAGE
    python domain_recon.py example.com                 JSON report
    python domain_recon.py example.com -f pdf          PDF report
    python domain_recon.py example.com -f both -o out/acme
    python domain_recon.py --self-test                 offline check, no network

LEGAL
    Only run this against domains you own or are explicitly authorized to
    assess. You are responsible for complying with the terms of service of
    the third-party data sources this tool queries.
"""

from __future__ import annotations

import argparse
import html
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

__version__ = "1.0.0"

# --------------------------------------------------------------------------
# Required third-party dependencies
# --------------------------------------------------------------------------

_MISSING: list[str] = []
try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:  # pragma: no cover
    _MISSING.append("requests")
try:
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    try:
        from requests.packages.urllib3.util.retry import Retry  # type: ignore
    except Exception:
        Retry = None  # type: ignore
try:
    import dns.exception
    import dns.resolver
    import dns.reversename
except ImportError:  # pragma: no cover
    _MISSING.append("dnspython")

if _MISSING:  # pragma: no cover
    sys.stderr.write(
        "Missing required package(s): {}\n"
        "Install with:  pip install {}\n".format(", ".join(_MISSING), " ".join(_MISSING))
    )
    raise SystemExit(1)

# reportlab is imported lazily: JSON-only runs should not require it.
try:  # pragma: no cover - availability depends on the host
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfgen import canvas as pdfcanvas
    from reportlab.platypus import (
        BaseDocTemplate,
        CondPageBreak,
        Frame,
        PageBreak,
        PageTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    REPORTLAB_AVAILABLE = True
    INK = colors.HexColor("#12253d")
    ACCENT = colors.HexColor("#1f6f8b")
    MUTED = colors.HexColor("#5b6b7d")
    RULE = colors.HexColor("#c9d4de")
    BAND = colors.HexColor("#eef3f7")
except ImportError:  # pragma: no cover
    REPORTLAB_AVAILABLE = False


# ==========================================================================
# SECTION 1 — utilities
# ==========================================================================

LOG = logging.getLogger("domain_recon")

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*\.[a-z]{{2,63}}$", re.IGNORECASE)

# Deliberately conservative: avoids matching things like "2024@2x.png".
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])"
    r"([A-Za-z0-9](?:[A-Za-z0-9._%+\-]{0,62}[A-Za-z0-9])?)"
    r"@"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})"
    r"(?![A-Za-z0-9\-])"
)

MODULES = ("whois", "dns", "subdomains", "emails")


class ReconError(Exception):
    """Raised for unrecoverable input or configuration problems."""


def setup_logging(verbosity: int = 0, quiet: bool = False) -> logging.Logger:
    """Configure the logger. Logs go to stderr so stdout stays clean."""
    level = logging.WARNING
    if quiet:
        level = logging.ERROR
    elif verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    LOG.handlers.clear()
    LOG.addHandler(handler)
    LOG.setLevel(level)
    LOG.propagate = False
    return LOG


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().replace(microsecond=0).isoformat()


def normalize_domain(raw: str) -> str:
    """Turn user input into a bare, lowercase, IDNA-encoded domain name.

    Accepts 'https://Example.COM/path', 'example.com.', 'user@example.com', etc.
    """
    if not raw or not raw.strip():
        raise ReconError("No domain supplied.")

    value = raw.strip()
    if "@" in value and "://" not in value:
        value = value.rsplit("@", 1)[1]
    if "://" in value:
        value = urlsplit(value).netloc or urlsplit(value).path
    value = value.split("/")[0].split("?")[0].split("#")[0]
    if value.startswith("[") and "]" in value:
        raise ReconError("IP addresses are not supported; supply a domain name.")
    if ":" in value:
        value = value.split(":")[0]
    value = value.strip(". \t").lower()

    if not value:
        raise ReconError(f"Could not parse a domain from {raw!r}.")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    if re.fullmatch(r"[\d.]+", value):
        raise ReconError("IP addresses are not supported; supply a domain name.")
    if not HOSTNAME_RE.match(value):
        raise ReconError(f"{value!r} does not look like a valid domain name.")
    if len(value) > 253:
        raise ReconError("Domain name exceeds the maximum length of 253 characters.")
    return value


def clean_hostname(candidate: str) -> Optional[str]:
    """Normalize a hostname harvested from a third-party source, or return None."""
    if not candidate:
        return None
    name = candidate.strip().strip("\"'").lower().rstrip(".")
    name = name.lstrip("*.").lstrip(".")
    if "://" in name:
        name = urlsplit(name).netloc
    name = name.split("/")[0].split(":")[0]
    if not name or "@" in name or " " in name:
        return None
    if not HOSTNAME_RE.match(name):
        return None
    return name


def in_scope(host: str, apex: str) -> bool:
    """True if `host` is the apex domain itself or a subdomain of it."""
    return host == apex or host.endswith("." + apex)


def truncate(text: Any, limit: int = 300) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def human_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m {secs}s"


def parse_iso(value: str) -> Optional[datetime]:
    """Best-effort parse of the date formats RDAP and WHOIS servers emit."""
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d", "%d.%m.%Y"):
        try:
            return datetime.strptime(text[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def days_between(later: Optional[datetime], earlier: Optional[datetime]) -> Optional[int]:
    if not later or not earlier:
        return None
    return (later - earlier).days


# ==========================================================================
# SECTION 2 — HTTP client
# ==========================================================================

DEFAULT_USER_AGENT = "domain-recon/1.0 (passive OSINT collector; contact: set --user-agent)"


class RateLimiter:
    """Enforces a minimum interval between requests to the same host."""

    def __init__(self, min_interval: float = 0.0) -> None:
        self.min_interval = max(0.0, min_interval)
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        if self.min_interval <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                earliest = self._last.get(host, 0.0) + self.min_interval
                if now >= earliest:
                    self._last[host] = now
                    return
                delay = earliest - now
            time.sleep(delay)


class HttpClient:
    """Thread-safe wrapper around requests.Session with retries and throttling."""

    def __init__(
        self,
        timeout: float = 20.0,
        retries: int = 2,
        user_agent: str = DEFAULT_USER_AGENT,
        rate_limit: float = 0.5,
        proxy: Optional[str] = None,
        verify_tls: bool = True,
    ) -> None:
        self.timeout = timeout
        self.limiter = RateLimiter(rate_limit)
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": user_agent, "Accept-Encoding": "gzip, deflate"}
        )
        self.session.verify = verify_tls
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})

        if Retry is not None:
            retry = Retry(
                total=retries,
                connect=retries,
                read=retries,
                status=retries,
                backoff_factor=1.0,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset(["GET", "HEAD"]),
                raise_on_status=False,
                respect_retry_after_header=True,
            )
            adapter = HTTPAdapter(max_retries=retry, pool_connections=32, pool_maxsize=32)
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)

    def get(
        self,
        url: str,
        *,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        timeout: Optional[float] = None,
        allow_redirects: bool = True,
        stream: bool = False,
    ) -> "requests.Response":
        host = urlsplit(url).netloc
        self.limiter.wait(host)
        LOG.debug("GET %s", url)
        return self.session.get(
            url,
            headers=headers,
            params=params,
            timeout=timeout or self.timeout,
            allow_redirects=allow_redirects,
            stream=stream,
        )

    def get_json(self, url: str, **kwargs) -> Any:
        response = self.get(url, **kwargs)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        try:
            return response.json()
        except ValueError as exc:
            raise ValueError(f"invalid JSON from {url}: {exc}") from exc

    def get_text(self, url: str, max_bytes: int = 2_000_000, **kwargs) -> Optional[str]:
        """GET a text body, capped at max_bytes so huge assets are not pulled."""
        response = self.get(url, stream=True, **kwargs)
        if response.status_code == 404:
            return None
        response.raise_for_status()

        content_type = response.headers.get("Content-Type", "")
        if content_type and not any(
            token in content_type.lower()
            for token in ("text/", "json", "xml", "javascript", "html")
        ):
            response.close()
            return None

        chunks, total = [], 0
        for chunk in response.iter_content(chunk_size=16384, decode_unicode=False):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        response.close()
        encoding = response.encoding or response.apparent_encoding or "utf-8"
        return b"".join(chunks).decode(encoding, errors="replace")

    def close(self) -> None:
        self.session.close()


# ==========================================================================
# SECTION 3 — WHOIS / RDAP
# ==========================================================================

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"

EVENT_MAP = {
    "registration": "created",
    "last changed": "updated",
    "last update of rdap database": "rdap_db_updated",
    "expiration": "expires",
    "transfer": "transferred",
    "deletion": "deleted",
}


def _vcard_to_contact(entity: dict) -> dict:
    """Flatten an RDAP entity's jCard into a plain dict."""
    contact: dict[str, Any] = {
        "roles": entity.get("roles") or [],
        "handle": entity.get("handle"),
    }
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list)):
        return contact

    for field in vcard[1]:
        if not isinstance(field, list) or len(field) < 4:
            continue
        name, value = field[0], field[3]
        if isinstance(value, list):
            value = ", ".join(str(part) for part in value if part)
        value = str(value).strip()
        if not value:
            continue
        if name == "fn":
            contact["name"] = value
        elif name == "org":
            contact["organization"] = value
        elif name == "email":
            contact.setdefault("emails", []).append(value)
        elif name == "tel":
            contact.setdefault("phones", []).append(value.replace("tel:", ""))
        elif name == "adr":
            contact["address"] = value.strip(", ")
        elif name in ("country", "region"):
            contact[name] = value
    return contact


def _walk_entities(entities: list, depth: int = 0) -> list[dict]:
    """RDAP nests entities (abuse contact inside registrar, etc). Flatten them."""
    found: list[dict] = []
    if depth > 3 or not isinstance(entities, list):
        return found
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        contact = _vcard_to_contact(entity)
        if any(key in contact for key in ("name", "organization", "emails", "phones")):
            found.append(contact)
        nested = entity.get("entities")
        if nested:
            found.extend(_walk_entities(nested, depth + 1))
    return found


def _parse_rdap(payload: dict) -> dict:
    result: dict[str, Any] = {
        "source": "RDAP",
        "domain": payload.get("ldhName"),
        "unicode_name": payload.get("unicodeName"),
        "handle": payload.get("handle"),
        "status": payload.get("status") or [],
        "dates": {},
        "nameservers": [],
        "contacts": [],
        "registrar": None,
        "registrar_iana_id": None,
        "abuse_email": None,
        "abuse_phone": None,
        "dnssec_signed": None,
        "port43": payload.get("port43"),
    }

    for event in payload.get("events") or []:
        action = str(event.get("eventAction", "")).lower()
        key = EVENT_MAP.get(action, action.replace(" ", "_"))
        if event.get("eventDate"):
            result["dates"][key] = event["eventDate"]

    for nameserver in payload.get("nameservers") or []:
        name = nameserver.get("ldhName") or nameserver.get("unicodeName")
        if name:
            result["nameservers"].append(name.lower().rstrip("."))

    secure_dns = payload.get("secureDNS") or {}
    if isinstance(secure_dns, dict) and "delegationSigned" in secure_dns:
        result["dnssec_signed"] = bool(secure_dns.get("delegationSigned"))

    contacts = _walk_entities(payload.get("entities") or [])
    result["contacts"] = contacts

    for contact in contacts:
        roles = [str(role).lower() for role in contact.get("roles", [])]
        if "registrar" in roles and not result["registrar"]:
            result["registrar"] = contact.get("organization") or contact.get("name")
        if "abuse" in roles:
            emails = contact.get("emails") or []
            phones = contact.get("phones") or []
            result["abuse_email"] = result["abuse_email"] or (emails[0] if emails else None)
            result["abuse_phone"] = result["abuse_phone"] or (phones[0] if phones else None)

    for entity in payload.get("entities") or []:
        if "registrar" in [str(r).lower() for r in entity.get("roles") or []]:
            for identifier in entity.get("publicIds") or []:
                if "IANA" in str(identifier.get("type", "")).upper():
                    result["registrar_iana_id"] = identifier.get("identifier")

    return result


def _rdap_lookup(domain: str, client: HttpClient) -> Optional[dict]:
    url = RDAP_BOOTSTRAP.format(domain=domain)
    try:
        payload = client.get_json(url, headers={"Accept": "application/rdap+json"})
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        LOG.debug("RDAP HTTP %s for %s", status, domain)
        return None
    except (requests.RequestException, ValueError) as exc:
        LOG.debug("RDAP failed for %s: %s", domain, exc)
        return None
    if not isinstance(payload, dict):
        return None
    return _parse_rdap(payload)


def _python_whois_lookup(domain: str) -> Optional[dict]:
    """Optional fallback via the python-whois package, if it is installed."""
    try:
        import whois  # type: ignore
    except ImportError:
        return None
    try:
        record = whois.whois(domain)
    except Exception as exc:  # the library raises a wide variety of errors
        LOG.debug("python-whois failed: %s", exc)
        return None
    if not record or not record.get("domain_name"):
        return None

    def first(value):
        if isinstance(value, (list, tuple)):
            return value[0] if value else None
        return value

    def as_iso(value):
        value = first(value)
        if value is None:
            return None
        return value.isoformat() if hasattr(value, "isoformat") else str(value)

    emails = record.get("emails") or []
    if isinstance(emails, str):
        emails = [emails]
    status = record.get("status") or []
    if isinstance(status, str):
        status = [status]

    return {
        "source": "WHOIS (python-whois)",
        "domain": str(first(record.get("domain_name")) or domain).lower(),
        "status": list(status),
        "dates": {
            "created": as_iso(record.get("creation_date")),
            "updated": as_iso(record.get("updated_date")),
            "expires": as_iso(record.get("expiration_date")),
        },
        "nameservers": sorted(
            {str(ns).lower().rstrip(".") for ns in (record.get("name_servers") or [])}
        ),
        "registrar": first(record.get("registrar")),
        "abuse_email": None,
        "contacts": [
            {
                "roles": ["registrant"],
                "name": first(record.get("name")),
                "organization": first(record.get("org")),
                "emails": list(emails),
                "country": first(record.get("country")),
                "address": first(record.get("address")),
            }
        ],
        "dnssec_signed": None,
    }


def _cli_whois_lookup(domain: str, timeout: float = 20.0) -> Optional[dict]:
    """Last resort: shell out to the system whois client and keep the raw text."""
    binary = shutil.which("whois")
    if not binary:
        return None
    try:
        proc = subprocess.run(
            [binary, domain], capture_output=True, text=True, timeout=timeout, check=False
        )
    except (subprocess.SubprocessError, OSError) as exc:
        LOG.debug("whois binary failed: %s", exc)
        return None
    output = (proc.stdout or "").strip()
    if not output:
        return None
    return {
        "source": "WHOIS (system client)",
        "domain": domain,
        "status": [],
        "dates": {},
        "nameservers": [],
        "registrar": None,
        "contacts": [],
        "raw_text": output[:20000],
        "dnssec_signed": None,
    }


def _looks_redacted(record: dict) -> bool:
    """Heuristic: are registrant identity fields privacy-masked?"""
    registrant = [
        contact
        for contact in record.get("contacts", [])
        if "registrant" in [str(role).lower() for role in contact.get("roles", [])]
    ]
    if not registrant:
        return True
    blob = " ".join(str(value) for contact in registrant for value in contact.values()).lower()
    markers = ("redacted", "privacy", "not disclosed", "data protected", "whoisguard", "withheld")
    return any(marker in blob for marker in markers)


def collect_whois(domain: str, client: HttpClient) -> dict:
    """Return registration data plus derived age/expiry figures."""
    started = time.monotonic()
    errors: list[str] = []
    record: Optional[dict] = None

    for name, fetch in (
        ("rdap", lambda: _rdap_lookup(domain, client)),
        ("python-whois", lambda: _python_whois_lookup(domain)),
        ("whois-cli", lambda: _cli_whois_lookup(domain, client.timeout)),
    ):
        try:
            record = fetch()
        except Exception as exc:  # never let one backend kill the run
            errors.append(f"{name}: {exc}")
            record = None
        if record:
            LOG.info("registration data retrieved via %s", name)
            break
        errors.append(f"{name}: no data returned")

    if not record:
        return {
            "available": False,
            "errors": errors,
            "elapsed_seconds": round(time.monotonic() - started, 2),
        }

    created = parse_iso(record.get("dates", {}).get("created", "") or "")
    expires = parse_iso(record.get("dates", {}).get("expires", "") or "")
    now = utc_now()
    record["derived"] = {
        "age_days": days_between(now, created),
        "days_until_expiry": days_between(expires, now),
        "expired": (expires < now) if expires else None,
        "registrant_redacted": _looks_redacted(record),
    }
    record["available"] = True
    record["errors"] = [e for e in errors if not e.endswith("no data returned")]
    record["elapsed_seconds"] = round(time.monotonic() - started, 2)
    return record


def registration_emails(record: dict) -> list[dict]:
    """Extract contact emails from a registration record for the email module."""
    out: list[dict] = []
    for contact in record.get("contacts", []) or []:
        roles = ", ".join(str(role) for role in contact.get("roles", [])) or "contact"
        for email in contact.get("emails", []) or []:
            out.append({"email": email.strip().lower(), "context": f"WHOIS/RDAP {roles}"})
    if record.get("abuse_email"):
        out.append(
            {
                "email": str(record["abuse_email"]).strip().lower(),
                "context": "WHOIS/RDAP abuse contact",
            }
        )
    return out


# ==========================================================================
# SECTION 4 — DNS
# ==========================================================================

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA", "SRV", "DNSKEY"]

# Selectors used by the major mail platforms; a hit shows who signs the mail.
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "s1", "s2", "k1", "k2",
    "mail", "dkim", "smtp", "mandrill", "zoho", "mailjet", "sendgrid",
    "protonmail", "protonmail2", "fm1", "fm2", "everlytickey1", "pm-bounces",
    "sig1", "ctct1", "hs1", "hs2", "mimecast20200101",
]

MX_PROVIDERS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "messagelabs.com": "Broadcom/Symantec",
    "zoho.com": "Zoho Mail",
    "yandex.net": "Yandex",
    "qq.com": "Tencent Exmail",
    "secureserver.net": "GoDaddy",
    "improvmx.com": "ImprovMX",
    "protonmail.ch": "Proton Mail",
    "fastmail.com": "Fastmail",
    "cloudflare.net": "Cloudflare Email Routing",
}


PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def build_resolver(
    nameservers: Optional[list[str]] = None, timeout: float = 5.0
) -> "dns.resolver.Resolver":
    """Build a resolver, falling back to public servers if the OS config is unreadable.

    dnspython reads nameservers from the registry on Windows and from
    /etc/resolv.conf elsewhere; both can come back empty or raise, in which case
    the run would otherwise fail with no usable resolver.
    """
    try:
        resolver = dns.resolver.Resolver()
    except Exception as exc:  # dns.resolver.NoResolverConfiguration and friends
        LOG.warning(
            "could not read the system DNS configuration (%s); using public resolvers %s. "
            "Pass --resolvers to choose your own.",
            exc, ", ".join(PUBLIC_RESOLVERS),
        )
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(PUBLIC_RESOLVERS)

    if nameservers:
        resolver.nameservers = list(nameservers)
    elif not getattr(resolver, "nameservers", None):
        LOG.warning(
            "no system DNS servers found; using public resolvers %s. "
            "Pass --resolvers to choose your own.",
            ", ".join(PUBLIC_RESOLVERS),
        )
        resolver.nameservers = list(PUBLIC_RESOLVERS)

    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


def dns_query(
    resolver: "dns.resolver.Resolver", name: str, rdtype: str, retry_tcp: bool = True
) -> tuple[list[str], Optional[str]]:
    """Return (values, error). An empty answer is not an error.

    Large responses (long TXT sets in particular) can be truncated or dropped
    over UDP, so a timeout is retried once over TCP before being reported.
    """
    try:
        answer = resolver.resolve(name, rdtype, raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoNameservers:
        return [], "no nameservers could answer"
    except dns.exception.Timeout:
        if not retry_tcp:
            return [], "timeout"
        try:
            answer = resolver.resolve(
                name, rdtype, raise_on_no_answer=False, tcp=True,
                lifetime=max(2.0, resolver.timeout),
            )
        except dns.resolver.NXDOMAIN:
            return [], "NXDOMAIN"
        except dns.exception.DNSException:
            return [], "timeout"
    except dns.exception.DNSException as exc:
        return [], f"{type(exc).__name__}: {exc}"

    if answer.rrset is None:
        return [], None

    values: list[str] = []
    for record in answer:
        text = record.to_text()
        if rdtype == "TXT":
            # dnspython chunks long TXT strings; rejoin and unquote.
            text = "".join(part.decode("utf-8", "replace") for part in record.strings)
        values.append(text.strip('"').strip())
    return sorted(set(values)), None


def _mail_provider(mx_records: Iterable[str]) -> Optional[str]:
    for record in mx_records:
        host = record.split()[-1].rstrip(".").lower()
        for suffix, provider in MX_PROVIDERS.items():
            if host.endswith(suffix):
                return provider
    return None


def _analyze_spf(txt_records: list[str], lookup_failed: bool = False) -> dict:
    spf = next((r for r in txt_records if r.lower().startswith("v=spf1")), None)
    result: dict[str, Any] = {
        "present": bool(spf), "record": spf, "policy": None,
        "includes": [], "issues": [], "lookup_failed": lookup_failed,
    }
    if not spf:
        if lookup_failed:
            result["present"] = None
            result["issues"].append("TXT lookup failed; SPF state could not be determined.")
        else:
            result["issues"].append(
                "No SPF record \u2014 the domain does not publish authorized senders."
            )
        return result

    tokens = spf.split()
    for token in tokens:
        lowered = token.lower()
        if lowered.startswith("include:"):
            result["includes"].append(token.split(":", 1)[1])
        elif lowered in ("-all", "~all", "?all", "+all"):
            result["policy"] = {
                "-all": "fail (strict)",
                "~all": "softfail",
                "?all": "neutral",
                "+all": "pass-all (permits any sender)",
            }[lowered]

    if result["policy"] is None:
        result["issues"].append("SPF has no 'all' mechanism; enforcement is undefined.")
    if result["policy"] == "pass-all (permits any sender)":
        result["issues"].append("SPF ends in '+all', which authorizes every sender.")
    if result["policy"] == "neutral":
        result["issues"].append("SPF policy is neutral and provides no enforcement.")
    lookups = [
        t for t in tokens
        if t.lower().startswith(("include:", "a:", "mx:", "ptr", "exists:", "redirect="))
    ]
    if len(lookups) > 10:
        result["issues"].append(
            "More than 10 DNS-querying mechanisms; SPF may exceed the lookup limit."
        )
    if len([r for r in txt_records if r.lower().startswith("v=spf1")]) > 1:
        result["issues"].append("Multiple SPF records published; RFC 7208 permits only one.")
    return result


def _analyze_dmarc(records: list[str], lookup_failed: bool = False) -> dict:
    dmarc = next((r for r in records if r.lower().startswith("v=dmarc1")), None)
    result: dict[str, Any] = {
        "present": bool(dmarc), "record": dmarc, "policy": None, "pct": None,
        "rua": [], "issues": [], "lookup_failed": lookup_failed,
    }
    if not dmarc:
        if lookup_failed:
            result["present"] = None
            result["issues"].append("_dmarc lookup failed; DMARC state could not be determined.")
        else:
            result["issues"].append(
                "No DMARC record \u2014 spoofed mail is not reported or rejected."
            )
        return result

    for token in [t.strip() for t in dmarc.split(";") if t.strip()]:
        if "=" not in token:
            continue
        key, value = (part.strip() for part in token.split("=", 1))
        key = key.lower()
        if key == "p":
            result["policy"] = value.lower()
        elif key == "sp":
            result["subdomain_policy"] = value.lower()
        elif key == "pct":
            result["pct"] = value
        elif key in ("rua", "ruf"):
            result[key] = [addr.strip() for addr in value.split(",")]

    if result["policy"] == "none":
        result["issues"].append(
            "DMARC policy is p=none \u2014 monitoring only, nothing is blocked."
        )
    if not result.get("rua"):
        result["issues"].append("No DMARC aggregate report address (rua) configured.")
    return result


def _analyze_dkim(
    resolver: "dns.resolver.Resolver", domain: str, selectors: list[str], workers: int
) -> dict:
    found: list[dict] = []

    def probe(selector: str):
        values, _err = dns_query(resolver, f"{selector}._domainkey.{domain}", "TXT")
        record = next((v for v in values if "p=" in v.lower() or "v=dkim1" in v.lower()), None)
        return selector, record

    with ThreadPoolExecutor(max_workers=max(2, min(workers, 16))) as pool:
        for selector, record in pool.map(probe, selectors):
            if record:
                found.append({"selector": selector, "record": record[:400]})

    return {
        "selectors_tested": len(selectors),
        "selectors_found": [item["selector"] for item in found],
        "records": found,
    }


def _reverse_lookup(resolver: "dns.resolver.Resolver", ip: str) -> Optional[str]:
    try:
        rev = dns.reversename.from_address(ip)
        answer = resolver.resolve(rev, "PTR", raise_on_no_answer=False)
        if answer.rrset:
            return str(answer[0]).rstrip(".")
    except (dns.exception.DNSException, ValueError):
        return None
    return None


def collect_dns(
    domain: str,
    nameservers: Optional[list[str]] = None,
    timeout: float = 5.0,
    workers: int = 10,
    dkim_selectors: Optional[list[str]] = None,
    reverse: bool = True,
) -> dict:
    """Collect DNS records for the apex domain plus derived mail-security state."""
    started = time.monotonic()
    resolver = build_resolver(nameservers, timeout)
    records: dict[str, list[str]] = {}
    errors: dict[str, str] = {}

    def fetch(rdtype: str):
        values, error = dns_query(resolver, domain, rdtype)
        return rdtype, values, error

    with ThreadPoolExecutor(max_workers=max(2, min(workers, len(RECORD_TYPES)))) as pool:
        for rdtype, values, error in pool.map(fetch, RECORD_TYPES):
            if values:
                records[rdtype] = values
            if error:
                errors[rdtype] = error

    txt_records = records.get("TXT", [])
    txt_failed = bool(errors.get("TXT")) and not txt_records
    dmarc_values, dmarc_error = dns_query(resolver, f"_dmarc.{domain}", "TXT")
    dmarc_failed = bool(dmarc_error) and dmarc_error != "NXDOMAIN" and not dmarc_values
    if dmarc_error and dmarc_error != "NXDOMAIN":
        errors["_dmarc TXT"] = dmarc_error

    ips = list(records.get("A", [])) + list(records.get("AAAA", []))
    ptr: dict[str, str] = {}
    if reverse and ips:
        with ThreadPoolExecutor(max_workers=max(2, min(workers, len(ips)))) as pool:
            for ip, name in zip(ips, pool.map(lambda i: _reverse_lookup(resolver, i), ips)):
                if name:
                    ptr[ip] = name

    result = {
        "records": records,
        "record_counts": {rtype: len(values) for rtype, values in records.items()},
        "reverse_dns": ptr,
        "errors": errors,
        "mail": {
            "mx": records.get("MX", []),
            "provider": _mail_provider(records.get("MX", [])),
            "spf": _analyze_spf(txt_records, lookup_failed=txt_failed),
            "dmarc": _analyze_dmarc(dmarc_values, lookup_failed=dmarc_failed),
            "dkim": _analyze_dkim(resolver, domain, dkim_selectors or DKIM_SELECTORS, workers),
        },
        "caa": records.get("CAA", []),
        "failed_lookups": sorted(
            rtype for rtype, error in errors.items() if error and error != "NXDOMAIN"
        ),
        "dnssec_dnskey_present": bool(records.get("DNSKEY")),
        "verification_txt": [
            record
            for record in txt_records
            if any(
                marker in record.lower()
                for marker in (
                    "-site-verification", "-domain-verification", "verify", "_verification",
                    "ms=", "docusign", "atlassian", "adobe-idp", "stripe-verification",
                )
            )
        ],
        "resolvers_used": list(resolver.nameservers),
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }

    LOG.info("DNS: %d record types populated", len(records))
    return result


def resolve_hosts(
    hosts: list[str],
    nameservers: Optional[list[str]] = None,
    timeout: float = 5.0,
    workers: int = 20,
) -> dict[str, dict]:
    """Resolve a batch of hostnames to A/AAAA/CNAME, for subdomain validation."""
    resolver = build_resolver(nameservers, timeout)

    def one(host: str) -> tuple[str, dict]:
        a_records, _ = dns_query(resolver, host, "A")
        aaaa_records, _ = dns_query(resolver, host, "AAAA")
        cname, _ = dns_query(resolver, host, "CNAME")
        return host, {
            "a": a_records,
            "aaaa": aaaa_records,
            "cname": cname[0].rstrip(".") if cname else None,
            "resolves": bool(a_records or aaaa_records or cname),
        }

    out: dict[str, dict] = {}
    if not hosts:
        return out
    with ThreadPoolExecutor(max_workers=max(2, min(workers, 64))) as pool:
        for host, data in pool.map(one, hosts):
            out[host] = data
    return out


# ==========================================================================
# SECTION 5 — passive subdomain discovery
# ==========================================================================


class SkipSource(Exception):
    """Raised by a source that is unavailable by configuration, not by failure."""


def source_crtsh(domain: str, client: HttpClient) -> set:
    """crt.sh certificate transparency search."""
    found: set[str] = set()
    payload = client.get_json(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        timeout=max(client.timeout, 45),
    )
    for entry in payload or []:
        for field in ("name_value", "common_name"):
            for line in str(entry.get(field, "")).splitlines():
                host = clean_hostname(line)
                if host:
                    found.add(host)
    return found


def source_certspotter(domain: str, client: HttpClient) -> set:
    """SSLMate Cert Spotter issuance API (free tier, no key for light use)."""
    found: set[str] = set()
    payload = client.get_json(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
    )
    for entry in payload or []:
        for name in entry.get("dns_names", []):
            host = clean_hostname(name)
            if host:
                found.add(host)
    return found


def source_anubis(domain: str, client: HttpClient) -> set:
    """JonLuca's Anubis subdomain database."""
    payload = client.get_json(f"https://jldc.me/anubis/subdomains/{domain}")
    return {h for h in (clean_hostname(n) for n in (payload or [])) if h}


def source_hackertarget(domain: str, client: HttpClient) -> set:
    """HackerTarget hostsearch (plain text, rate limited to a few queries a day)."""
    text = client.get_text("https://api.hackertarget.com/hostsearch/", params={"q": domain})
    found: set[str] = set()
    if not text or "error" in text.lower() or "API count exceeded" in text:
        return found
    for line in text.splitlines():
        host = clean_hostname(line.split(",")[0])
        if host:
            found.add(host)
    return found


def source_alienvault(domain: str, client: HttpClient) -> set:
    """AlienVault OTX passive DNS."""
    payload = client.get_json(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    )
    found: set[str] = set()
    for entry in (payload or {}).get("passive_dns", []):
        host = clean_hostname(entry.get("hostname", ""))
        if host:
            found.add(host)
    return found


def source_rapiddns(domain: str, client: HttpClient) -> set:
    """RapidDNS subdomain view (HTML table)."""
    html_text = client.get_text(f"https://rapiddns.io/subdomain/{domain}?full=1")
    found: set[str] = set()
    if not html_text:
        return found
    for match in re.findall(r"<td>([^<]+)</td>", html_text):
        host = clean_hostname(match)
        if host:
            found.add(host)
    return found


def source_wayback(domain: str, client: HttpClient) -> set:
    """Internet Archive CDX index — hostnames seen in archived URLs."""
    text = client.get_text(
        "https://web.archive.org/cdx/search/cdx",
        params={
            "url": f"*.{domain}/*",
            "output": "text",
            "fl": "original",
            "collapse": "urlkey",
            "limit": "20000",
        },
        timeout=max(client.timeout, 45),
    )
    found: set[str] = set()
    for line in (text or "").splitlines():
        host = clean_hostname(line)
        if host:
            found.add(host)
    return found


def source_urlscan(domain: str, client: HttpClient) -> set:
    """urlscan.io public scan results."""
    payload = client.get_json(
        "https://urlscan.io/api/v1/search/",
        params={"q": f"page.domain:{domain}", "size": "1000"},
    )
    found: set[str] = set()
    for entry in (payload or {}).get("results", []):
        page = entry.get("page", {}) or {}
        for key in ("domain", "apexDomain"):
            host = clean_hostname(str(page.get(key, "")))
            if host:
                found.add(host)
        task_domain = (entry.get("task", {}) or {}).get("domain")
        host = clean_hostname(str(task_domain or ""))
        if host:
            found.add(host)
    return found


def source_securitytrails(domain: str, client: HttpClient) -> set:
    key = os.getenv("SECURITYTRAILS_API_KEY")
    if not key:
        raise SkipSource("SECURITYTRAILS_API_KEY not set")
    payload = client.get_json(
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        params={"children_only": "false"},
        headers={"APIKEY": key},
    )
    found: set[str] = set()
    for prefix in (payload or {}).get("subdomains", []):
        host = clean_hostname(f"{prefix}.{domain}")
        if host:
            found.add(host)
    return found


def source_virustotal(domain: str, client: HttpClient) -> set:
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        raise SkipSource("VIRUSTOTAL_API_KEY not set")
    found: set[str] = set()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    for _ in range(5):  # follow up to 5 pages
        payload = client.get_json(url, headers={"x-apikey": key})
        if not payload:
            break
        for entry in payload.get("data", []):
            host = clean_hostname(entry.get("id", ""))
            if host:
                found.add(host)
        url = (payload.get("links") or {}).get("next")
        if not url:
            break
    return found


SUBDOMAIN_SOURCES: dict[str, Callable[[str, HttpClient], set]] = {
    "crt.sh": source_crtsh,
    "certspotter": source_certspotter,
    "anubis": source_anubis,
    "hackertarget": source_hackertarget,
    "alienvault-otx": source_alienvault,
    "rapiddns": source_rapiddns,
    "wayback": source_wayback,
    "urlscan": source_urlscan,
    "securitytrails": source_securitytrails,
    "virustotal": source_virustotal,
}

KEYED_SOURCES = ("securitytrails", "virustotal")


def collect_subdomains(
    domain: str,
    client: HttpClient,
    enabled: Optional[list[str]] = None,
    workers: int = 8,
) -> dict:
    """Query every enabled source in parallel and merge the results."""
    started = time.monotonic()
    names = enabled or list(SUBDOMAIN_SOURCES)
    for name in [n for n in names if n not in SUBDOMAIN_SOURCES]:
        LOG.warning("unknown subdomain source ignored: %s", name)
    names = [n for n in names if n in SUBDOMAIN_SOURCES]

    hosts: dict[str, set[str]] = {}
    stats: dict[str, dict] = {}
    errors: dict[str, str] = {}

    def run(name: str) -> tuple[str, set, Optional[str], float]:
        begin = time.monotonic()
        try:
            result = SUBDOMAIN_SOURCES[name](domain, client)
        except SkipSource as exc:
            return name, set(), f"skipped ({exc})", time.monotonic() - begin
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "?"
            return name, set(), f"HTTP {status}", time.monotonic() - begin
        except (requests.RequestException, ValueError) as exc:
            return name, set(), str(exc)[:200], time.monotonic() - begin
        except Exception as exc:  # a bad source must not abort the scan
            return name, set(), f"{type(exc).__name__}: {exc}"[:200], time.monotonic() - begin
        return name, result, None, time.monotonic() - begin

    with ThreadPoolExecutor(max_workers=max(2, min(workers, len(names) or 2))) as pool:
        futures = [pool.submit(run, name) for name in names]
        for future in as_completed(futures):
            name, result, error, elapsed = future.result()
            scoped = {h for h in result if in_scope(h, domain)}
            for host in scoped:
                hosts.setdefault(host, set()).add(name)
            stats[name] = {
                "returned": len(result),
                "in_scope": len(scoped),
                "seconds": round(elapsed, 2),
                "status": (
                    "skipped" if error and error.startswith("skipped")
                    else ("error" if error else "ok")
                ),
            }
            if error:
                errors[name] = error
                LOG.info("subdomain source %s: %s", name, error)
            else:
                LOG.info("subdomain source %s: %d in scope", name, len(scoped))

    subdomains = [
        {"host": host, "sources": sorted(sources)} for host, sources in sorted(hosts.items())
    ]

    return {
        "count": len(subdomains),
        "subdomains": subdomains,
        "source_stats": stats,
        "errors": errors,
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }


def attach_resolution(result: dict, resolutions: dict[str, dict]) -> dict:
    """Merge DNS resolution data into the subdomain list and add a summary."""
    live = 0
    for entry in result["subdomains"]:
        data = resolutions.get(entry["host"])
        if not data:
            continue
        entry["a"] = data.get("a", [])
        entry["aaaa"] = data.get("aaaa", [])
        entry["cname"] = data.get("cname")
        entry["resolves"] = data.get("resolves", False)
        if entry["resolves"]:
            live += 1
    if resolutions:
        result["resolved_count"] = live
        result["unresolved_count"] = len(resolutions) - live
        result["unique_ips"] = sorted(
            {
                ip
                for entry in result["subdomains"]
                for ip in (entry.get("a", []) + entry.get("aaaa", []))
            }
        )
    return result


# ==========================================================================
# SECTION 6 — email harvesting
# ==========================================================================

# Paths worth trying directly — contact details cluster here.
SEED_PATHS = [
    "/", "/contact", "/contact-us", "/contactus", "/about", "/about-us",
    "/team", "/our-team", "/people", "/staff", "/support", "/help",
    "/imprint", "/impressum", "/legal", "/privacy", "/privacy-policy",
    "/terms", "/security", "/security.txt", "/.well-known/security.txt",
    "/press", "/media", "/careers", "/jobs", "/investors",
]

# Local parts and domains that are almost always noise from bundled assets.
NOISE_LOCAL = {
    "example", "user", "username", "youremail", "your-email", "yourname",
    "name", "email", "test", "foo", "bar", "someone", "firstname", "lastname",
    "domain", "yourdomain", "no-reply-example", "john.doe", "jane.doe",
}
NOISE_DOMAINS = {
    "example.com", "example.org", "example.net", "domain.com", "email.com",
    "yourdomain.com", "sentry.io", "wixpress.com", "schema.org", "w3.org",
    "sentry.wixpress.com", "godaddy.com", "squarespace.com",
}
NOISE_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js", ".ico",
    ".woff", ".woff2", ".ttf", ".mp4", ".pdf",
)
SKIP_EXTENSIONS = (
    ".pdf", ".zip", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".css", ".js", ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".eot", ".rss",
    ".xml", ".dmg", ".exe", ".tar", ".gz",
)

LINK_RE = re.compile(r"""href\s*=\s*["']([^"'#>]+)["']""", re.IGNORECASE)
MAILTO_RE = re.compile(r"""mailto:([^"'?>\s]+)""", re.IGNORECASE)
SCRIPT_RE = re.compile(r"<(script|style|noscript)\b.*?</\1>", re.IGNORECASE | re.DOTALL)
COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

# Human-obfuscated addresses: "name (at) domain (dot) com", "name at domain dot com".
# The separators must be bracketed or whitespace-delimited — without that requirement
# the pattern matches inside ordinary words ("authentication.click" -> "authentic@ion.click").
OBFUSCATED_RE = re.compile(
    r"([A-Za-z0-9._%+\-]{1,64})"
    r"(?:\s*[\(\[\{<]\s*(?:at|@)\s*[\)\]\}>]\s*|\s+(?:at|@)\s+)"
    r"([A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*)"
    r"(?:\s*[\(\[\{<]\s*(?:dot|\.)\s*[\)\]\}>]\s*|\s+(?:dot|\.)\s+|\.)"
    r"([A-Za-z]{2,12})\b",
    re.IGNORECASE,
)


def _is_plausible(email: str) -> bool:
    if email.count("@") != 1:
        return False
    local, _, domain = email.partition("@")
    if not local or not domain or ".." in email:
        return False
    if len(email) > 254 or len(local) > 64:
        return False
    if local.lower() in NOISE_LOCAL or domain.lower() in NOISE_DOMAINS:
        return False
    if domain.lower().endswith(NOISE_SUFFIXES):
        return False
    if re.fullmatch(r"[0-9a-f]{16,}", local.lower()):  # hashes in asset URLs
        return False
    if domain.count(".") > 5:
        return False
    return True


def extract_emails(text: str) -> set[str]:
    """Pull addresses out of a blob of HTML or text, including light obfuscation.

    Entity-encoded addresses (&#64;) are decoded first; script, style and comment
    blocks are dropped because minified bundles are a rich source of false positives.
    """
    text = html.unescape(text)
    text = COMMENT_RE.sub(" ", SCRIPT_RE.sub(" ", text))

    found: set[str] = set()
    for match in MAILTO_RE.finditer(text):
        candidate = requests.utils.unquote(match.group(1)).strip().lower()
        if _is_plausible(candidate):
            found.add(candidate)
    for match in EMAIL_RE.finditer(text):
        candidate = f"{match.group(1)}@{match.group(2)}".lower()
        if _is_plausible(candidate):
            found.add(candidate)
    for match in OBFUSCATED_RE.finditer(text):
        candidate = f"{match.group(1)}@{match.group(2)}.{match.group(3)}".lower()
        if _is_plausible(candidate):
            found.add(candidate)
    return found


class Crawler:
    """Depth-limited, same-site crawler that obeys robots.txt."""

    def __init__(
        self,
        domain: str,
        client: HttpClient,
        max_pages: int = 25,
        max_depth: int = 2,
        respect_robots: bool = True,
    ) -> None:
        self.domain = domain
        self.client = client
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.robots: dict[str, Optional[RobotFileParser]] = {}
        self.visited: set[str] = set()
        self.pages_fetched = 0
        self.errors: list[str] = []

    def _robot_for(self, base: str) -> Optional[RobotFileParser]:
        if base in self.robots:
            return self.robots[base]
        parser: Optional[RobotFileParser] = None
        try:
            text = self.client.get_text(urljoin(base, "/robots.txt"), max_bytes=200_000)
            if text:
                parser = RobotFileParser()
                parser.parse(text.splitlines())
        except requests.RequestException as exc:
            LOG.debug("robots.txt unavailable for %s: %s", base, exc)
        self.robots[base] = parser
        return parser

    def _allowed(self, url: str) -> bool:
        if not self.respect_robots:
            return True
        parts = urlsplit(url)
        parser = self._robot_for(f"{parts.scheme}://{parts.netloc}")
        if parser is None:
            return True  # no robots.txt published => no restriction
        agent = self.client.session.headers.get("User-Agent", "*")
        try:
            return parser.can_fetch(agent, url)
        except Exception:
            return True

    def _normalize(self, url: str) -> Optional[str]:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return None
        host = parts.netloc.split(":")[0].lower()
        if not in_scope(host, self.domain):
            return None
        path = parts.path or "/"
        if path.lower().endswith(SKIP_EXTENSIONS):
            return None
        return f"{parts.scheme}://{parts.netloc}{path}"

    def _reachable_base(self) -> Optional[str]:
        for candidate in (
            f"https://{self.domain}",
            f"https://www.{self.domain}",
            f"http://{self.domain}",
        ):
            try:
                response = self.client.get(candidate, timeout=min(self.client.timeout, 15))
                if response.status_code < 500:
                    parts = urlsplit(response.url)
                    return f"{parts.scheme}://{parts.netloc}"
            except requests.RequestException:
                continue
        return None

    def crawl(self) -> tuple[dict[str, set[str]], list[str]]:
        """Return {email: {source urls}} and the list of pages actually fetched."""
        results: dict[str, set[str]] = {}
        fetched: list[str] = []
        queue: deque = deque()

        base = self._reachable_base()
        if not base:
            self.errors.append("website unreachable over HTTPS and HTTP")
            return results, fetched

        for path in SEED_PATHS:
            url = self._normalize(urljoin(base, path))
            if url:
                queue.append((url, 0))

        while queue and self.pages_fetched < self.max_pages:
            url, depth = queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)
            if not self._allowed(url):
                LOG.debug("robots.txt disallows %s", url)
                continue

            try:
                page = self.client.get_text(url, max_bytes=1_500_000)
            except requests.HTTPError:
                continue
            except requests.RequestException as exc:
                self.errors.append(f"{url}: {truncate(exc, 120)}")
                continue
            if not page:
                continue

            self.pages_fetched += 1
            fetched.append(url)

            for email in extract_emails(page):
                results.setdefault(email, set()).add(url)

            if depth < self.max_depth:
                for href in LINK_RE.findall(page):
                    candidate = self._normalize(urljoin(url, href.strip()))
                    if candidate and candidate not in self.visited:
                        queue.append((candidate, depth + 1))

        return results, fetched


def _hunter_lookup(domain: str, client: HttpClient) -> tuple[list[dict], Optional[str]]:
    key = os.getenv("HUNTER_API_KEY")
    if not key:
        return [], None
    try:
        payload = client.get_json(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "api_key": key, "limit": "100"},
        )
    except (requests.RequestException, ValueError) as exc:
        return [], f"hunter.io: {truncate(exc, 150)}"

    out: list[dict] = []
    for item in ((payload or {}).get("data", {}) or {}).get("emails", []) or []:
        address = str(item.get("value", "")).lower()
        if not _is_plausible(address):
            continue
        label = " ".join(p for p in [item.get("first_name"), item.get("last_name")] if p)
        detail = ", ".join(
            p for p in [label or None, item.get("position"), item.get("department")] if p
        )
        out.append(
            {
                "email": address,
                "context": f"hunter.io{' — ' + detail if detail else ''}",
                "confidence": item.get("confidence"),
            }
        )
    return out, None


def collect_emails(
    domain: str,
    client: HttpClient,
    seeded: Optional[Iterable[dict]] = None,
    soa_records: Optional[list[str]] = None,
    crawl: bool = True,
    max_pages: int = 25,
    max_depth: int = 2,
    respect_robots: bool = True,
) -> dict:
    """Merge every email source into one deduplicated, attributed list."""
    started = time.monotonic()
    entries: dict[str, dict] = {}
    errors: list[str] = []

    def add(email: str, context: str, **extra) -> None:
        email = email.strip().lower().strip(".,;:<>()[]")
        if not _is_plausible(email):
            return
        entry = entries.setdefault(
            email,
            {
                "email": email,
                "sources": [],
                "on_domain": in_scope(email.split("@")[1], domain),
            },
        )
        if context not in entry["sources"]:
            entry["sources"].append(context)
        entry.update({k: v for k, v in extra.items() if v is not None})

    for item in seeded or []:
        add(item["email"], item.get("context", "registration record"))

    # The SOA RNAME encodes the zone admin's address with the first dot as '@'.
    for soa in soa_records or []:
        parts = soa.split()
        if len(parts) >= 2:
            rname = parts[1].rstrip(".")
            if "." in rname:
                local, _, mail_domain = rname.partition(".")
                add(f"{local}@{mail_domain}", "DNS SOA responsible party")

    pages: list[str] = []
    if crawl:
        crawler = Crawler(domain, client, max_pages, max_depth, respect_robots)
        crawled, pages = crawler.crawl()
        errors.extend(crawler.errors)
        for email, urls in crawled.items():
            for url in sorted(urls)[:3]:
                add(email, f"website: {url}")

    hunter_entries, hunter_error = _hunter_lookup(domain, client)
    if hunter_error:
        errors.append(hunter_error)
    for item in hunter_entries:
        add(item["email"], item["context"], confidence=item.get("confidence"))

    ordered = sorted(entries.values(), key=lambda e: (not e["on_domain"], e["email"]))
    on_domain = [e for e in ordered if e["on_domain"]]

    return {
        "count": len(ordered),
        "on_domain_count": len(on_domain),
        "external_count": len(ordered) - len(on_domain),
        "emails": ordered,
        "pages_crawled": pages,
        "pages_crawled_count": len(pages),
        "hunter_enabled": bool(os.getenv("HUNTER_API_KEY")),
        "errors": errors,
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }


# ==========================================================================
# SECTION 7 — orchestration
# ==========================================================================


class ReconOptions:
    """Everything the CLI can tune, in one place."""

    def __init__(
        self,
        domain: str,
        modules: tuple = MODULES,
        timeout: float = 20.0,
        dns_timeout: float = 5.0,
        workers: int = 10,
        rate_limit: float = 0.5,
        nameservers: Optional[list[str]] = None,
        subdomain_sources: Optional[list[str]] = None,
        resolve_subdomains: bool = True,
        max_resolve: int = 2000,
        reverse_dns: bool = True,
        crawl: bool = True,
        max_pages: int = 25,
        max_depth: int = 2,
        respect_robots: bool = True,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        verify_tls: bool = True,
    ) -> None:
        self.domain = domain
        self.modules = modules
        self.timeout = timeout
        self.dns_timeout = dns_timeout
        self.workers = workers
        self.rate_limit = rate_limit
        self.nameservers = nameservers
        self.subdomain_sources = subdomain_sources
        self.resolve_subdomains = resolve_subdomains
        self.max_resolve = max_resolve
        self.reverse_dns = reverse_dns
        self.crawl = crawl
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.user_agent = user_agent
        self.proxy = proxy
        self.verify_tls = verify_tls

    def as_dict(self) -> dict:
        return {
            "modules": list(self.modules),
            "timeout": self.timeout,
            "dns_timeout": self.dns_timeout,
            "workers": self.workers,
            "rate_limit": self.rate_limit,
            "nameservers": self.nameservers,
            "subdomain_sources": self.subdomain_sources,
            "resolve_subdomains": self.resolve_subdomains,
            "reverse_dns": self.reverse_dns,
            "crawl_website": self.crawl,
            "max_pages": self.max_pages,
            "max_depth": self.max_depth,
            "respect_robots": self.respect_robots,
            "proxy_used": bool(self.proxy),
            "tls_verification": self.verify_tls,
        }


def _state(analysis: dict, value: Optional[str]) -> str:
    """Distinguish 'present with policy X' from 'absent' from 'lookup failed'."""
    if analysis.get("lookup_failed") or analysis.get("present") is None:
        return "unknown (lookup failed)"
    if not analysis.get("present"):
        return "absent"
    return value or "present"


def build_summary(result: dict) -> dict:
    """Condensed figures used by the console output and the PDF summary table."""
    whois_data = result.get("whois", {}) or {}
    dns_data = result.get("dns", {}) or {}
    sub_data = result.get("subdomains", {}) or {}
    email_data = result.get("emails", {}) or {}
    mail = dns_data.get("mail", {}) or {}

    spf = mail.get("spf", {}) or {}
    dmarc = mail.get("dmarc", {}) or {}
    findings: list[str] = list(spf.get("issues", [])) + list(dmarc.get("issues", []))

    failed = set(dns_data.get("failed_lookups", []) or [])
    if dns_data and not dns_data.get("caa") and "CAA" not in failed:
        findings.append("No CAA record — any CA may issue certificates for this domain.")
    if dns_data and not dns_data.get("dnssec_dnskey_present") and "DNSKEY" not in failed:
        findings.append("No DNSKEY published — the zone is not DNSSEC signed.")
    if failed:
        findings.append(
            "Lookups did not complete for: " + ", ".join(sorted(failed))
            + ". Those record types are unknown rather than absent."
        )

    expiry = (whois_data.get("derived", {}) or {}).get("days_until_expiry")
    if isinstance(expiry, int) and expiry < 60:
        findings.append(
            f"Domain registration expires in {expiry} days."
            if expiry >= 0
            else f"Domain registration expired {abs(expiry)} days ago."
        )

    errors = 0
    for section in MODULES:
        payload = result.get(section, {}) or {}
        section_errors = payload.get("errors")
        if isinstance(section_errors, (dict, list)):
            errors += len(section_errors)

    return {
        "registrar": whois_data.get("registrar"),
        "created": (whois_data.get("dates", {}) or {}).get("created"),
        "expires": (whois_data.get("dates", {}) or {}).get("expires"),
        "domain_age_days": (whois_data.get("derived", {}) or {}).get("age_days"),
        "nameserver_count": len(
            whois_data.get("nameservers", []) or dns_data.get("records", {}).get("NS", [])
        ),
        "dns_record_types": len(dns_data.get("record_counts", {})),
        "dns_records_total": sum((dns_data.get("record_counts", {}) or {}).values()),
        "mail_provider": mail.get("provider"),
        "spf": _state(spf, spf.get("policy")),
        "dmarc": _state(dmarc, dmarc.get("policy")),
        "dkim_selectors_found": len((mail.get("dkim", {}) or {}).get("selectors_found", [])),
        "subdomains_found": sub_data.get("count", 0),
        "subdomains_resolving": sub_data.get("resolved_count"),
        "unique_ips": len(sub_data.get("unique_ips", []) or []),
        "emails_found": email_data.get("count", 0),
        "emails_on_domain": email_data.get("on_domain_count", 0),
        "pages_crawled": email_data.get("pages_crawled_count", 0),
        "observations": findings,
        "source_errors": errors,
    }


def run_recon(options: ReconOptions, progress: Optional[Callable[[str, str], None]] = None) -> dict:
    """Execute the reconnaissance run and return the full result document."""
    started = time.monotonic()

    def notify(stage: str, message: str) -> None:
        LOG.info("%s: %s", stage, message)
        if progress:
            progress(stage, message)

    result: dict = {
        "meta": {
            "tool": "domain_recon",
            "version": __version__,
            "target": options.domain,
            "generated_utc": utc_now_iso(),
            "python": platform.python_version(),
            "host_platform": platform.platform(),
            "options": options.as_dict(),
            "notice": (
                "Passive collection of publicly available information only. "
                "No port scanning, credential testing, or exploitation was performed."
            ),
        }
    }

    client = HttpClient(
        timeout=options.timeout,
        user_agent=options.user_agent or DEFAULT_USER_AGENT,
        rate_limit=options.rate_limit,
        proxy=options.proxy,
        verify_tls=options.verify_tls,
    )

    try:
        whois_data: dict = {}
        if "whois" in options.modules:
            notify("whois", "querying RDAP/WHOIS registries")
            whois_data = collect_whois(options.domain, client)
            result["whois"] = whois_data
            notify(
                "whois",
                f"registrar: {whois_data.get('registrar') or 'unknown'}"
                if whois_data.get("available")
                else "no registration record retrieved",
            )

        dns_data: dict = {}
        if "dns" in options.modules:
            notify("dns", "resolving record types and mail policy")
            dns_data = collect_dns(
                options.domain,
                nameservers=options.nameservers,
                timeout=options.dns_timeout,
                workers=options.workers,
                reverse=options.reverse_dns,
            )
            result["dns"] = dns_data
            notify(
                "dns",
                f"{sum(dns_data['record_counts'].values())} records across "
                f"{len(dns_data['record_counts'])} types",
            )

        if "subdomains" in options.modules:
            notify("subdomains", "querying certificate transparency and passive DNS")
            sub_data = collect_subdomains(
                options.domain, client,
                enabled=options.subdomain_sources, workers=options.workers,
            )
            if options.resolve_subdomains and sub_data["count"]:
                hosts = [e["host"] for e in sub_data["subdomains"]][: options.max_resolve]
                notify("subdomains", f"resolving {len(hosts)} of {sub_data['count']} hostnames")
                resolutions = resolve_hosts(
                    hosts,
                    nameservers=options.nameservers,
                    timeout=options.dns_timeout,
                    workers=max(options.workers * 2, 20),
                )
                sub_data = attach_resolution(sub_data, resolutions)
            result["subdomains"] = sub_data
            notify(
                "subdomains",
                f"{sub_data['count']} unique names"
                + (
                    f", {sub_data.get('resolved_count', 0)} resolving"
                    if "resolved_count" in sub_data
                    else ""
                ),
            )

        if "emails" in options.modules:
            notify("emails", "collecting from registration records and public pages")
            email_data = collect_emails(
                options.domain,
                client,
                seeded=registration_emails(whois_data) if whois_data.get("available") else [],
                soa_records=(dns_data.get("records", {}) or {}).get("SOA", []),
                crawl=options.crawl,
                max_pages=options.max_pages,
                max_depth=options.max_depth,
                respect_robots=options.respect_robots,
            )
            result["emails"] = email_data
            notify(
                "emails",
                f"{email_data['count']} unique addresses "
                f"({email_data['on_domain_count']} on-domain)",
            )
    finally:
        client.close()

    result["meta"]["elapsed_seconds"] = round(time.monotonic() - started, 2)
    result["summary"] = build_summary(result)
    return result


# ==========================================================================
# SECTION 8 — reporting
# ==========================================================================

MAX_TABLE_ROWS = 1500  # keeps enormous subdomain lists from producing 400-page PDFs


def write_json(result: dict, path: Path, pretty: bool = True) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(
            result, handle, indent=2 if pretty else None,
            ensure_ascii=False, sort_keys=False, default=str,
        )
        handle.write("\n")
    return path


def _register_fonts() -> tuple[str, str]:
    """Use a Unicode TTF when one is available; fall back to Helvetica."""
    candidates = [
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ("/usr/share/fonts/dejavu/DejaVuSans.ttf",
         "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf"),
        ("/Library/Fonts/Arial Unicode.ttf", "/Library/Fonts/Arial Unicode.ttf"),
        ("/System/Library/Fonts/Supplemental/Arial.ttf",
         "/System/Library/Fonts/Supplemental/Arial Bold.ttf"),
        ("C:\\Windows\\Fonts\\arial.ttf", "C:\\Windows\\Fonts\\arialbd.ttf"),
    ]
    for regular, bold in candidates:
        if os.path.exists(regular) and os.path.exists(bold):
            try:
                pdfmetrics.registerFont(TTFont("ReportBody", regular))
                pdfmetrics.registerFont(TTFont("ReportBody-Bold", bold))
                pdfmetrics.registerFontFamily(
                    "ReportBody", normal="ReportBody", bold="ReportBody-Bold"
                )
                return "ReportBody", "ReportBody-Bold"
            except Exception as exc:  # corrupt font, bad permissions, etc.
                LOG.debug("font registration failed for %s: %s", regular, exc)
    return "Helvetica", "Helvetica-Bold"


def _presence(analysis: dict) -> str:
    if analysis.get("lookup_failed") or analysis.get("present") is None:
        return "unknown (lookup failed)"
    return "present" if analysis.get("present") else "absent"


def derived_bool(value: Optional[bool]) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"


class PdfReport:
    """Builds the multi-section PDF. Only instantiated when reportlab is present."""

    def __init__(self, result: dict, page_size: str = "letter") -> None:
        self.result = result
        self.pagesize = A4 if str(page_size).lower() == "a4" else letter
        self.body_font, self.bold_font = _register_fonts()
        self.styles = self._build_styles()
        self.content_width = self.pagesize[0] - 1.5 * inch

    def _build_styles(self) -> dict:
        base = getSampleStyleSheet()
        body = ParagraphStyle(
            "Body", parent=base["BodyText"], fontName=self.body_font,
            fontSize=9, leading=12.5, textColor=INK, spaceAfter=4,
        )
        return {
            "title": ParagraphStyle(
                "TitleBig", parent=base["Title"], fontName=self.bold_font,
                fontSize=22, leading=26, textColor=INK, alignment=0, spaceAfter=2,
            ),
            "subtitle": ParagraphStyle(
                "Subtitle", parent=body, fontSize=11.5, leading=15,
                textColor=ACCENT, spaceAfter=10,
            ),
            "h1": ParagraphStyle(
                "H1", parent=base["Heading1"], fontName=self.bold_font,
                fontSize=14, leading=18, textColor=INK, spaceBefore=14, spaceAfter=6,
            ),
            "h2": ParagraphStyle(
                "H2", parent=base["Heading2"], fontName=self.bold_font,
                fontSize=10.5, leading=14, textColor=ACCENT, spaceBefore=10, spaceAfter=4,
            ),
            "body": body,
            "small": ParagraphStyle("Small", parent=body, fontSize=7.8, leading=10.5, spaceAfter=2),
            "mono": ParagraphStyle(
                "Mono", parent=body, fontName="Courier", fontSize=7.6, leading=10, spaceAfter=1
            ),
            "muted": ParagraphStyle("Muted", parent=body, fontSize=8.2, leading=11, textColor=MUTED),
            "cell": ParagraphStyle("Cell", parent=body, fontSize=8, leading=10.5, spaceAfter=0),
            "cellhead": ParagraphStyle(
                "CellHead", parent=body, fontName=self.bold_font, fontSize=8,
                leading=10.5, textColor=colors.white, spaceAfter=0,
            ),
        }

    # ----------------------------------------------------------- helpers

    def p(self, text: Any, style: str = "body"):
        return Paragraph(html.escape(str(text)) if text is not None else "—", self.styles[style])

    def cell(self, text: Any, style: str = "cell"):
        if text is None or text == "" or text == []:
            text = "—"
        if isinstance(text, (list, tuple)):
            text = ", ".join(str(item) for item in text)
        return Paragraph(html.escape(str(text)).replace("\n", "<br/>"), self.styles[style])

    def kv_table(self, rows: list, label_width: float = 1.85):
        data = [[self.cell(label), self.cell(value)] for label, value in rows]
        table = Table(
            data,
            colWidths=[label_width * inch, self.content_width - label_width * inch],
            hAlign="LEFT",
        )
        table.setStyle(
            TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, -1), BAND),
                ("TEXTCOLOR", (0, 0), (0, -1), INK),
                ("GRID", (0, 0), (-1, -1), 0.4, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        return table

    def grid_table(self, headers: list, rows: list, widths: list):
        data = [[self.cell(head, "cellhead") for head in headers]]
        data.extend([[self.cell(value) for value in row] for row in rows])
        table = Table(
            data, colWidths=[w * self.content_width for w in widths],
            repeatRows=1, hAlign="LEFT",
        )
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), INK),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, RULE),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ]
        for index in range(1, len(data)):
            if index % 2 == 0:
                style.append(("BACKGROUND", (0, index), (-1, index), BAND))
        table.setStyle(TableStyle(style))
        return table

    def section(self, title: str) -> list:
        rule = Table([[""]], colWidths=[self.content_width], rowHeights=[2])
        rule.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), ACCENT)]))
        return [
            # Start a new page rather than leaving a heading stranded at the foot.
            CondPageBreak(1.6 * inch),
            Paragraph(html.escape(title), self.styles["h1"]),
            rule,
            Spacer(1, 6),
        ]

    # ---------------------------------------------------------- sections

    def _cover(self) -> list:
        meta = self.result.get("meta", {})
        summary = self.result.get("summary", {})
        flow: list = [
            self.p("Domain Reconnaissance Report", "title"),
            self.p(meta.get("target", "unknown"), "subtitle"),
        ]

        notice = Table(
            [[self.cell(
                "Scope: passive collection of publicly available information only — registry "
                "records, DNS, certificate transparency, passive DNS aggregators and the target's "
                "own published pages. No port scanning, credential testing, or exploitation was "
                "performed. Verify authorization before acting on this report.", "small")]],
            colWidths=[self.content_width],
        )
        notice.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), BAND),
            ("BOX", (0, 0), (-1, -1), 0.6, ACCENT),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        flow += [notice, Spacer(1, 12)]

        flow += self.section("Run details")
        flow.append(self.kv_table([
            ("Target", meta.get("target")),
            ("Generated (UTC)", meta.get("generated_utc")),
            ("Tool version", f"{meta.get('tool')} {meta.get('version')}"),
            ("Modules run", ", ".join(meta.get("options", {}).get("modules", []))),
            ("Duration", f"{meta.get('elapsed_seconds', 0)} s"),
            ("Source errors", summary.get("source_errors", 0)),
        ]))

        resolving = summary.get("subdomains_resolving")
        flow += self.section("Summary")
        flow.append(self.grid_table(
            ["Metric", "Value", "Metric", "Value"],
            [
                ["Registrar", truncate(summary.get("registrar") or "—", 40),
                 "Subdomains found", summary.get("subdomains_found", 0)],
                ["Created", summary.get("created") or "—",
                 "Subdomains resolving", resolving if resolving is not None else "not checked"],
                ["Expires", summary.get("expires") or "—",
                 "Unique IPs", summary.get("unique_ips", 0)],
                ["Domain age (days)",
                 summary.get("domain_age_days") if summary.get("domain_age_days") is not None else "—",
                 "Email addresses", summary.get("emails_found", 0)],
                ["DNS records",
                 f"{summary.get('dns_records_total', 0)} across {summary.get('dns_record_types', 0)} types",
                 "…on target domain", summary.get("emails_on_domain", 0)],
                ["Mail provider", summary.get("mail_provider") or "—",
                 "Pages crawled", summary.get("pages_crawled", 0)],
                ["SPF", summary.get("spf") or "—", "DMARC", summary.get("dmarc") or "—"],
                ["DKIM selectors", summary.get("dkim_selectors_found", 0),
                 "Nameservers", summary.get("nameserver_count", 0)],
            ],
            [0.20, 0.30, 0.20, 0.30],
        ))

        observations = summary.get("observations", [])
        if observations:
            flow.append(Spacer(1, 10))
            flow.append(self.p("Observations", "h2"))
            flow.append(self.p(
                "Configuration notes drawn from public records. These are not vulnerability "
                "findings and warrant confirmation before being reported.", "muted"))
            flow.append(Spacer(1, 3))
            flow.append(self.grid_table(
                ["#", "Observation"],
                [[i, text] for i, text in enumerate(observations, 1)],
                [0.06, 0.94],
            ))
        return flow

    def _whois(self) -> list:
        data = self.result.get("whois")
        if not data:
            return []
        flow = self.section("Registration (WHOIS / RDAP)")
        if not data.get("available"):
            flow.append(self.p("No registration record could be retrieved.", "body"))
            for error in data.get("errors", []):
                flow.append(self.p(f"• {error}", "small"))
            return flow

        dates = data.get("dates", {})
        derived = data.get("derived", {})
        flow.append(self.kv_table([
            ("Data source", data.get("source")),
            ("Domain", data.get("domain")),
            ("Registrar", data.get("registrar")),
            ("Registrar IANA ID", data.get("registrar_iana_id")),
            ("Created", dates.get("created")),
            ("Updated", dates.get("updated")),
            ("Expires", dates.get("expires")),
            ("Domain age (days)", derived.get("age_days")),
            ("Days until expiry", derived.get("days_until_expiry")),
            ("DNSSEC delegation signed", derived_bool(data.get("dnssec_signed"))),
            ("Registrant details redacted", derived_bool(derived.get("registrant_redacted"))),
            ("Abuse contact", data.get("abuse_email")),
            ("Abuse phone", data.get("abuse_phone")),
            ("Status codes", ", ".join(data.get("status", [])) or "—"),
            ("Registry nameservers", ", ".join(data.get("nameservers", [])) or "—"),
        ]))

        contacts = data.get("contacts", [])
        if contacts:
            flow.append(Spacer(1, 8))
            flow.append(self.p("Published contacts", "h2"))
            rows = [
                [
                    ", ".join(str(role) for role in contact.get("roles", [])) or "—",
                    contact.get("name") or "—",
                    contact.get("organization") or "—",
                    ", ".join(contact.get("emails", []) or []) or "—",
                    contact.get("country") or "—",
                ]
                for contact in contacts
            ]
            flow.append(self.grid_table(
                ["Role", "Name", "Organization", "Email", "Country"],
                rows, [0.16, 0.20, 0.22, 0.30, 0.12],
            ))

        if data.get("raw_text"):
            flow.append(Spacer(1, 8))
            flow.append(self.p("Raw WHOIS response (truncated)", "h2"))
            for line in str(data["raw_text"]).splitlines()[:60]:
                flow.append(Paragraph(html.escape(line[:160]) or "&nbsp;", self.styles["mono"]))
        return flow

    def _dns(self) -> list:
        data = self.result.get("dns")
        if not data:
            return []
        flow = self.section("DNS records")
        records = data.get("records", {})
        if records:
            rows = [
                [rtype, "\n".join(truncate(v, 220) for v in values)]
                for rtype, values in sorted(records.items())
            ]
            flow.append(self.grid_table(["Type", "Value(s)"], rows, [0.12, 0.88]))
        else:
            flow.append(self.p("No records resolved.", "body"))

        ptr = data.get("reverse_dns", {})
        if ptr:
            flow.append(Spacer(1, 8))
            flow.append(self.p("Reverse DNS", "h2"))
            flow.append(self.grid_table(
                ["IP address", "PTR"],
                [[ip, name] for ip, name in sorted(ptr.items())], [0.35, 0.65],
            ))

        verification = data.get("verification_txt", [])
        if verification:
            flow.append(Spacer(1, 8))
            flow.append(self.p("Third-party verification TXT records", "h2"))
            flow.append(self.p(
                "These indicate which SaaS platforms the domain is enrolled in.", "muted"))
            flow.append(self.grid_table(
                ["Record"], [[truncate(record, 240)] for record in verification], [1.0]))

        flow += self._mail_security(data.get("mail", {}), data.get("caa", []))
        return flow

    def _mail_security(self, mail: dict, caa: list) -> list:
        if not mail:
            return []
        spf = mail.get("spf", {}) or {}
        dmarc = mail.get("dmarc", {}) or {}
        dkim = mail.get("dkim", {}) or {}

        flow = [Spacer(1, 10), self.p("Mail authentication posture", "h2")]
        rows = [
            ["SPF", _presence(spf), truncate(spf.get("record") or "—", 220)],
            ["SPF policy", spf.get("policy") or "—", ", ".join(spf.get("includes", [])) or "—"],
            ["DMARC", _presence(dmarc), truncate(dmarc.get("record") or "—", 220)],
            ["DMARC policy", dmarc.get("policy") or "—",
             ", ".join(dmarc.get("rua", []) or []) or "no aggregate reporting address"],
            ["DKIM",
             f"{len(dkim.get('selectors_found', []))} of "
             f"{dkim.get('selectors_tested', 0)} common selectors",
             ", ".join(dkim.get("selectors_found", [])) or "—"],
            ["CAA", "present" if caa else "absent",
             "\n".join(truncate(record, 200) for record in caa) or "any CA may issue"],
            ["MX", f"{len(mail.get('mx', []))} host(s)", "\n".join(mail.get("mx", [])) or "—"],
            ["Mail provider", mail.get("provider") or "unidentified", ""],
        ]
        flow.append(self.grid_table(["Control", "State", "Detail"], rows, [0.16, 0.20, 0.64]))

        issues = list(spf.get("issues", [])) + list(dmarc.get("issues", []))
        if issues:
            flow.append(Spacer(1, 6))
            flow.append(self.grid_table(
                ["Notes on mail configuration"], [[issue] for issue in issues], [1.0]))
        return flow

    def _subdomains(self) -> list:
        data = self.result.get("subdomains")
        if not data:
            return []
        flow = self.section("Subdomains")
        flow.append(self.p(
            f"{data.get('count', 0)} unique hostnames aggregated from "
            f"{len(data.get('source_stats', {}))} passive sources."
            + (f" {data.get('resolved_count', 0)} currently resolve."
               if "resolved_count" in data else ""),
            "body",
        ))

        entries = data.get("subdomains", [])
        if entries:
            shown = entries[:MAX_TABLE_ROWS]
            resolved_known = any("resolves" in entry for entry in shown)
            rows = []
            for index, entry in enumerate(shown, 1):
                addresses = (entry.get("a", []) or []) + (entry.get("aaaa", []) or [])
                target = ", ".join(addresses[:4]) or (entry.get("cname") or "—")
                if len(addresses) > 4:
                    target += f" (+{len(addresses) - 4})"
                row = [index, entry["host"]]
                if resolved_known:
                    row.append("yes" if entry.get("resolves") else "no")
                    row.append(target)
                row.append(", ".join(entry.get("sources", [])))
                rows.append(row)

            if resolved_known:
                headers = ["#", "Hostname", "Live", "Resolves to", "Sources"]
                widths = [0.05, 0.32, 0.07, 0.29, 0.27]
            else:
                headers = ["#", "Hostname", "Sources"]
                widths = [0.05, 0.55, 0.40]
            flow.append(Spacer(1, 4))
            flow.append(self.grid_table(headers, rows, widths))
            if len(entries) > MAX_TABLE_ROWS:
                flow.append(Spacer(1, 4))
                flow.append(self.p(
                    f"Showing the first {MAX_TABLE_ROWS} of {len(entries)} hostnames. "
                    "The full list is in the JSON output.", "muted"))

        stats = data.get("source_stats", {})
        if stats:
            flow.append(Spacer(1, 10))
            flow.append(self.p("Source performance", "h2"))
            flow.append(self.grid_table(
                ["Source", "Status", "Returned", "In scope", "Seconds"],
                [[name, v.get("status"), v.get("returned"), v.get("in_scope"), v.get("seconds")]
                 for name, v in sorted(stats.items())],
                [0.30, 0.16, 0.18, 0.18, 0.18],
            ))
        return flow

    def _emails(self) -> list:
        data = self.result.get("emails")
        if not data:
            return []
        flow = self.section("Email addresses")
        flow.append(self.p(
            f"{data.get('count', 0)} unique addresses "
            f"({data.get('on_domain_count', 0)} on the target domain, "
            f"{data.get('external_count', 0)} external), collected from registration records, "
            f"DNS and {data.get('pages_crawled_count', 0)} public pages.",
            "body",
        ))

        entries = data.get("emails", [])
        if entries:
            rows = [
                [index, entry["email"],
                 "on-domain" if entry.get("on_domain") else "external",
                 "\n".join(truncate(source, 90) for source in entry.get("sources", [])[:3])]
                for index, entry in enumerate(entries[:MAX_TABLE_ROWS], 1)
            ]
            flow.append(Spacer(1, 4))
            flow.append(self.grid_table(
                ["#", "Address", "Scope", "Where it was found"],
                rows, [0.05, 0.33, 0.12, 0.50],
            ))
        else:
            flow.append(self.p("No addresses were found in the sources queried.", "body"))

        pages = data.get("pages_crawled", [])
        if pages:
            flow.append(Spacer(1, 10))
            flow.append(self.p("Pages retrieved", "h2"))
            flow.append(self.grid_table(["URL"], [[truncate(url, 200)] for url in pages], [1.0]))
        return flow

    def _appendix(self) -> list:
        flow = [PageBreak()] + self.section("Appendix: collection notes")
        meta = self.result.get("meta", {})
        options = meta.get("options", {})
        resolvers = (self.result.get("dns", {}) or {}).get("resolvers_used", [])
        flow.append(self.kv_table([
            ("HTTP timeout", f"{options.get('timeout')} s"),
            ("DNS timeout", f"{options.get('dns_timeout')} s"),
            ("Worker threads", options.get("workers")),
            ("Per-host rate limit", f"{options.get('rate_limit')} s between requests"),
            ("Resolvers", ", ".join(resolvers) or "system default"),
            ("Subdomain resolution", derived_bool(options.get("resolve_subdomains"))),
            ("Website crawl", derived_bool(options.get("crawl_website"))),
            ("robots.txt respected", derived_bool(options.get("respect_robots"))),
            ("Crawl limits", f"{options.get('max_pages')} pages, depth {options.get('max_depth')}"),
            ("Proxy used", derived_bool(options.get("proxy_used"))),
            ("Python", meta.get("python")),
        ]))

        errors: list = []
        for section in MODULES:
            payload = self.result.get(section, {}) or {}
            section_errors = payload.get("errors")
            if isinstance(section_errors, dict):
                errors.extend(
                    [section, key, truncate(value, 200)] for key, value in section_errors.items()
                )
            elif isinstance(section_errors, list):
                errors.extend([section, "—", truncate(value, 200)] for value in section_errors)
        if errors:
            flow.append(Spacer(1, 10))
            flow.append(self.p("Errors and skipped sources", "h2"))
            flow.append(self.p(
                "Sources that failed or were skipped. Absence of data below does not mean "
                "absence of the asset — it means this run did not observe it.", "muted"))
            flow.append(Spacer(1, 3))
            flow.append(self.grid_table(["Module", "Source", "Detail"], errors, [0.16, 0.22, 0.62]))

        flow.append(Spacer(1, 12))
        flow.append(self.p("Methodology", "h2"))
        flow.append(self.p(
            "Registration data is retrieved over RDAP with a WHOIS fallback. DNS records come "
            "from ordinary recursive queries. Subdomains are aggregated from certificate "
            "transparency logs, passive DNS aggregators and web archives — no brute forcing or "
            "zone transfers. Email addresses are taken from registration contacts, the SOA "
            "responsible-party field and pages published by the target itself, subject to "
            "robots.txt. Results reflect a single point in time and public data sets that lag "
            "reality; treat them as leads to confirm, not as an authoritative inventory.",
            "body"))
        return flow

    def build(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        meta = self.result.get("meta", {})
        target = meta.get("target", "domain")
        body_font = self.body_font

        class NumberedCanvas(pdfcanvas.Canvas):
            """Two-pass canvas so the footer can print 'Page X of Y'."""

            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._saved_states: list = []

            def showPage(self):
                self._saved_states.append(dict(self.__dict__))
                self._startPage()

            def save(self):
                total = len(self._saved_states)
                for state in self._saved_states:
                    self.__dict__.update(state)
                    self._draw_footer(total)
                    super().showPage()
                super().save()

            def _draw_footer(self, total: int) -> None:
                width, _height = self._pagesize
                self.setStrokeColor(RULE)
                self.setLineWidth(0.5)
                self.line(0.75 * inch, 0.62 * inch, width - 0.75 * inch, 0.62 * inch)
                self.setFont(body_font, 7.5)
                self.setFillColor(MUTED)
                footer = f"{target} · generated {meta.get('generated_utc', '')} · passive OSINT"
                self.drawString(0.75 * inch, 0.45 * inch, footer[:110])
                self.drawRightString(
                    width - 0.75 * inch, 0.45 * inch, f"Page {self._pageNumber} of {total}"
                )

        doc = BaseDocTemplate(
            str(path),
            pagesize=self.pagesize,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.85 * inch,
            title=f"Domain Reconnaissance Report — {target}",
            author="domain_recon",
            subject=f"Passive OSINT report for {target}",
        )
        doc.addPageTemplates([
            PageTemplate(
                id="main",
                frames=[Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="body")],
            )
        ])

        story: list = []
        story += self._cover()
        story += self._whois()
        story += self._dns()
        story += self._subdomains()
        story += self._emails()
        story += self._appendix()

        doc.build(story, canvasmaker=NumberedCanvas)
        return path


def write_pdf(result: dict, path: Path, page_size: str = "letter") -> Path:
    if not REPORTLAB_AVAILABLE:
        raise ReconError(
            "PDF output requires reportlab. Install it with:  pip install reportlab\n"
            "(or use --format json, which has no extra dependency)"
        )
    return PdfReport(result, page_size=page_size).build(Path(path))


# ==========================================================================
# SECTION 9 — offline self-test
# ==========================================================================


def _sample_result() -> dict:
    """A synthetic, fully populated result used by --self-test."""
    sources = ["crt.sh", "certspotter", "anubis", "alienvault-otx", "wayback", "urlscan"]
    names = [
        "www", "api", "staging", "dev", "mail", "vpn", "cdn", "admin", "git",
        "jira", "grafana", "test", "shop", "blog", "docs", "status", "legacy-crm",
    ]
    subdomains = []
    for index, name in enumerate(names):
        resolves = index % 4 != 3
        subdomains.append({
            "host": f"{name}.acme-corp.io",
            "sources": sources[: (index % 4) + 1],
            "a": [f"203.0.113.{10 + index}"] if resolves else [],
            "aaaa": ["2001:db8::1"] if resolves and index % 5 == 0 else [],
            "cname": f"{name}.edge.example-provider.net" if index % 6 == 0 else None,
            "resolves": resolves,
        })

    result = {
        "meta": {
            "tool": "domain_recon", "version": __version__, "target": "acme-corp.io",
            "generated_utc": "2026-01-01T00:00:00+00:00", "python": platform.python_version(),
            "host_platform": platform.platform(), "elapsed_seconds": 41.7,
            "options": {
                "modules": list(MODULES), "timeout": 20.0, "dns_timeout": 5.0, "workers": 10,
                "rate_limit": 0.5, "nameservers": None, "subdomain_sources": None,
                "resolve_subdomains": True, "reverse_dns": True, "crawl_website": True,
                "max_pages": 25, "max_depth": 2, "respect_robots": True,
                "proxy_used": False, "tls_verification": True,
            },
            "notice": "Passive collection of publicly available information only.",
        },
        "whois": {
            "available": True, "source": "RDAP", "domain": "acme-corp.io",
            "registrar": "Example Registrar, LLC", "registrar_iana_id": "1234",
            "status": ["client transfer prohibited"],
            "dates": {"created": "2011-04-18T09:12:00Z", "updated": "2025-03-02T11:40:11Z",
                      "expires": "2026-10-18T09:12:00Z"},
            "nameservers": ["ns1.example-dns.net", "ns2.example-dns.net"],
            "abuse_email": "abuse@example-registrar.test", "abuse_phone": "+1.5555550100",
            "dnssec_signed": False,
            "contacts": [
                {"roles": ["registrant"], "name": "REDACTED FOR PRIVACY",
                 "organization": "Acme Corporation", "emails": [], "country": "US"},
                {"roles": ["abuse"], "name": "Abuse Desk",
                 "emails": ["abuse@example-registrar.test"], "country": "US"},
            ],
            "derived": {"age_days": 5617, "days_until_expiry": 45, "expired": False,
                        "registrant_redacted": True},
            "errors": [], "elapsed_seconds": 1.8,
        },
        "dns": {
            "records": {
                "A": ["203.0.113.10"], "AAAA": ["2001:db8::10"],
                "MX": ["10 mx1.example-mail.net.", "20 mx2.example-mail.net."],
                "NS": ["ns1.example-dns.net.", "ns2.example-dns.net."],
                "SOA": ["ns1.example-dns.net. hostmaster.acme-corp.io. 2026010101 7200 3600 1209600 3600"],
                "TXT": ["v=spf1 include:_spf.example-mail.net ~all",
                        "google-site-verification=AbC123dEf456"],
                "CAA": ['0 issue "letsencrypt.org"'],
            },
            "record_counts": {"A": 1, "AAAA": 1, "MX": 2, "NS": 2, "SOA": 1, "TXT": 2, "CAA": 1},
            "reverse_dns": {"203.0.113.10": "edge-10.example-provider.net"},
            "errors": {"SRV": "NXDOMAIN"}, "failed_lookups": [],
            "mail": {
                "mx": ["10 mx1.example-mail.net.", "20 mx2.example-mail.net."], "provider": None,
                "spf": _analyze_spf(["v=spf1 include:_spf.example-mail.net ~all"]),
                "dmarc": _analyze_dmarc(["v=DMARC1; p=none; rua=mailto:dmarc@acme-corp.io"]),
                "dkim": {"selectors_tested": 26, "selectors_found": ["google", "selector1"],
                         "records": [{"selector": "google", "record": "v=DKIM1; k=rsa; p=MIIBIjANBg..."}]},
            },
            "caa": ['0 issue "letsencrypt.org"'], "dnssec_dnskey_present": False,
            "verification_txt": ["google-site-verification=AbC123dEf456"],
            "resolvers_used": ["1.1.1.1", "8.8.8.8"], "elapsed_seconds": 6.4,
        },
        "subdomains": {
            "count": len(subdomains), "subdomains": subdomains,
            "resolved_count": sum(1 for s in subdomains if s["resolves"]),
            "unresolved_count": sum(1 for s in subdomains if not s["resolves"]),
            "unique_ips": sorted({ip for s in subdomains for ip in s["a"]}),
            "source_stats": {
                name: {"returned": 40 - i * 5, "in_scope": 30 - i * 4,
                       "seconds": round(1.2 + i * 0.4, 2), "status": "ok"}
                for i, name in enumerate(sources)
            },
            "errors": {"hackertarget": "HTTP 429",
                       "securitytrails": "skipped (SECURITYTRAILS_API_KEY not set)"},
            "elapsed_seconds": 12.9,
        },
        "emails": {
            "count": 4, "on_domain_count": 3, "external_count": 1,
            "emails": [
                {"email": "careers@acme-corp.io", "on_domain": True,
                 "sources": ["website: https://acme-corp.io/careers"]},
                {"email": "hostmaster@acme-corp.io", "on_domain": True,
                 "sources": ["DNS SOA responsible party"]},
                {"email": "security@acme-corp.io", "on_domain": True,
                 "sources": ["website: https://acme-corp.io/.well-known/security.txt"]},
                {"email": "abuse@example-registrar.test", "on_domain": False,
                 "sources": ["WHOIS/RDAP abuse contact"]},
            ],
            "pages_crawled": ["https://acme-corp.io/", "https://acme-corp.io/careers",
                              "https://acme-corp.io/.well-known/security.txt"],
            "pages_crawled_count": 3, "hunter_enabled": False, "errors": [],
            "elapsed_seconds": 9.1,
        },
    }
    result["summary"] = build_summary(result)
    return result


def self_test(outdir: Path) -> int:
    """Offline checks: parsing, analysis and both writers. No network access."""
    checks: list[tuple[str, bool, str]] = []

    def check(label: str, condition: bool, detail: str = "") -> None:
        checks.append((label, bool(condition), detail))

    check("domain normalization",
          normalize_domain("https://Example.COM:443/path") == "example.com")
    try:
        normalize_domain("192.168.1.1")
        check("rejects IP addresses", False, "no error raised")
    except ReconError:
        check("rejects IP addresses", True)

    check("hostname cleaning", clean_hostname("*.Mail.Example.com.") == "mail.example.com")

    found = extract_emails(
        '<a href="mailto:Info%40acme-corp.io">m</a> press (at) acme-corp (dot) io '
        'billing&#64;acme-corp.io <script>x="junk@spam.test"</script> '
        "authentication.click avatars.githubusercontent.com"
    )
    check("email extraction", found == {"info@acme-corp.io", "press@acme-corp.io",
                                        "billing@acme-corp.io"}, str(sorted(found)))

    spf = _analyze_spf(["v=spf1 include:a.net +all"])
    check("SPF analysis", spf["present"] and "authorizes every sender" in " ".join(spf["issues"]))
    check("SPF failure is not absence", _analyze_spf([], lookup_failed=True)["present"] is None)
    dmarc = _analyze_dmarc(["v=DMARC1; p=quarantine; rua=mailto:x@y.test"])
    check("DMARC analysis", dmarc["policy"] == "quarantine" and dmarc["rua"])

    result = _sample_result()
    check("summary build", result["summary"]["subdomains_found"] == 17
          and "p=none" in " ".join(result["summary"]["observations"]))

    outdir = Path(outdir)
    json_path = write_json(result, outdir / "self_test_report.json")
    check("JSON writer", json_path.exists() and json_path.stat().st_size > 2000, str(json_path))
    reloaded = json.loads(json_path.read_text(encoding="utf-8"))
    check("JSON round-trip", reloaded["meta"]["target"] == "acme-corp.io")

    if REPORTLAB_AVAILABLE:
        pdf_path = write_pdf(result, outdir / "self_test_report.pdf")
        check("PDF writer", pdf_path.exists() and pdf_path.stat().st_size > 10000, str(pdf_path))
    else:
        check("PDF writer", True, "skipped — reportlab not installed (JSON output still works)")

    width = max(len(label) for label, _, _ in checks) + 2
    failures = 0
    print("\nSelf-test (offline, no network):\n")
    for label, ok, detail in checks:
        failures += 0 if ok else 1
        print(f"  [{'PASS' if ok else 'FAIL'}] {label.ljust(width)}{detail}")
    print(f"\n{len(checks) - failures}/{len(checks)} checks passed.\n")
    return 0 if failures == 0 else 1


# ==========================================================================
# SECTION 10 — command-line interface
# ==========================================================================

BANNER = r"""
  ___                 _         ___
 |   \ ___ _ __  __ _(_)_ _    | _ \___ __ ___ _ _
 | |) / _ \ '  \/ _` | | ' \   |   / -_) _/ _ \ ' \
 |___/\___/_|_|_\__,_|_|_||_|  |_|_\___\__\___/_||_|
 passive OSINT collection {dash} v{version}
"""

EPILOG = """
examples:
  python domain_recon.py example.com                    JSON report in the current directory
  python domain_recon.py example.com -f pdf             PDF report instead
  python domain_recon.py example.com -f both -o out/acme
  python domain_recon.py example.com --modules dns,whois
  python domain_recon.py example.com --no-crawl -f pdf  skip the website crawl
  python domain_recon.py example.com -f json -o -       stream JSON to stdout
  python domain_recon.py --self-test                    offline check, no network

optional API keys (read from the environment, skipped when unset):
  SECURITYTRAILS_API_KEY, VIRUSTOTAL_API_KEY, HUNTER_API_KEY

Only run this against domains you own or are explicitly authorized to assess.
"""


IS_WINDOWS = os.name == "nt"


class Glyphs:
    """Decorative characters, with ASCII fallbacks for legacy Windows code pages.

    Python writes Unicode straight to a Windows console, but when output is
    redirected to a file or pipe the stream falls back to the ANSI code page
    (cp1252), which cannot encode box-drawing or check marks.
    """

    def __init__(self, unicode_ok: bool) -> None:
        if unicode_ok:
            self.check, self.arrow, self.bullet = "\u2713", "\u203a", "\u2022"
            self.rule, self.to, self.sep, self.dash = "\u2500", "\u2192", "\u00b7", "\u2014"
        else:
            self.check, self.arrow, self.bullet = "[ok]", ">", "*"
            self.rule, self.to, self.sep, self.dash = "-", "->", "|", "-"


def prepare_console() -> "Glyphs":
    """Make console output safe on every platform and pick a glyph set."""
    unicode_ok = True
    for stream in (sys.stdout, sys.stderr):
        # errors="replace" guarantees that odd characters in third-party data
        # (registrar names, WHOIS contacts) can never crash the run.
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
        encoding = getattr(stream, "encoding", None) or "ascii"
        try:
            "\u2713\u2500\u2192".encode(encoding)
        except (UnicodeEncodeError, LookupError):
            unicode_ok = False
    return Glyphs(unicode_ok)


def enable_ansi_colors() -> bool:
    """Turn on virtual-terminal processing so ANSI codes work in older consoles."""
    if not IS_WINDOWS:
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        enable_vt = 0x0004
        for handle_id in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            kernel32.SetConsoleMode(handle, mode.value | enable_vt)
        return True
    except Exception:  # non-console host, ctypes unavailable, etc.
        return False


G = Glyphs(True)  # replaced during startup by prepare_console()


class Palette:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domain_recon.py",
        description=(
            "Aggregate publicly available information about a domain: WHOIS/RDAP "
            "registration data, DNS records, passively discovered subdomains and "
            "email addresses. Output as a structured JSON file or a PDF report."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("domain", nargs="?", help="target domain, e.g. example.com")
    parser.add_argument("--version", action="version", version=f"domain_recon {__version__}")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline checks and write a sample report, then exit")

    out = parser.add_argument_group("output")
    out.add_argument("-f", "--format", choices=("json", "pdf", "both"), default="json",
                     help="output format (default: json)")
    out.add_argument("-o", "--output", metavar="PATH",
                     help="output file or base name without extension; '-' streams JSON to stdout")
    out.add_argument("--outdir", metavar="DIR", default=".",
                     help="directory for generated files (default: current directory)")
    out.add_argument("--page-size", choices=("letter", "a4"), default="letter", help="PDF page size")
    out.add_argument("--compact-json", action="store_true", help="write JSON without indentation")

    scope = parser.add_argument_group("collection scope")
    scope.add_argument("--modules", default=",".join(MODULES),
                       help=f"comma-separated modules to run (default: {','.join(MODULES)})")
    scope.add_argument("--skip", default="", help="comma-separated modules to skip")
    scope.add_argument("--sources", default=None,
                       help="comma-separated subdomain sources (default: all available)")
    scope.add_argument("--list-sources", action="store_true",
                       help="list subdomain sources and exit")
    scope.add_argument("--no-resolve", action="store_true",
                       help="do not resolve discovered subdomains")
    scope.add_argument("--max-resolve", type=int, default=2000,
                       help="cap on subdomains to resolve (default: 2000)")
    scope.add_argument("--no-reverse", action="store_true", help="skip reverse DNS lookups")
    scope.add_argument("--no-crawl", action="store_true",
                       help="do not fetch the target's web pages for emails")
    scope.add_argument("--pages", type=int, default=25, help="max pages to crawl (default: 25)")
    scope.add_argument("--depth", type=int, default=2, help="max crawl link depth (default: 2)")
    scope.add_argument("--ignore-robots", action="store_true",
                       help="crawl pages disallowed by robots.txt (off by default)")

    net = parser.add_argument_group("network")
    net.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout (default: 20)")
    net.add_argument("--dns-timeout", type=float, default=5.0, help="DNS timeout (default: 5)")
    net.add_argument("--workers", type=int, default=10, help="worker threads (default: 10)")
    net.add_argument("--rate", type=float, default=0.5,
                     help="minimum seconds between requests to one host (default: 0.5)")
    net.add_argument("--resolvers", help="comma-separated DNS resolvers, e.g. 1.1.1.1,8.8.8.8")
    net.add_argument("--user-agent", help="custom User-Agent header")
    net.add_argument("--proxy", help="HTTP/HTTPS proxy URL")
    net.add_argument("--insecure", action="store_true",
                     help="disable TLS certificate verification")

    log = parser.add_argument_group("logging")
    log.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug")
    log.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    log.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    return parser


def resolve_modules(args, parser) -> tuple:
    requested = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
    skipped = {m.strip().lower() for m in args.skip.split(",") if m.strip()}
    unknown = [m for m in requested + list(skipped) if m not in MODULES]
    if unknown:
        parser.error(
            f"unknown module(s): {', '.join(sorted(set(unknown)))}. "
            f"Choose from: {', '.join(MODULES)}"
        )
    selected = tuple(m for m in MODULES if m in requested and m not in skipped)
    if not selected:
        parser.error("no modules selected")
    return selected


def output_paths(args, domain: str) -> dict:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if args.output and args.output != "-":
        base = Path(args.output)
        if base.suffix.lower() in (".json", ".pdf"):
            base = base.with_suffix("")
    else:
        base = Path(args.outdir) / f"{domain.replace('.', '_')}_recon_{stamp}"
    return {"json": base.with_suffix(".json"), "pdf": base.with_suffix(".pdf")}


def print_summary(result: dict, palette: Palette, stream) -> None:
    summary = result.get("summary", {})
    meta = result.get("meta", {})

    def write(text: str = "") -> None:
        print(text, file=stream)

    write()
    write(palette.bold(f"  Target: {meta.get('target')}")
          + palette.dim(f"   ({human_duration(meta.get('elapsed_seconds', 0))})"))
    write(palette.dim("  " + G.rule * 58))

    rows = [
        ("Registrar", summary.get("registrar") or G.dash),
        ("Created / expires",
         f"{(summary.get('created') or G.dash)[:10]} {G.to} "
         f"{(summary.get('expires') or G.dash)[:10]}"),
        ("DNS records",
         f"{summary.get('dns_records_total', 0)} across {summary.get('dns_record_types', 0)} types"),
        ("Mail",
         f"SPF {summary.get('spf') or G.dash} {G.sep} DMARC {summary.get('dmarc') or G.dash} "
         f"{G.sep} DKIM {summary.get('dkim_selectors_found', 0)} selector(s)"
         + (f" {G.sep} {summary['mail_provider']}" if summary.get("mail_provider") else "")),
        ("Subdomains",
         f"{summary.get('subdomains_found', 0)} found"
         + (f", {summary['subdomains_resolving']} resolving"
            if summary.get("subdomains_resolving") is not None else "")),
        ("Emails",
         f"{summary.get('emails_found', 0)} found "
         f"({summary.get('emails_on_domain', 0)} on-domain)"),
    ]
    for label, value in rows:
        write(f"  {palette.cyan(label.ljust(18))} {value}")

    observations = summary.get("observations", [])
    if observations:
        write()
        write(palette.bold("  Observations"))
        for note in observations:
            write(f"  {palette.yellow(G.bullet)} {note}")

    if summary.get("source_errors"):
        write()
        write(palette.dim(
            f"  {summary['source_errors']} source(s) errored or were skipped "
            f"{G.dash} see the report appendix."
        ))
    write()


def main(argv: Optional[list] = None) -> int:
    global G

    parser = build_parser()
    args = parser.parse_args(argv)
    G = prepare_console()
    palette = Palette(
        enabled=not args.no_color and sys.stderr.isatty() and enable_ansi_colors()
    )

    if args.list_sources:
        print("Subdomain sources:")
        for name in sorted(SUBDOMAIN_SOURCES):
            print(f"  {name:<16}{'(requires API key)' if name in KEYED_SOURCES else ''}")
        return 0

    if args.self_test:
        setup_logging(args.verbose, args.quiet)
        return self_test(Path(args.outdir))

    if not args.domain:
        parser.error("a domain is required (or use --self-test / --list-sources)")

    setup_logging(args.verbose, args.quiet)
    stdout_json = args.output == "-"
    progress_stream = sys.stderr

    try:
        domain = normalize_domain(args.domain)
    except ReconError as exc:
        print(palette.red(f"error: {exc}"), file=sys.stderr)
        return 2

    modules = resolve_modules(args, parser)
    if args.format in ("pdf", "both"):
        if stdout_json:
            parser.error("'-o -' streams JSON only; choose --format json or a real output path")
        if not REPORTLAB_AVAILABLE:
            print(palette.red(
                "error: PDF output requires reportlab.  pip install reportlab\n"
                "       (or use --format json, which needs no extra package)"
            ), file=sys.stderr)
            return 1

    if not args.quiet:
        print(palette.cyan(BANNER.format(version=__version__, dash=G.dash)), file=progress_stream)
        print(palette.dim("  Public sources only. Use with authorization.\n"),
              file=progress_stream)

    def progress(stage: str, message: str) -> None:
        if not args.quiet:
            print(f"  {palette.green(G.arrow)} {palette.bold(stage.ljust(11))} {message}",
                  file=progress_stream, flush=True)

    options = ReconOptions(
        domain=domain,
        modules=modules,
        timeout=args.timeout,
        dns_timeout=args.dns_timeout,
        workers=max(1, args.workers),
        rate_limit=max(0.0, args.rate),
        nameservers=(
            [ns.strip() for ns in args.resolvers.split(",") if ns.strip()]
            if args.resolvers else None
        ),
        subdomain_sources=(
            [s.strip() for s in args.sources.split(",") if s.strip()] if args.sources else None
        ),
        resolve_subdomains=not args.no_resolve,
        max_resolve=max(0, args.max_resolve),
        reverse_dns=not args.no_reverse,
        crawl=not args.no_crawl,
        max_pages=max(1, args.pages),
        max_depth=max(0, args.depth),
        respect_robots=not args.ignore_robots,
        user_agent=args.user_agent,
        proxy=args.proxy,
        verify_tls=not args.insecure,
    )

    try:
        result = run_recon(options, progress=progress)
    except KeyboardInterrupt:
        print(palette.red("\ninterrupted — no report written"), file=sys.stderr)
        return 130
    except Exception as exc:  # surface unexpected failures without a traceback wall
        print(palette.red(f"error: unexpected failure: {exc}"), file=sys.stderr)
        if args.verbose >= 2:
            raise
        return 1

    if stdout_json:
        json.dump(result, sys.stdout, indent=None if args.compact_json else 2, default=str)
        sys.stdout.write("\n")
        return 0

    paths = output_paths(args, domain)
    written: list[Path] = []
    try:
        if args.format in ("json", "both"):
            written.append(write_json(result, paths["json"], pretty=not args.compact_json))
        if args.format in ("pdf", "both"):
            written.append(write_pdf(result, paths["pdf"], page_size=args.page_size))
    except (OSError, ReconError) as exc:
        print(palette.red(f"error: could not write report: {exc}"), file=sys.stderr)
        return 1

    if not args.quiet:
        print_summary(result, palette, progress_stream)
        for path in written:
            size_kb = path.stat().st_size / 1024
            print(f"  {palette.green(G.check)} {path}  {palette.dim(f'({size_kb:.0f} KB)')}",
                  file=progress_stream)
        print(file=progress_stream)

    for path in written:  # machine-readable paths on stdout
        print(str(path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
