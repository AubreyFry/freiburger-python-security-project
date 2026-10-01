#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_scanner.py - turn Nmap service scans into a prioritized CVE report.

CSIT 2033 - Week 6 Lab: Vulnerability scanner (CVE lookup integration)
Cybersecurity strategy: Defensive

Pipeline
  1. Parse service/version data from Nmap XML (nmap -sV -oX) or manual input.
  2. Resolve each service to a CPE 2.3 name (from Nmap, from manual input, or
     from a built-in table of common products).
  3. Query the NVD CVE API 2.0 for CVEs that affect that exact version.
  4. Prioritize: CISA Known Exploited Vulnerabilities and CVSS 9.0+ first,
     then CVSS 7.0+ and CVEs with public exploit references.
  5. Write a self-contained HTML report (optionally PDF and JSON) with
     remediation links for every finding.

Examples
  python vuln_scanner.py -x scan.xml
  python vuln_scanner.py -x scan.xml -o vuln_report -f html,pdf,json
  python vuln_scanner.py -m "OpenSSH 7.2p2" -m "10.0.0.5:80 Apache httpd 2.4.49"
  python vuln_scanner.py --manual-file services.csv
  python vuln_scanner.py --demo            # offline run on synthetic data
  python vuln_scanner.py --self-test       # offline checks, no network

Requirements
  Python 3.8+ and the standard library. Optional extras:
    reportlab   - PDF output          (pip install reportlab)
    defusedxml  - hardened XML parser (pip install defusedxml)
  A free NVD API key raises the rate limit from 5 to 50 requests per
  30 seconds. Pass --api-key or set the NVD_API_KEY environment variable.

This product uses data from the NVD API but is not endorsed or certified by
the NVD.
"""

from __future__ import annotations

import argparse
import csv
import html
import io
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, OrderedDict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from functools import cmp_to_key
from typing import Any, Dict, List, Optional, Sequence, Tuple
from xml.etree.ElementTree import ParseError as XMLParseError

try:  # hardened parser when available
    import defusedxml.ElementTree as ET  # type: ignore
    SAFE_XML = True
except ImportError:  # pragma: no cover - depends on the environment
    import xml.etree.ElementTree as ET
    SAFE_XML = False

TOOL = "vuln_scanner.py"
__version__ = "1.0.0"

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{}"
CVE_ORG_URL = "https://www.cve.org/CVERecord?id={}"
CWE_URL = "https://cwe.mitre.org/data/definitions/{}.html"
KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={}"
NVD_KEY_URL = "https://nvd.nist.gov/developers/request-an-api-key"
NVD_NOTICE = ("This product uses data from the NVD API but is not endorsed or "
              "certified by the NVD.")

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None", "Unscored"]
SEV_HEX = {"Critical": "#8C1C2C", "High": "#C2461B", "Medium": "#A87C00",
           "Low": "#2F7466", "None": "#7A8494", "Unscored": "#9AA3B0"}
PRIORITY_LABEL = {1: "Fix now", 2: "Fix soon", 3: "Schedule", 4: "Track"}
PRIORITY_HEX = {1: SEV_HEX["Critical"], 2: SEV_HEX["High"],
                3: SEV_HEX["Medium"], 4: SEV_HEX["Unscored"]}

CONFIDENCE = {"nvd-cpe": "High", "local-range": "Medium", "keyword": "Low"}
CONFIDENCE_RANK = {"High": 0, "Medium": 1, "Low": 2}
METHOD_TEXT = {
    "nvd-cpe": "NVD matched this exact CPE and version (isVulnerable).",
    "local-range": ("Product-wide NVD query, checked locally against each "
                    "CVE's affected version ranges."),
    "keyword": ("Keyword search of CVE descriptions. Low confidence: verify "
                "each result by hand."),
}
ORIGIN_TEXT = {"nmap": "reported by Nmap", "manual": "from manual input",
               "alias": "mapped from the product name"}

REF_TAG_PRIORITY = ("Patch", "Vendor Advisory", "Mitigation", "Release Notes",
                    "Third Party Advisory")
KEYWORD_RESULT_LIMIT = 25

# Product name (as Nmap or a person writes it) -> NVD vendor:product pairs.
# Used when Nmap reports no CPE, or when its CPE vendor is unknown to NVD.
# Matched on word boundaries, first hit wins, so specific names come first.
PRODUCT_ALIASES: List[Tuple[str, List[Tuple[str, str]]]] = [
    ("openssh", [("openbsd", "openssh")]),
    ("dropbear", [("dropbear_ssh_project", "dropbear_ssh")]),
    ("apache tomcat", [("apache", "tomcat")]),
    ("tomcat", [("apache", "tomcat")]),
    ("apache httpd", [("apache", "http_server")]),
    ("apache http server", [("apache", "http_server")]),
    ("nginx", [("f5", "nginx"), ("nginx", "nginx")]),
    ("lighttpd", [("lighttpd", "lighttpd")]),
    ("microsoft iis", [("microsoft", "internet_information_services")]),
    ("jetty", [("eclipse", "jetty")]),
    ("vsftpd", [("vsftpd_project", "vsftpd"), ("beasts", "vsftpd")]),
    ("proftpd", [("proftpd", "proftpd")]),
    ("pure-ftpd", [("pureftpd", "pure-ftpd")]),
    ("mariadb", [("mariadb", "mariadb")]),
    ("mysql", [("oracle", "mysql"), ("mysql", "mysql")]),
    ("postgresql", [("postgresql", "postgresql")]),
    ("redis", [("redis", "redis")]),
    ("mongodb", [("mongodb", "mongodb")]),
    ("elasticsearch", [("elastic", "elasticsearch")]),
    ("samba", [("samba", "samba")]),
    ("isc bind", [("isc", "bind")]),
    ("bind", [("isc", "bind")]),
    ("dnsmasq", [("thekelleys", "dnsmasq")]),
    ("exim", [("exim", "exim")]),
    ("postfix", [("postfix", "postfix")]),
    ("dovecot", [("dovecot", "dovecot")]),
    ("squid", [("squid-cache", "squid")]),
    ("haproxy", [("haproxy", "haproxy")]),
    ("openssl", [("openssl", "openssl")]),
    ("php", [("php", "php")]),
    ("node.js", [("nodejs", "node.js")]),
    ("grafana", [("grafana", "grafana")]),
    ("jenkins", [("jenkins", "jenkins")]),
]

# Distribution markers in banners. Distros backport fixes without changing the
# upstream version, so version-based matching over-reports on these hosts.
DISTRO_HINTS: List[Tuple["re.Pattern[str]", str, str]] = [
    (re.compile(r"ubuntu", re.I), "Ubuntu", "https://ubuntu.com/security/cves"),
    (re.compile(r"debian|\+deb\d|\bdeb\d+u\d", re.I), "Debian",
     "https://security-tracker.debian.org/tracker/"),
    (re.compile(r"red ?hat|rhel|centos|rocky|almalinux|\bel[6-9]\b", re.I),
     "Red Hat family", "https://access.redhat.com/security/security-updates/cve"),
    (re.compile(r"suse", re.I), "SUSE", "https://www.suse.com/security/cve/"),
    (re.compile(r"alpine", re.I), "Alpine", "https://security.alpinelinux.org/"),
    (re.compile(r"freebsd", re.I), "FreeBSD",
     "https://www.freebsd.org/security/advisories/"),
]


# ---------------------------------------------------------------------------
# Errors and logging
# ---------------------------------------------------------------------------

class InputError(Exception):
    """The input could not be used (missing file, not Nmap XML, bad entry)."""


class NVDError(Exception):
    """An NVD API request failed."""


class ReportDependencyError(Exception):
    """An optional output format needs a package that is not installed."""


class Log:
    """Plain ASCII console output; safe on Windows cp1252 consoles."""

    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self.warnings: List[str] = []

    def info(self, msg: str = "") -> None:
        if not self.quiet:
            print(msg, flush=True)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)
        print(f"warning: {msg}", file=sys.stderr, flush=True)


def _configure_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

_VERSION_TOKEN = re.compile(r"\d+|[a-z]+")
_PRE_RELEASE = {"dev": 0, "alpha": 1, "beta": 2, "pre": 3, "preview": 3,
                "rc": 4, "cr": 4}


def _version_key(version: str) -> List[Tuple[int, int, str]]:
    """Tokenize a version so that 7.2 < 7.2p1 < 7.2p2 < 7.3 and 2.0rc1 < 2.0.

    Each token is (kind, number, text): kind 2 = number, 1 = post-release
    letters (p1, k, patch), -1 = pre-release (alpha, beta, rc). Missing
    tokens compare as kind 0, which sits between pre- and post-release.
    """
    v = (version or "").strip().lower()
    if len(v) > 1 and v[0] == "v" and v[1].isdigit():
        v = v[1:]
    raw = _VERSION_TOKEN.findall(v)
    key: List[Tuple[int, int, str]] = []
    for i, tok in enumerate(raw):
        if tok.isdigit():
            key.append((2, int(tok), ""))
            continue
        next_is_number = i + 1 < len(raw) and raw[i + 1].isdigit()
        if tok in _PRE_RELEASE:
            key.append((-1, _PRE_RELEASE[tok], ""))
        elif tok in ("a", "b") and next_is_number:  # 3.0a1 / 3.0b2
            key.append((-1, 1 if tok == "a" else 2, ""))
        else:                                      # 7.2p2 / 1.0.2k
            key.append((1, 0, tok))
    return key


def compare_versions(a: str, b: str) -> int:
    """Return -1, 0 or 1. Trailing zeros are ignored (1.0 == 1.0.0).

    Where one version runs out of tokens it is padded with a zero when the
    other side continues with a number, and with a neutral marker otherwise,
    so 2.0rc1 < 2.0 < 2.0p1 and 1.0 == 1.0.0.
    """
    ka, kb = _version_key(a), _version_key(b)
    zero, neutral = (2, 0, ""), (0, 0, "")
    for i in range(max(len(ka), len(kb))):
        x = ka[i] if i < len(ka) else None
        y = kb[i] if i < len(kb) else None
        if x is None:
            x = zero if y[0] == 2 else neutral
        if y is None:
            y = zero if x[0] == 2 else neutral
        if x != y:
            return -1 if x < y else 1
    return 0


def max_version(versions: Sequence[str]) -> str:
    return max(versions, key=cmp_to_key(compare_versions)) if versions else ""


def clean_version(raw: str) -> str:
    """'6.6.1p1 Ubuntu 2ubuntu2.13' -> '6.6.1p1'."""
    for tok in (raw or "").replace(",", " ").split():
        tok = tok.strip("()[];")
        if tok and tok[0].isdigit():
            return tok.rstrip("-_.")
    return ""


def detect_distro(text: str) -> Optional[Tuple[str, str]]:
    for pattern, name, url in DISTRO_HINTS:
        if pattern.search(text or ""):
            return name, url
    return None


# ---------------------------------------------------------------------------
# CPE handling
# ---------------------------------------------------------------------------

_CPE23_SPLIT = re.compile(r"(?<!\\):")


def _cpe_escape(value: str) -> str:
    if value in ("*", "-"):
        return value
    if not value:
        return "*"
    return re.sub(r"([^A-Za-z0-9._\-])", r"\\\1", value)


@dataclass(frozen=True)
class CPE:
    part: str
    vendor: str
    product: str
    version: str = "*"
    update: str = "*"

    @property
    def has_version(self) -> bool:
        return self.version not in ("*", "-", "")

    @property
    def full_version(self) -> str:
        """Version with the update field folded in: 7.2 + p2 -> 7.2p2."""
        if self.update in ("*", "-", ""):
            return self.version
        return self.version + self.update

    @property
    def vendor_product(self) -> str:
        return f"{self.vendor}:{self.product}"

    def to23(self) -> str:
        fields = [self.part, self.vendor, self.product, self.version,
                  self.update] + ["*"] * 6
        return "cpe:2.3:" + ":".join(_cpe_escape(f) for f in fields)

    def match_string(self) -> str:
        """Every version of this product, for virtualMatchString queries."""
        return CPE(self.part, self.vendor, self.product).to23()


def parse_cpe(text: str) -> Optional[CPE]:
    """Parse a CPE 2.3 formatted string or a CPE 2.2 URI (Nmap's format)."""
    s = (text or "").strip()
    low = s.lower()
    if low.startswith("cpe:2.3:"):
        fields = _CPE23_SPLIT.split(s)[2:] + ["*"] * 11
        vals = [re.sub(r"\\(.)", r"\1", f).lower() for f in fields[:5]]
    elif low.startswith("cpe:/"):
        fields = s[5:].split(":") + [""] * 5
        vals = [urllib.parse.unquote(f).lower() for f in fields[:5]]
    else:
        return None
    part, vendor, product, version, update = vals
    if part not in ("a", "o", "h") or not vendor or not product:
        return None
    return CPE(part, vendor, product, version or "*", update or "*")


def alias_candidates(product: str) -> List[Tuple[str, str]]:
    name = " ".join((product or "").lower().split())
    for alias, pairs in PRODUCT_ALIASES:
        if re.search(r"(?<![\w.-])" + re.escape(alias) + r"(?![\w-])", name):
            return pairs
    return []


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Service:
    host: str = ""
    port: Optional[int] = None
    protocol: str = "tcp"
    hostname: str = ""
    name: str = ""
    product: str = ""
    version_raw: str = ""
    extrainfo: str = ""
    ostype: str = ""
    cpes: List[str] = field(default_factory=list)
    source: str = "nmap"          # nmap | manual
    detection: str = ""           # Nmap service method: probed | table
    # Filled in during assessment
    version: str = ""
    cpe: Optional[CPE] = None
    cpe_origin: str = ""          # nmap | manual | alias
    status: str = "pending"       # pending | assessed | not_assessed | error
    method: str = ""
    reason: str = ""
    distro: Optional[Tuple[str, str]] = None
    notes: List[str] = field(default_factory=list)
    findings: List["Finding"] = field(default_factory=list)

    @property
    def endpoint(self) -> str:
        host = self.host
        if host and ":" in host:
            host = f"[{host}]"
        if host and self.port:
            return f"{host}:{self.port}/{self.protocol}"
        if host:
            return host
        if self.port:
            return f"port {self.port}/{self.protocol}"
        return "manual entry"

    @property
    def label(self) -> str:
        name = self.product or self.name or "unknown service"
        return f"{name} {self.version}" if self.version else name


@dataclass
class CVERecord:
    id: str
    description: str = ""
    published: str = ""
    last_modified: str = ""
    status: str = ""
    score: Optional[float] = None
    cvss_version: str = ""
    vector: str = ""
    cvss_source: str = ""
    cwes: List[str] = field(default_factory=list)
    references: List[Dict[str, Any]] = field(default_factory=list)
    kev: bool = False
    kev_added: str = ""
    kev_due: str = ""
    kev_action: str = ""
    kev_name: str = ""
    exploit_ref: bool = False
    configurations: List[Dict[str, Any]] = field(default_factory=list, repr=False)

    @property
    def severity(self) -> str:
        return severity_for(self.score)

    @property
    def rejected(self) -> bool:
        return (self.status.lower() == "rejected"
                or self.description.startswith("** REJECT **"))

    @classmethod
    def from_nvd(cls, item: Dict[str, Any]) -> Optional["CVERecord"]:
        cve = item.get("cve", item) if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not cve.get("id"):
            return None
        desc = next((d.get("value", "") for d in cve.get("descriptions") or []
                     if d.get("lang") == "en"), "")
        score, version, vector, source = pick_cvss(cve.get("metrics") or {})
        cwes = sorted({d.get("value", "")
                       for w in cve.get("weaknesses") or []
                       for d in w.get("description") or []
                       if re.fullmatch(r"CWE-\d+", d.get("value", ""))},
                      key=lambda c: int(c[4:]))
        refs = []
        for ref in cve.get("references") or []:
            url = safe_url(ref.get("url", ""))
            if url:
                refs.append({"url": url, "source": ref.get("source", ""),
                             "tags": [t for t in ref.get("tags") or []
                                      if isinstance(t, str)]})
        return cls(
            id=str(cve["id"]),
            description=" ".join(desc.split()),
            published=cve.get("published", ""),
            last_modified=cve.get("lastModified", ""),
            status=cve.get("vulnStatus", ""),
            score=score, cvss_version=version, vector=vector,
            cvss_source=source, cwes=cwes, references=refs,
            kev="cisaExploitAdd" in cve,
            kev_added=cve.get("cisaExploitAdd", ""),
            kev_due=cve.get("cisaActionDue", ""),
            kev_action=cve.get("cisaRequiredAction", ""),
            kev_name=cve.get("cisaVulnerabilityName", ""),
            exploit_ref=any("Exploit" in r["tags"] for r in refs),
            configurations=cve.get("configurations") or [],
        )


@dataclass
class Finding:
    cve: CVERecord
    service: Service
    method: str
    confidence: str
    fixed_in: str = ""
    affected_through: str = ""

    @property
    def priority(self) -> int:
        return priority_for(self.cve)

    def sort_key(self) -> Tuple:
        c = self.cve
        m = re.match(r"CVE-(\d+)-(\d+)", c.id)
        newest = (-int(m.group(1)), -int(m.group(2))) if m else (0, 0)
        return (self.priority, 0 if c.kev else 1,
                -(c.score if c.score is not None else -1.0),
                0 if c.exploit_ref else 1,
                CONFIDENCE_RANK.get(self.confidence, 3), newest, c.id)


@dataclass
class Report:
    title: str
    generated: datetime
    services: List[Service]
    findings: List[Finding]
    scans: List[Dict[str, Any]]
    manual_count: int
    stats: Dict[str, Any]
    demo: bool = False
    min_cvss: float = 0.0
    nvd_requests: int = 0
    cache_hits: int = 0
    api_key_used: bool = False

    @property
    def generated_str(self) -> str:
        return self.generated.strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

_CVSS_KEYS = (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
              ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0"))


def pick_cvss(metrics: Dict[str, Any]) -> Tuple[Optional[float], str, str, str]:
    """Prefer v3.1, then v3.0, v4.0, v2.0; within a version prefer NVD's own
    (Primary) score over a CNA's (Secondary) score."""
    for key, label in _CVSS_KEYS:
        entries = [e for e in metrics.get(key) or [] if isinstance(e, dict)]
        if not entries:
            continue
        entries.sort(key=lambda e: 0 if e.get("type") == "Primary" else 1)
        for entry in entries:
            data = entry.get("cvssData") or {}
            try:
                score = float(data.get("baseScore"))
            except (TypeError, ValueError):
                continue
            return score, label, str(data.get("vectorString", "")), \
                str(entry.get("source", ""))
    return None, "", "", ""


def severity_for(score: Optional[float]) -> str:
    """CVSS v3/v4 qualitative bands (v2-only scores are mapped onto them)."""
    if score is None:
        return "Unscored"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 0.1:
        return "Low"
    return "None"


def priority_for(cve: CVERecord) -> int:
    s = cve.score
    if cve.kev or (s is not None and s >= 9.0):
        return 1
    if s is not None and (s >= 7.0 or (cve.exploit_ref and s >= 4.0)):
        return 2
    if s is not None and s >= 4.0:
        return 3
    return 4


def safe_url(url: Any) -> str:
    """Only plain http(s) links make it into reports."""
    if not isinstance(url, str):
        return ""
    url = url.strip()
    if any(ch in url for ch in '"<>\\\x00\r\n\t '):
        return ""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return ""
    if parts.scheme.lower() in ("http", "https") and parts.netloc:
        return url
    return ""


def remediation_refs(cve: CVERecord, limit: int = 3) -> List[Dict[str, Any]]:
    ranked = []
    for idx, ref in enumerate(cve.references):
        ranks = [REF_TAG_PRIORITY.index(t) for t in ref["tags"] if t in REF_TAG_PRIORITY]
        if ranks:
            ranked.append((min(ranks), idx, ref))
    ranked.sort(key=lambda x: (x[0], x[1]))
    return [r for _, _, r in ranked[:limit]]


def ref_label(ref: Dict[str, Any]) -> str:
    tag = next((t for t in REF_TAG_PRIORITY if t in ref.get("tags", [])),
               (ref.get("tags") or ["Reference"])[0])
    host = urllib.parse.urlsplit(ref["url"]).netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return f"{tag} ({host})"


def _gist(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    first = m.group(1) if m else text
    if len(first) > limit:
        first = first[:limit - 3].rsplit(" ", 1)[0].rstrip(",;:") + "..."
    return first


def _truncate(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    return text[:limit - 3].rsplit(" ", 1)[0].rstrip(",;:") + "..."


# ---------------------------------------------------------------------------
# Matching a version against a CVE's NVD configurations
# ---------------------------------------------------------------------------

_RANGE_KEYS = ("versionStartIncluding", "versionStartExcluding",
               "versionEndIncluding", "versionEndExcluding")


def _same_release(target: str, crit: CPE) -> bool:
    """Exact criteria match. A wildcard update also accepts point releases of
    the same version (criteria 7.0 with update * matches 7.0p1)."""
    if compare_versions(target, crit.full_version) == 0:
        return True
    if crit.update == "*":
        base, tkey = _version_key(crit.version), _version_key(target)
        if len(tkey) > len(base) and tkey[:len(base)] == base \
                and tkey[len(base)][0] != 2:
            return True
    return False


def _criteria_applies(match: Dict[str, Any], crit: CPE, target: str) -> Optional[bool]:
    if any(match.get(k) for k in _RANGE_KEYS):
        lo_in, lo_ex = match.get("versionStartIncluding"), match.get("versionStartExcluding")
        hi_in, hi_ex = match.get("versionEndIncluding"), match.get("versionEndExcluding")
        if lo_in and compare_versions(target, lo_in) < 0:
            return False
        if lo_ex and compare_versions(target, lo_ex) <= 0:
            return False
        if hi_in and compare_versions(target, hi_in) > 0:
            return False
        if hi_ex and compare_versions(target, hi_ex) >= 0:
            return False
        return True
    if crit.version == "*":
        return True          # every version is affected
    if crit.version == "-":
        return None          # "no version" entries say nothing about ours
    return _same_release(target, crit)


def match_details(configurations: List[Dict[str, Any]], cpe: CPE,
                  target: str) -> Tuple[bool, str, str]:
    """Return (affected, fixed_in, affected_through) for vendor:product at
    version `target`. Platform (AND) conditions are not evaluated, so a CVE
    that only applies on a specific OS still counts as a match."""
    affected, fixed, through = False, [], []
    for conf in configurations or []:
        if conf.get("negate"):
            continue
        for node in conf.get("nodes") or []:
            if node.get("negate"):
                continue
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                crit = parse_cpe(m.get("criteria", ""))
                if not crit or crit.vendor != cpe.vendor or crit.product != cpe.product:
                    continue
                if _criteria_applies(m, crit, target):
                    affected = True
                    if m.get("versionEndExcluding"):
                        fixed.append(str(m["versionEndExcluding"]))
                    elif m.get("versionEndIncluding"):
                        through.append(str(m["versionEndIncluding"]))
    return affected, max_version(fixed), max_version(through)


# ---------------------------------------------------------------------------
# Input: Nmap XML
# ---------------------------------------------------------------------------

def _pick_address(host_el: Any) -> str:
    addrs = {a.get("addrtype"): a.get("addr", "") for a in host_el.findall("address")}
    return addrs.get("ipv4") or addrs.get("ipv6") or addrs.get("mac") or "unknown"


def _pick_hostname(host_el: Any) -> str:
    names = host_el.findall("hostnames/hostname")
    for wanted in ("user", "PTR"):
        for n in names:
            if n.get("type") == wanted and n.get("name"):
                return n.get("name")
    return names[0].get("name", "") if names else ""


def parse_nmap_xml_bytes(raw: bytes, source_name: str = "scan.xml") -> Tuple[List[Service], Dict[str, Any]]:
    if not raw.strip():
        raise InputError(f"{source_name} is empty. Did the Nmap scan finish?")
    if not SAFE_XML and b"<!ENTITY" in raw:
        raise InputError(f"{source_name} declares XML entities; refusing to parse it "
                         "without defusedxml (pip install defusedxml).")
    try:
        root = ET.fromstring(raw)
    except (XMLParseError, ValueError) as exc:
        hint = (" The file looks truncated; was the scan interrupted?"
                if b"</nmaprun>" not in raw else "")
        raise InputError(f"{source_name} is not valid XML ({exc}).{hint}") from exc
    if root.tag != "nmaprun":
        raise InputError(f"{source_name} is not Nmap XML (root element <{root.tag}>). "
                         "Save Nmap output with -oX.")
    meta: Dict[str, Any] = {"file": source_name, "nmap_version": root.get("version", ""),
                            "args": root.get("args", ""), "started": root.get("startstr", ""),
                            "hosts_total": 0, "hosts_up": 0, "open_ports": 0}
    services: List[Service] = []
    for host in root.findall("host"):
        meta["hosts_total"] += 1
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        meta["hosts_up"] += 1
        addr, hostname = _pick_address(host), _pick_hostname(host)
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            meta["open_ports"] += 1
            svc = port.find("service")

            def attr(name: str, _svc: Any = svc) -> str:
                return (_svc.get(name) or "").strip() if _svc is not None else ""

            cpes = [c.text.strip() for c in (svc.findall("cpe") if svc is not None else [])
                    if c.text and c.text.strip()]
            try:
                portid: Optional[int] = int(port.get("portid", ""))
            except ValueError:
                portid = None
            services.append(Service(
                host=addr, hostname=hostname, port=portid,
                protocol=port.get("protocol", "tcp"), name=attr("name"),
                product=attr("product"), version_raw=attr("version"),
                extrainfo=attr("extrainfo"), ostype=attr("ostype"),
                cpes=cpes, source="nmap", detection=attr("method")))
    return services, meta


def parse_nmap_xml(path: str) -> Tuple[List[Service], Dict[str, Any]]:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror or exc}") from exc
    return parse_nmap_xml_bytes(raw, os.path.basename(path))


# ---------------------------------------------------------------------------
# Input: manual entries
# ---------------------------------------------------------------------------

_MANUAL_PREFIX = re.compile(
    r"^(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+):(?P<port>\d{1,5})"
    r"(?:/(?P<proto>tcp|udp|sctp))?\s+(?P<rest>\S.*)$", re.I)


def parse_manual_entry(text: str) -> Service:
    """Accepts 'OpenSSH 7.2p2', '10.0.0.5:80/tcp Apache httpd 2.4.49',
    '[2001:db8::1]:22 OpenSSH 8.9p1' or a CPE (2.2 or 2.3)."""
    entry = " ".join((text or "").split())
    if not entry:
        raise InputError("empty manual entry")
    host, port, proto, rest = "", None, "tcp", entry
    m = _MANUAL_PREFIX.match(entry)
    if m:
        host = m.group("host").strip("[]")
        port = int(m.group("port"))
        proto = (m.group("proto") or "tcp").lower()
        rest = m.group("rest")
        if not 0 < port < 65536:
            raise InputError(f"port out of range in manual entry: {text!r}")
    if rest.lower().startswith("cpe:"):
        token = rest.split()[0]
        cpe = parse_cpe(token)
        if not cpe:
            raise InputError(f"could not parse the CPE in manual entry: {text!r}")
        return Service(host=host, port=port, protocol=proto,
                       product=cpe.product.replace("_", " "),
                       version_raw=cpe.full_version if cpe.has_version else "",
                       cpes=[token], source="manual")
    tokens = rest.split()
    idx = next((i for i, t in enumerate(tokens) if t[0].isdigit()), None)
    if idx == 0:
        raise InputError(f"manual entry needs a product name before the version: {text!r}")
    product = " ".join(tokens[:idx]) if idx is not None else rest
    version = " ".join(tokens[idx:]) if idx is not None else ""
    return Service(host=host, port=port, protocol=proto, product=product,
                   version_raw=version, source="manual")


def parse_manual_file(path: str) -> List[Service]:
    """One manual entry per line, or a CSV with a header row containing
    product (and optionally host, port, protocol, version, cpe)."""
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        raise InputError(f"{path} has no entries")
    header = [h.strip().lower() for h in lines[0].split(",")]
    services: List[Service] = []
    if "product" in header or "cpe" in header:
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        for lineno, row in enumerate(reader, start=2):
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            if not (row.get("product") or row.get("cpe")):
                continue
            port = None
            if row.get("port"):
                if not row["port"].isdigit() or not 0 < int(row["port"]) < 65536:
                    raise InputError(f"{path} line {lineno}: bad port {row['port']!r}")
                port = int(row["port"])
            if row.get("cpe") and not parse_cpe(row["cpe"]):
                raise InputError(f"{path} line {lineno}: bad CPE {row['cpe']!r}")
            cpe = parse_cpe(row.get("cpe", ""))
            services.append(Service(
                host=row.get("host", ""), port=port,
                protocol=(row.get("protocol") or "tcp").lower(),
                product=row.get("product") or (cpe.product.replace("_", " ") if cpe else ""),
                version_raw=row.get("version") or (cpe.full_version if cpe and cpe.has_version else ""),
                cpes=[row["cpe"]] if row.get("cpe") else [], source="manual"))
    else:
        for lineno, line in enumerate(lines, start=1):
            try:
                services.append(parse_manual_entry(line))
            except InputError as exc:
                raise InputError(f"{path} entry {lineno}: {exc}") from exc
    return services


# ---------------------------------------------------------------------------
# NVD CVE API 2.0 client
# ---------------------------------------------------------------------------

class NVDClient:
    """Rate-limited, caching client for https://services.nvd.nist.gov.

    Without a key NVD allows 5 requests per rolling 30 seconds (50 with a
    key). The client spaces requests accordingly, retries on 403/429/5xx with
    backoff, and caches responses on disk so reruns cost nothing.
    """

    def __init__(self, api_key: Optional[str] = None, cache_file: Optional[str] = None,
                 cache_hours: float = 24.0, timeout: float = 45.0,
                 max_retries: int = 4, log: Optional[Log] = None) -> None:
        self.api_key = (api_key or "").strip() or None
        self.min_interval = 0.7 if self.api_key else 6.2
        self.cache_file = cache_file
        self.cache_ttl = max(0.0, cache_hours) * 3600
        self.timeout = timeout
        self.max_retries = max(1, max_retries)
        self.log = log or Log()
        self.requests_made = 0
        self.cache_hits = 0
        self._last_request = 0.0
        self._failures = 0            # consecutive queries that exhausted their retries
        self.max_failures = 2         # then stop calling NVD for the rest of the run
        self._cache: Dict[str, Any] = self._load_cache()

    # -- cache ---------------------------------------------------------------
    def _load_cache(self) -> Dict[str, Any]:
        if not self.cache_file or not os.path.exists(self.cache_file):
            return {}
        try:
            with open(self.cache_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            self.log.warn(f"ignoring unreadable cache file {self.cache_file}")
            return {}

    def _save_cache(self) -> None:
        if not self.cache_file:
            return
        folder = os.path.dirname(os.path.abspath(self.cache_file))
        try:
            fd, tmp = tempfile.mkstemp(prefix=".nvd_cache_", dir=folder)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._cache, fh)
            os.replace(tmp, self.cache_file)
        except OSError as exc:
            self.log.warn(f"could not write cache {self.cache_file}: {exc}")

    # -- HTTP ----------------------------------------------------------------
    def _throttle(self) -> None:
        wait = self.min_interval - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    @staticmethod
    def build_url(params: Dict[str, str], flags: Sequence[str] = ()) -> str:
        query = urllib.parse.urlencode(params, safe=":*", quote_via=urllib.parse.quote)
        for flag in flags:            # NVD flags take no value, e.g. &isVulnerable
            query += "&" + flag
        return f"{NVD_CVE_API}?{query}"

    def _get_json(self, url: str) -> Dict[str, Any]:
        cached = self._cache.get(url)
        if cached and time.time() - cached.get("ts", 0) < self.cache_ttl:
            self.cache_hits += 1
            if "error" in cached:     # a definite "no" such as 404 Invalid cpeName
                raise NVDError(cached["error"])
            return cached["data"]
        if self._failures >= self.max_failures:
            raise NVDError("skipped because NVD failed repeatedly earlier in this run")
        headers = {"User-Agent": f"{TOOL}/{__version__} (CSIT 2033 vulnerability lab)",
                   "Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        last_error = ""
        for attempt in range(self.max_retries):
            self._throttle()
            request = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                    body = resp.read()
                self.requests_made += 1
                data = json.loads(body.decode("utf-8"))
                if not isinstance(data, dict):
                    raise NVDError("unexpected response shape")
                self._cache[url] = {"ts": time.time(), "data": data}
                self._save_cache()
                self._failures = 0
                return data
            except urllib.error.HTTPError as exc:
                self.requests_made += 1
                detail = (exc.headers.get("message") if exc.headers else "") or exc.reason
                last_error = f"HTTP {exc.code}: {detail}"
                if exc.code not in (403, 429, 500, 502, 503, 504):
                    if exc.code in (400, 404):   # same answer next time; skip it on reruns
                        self._cache[url] = {"ts": time.time(), "error": last_error}
                        self._save_cache()
                    raise NVDError(last_error) from exc
            except (urllib.error.URLError, socket.timeout, TimeoutError,
                    ConnectionError) as exc:
                last_error = f"network error: {getattr(exc, 'reason', exc)}"
            except (ValueError, UnicodeDecodeError) as exc:
                raise NVDError(f"NVD returned invalid JSON: {exc}") from exc
            if attempt + 1 < self.max_retries:
                delay = min(60.0, self.min_interval * (2 ** attempt) + 2)
                self.log.info(f"      NVD {last_error}; retrying in {delay:.0f}s")
                time.sleep(delay)
        self._failures += 1
        if self._failures >= self.max_failures:
            self.log.warn("NVD is not responding; skipping the remaining lookups. "
                          "Re-run later (cached answers are kept).")
        raise NVDError(f"{last_error} (gave up after {self.max_retries} attempts)")

    def search(self, params: Dict[str, str], flags: Sequence[str] = (),
               max_pages: int = 10) -> Tuple[List[Dict[str, Any]], int]:
        """Run a CVE query, following pagination. Returns (items, totalResults)."""
        items: List[Dict[str, Any]] = []
        start, total = 0, 0
        for _ in range(max_pages):
            query = dict(params, resultsPerPage="2000", startIndex=str(start))
            data = self._get_json(self.build_url(query, flags))
            page = data.get("vulnerabilities") or []
            total = int(data.get("totalResults", len(page)) or 0)
            items.extend(page)
            start += len(page)
            if not page or start >= total:
                break
        return items, total


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------

@dataclass
class LookupResult:
    matches: List[Tuple[CVERecord, str, str]] = field(default_factory=list)
    method: str = ""
    product_known: bool = False
    error: str = ""


def prepare_service(svc: Service) -> None:
    """Pick the CPE to query and decide whether the service can be checked."""
    svc.version = clean_version(svc.version_raw)
    svc.distro = detect_distro(" ".join((svc.version_raw, svc.extrainfo, svc.ostype)))
    parsed = [c for c in (parse_cpe(x) for x in svc.cpes) if c]
    chosen = (next((c for c in parsed if c.part == "a" and c.has_version), None)
              or next((c for c in parsed if c.has_version), None)
              or next((c for c in parsed if c.part == "a"), None))
    if chosen and not chosen.has_version and svc.version:
        chosen = replace(chosen, version=svc.version.lower())
    if chosen and chosen.has_version:
        svc.cpe, svc.cpe_origin = chosen, svc.source
        if not svc.version:
            svc.version = chosen.full_version
    if svc.cpe or (svc.product and svc.version):
        svc.status = "pending"
        return
    svc.status = "not_assessed"
    if svc.name == "tcpwrapped":
        svc.reason = "tcpwrapped: the service closed the connection before sending a banner."
    elif svc.source == "nmap" and svc.detection == "table":
        svc.reason = ("Service name guessed from the port number only. "
                      "Re-run Nmap with -sV to detect versions.")
    elif not svc.product:
        svc.reason = "No product was identified from the service banner."
    else:
        svc.reason = (f"{svc.product} was identified but not its version, "
                      "so CVEs cannot be matched. Check the version by hand.")


class Assessor:
    def __init__(self, client: Any, log: Log, keyword_fallback: bool = True) -> None:
        self.client = client
        self.log = log
        self.keyword_fallback = keyword_fallback
        self._memo: Dict[str, LookupResult] = {}
        self._records: Dict[str, CVERecord] = {}

    def _record(self, item: Dict[str, Any]) -> Optional[CVERecord]:
        cve = item.get("cve", item) if isinstance(item, dict) else {}
        cid = cve.get("id") if isinstance(cve, dict) else None
        if cid and cid in self._records:
            return self._records[cid]
        rec = CVERecord.from_nvd(item)
        if rec:
            self._records[rec.id] = rec
        return rec

    def assess(self, services: List[Service]) -> None:
        for svc in services:
            prepare_service(svc)
        todo = [s for s in services if s.status == "pending"]
        if not todo:
            self.log.info("No services reported a version, so there is nothing to look up.")
            return
        interval = getattr(self.client, "min_interval", 0)
        if interval >= 5:
            self.log.info(f"Checking {len(todo)} service(s) against NVD. Without an API key NVD "
                          f"allows 5 requests per 30 s, so each lookup waits about {interval:.0f} s.")
        else:
            self.log.info(f"Checking {len(todo)} service(s) against NVD.")
        for idx, svc in enumerate(todo, 1):
            self.log.info(f"[{idx}/{len(todo)}] {svc.endpoint}  {svc.label}")
            self._assess_service(svc)
            found = len(svc.findings)
            if svc.status == "assessed":
                self.log.info(f"      {found} CVE{'s' if found != 1 else ''} "
                              f"({CONFIDENCE.get(svc.method, 'n/a').lower()} confidence)")

    def _candidates(self, svc: Service) -> List[Tuple[CPE, str]]:
        out: List[Tuple[CPE, str]] = []
        if svc.cpe:
            out.append((svc.cpe, svc.cpe_origin))
        version = svc.cpe.version if svc.cpe else svc.version.lower()
        update = svc.cpe.update if svc.cpe else "*"
        part = svc.cpe.part if svc.cpe and svc.cpe.part == "a" else "a"
        for vendor, product in alias_candidates(svc.product):
            cand = CPE(part, vendor, product, version, update)
            if version and all(c.vendor_product != cand.vendor_product for c, _ in out):
                out.append((cand, "alias"))
        return out

    def _assess_service(self, svc: Service) -> None:
        misses, errors = [], []
        for cpe, origin in self._candidates(svc):
            result = self._lookup(cpe)
            if result.error:
                errors.append(f"NVD lookup failed for {cpe.to23()}: {result.error}")
                continue
            if not result.product_known:
                misses.append(cpe.vendor_product)
                continue
            svc.cpe, svc.cpe_origin, svc.method, svc.status = cpe, origin, result.method, "assessed"
            if misses:
                svc.notes.append("NVD has no CVEs under " + ", ".join(misses)
                                 + f", so the product was matched as {cpe.vendor_product}.")
            self._attach(svc, result)
            svc.notes.extend(errors)
            return
        # A failed CPE lookup is not the same as an unknown product, so only
        # fall back to a keyword search when every CPE was definitely unknown.
        if self.keyword_fallback and svc.product and svc.version and not errors:
            result = self._keyword_lookup(svc)
            if not result.error:
                svc.method, svc.status = "keyword", "assessed"
                svc.notes.append("No NVD product name (CPE) could be found for this service, "
                                 "so results come from a keyword search and may not apply.")
                self._attach(svc, result)
                svc.notes.extend(errors)
                return
            errors.append(f"NVD keyword search failed: {result.error}")
        svc.notes.extend(errors)
        if errors:
            svc.status = "error"
            svc.reason = errors[-1]
        else:
            svc.status = "not_assessed"
            svc.reason = ("NVD has no records for "
                          + (", ".join(misses) if misses else "this product")
                          + ". Check the vendor's advisories by hand.")

    def _attach(self, svc: Service, result: LookupResult) -> None:
        seen = set()
        for rec, fixed, through in result.matches:
            if rec.id in seen or rec.rejected:
                continue
            seen.add(rec.id)
            svc.findings.append(Finding(cve=rec, service=svc, method=result.method,
                                        confidence=CONFIDENCE[result.method],
                                        fixed_in=fixed, affected_through=through))

    def _lookup(self, cpe: CPE) -> LookupResult:
        key = cpe.to23()
        if key in self._memo:
            return self._memo[key]
        target = cpe.full_version
        self.log.info(f"      NVD query: {key}")
        first_error = ""
        # Step 1: let NVD decide which CVEs affect this exact CPE.
        try:
            items, _ = self.client.search({"cpeName": key}, flags=("isVulnerable",))
            matches = []
            for item in items:
                rec = self._record(item)
                if rec and not rec.rejected:
                    hit, fixed, through = match_details(rec.configurations, cpe, target)
                    matches.append((rec, fixed if hit else "", through if hit else ""))
            if matches:
                result = LookupResult(matches, "nvd-cpe", True)
                self._memo[key] = result
                return result
        except NVDError as exc:
            first_error = str(exc)
            self.log.info(f"      exact-CPE query failed ({exc}); trying product-wide query")
        # Step 2: pull every CVE for the product and check version ranges here.
        # This catches version spellings NVD's matcher misses (7.2p2 vs 7.2:p2).
        try:
            items, total = self.client.search({"virtualMatchString": cpe.match_string()})
        except NVDError as exc:
            err = f"{first_error}; {exc}" if first_error and first_error != str(exc) else str(exc)
            result = LookupResult(error=err)
            self._memo[key] = result
            return result
        if total == 0:
            result = LookupResult([], "local-range", False)
        else:
            matches = []
            for item in items:
                rec = self._record(item)
                if not rec or rec.rejected:
                    continue
                hit, fixed, through = match_details(rec.configurations, cpe, target)
                if hit:
                    matches.append((rec, fixed, through))
            result = LookupResult(matches, "local-range", True)
        self._memo[key] = result
        return result

    def _keyword_lookup(self, svc: Service) -> LookupResult:
        phrase = f"{svc.product} {svc.version}"
        self.log.info(f"      NVD keyword search: {phrase!r}")
        try:
            items, _ = self.client.search({"keywordSearch": phrase}, max_pages=1)
        except NVDError as exc:
            return LookupResult(error=str(exc))
        first_word = svc.product.split()[0].lower()
        matches = []
        for item in items:
            rec = self._record(item)
            if rec and not rec.rejected and first_word in rec.description.lower():
                matches.append((rec, "", ""))
        matches.sort(key=lambda m: -(m[0].score or 0.0))
        return LookupResult(matches[:KEYWORD_RESULT_LIMIT], "keyword", True)


# ---------------------------------------------------------------------------
# Building the report model
# ---------------------------------------------------------------------------

def _host_sort_key(host: str) -> Tuple:
    try:
        ip = ipaddress.ip_address(host)
        return (0, ip.version, int(ip))
    except ValueError:
        return (1 if host else 2, 0, host.lower())


def dedupe_and_sort(services: List[Service]) -> List[Service]:
    seen, out = set(), []
    for s in services:
        key = (s.host, s.port, s.protocol, s.product.lower(), s.version_raw, tuple(s.cpes))
        if key not in seen:
            seen.add(key)
            out.append(s)
    out.sort(key=lambda s: (_host_sort_key(s.host), s.port or 0, s.protocol))
    return out


def compute_stats(services: List[Service], findings: List[Finding]) -> Dict[str, Any]:
    assessed = [s for s in services if s.status == "assessed"]
    severity = OrderedDict((k, 0) for k in SEVERITY_ORDER)
    priority = OrderedDict((k, 0) for k in PRIORITY_LABEL)
    for f in findings:
        severity[f.cve.severity] += 1
        priority[f.priority] += 1
    return {
        "hosts": len({s.host for s in services if s.host}),
        "services": len(services),
        "assessed": len(assessed),
        "affected": sum(1 for s in assessed if s.findings),
        "not_assessed": sum(1 for s in services if s.status == "not_assessed"),
        "errors": sum(1 for s in services if s.status == "error"),
        "findings": len(findings),
        "unique_cves": len({f.cve.id for f in findings}),
        "kev": sum(1 for f in findings if f.cve.kev),
        "severity": dict(severity),
        "priority": dict(priority),
    }


def assess_and_build(services: List[Service], scans: List[Dict[str, Any]],
                     manual_count: int, client: Any, log: Log,
                     keyword_fallback: bool = True, min_cvss: float = 0.0,
                     title: str = "Vulnerability report", demo: bool = False) -> Report:
    services = dedupe_and_sort(services)
    Assessor(client, log, keyword_fallback).assess(services)
    for s in services:
        if min_cvss > 0:
            s.findings = [f for f in s.findings
                          if f.cve.score is not None and f.cve.score >= min_cvss]
        s.findings.sort(key=Finding.sort_key)
    findings = sorted((f for s in services for f in s.findings), key=Finding.sort_key)
    return Report(title=title, generated=datetime.now(timezone.utc), services=services,
                  findings=findings, scans=scans, manual_count=manual_count,
                  stats=compute_stats(services, findings), demo=demo, min_cvss=min_cvss,
                  nvd_requests=getattr(client, "requests_made", 0),
                  cache_hits=getattr(client, "cache_hits", 0),
                  api_key_used=bool(getattr(client, "api_key", None)))


def verdict_sentence(st: Dict[str, Any]) -> str:
    if st["assessed"] == 0:
        return "No service in this scan reported a version, so nothing could be checked for CVEs."
    if st["findings"] == 0:
        n = st["assessed"]
        return f"No published CVEs match the {n} service{'s' if n != 1 else ''} that reported a version."
    aff, n = st["affected"], st["assessed"]
    first = (f"{aff} of {n} checked service{'s' if n != 1 else ''} "
             f"{'runs' if aff == 1 else 'run'} a version with published CVEs.")
    p1, p2, kev = st["priority"][1], st["priority"][2], st["kev"]
    if p1:
        second = f"{p1} finding{'s' if p1 != 1 else ''} should be fixed now"
        second += (f", including {kev} on CISA's list of vulnerabilities exploited in the wild."
                   if kev else ".")
    elif p2:
        second = f"{p2} high-priority finding{'s' if p2 != 1 else ''} should be scheduled soon."
    else:
        second = "None of them rate high or critical."
    return f"{first} {second}"


def scope_sentence(r: Report) -> str:
    inputs = []
    for s in r.scans:
        extra = "; ".join(x for x in (f"Nmap {s['nmap_version']}" if s.get("nmap_version") else "",
                                      s.get("args", "")) if x)
        inputs.append(f"{s['file']} ({extra})" if extra else s["file"])
    if r.manual_count:
        inputs.append(f"{r.manual_count} manual entr{'y' if r.manual_count == 1 else 'ies'}")
    text = "Input: " + ", ".join(inputs) + "."
    if r.scans:
        up = sum(s["hosts_up"] for s in r.scans)
        total = sum(s["hosts_total"] for s in r.scans)
        ports = sum(s["open_ports"] for s in r.scans)
        text += (f" {up} of {total} host{'s' if total != 1 else ''} responded, "
                 f"with {ports} open port{'s' if ports != 1 else ''}.")
    st = r.stats
    text += (f" {st['assessed']} service{'s' if st['assessed'] != 1 else ''} "
             f"{'was' if st['assessed'] == 1 else 'were'} checked against the NVD")
    unchecked = st["not_assessed"] + st["errors"]
    text += f"; {unchecked} could not be checked." if unchecked else "."
    if r.min_cvss > 0:
        text += f" Only findings with CVSS {r.min_cvss:.1f} or higher are shown."
    return text


def _article(word: str) -> str:
    return "an" if word[:1].lower() in "aeiou" else "a"


def upgrade_guidance(svc: Service) -> str:
    """One sentence on the upgrade that clears the most findings. A finding
    listed as 'affected through X' is cleared by any release newer than X."""
    if not svc.findings:
        return ""
    total = len(svc.findings)
    fixed = [f.fixed_in for f in svc.findings if f.fixed_in]
    if not fixed:
        through = [f.affected_through for f in svc.findings if f.affected_through]
        if not through:
            return ("NVD lists no fixed version for these CVEs. Follow the vendor "
                    "advisories linked below.")
        return (f"NVD lists {len(through)} of {total} finding{'s' if total != 1 else ''} as "
                f"affecting versions through {max_version(through)}, so a newer release is "
                "needed. Confirm the fixed version in the vendor advisories.")
    target = max_version(fixed)

    def cleared(f: Finding) -> bool:
        return bool(f.fixed_in) or bool(f.affected_through
                                        and compare_versions(target, f.affected_through) > 0)

    done = sum(1 for f in svc.findings if cleared(f))
    text = (f"Upgrading to {target} or later resolves {done} of {total} "
            f"finding{'s' if total != 1 else ''}, based on NVD's affected version ranges.")
    left_through = [f.affected_through for f in svc.findings if not cleared(f) and f.affected_through]
    left_none = total - done - len(left_through)
    if left_through:
        n = len(left_through)
        text += (f" {n} more {'is' if n == 1 else 'are'} listed as affected through "
                 f"{max_version(left_through)}, so look for a release newer than that.")
    if left_none:
        text += (f" {'The other' if not left_through else 'The remaining'} {left_none} "
                 f"{'has' if left_none == 1 else 'have'} no fixed version in NVD; "
                 "check the linked advisories.")
    return text


def fix_text(f: Finding) -> str:
    if f.fixed_in:
        return f"Upgrade to {f.fixed_in} or later"
    if f.affected_through:
        return f"Affected through {f.affected_through}; upgrade past it"
    if f.cve.kev and f.cve.kev_action:
        return _truncate(f.cve.kev_action, 120)
    return "No fixed version listed; follow the advisory"


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

HTML_CSS = """
:root{
  --paper:#F3F5F8; --sheet:#FFFFFF; --ink:#16233A; --muted:#566275;
  --rule:#D6DCE4; --head:#E8ECF1; --link:#1F4FA8;
  --sev-critical:#8C1C2C; --sev-high:#C2461B; --sev-medium:#A87C00;
  --sev-low:#2F7466; --sev-none:#7A8494; --sev-unscored:#9AA3B0;
  --serif:"Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua",Georgia,serif;
  --sans:"Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,Consolas,"SFMono-Regular",Menlo,monospace;
}
*{box-sizing:border-box}
html{background:var(--paper)}
body{margin:0;color:var(--ink);font:15px/1.55 var(--sans);-webkit-text-size-adjust:100%}
a{color:var(--link);text-underline-offset:2px}
a:focus-visible,summary:focus-visible,th:focus-visible,input:focus-visible{outline:2px solid var(--link);outline-offset:2px}
code{font:0.84em/1.4 var(--mono);overflow-wrap:anywhere}
small{display:block;color:var(--muted);font-size:.8rem;line-height:1.4;margin-top:2px}
.sheet{max-width:1140px;margin:0 auto;padding:36px 28px 64px}
.masthead{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:baseline;gap:4px 24px;border-bottom:2px solid var(--ink);padding-bottom:12px;margin-bottom:32px}
.masthead h1{font:600 1.05rem/1.2 var(--sans);margin:0}
.masthead p{margin:0;color:var(--muted);font-size:.88rem}
.notice{background:#FFF6DB;border-left:4px solid var(--sev-medium);padding:10px 14px;margin:0 0 28px;max-width:75ch}
.verdict{font:400 clamp(1.55rem,3.1vw,2.3rem)/1.22 var(--serif);max-width:30em;margin:0 0 24px}
.strip{display:flex;height:16px;border-radius:2px;overflow:hidden;background:var(--rule)}
.strip span{display:block;height:100%}
.strip span+span{border-left:2px solid var(--paper)}
.legend{display:flex;flex-wrap:wrap;gap:4px 22px;margin:10px 0 0;padding:0;list-style:none;font-size:.9rem;color:var(--muted)}
.legend li::before{content:"";display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:7px;background:var(--c)}
.legend b{color:var(--ink);font-variant-numeric:tabular-nums}
.scope{color:var(--muted);max-width:78ch;margin:20px 0 0;font-size:.93rem}
section{margin-top:52px}
h2{font:600 1.5rem/1.25 var(--serif);margin:0 0 6px}
.lede{margin:0 0 18px;color:var(--muted);max-width:75ch}
.controls{display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px;margin:0 0 10px}
.controls input{font:inherit;font-size:.92rem;padding:6px 10px;border:1px solid var(--rule);border-radius:3px;min-width:16em;background:var(--sheet);color:var(--ink)}
.controls span{color:var(--muted);font-size:.88rem}
.tablewrap{overflow-x:auto;background:var(--sheet);border:1px solid var(--rule)}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;vertical-align:top;padding:9px 12px;border-bottom:1px solid var(--rule)}
th{background:var(--head);font-weight:600;white-space:nowrap}
#fixfirst th{cursor:pointer;user-select:none}
#fixfirst th[aria-sort=ascending]::after{content:" \\25B4"}
#fixfirst th[aria-sort=descending]::after{content:" \\25BE"}
tbody tr:last-child td{border-bottom:0}
td.prio{white-space:nowrap;border-left:4px solid var(--p)}
td.prio b{font-variant-numeric:tabular-nums}
td.cveid a{font-weight:600;white-space:nowrap}
.sev{white-space:nowrap;color:var(--c);font-weight:600}
.sev b{font-variant-numeric:tabular-nums}
.badge{display:inline-block;font-size:.72rem;font-weight:600;line-height:1.35;padding:1px 6px;border-radius:3px;margin:3px 6px 0 0;white-space:nowrap}
.badge.kev{background:var(--sev-critical);color:#fff}
.badge.xp{border:1px solid var(--sev-high);color:var(--sev-high)}
.links a{display:inline-block;margin-right:12px}
.svc{padding:22px 0 10px;border-top:1px solid var(--rule)}
.svc:first-of-type{border-top:0;padding-top:4px}
.svc h3{font:600 1.18rem/1.3 var(--serif);margin:0 0 10px}
.svc h3 .ep{font-family:var(--sans);font-size:.92rem;font-weight:600;color:var(--muted);margin-right:8px}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:4px 18px;margin:0 0 12px;font-size:.9rem}
dl.meta dt{color:var(--muted)}
dl.meta dd{margin:0;min-width:0}
.caveat{border-left:3px solid var(--sev-medium);padding:4px 0 4px 12px;margin:0 0 12px;max-width:80ch;font-size:.9rem}
.svcnote{color:var(--muted);font-size:.88rem;margin:0 0 10px;max-width:80ch}
.cves{background:var(--sheet);border:1px solid var(--rule);margin-top:6px}
details.cve+details.cve{border-top:1px solid var(--rule)}
details.cve summary{display:flex;flex-wrap:wrap;gap:2px 14px;align-items:baseline;padding:9px 14px 9px 12px;cursor:pointer;list-style:none;border-left:4px solid var(--p)}
details.cve summary::-webkit-details-marker{display:none}
details.cve summary::before{content:"\\25B8";color:var(--muted);width:.8em}
details.cve[open] summary::before{content:"\\25BE"}
details.cve summary .id{font-weight:600;min-width:9.2em}
details.cve summary .sev{min-width:6.6em}
details.cve summary .gist{flex:1 1 22em;color:var(--muted);min-width:0}
details.cve summary .badge{margin-top:0}
.cvebody{padding:4px 18px 16px 34px;border-left:4px solid var(--p)}
.cvebody p{margin:6px 0 10px;max-width:80ch}
.cvebody dl.meta{margin-bottom:8px}
.empty{background:var(--sheet);border:1px solid var(--rule);padding:14px 16px;margin:0}
.method p{max-width:78ch;margin:0 0 12px}
footer{margin-top:56px;padding-top:14px;border-top:1px solid var(--rule);color:var(--muted);font-size:.82rem}
footer p{margin:0 0 4px}
@media (max-width:640px){
  .sheet{padding:22px 14px 48px}
  dl.meta{grid-template-columns:1fr}
  dl.meta dt{margin-top:6px}
  .cvebody{padding-left:18px}
}
@media print{
  html{background:#fff}
  .sheet{max-width:none;padding:0}
  .controls{display:none}
  .tablewrap,.cves{border-color:#bbb}
  tr,details.cve{break-inside:avoid}
  a{color:inherit}
}
"""

HTML_JS = """
(function(){
  var table=document.getElementById('fixfirst');
  if(table){
    var body=table.tBodies[0], rows=[].slice.call(body.rows);
    var input=document.getElementById('filter'), count=document.getElementById('count');
    var update=function(){
      var q=input.value.trim().toLowerCase(), shown=0;
      rows.forEach(function(r){var ok=!q||r.textContent.toLowerCase().indexOf(q)>-1;r.hidden=!ok;if(ok)shown++;});
      count.textContent='Showing '+shown+' of '+rows.length;
    };
    input.addEventListener('input',update);
    var heads=[].slice.call(table.tHead.rows[0].cells);
    heads.forEach(function(th,i){
      th.tabIndex=0;
      var sort=function(){
        var dir=th.getAttribute('aria-sort')==='ascending'?-1:1;
        heads.forEach(function(h){h.removeAttribute('aria-sort');});
        th.setAttribute('aria-sort',dir===1?'ascending':'descending');
        rows.sort(function(a,b){
          var x=a.cells[i].getAttribute('data-sort'), y=b.cells[i].getAttribute('data-sort');
          if(x===null||y===null){x=a.cells[i].textContent;y=b.cells[i].textContent;return x.localeCompare(y)*dir;}
          return (parseFloat(x)-parseFloat(y))*dir;
        });
        rows.forEach(function(r){body.appendChild(r);});
      };
      th.addEventListener('click',sort);
      th.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();sort();}});
    });
    update();
  }
  window.addEventListener('beforeprint',function(){
    [].forEach.call(document.querySelectorAll('details'),function(d){d.open=true;});
  });
})();
"""

_SEV_VAR = {"Critical": "--sev-critical", "High": "--sev-high", "Medium": "--sev-medium",
            "Low": "--sev-low", "None": "--sev-none", "Unscored": "--sev-unscored"}
_PRIO_VAR = {1: "--sev-critical", 2: "--sev-high", 3: "--sev-medium", 4: "--sev-unscored"}


def _e(text: Any) -> str:
    return html.escape("" if text is None else str(text), quote=True)


def _a(url: str, text: str) -> str:
    u = safe_url(url)
    if not u:
        return _e(text)
    return f'<a href="{_e(u)}" target="_blank" rel="noopener noreferrer">{_e(text)}</a>'


def _sev_html(c: CVERecord) -> str:
    var = _SEV_VAR[c.severity]
    if c.score is None:
        return f'<span class="sev" style="--c:var({var})">Unscored</span>'
    return f'<span class="sev" style="--c:var({var})"><b>{c.score:.1f}</b> {_e(c.severity)}</span>'


def _badges_html(c: CVERecord) -> str:
    out = ""
    if c.kev:
        out += '<span class="badge kev" title="Listed in the CISA Known Exploited Vulnerabilities catalog">Known exploited</span>'
    if c.exploit_ref:
        out += '<span class="badge xp" title="NVD lists a reference tagged Exploit">Public exploit</span>'
    return out


def _remediation_links_html(f: Finding, limit: int = 2) -> str:
    c = f.cve
    links = []
    if c.kev:
        links.append(_a(KEV_URL.format(c.id), "CISA KEV entry"))
    for ref in remediation_refs(c, limit):
        links.append(_a(ref["url"], ref_label(ref)))
    links.append(_a(NVD_DETAIL_URL.format(c.id), "NVD entry"))
    return '<small class="links">' + "".join(links) + "</small>"


def _strip_html(st: Dict[str, Any]) -> str:
    total = st["findings"]
    legend = []
    for sev in SEVERITY_ORDER:
        n = st["severity"][sev]
        if n or sev in ("Critical", "High", "Medium", "Low"):
            legend.append(f'<li style="--c:var({_SEV_VAR[sev]})"><b>{n}</b> {sev.lower()}</li>')
    if not total:
        bar = '<div class="strip" aria-hidden="true"></div>'
    else:
        segs = []
        for sev in SEVERITY_ORDER:
            n = st["severity"][sev]
            if n:
                segs.append(f'<span style="width:{n * 100 / total:.3f}%;background:var({_SEV_VAR[sev]})" '
                            f'title="{sev}: {n}"></span>')
        label = ", ".join(f"{st['severity'][s]} {s.lower()}" for s in SEVERITY_ORDER if st["severity"][s])
        bar = f'<div class="strip" role="img" aria-label="Findings by severity: {_e(label)}">{"".join(segs)}</div>'
    return bar + '<ul class="legend">' + "".join(legend) + "</ul>"


def _fix_first_html(r: Report, anchors: Dict[int, str]) -> str:
    if not r.findings:
        msg = ("No findings. Every service that reported a version is clear of published CVEs, "
               "but review the services that could not be checked below."
               if r.stats["assessed"] else
               "No findings, because no service reported a version. Re-run Nmap with -sV.")
        return f'<p class="empty">{_e(msg)}</p>'
    rows = []
    for i, f in enumerate(r.findings):
        c, s = f.cve, f.service
        score_sort = f"{c.score:.1f}" if c.score is not None else "-1"
        anchor = anchors.get(id(s), "")
        svc_link = (f'<a href="#{anchor}">{_e(s.endpoint)}</a>' if anchor else _e(s.endpoint))
        rows.append(
            f'<tr><td class="prio" style="--p:var({_PRIO_VAR[f.priority]})" data-sort="{i}">'
            f'<b>P{f.priority}</b> {_e(PRIORITY_LABEL[f.priority])}</td>'
            f'<td class="cveid">{_a(NVD_DETAIL_URL.format(c.id), c.id)}<br>{_badges_html(c)}</td>'
            f'<td data-sort="{score_sort}">{_sev_html(c)}<small>CVSS {_e(c.cvss_version or "n/a")}</small></td>'
            f'<td>{svc_link}<small>{_e(s.label)}</small></td>'
            f'<td>{_e(fix_text(f))}{_remediation_links_html(f)}</td>'
            f'<td data-sort="{CONFIDENCE_RANK.get(f.confidence, 3)}">{_e(f.confidence)}</td></tr>')
    return ('<div class="controls"><input id="filter" type="search" '
            'placeholder="Filter by CVE, host, product or text" aria-label="Filter findings">'
            '<span id="count" aria-live="polite"></span></div>'
            '<div class="tablewrap"><table id="fixfirst"><thead><tr>'
            '<th scope="col">Priority</th><th scope="col">CVE</th><th scope="col">Severity</th>'
            '<th scope="col">Service</th><th scope="col">Remediation</th><th scope="col">Match</th>'
            '</tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>")


def _cve_details_html(f: Finding) -> str:
    c = f.cve
    pvar = _PRIO_VAR[f.priority]
    meta = []
    if c.published:
        meta.append(("Published", _e(c.published[:10])))
    if c.score is not None:
        vec = f" <code>{_e(c.vector)}</code>" if c.vector else ""
        meta.append(("CVSS", f"{c.score:.1f} (v{_e(c.cvss_version)}){vec}"))
    else:
        meta.append(("CVSS", "Not yet scored by NVD or the CNA"))
    if c.cwes:
        meta.append(("Weakness", " ".join(_a(CWE_URL.format(w[4:]), w) for w in c.cwes)))
    meta.append(("Fix", _e(fix_text(f))))
    if c.kev:
        kev = _e(c.kev_action or "Apply vendor mitigations.")
        if c.kev_due:
            kev += f" CISA due date for federal agencies: {_e(c.kev_due)}."
        meta.append(("CISA KEV", kev))
    meta.append(("Match", f"{_e(f.confidence)} confidence. {_e(METHOD_TEXT.get(f.method, ''))}"))
    refs = remediation_refs(c, 6)
    others = [r for r in c.references if r not in refs][: max(0, 8 - len(refs))]
    ref_links = [_a(r["url"], ref_label(r)) for r in refs + others]
    ref_links.append(_a(NVD_DETAIL_URL.format(c.id), "NVD entry"))
    ref_links.append(_a(CVE_ORG_URL.format(c.id), "CVE.org record"))
    meta.append(("References", '<span class="links">' + "".join(ref_links) + "</span>"))
    dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in meta)
    return (f'<details class="cve" style="--p:var({pvar})"><summary>'
            f'<span class="id">{_e(c.id)}</span>{_sev_html(c)}'
            f'<span class="gist">{_e(_gist(c.description, 120))}</span>{_badges_html(c)}</summary>'
            f'<div class="cvebody"><p>{_e(c.description or "No description provided.")}</p>'
            f'<dl class="meta">{dl}</dl></div></details>')


def _service_html(svc: Service, anchor: str) -> str:
    meta = []
    if svc.hostname:
        meta.append(("Hostname", _e(svc.hostname)))
    if svc.source == "nmap":
        banner = " ".join(x for x in (svc.product, svc.version_raw) if x) or svc.name
        if svc.extrainfo:
            banner += f" ({svc.extrainfo})"
        meta.append(("Nmap banner", _e(banner)))
    else:
        meta.append(("Input", "Manual entry"))
    if svc.cpe:
        meta.append(("CPE", f"<code>{_e(svc.cpe.to23())}</code> "
                            f"<span class=\"muted\">{_e(ORIGIN_TEXT.get(svc.cpe_origin, ''))}</span>"))
    meta.append(("Lookup", _e(METHOD_TEXT.get(svc.method, "Not run"))))
    counts = Counter(f.cve.severity for f in svc.findings)
    if svc.findings:
        summary = ", ".join(f"{counts[s]} {s.lower()}" for s in SEVERITY_ORDER if counts[s])
        meta.append(("Findings", f"{len(svc.findings)} ({_e(summary)})"))
    else:
        meta.append(("Findings", "None. No published CVEs match this version."))
    guidance = upgrade_guidance(svc)
    if guidance:
        meta.append(("Upgrade", _e(guidance)))
    dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in meta)
    parts = [f'<article class="svc" id="{anchor}"><h3><span class="ep">{_e(svc.endpoint)}</span>'
             f'{_e(svc.label)}</h3><dl class="meta">{dl}</dl>']
    if svc.distro and svc.findings:
        name, url = svc.distro
        parts.append(f'<p class="caveat">The banner points to {_e(_article(name))} {_e(name)} package. Distributions '
                     f'backport security fixes without changing the upstream version number, so some '
                     f'of these CVEs may already be patched on this host. Confirm each one in the '
                     f'{_a(url, name + " security tracker")}.</p>')
    for note in svc.notes:
        parts.append(f'<p class="svcnote">{_e(note)}</p>')
    if svc.findings:
        parts.append('<div class="cves">' + "".join(_cve_details_html(f) for f in svc.findings) + "</div>")
    parts.append("</article>")
    return "".join(parts)


def _not_assessed_html(services: List[Service]) -> str:
    rows = "".join(
        f"<tr><td>{_e(s.endpoint)}</td><td>{_e(s.label)}</td><td>{_e(s.reason)}</td></tr>"
        for s in services)
    return ('<div class="tablewrap"><table><thead><tr><th scope="col">Endpoint</th>'
            '<th scope="col">Service</th><th scope="col">Why it was not checked</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></div>")


METHOD_PARAGRAPHS = [
    "Service versions come from Nmap version detection (-sV) or from manual entries. Each "
    "service is mapped to a CPE 2.3 name, using the CPE Nmap reports when there is one and a "
    "built-in table of common products otherwise.",
    "Each CPE is sent to the NVD CVE API 2.0 with isVulnerable, so NVD itself decides which "
    "CVEs affect that version (high confidence). When NVD returns nothing for the exact name, "
    "often because Nmap and NVD spell a version differently, the tool downloads every CVE for "
    "the product and checks the version against each CVE's affected ranges locally (medium "
    "confidence, because platform conditions such as 'only on Windows' are not evaluated). "
    "Keyword searches of CVE descriptions are used only when no CPE exists (low confidence).",
    "Priority: P1 Fix now means the CVE is in CISA's Known Exploited Vulnerabilities catalog "
    "or scores CVSS 9.0 or higher. P2 Fix soon means CVSS 7.0 to 8.9, or 4.0 and up with a "
    "public exploit referenced in NVD. P3 Schedule is CVSS 4.0 to 6.9 and P4 Track is below "
    "4.0 or not yet scored. Scores use CVSS v3.1 when available, then v3.0, v4.0 and v2.0; "
    "v2-only scores are placed on the v3 severity bands.",
    "Limits: version matching cannot see backported patches, configuration, or compensating "
    "controls, so treat each finding as a lead to verify rather than a confirmed "
    "vulnerability. Services without a detected version need a manual check.",
]


def render_html(r: Report) -> str:
    st = r.stats
    assessed = [s for s in r.services if s.status == "assessed"]
    skipped = [s for s in r.services if s.status in ("not_assessed", "error")]
    anchors = {id(s): f"svc-{i + 1}" for i, s in enumerate(assessed)}
    out = [
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<meta name="generator" content="{_e(TOOL)} {__version__}">\n'
        f"<title>{_e(r.title)}</title>\n<style>{HTML_CSS}</style>\n</head>\n<body>\n"
        '<main class="sheet">\n',
        f'<header class="masthead"><h1>{_e(r.title)}</h1>'
        f"<p>Generated {_e(r.generated_str)} by {_e(TOOL)} {__version__}</p></header>\n",
    ]
    if r.demo:
        out.append('<p class="notice">Offline demo. Every CVE ID, score and description in this '
                   "report is synthetic test data, not a real vulnerability.</p>\n")
    out.append(f'<p class="verdict">{_e(verdict_sentence(st))}</p>\n')
    out.append(_strip_html(st))
    out.append(f'\n<p class="scope">{_e(scope_sentence(r))}</p>\n')

    out.append('<section id="fix-first"><h2>Fix first</h2>'
               '<p class="lede">Every finding, most urgent first. Click a column heading to '
               're-sort, or type to filter.</p>')
    out.append(_fix_first_html(r, anchors))
    out.append("</section>\n")

    if assessed:
        out.append('<section id="services"><h2>Services checked</h2>'
                   '<p class="lede">One entry per service that reported a version. Open a CVE to '
                   "see its description, weakness type, fix and references.</p>")
        out.extend(_service_html(s, anchors[id(s)]) for s in assessed)
        out.append("</section>\n")

    if skipped:
        out.append('<section id="not-checked"><h2>Not checked</h2>'
                   '<p class="lede">Open ports that could not be matched to CVEs. They are not '
                   "known to be safe; review them by hand.</p>")
        out.append(_not_assessed_html(skipped))
        out.append("</section>\n")

    out.append('<section id="method" class="method"><h2>How this report was made</h2>')
    out.extend(f"<p>{_e(p)}</p>" for p in METHOD_PARAGRAPHS)
    out.append("</section>\n")

    lookups = (f"{r.nvd_requests} NVD API request{'s' if r.nvd_requests != 1 else ''}"
               + (f" and {r.cache_hits} cached response{'s' if r.cache_hits != 1 else ''}"
                  if r.cache_hits else ""))
    out.append(f"<footer><p>{_e(NVD_NOTICE)}</p><p>CVE data retrieved {_e(r.generated_str)} "
               f"using {_e(lookups)}"
               f"{' (synthetic fixtures)' if r.demo else ''}. CISA KEV status comes from the "
               "NVD record.</p></footer>\n")
    out.append(f"</main>\n<script>{HTML_JS}</script>\n</body>\n</html>\n")
    return "".join(out)


# ---------------------------------------------------------------------------
# PDF report (reportlab)
# ---------------------------------------------------------------------------

def _pdf_text(text: Any) -> str:
    """Escape for reportlab paragraph markup and drop glyphs the built-in
    fonts cannot draw (they would render as black boxes)."""
    s = "" if text is None else str(text)
    s = s.encode("cp1252", "replace").decode("cp1252")
    return html.escape(s, quote=False)


def write_pdf(r: Report, path: str) -> None:
    try:
        from reportlab.graphics.shapes import Drawing, Rect
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate,
                                        Spacer, Table, TableStyle)
    except ImportError as exc:
        raise ReportDependencyError("PDF output needs reportlab (pip install reportlab)") from exc

    ink, muted = colors.HexColor("#16233A"), colors.HexColor("#566275")
    rule, head_bg = colors.HexColor("#D6DCE4"), colors.HexColor("#E8ECF1")
    link_hex = "#1F4FA8"
    t = _pdf_text

    base = ParagraphStyle("base", fontName="Helvetica", fontSize=9, leading=12.5, textColor=ink)
    small = ParagraphStyle("small", parent=base, fontSize=7.5, leading=9.8, textColor=muted)
    cell = ParagraphStyle("cell", parent=base, fontSize=7.8, leading=10)
    title = ParagraphStyle("title", parent=base, fontName="Times-Bold", fontSize=21, leading=25)
    verdict = ParagraphStyle("verdict", parent=base, fontName="Times-Roman", fontSize=15,
                             leading=19.5, spaceBefore=14, spaceAfter=10)
    h2 = ParagraphStyle("h2", parent=base, fontName="Times-Bold", fontSize=14.5, leading=18, keepWithNext=1,
                        spaceBefore=18, spaceAfter=6)
    h3 = ParagraphStyle("h3", parent=base, fontName="Helvetica-Bold", fontSize=10, leading=13, keepWithNext=1,
                        spaceBefore=10, spaceAfter=4)
    notice = ParagraphStyle("notice", parent=base, backColor=colors.HexColor("#FFF6DB"),
                            borderPadding=(5, 7, 5, 7), spaceBefore=8, spaceAfter=6)
    caveat = ParagraphStyle("caveat", parent=small, textColor=ink, leftIndent=8,
                            borderPadding=(0, 0, 0, 6), spaceBefore=2, spaceAfter=4)

    def link(url: str, label: str) -> str:
        u = safe_url(url)
        return f'<a href="{html.escape(u, quote=True)}" color="{link_hex}">{t(label)}</a>' if u else t(label)

    def sev_markup(c: CVERecord) -> str:
        col = SEV_HEX[c.severity]
        if c.score is None:
            return f'<font color="{col}"><b>Unscored</b></font>'
        return f'<font color="{col}"><b>{c.score:.1f}</b> {c.severity}</font>'

    def links_markup(f: Finding, limit: int = 2) -> str:
        items = []
        if f.cve.kev:
            items.append(link(KEV_URL.format(f.cve.id), "CISA KEV entry"))
        items += [link(ref["url"], ref_label(ref)) for ref in remediation_refs(f.cve, limit)]
        items.append(link(NVD_DETAIL_URL.format(f.cve.id), "NVD entry"))
        return "&nbsp;&nbsp; ".join(items)

    doc = SimpleDocTemplate(path, pagesize=letter, leftMargin=0.6 * inch, rightMargin=0.6 * inch,
                            topMargin=0.6 * inch, bottomMargin=0.75 * inch,
                            title=r.title, author=f"{TOOL} {__version__}")
    width = doc.width
    st = r.stats
    story: List[Any] = [Paragraph(t(r.title), title),
                        Paragraph(t(f"Generated {r.generated_str} by {TOOL} {__version__}"), small)]
    if r.demo:
        story.append(Paragraph("Offline demo. Every CVE ID, score and description in this report "
                               "is synthetic test data, not a real vulnerability.", notice))
    story.append(Paragraph(t(verdict_sentence(st)), verdict))

    strip = Drawing(width, 11)
    total = st["findings"]
    if total:
        x = 0.0
        for sev in SEVERITY_ORDER:
            n = st["severity"][sev]
            if n:
                w = width * n / total
                strip.add(Rect(x, 0, w, 11, fillColor=colors.HexColor(SEV_HEX[sev]),
                               strokeColor=colors.white, strokeWidth=1))
                x += w
    else:
        strip.add(Rect(0, 0, width, 11, fillColor=rule, strokeColor=None))
    story += [strip, Spacer(1, 5)]
    legend = "&nbsp;&nbsp;&nbsp; ".join(
        f'<font color="{SEV_HEX[s]}"><b>{st["severity"][s]}</b></font> {s.lower()}'
        for s in SEVERITY_ORDER if st["severity"][s] or s in ("Critical", "High", "Medium", "Low"))
    story += [Paragraph(legend, small), Spacer(1, 8), Paragraph(t(scope_sentence(r)), base)]

    # Fix first -------------------------------------------------------------
    story.append(Paragraph("Fix first", h2))
    if r.findings:
        data = [[Paragraph(f"<b>{h}</b>", cell) for h in
                 ("Priority", "CVE", "Severity", "Service", "Remediation")]]
        cmds: List[Tuple] = [
            ("BACKGROUND", (0, 0), (-1, 0), head_bg),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, rule),
            ("BOX", (0, 0), (-1, -1), 0.4, rule),
            ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        for i, f in enumerate(r.findings, start=1):
            c = f.cve
            flags = []
            if c.kev:
                flags.append(f'<font color="{SEV_HEX["Critical"]}"><b>Known exploited</b></font>')
            if c.exploit_ref:
                flags.append(f'<font color="{SEV_HEX["High"]}">Public exploit</font>')
            cve_cell = link(NVD_DETAIL_URL.format(c.id), c.id)
            if flags:
                cve_cell += "<br/>" + "<br/>".join(flags)
            data.append([
                Paragraph(f"<b>P{f.priority}</b><br/>{PRIORITY_LABEL[f.priority]}", cell),
                Paragraph(cve_cell, cell),
                Paragraph(f"{sev_markup(c)}<br/><font color='#566275'>CVSS {t(c.cvss_version or 'n/a')}"
                          f"</font>", cell),
                Paragraph(f"{t(f.service.endpoint)}<br/><font color='#566275'>{t(f.service.label)}"
                          f"</font>", cell),
                Paragraph(f"{t(fix_text(f))}<br/>{links_markup(f)}", cell),
            ])
            cmds.append(("LINEBEFORE", (0, i), (0, i), 3, colors.HexColor(PRIORITY_HEX[f.priority])))
        cols = [0.62, 1.22, 0.78, 1.85, 2.83]
        scale = width / (sum(cols) * inch)
        table = Table(data, colWidths=[c_ * inch * scale for c_ in cols], repeatRows=1)
        table.setStyle(TableStyle(cmds))
        story.append(table)
    else:
        story.append(Paragraph("No findings to fix.", base))

    # Services --------------------------------------------------------------
    assessed = [s for s in r.services if s.status == "assessed"]
    if assessed:
        heading: List[Any] = [Paragraph("Services checked", h2)]   # kept with the first block
        for svc in assessed:
            rows = []
            if svc.hostname:
                rows.append(("Hostname", t(svc.hostname)))
            if svc.source == "nmap":
                banner = " ".join(x for x in (svc.product, svc.version_raw) if x) or svc.name
                if svc.extrainfo:
                    banner += f" ({svc.extrainfo})"
                rows.append(("Nmap banner", t(banner)))
            if svc.cpe:
                rows.append(("CPE", f'<font name="Courier" size="7.5">{t(svc.cpe.to23())}</font> '
                                    f'<font color="#566275">{t(ORIGIN_TEXT.get(svc.cpe_origin, ""))}</font>'))
            rows.append(("Lookup", t(METHOD_TEXT.get(svc.method, ""))))
            counts = Counter(f.cve.severity for f in svc.findings)
            rows.append(("Findings", t(f"{len(svc.findings)} (" + ", ".join(
                f"{counts[s]} {s.lower()}" for s in SEVERITY_ORDER if counts[s]) + ")")
                if svc.findings else "None. No published CVEs match this version."))
            guidance = upgrade_guidance(svc)
            if guidance:
                rows.append(("Upgrade", t(guidance)))
            meta = Table([[Paragraph(k, small), Paragraph(v, cell)] for k, v in rows],
                         colWidths=[0.95 * inch, width - 0.95 * inch])
            meta.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                      ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                      ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                                      ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5)]))
            block: List[Any] = heading + [Paragraph(f"{t(svc.endpoint)}&nbsp;&nbsp; {t(svc.label)}", h3), meta]
            heading = []
            if svc.distro and svc.findings:
                name, url = svc.distro
                block.append(Paragraph(
                    f"The banner points to {_article(name)} {t(name)} package. Distributions backport security fixes "
                    f"without changing the upstream version, so some of these CVEs may already be "
                    f"patched. Confirm each one in the {link(url, name + ' security tracker')}.", caveat))
            for note in svc.notes:
                block.append(Paragraph(t(note), caveat))
            story.append(KeepTogether(block))

    # Finding details -------------------------------------------------------
    if r.findings:
        heading = [Paragraph("Finding details", h2)]
        for f in r.findings:
            c = f.cve
            head = (f"{link(NVD_DETAIL_URL.format(c.id), c.id)}&nbsp;&nbsp; {sev_markup(c)}"
                    f"&nbsp;&nbsp; <font color='#566275'>P{f.priority} {PRIORITY_LABEL[f.priority]}"
                    f"&nbsp;&nbsp; {t(f.service.endpoint)} {t(f.service.label)}</font>")
            facts = []
            if c.published:
                facts.append(f"Published {t(c.published[:10])}")
            if c.vector:
                facts.append(f'<font name="Courier" size="7">{t(c.vector)}</font>')
            if c.cwes:
                facts.append(" ".join(link(CWE_URL.format(w[4:]), w) for w in c.cwes))
            facts.append(f"{t(f.confidence)} confidence")
            body = heading + [Paragraph(head, ParagraphStyle("fh", parent=base, spaceBefore=8, spaceAfter=2)),
                    Paragraph(t(_truncate(c.description, 700) or "No description provided."), base),
                    Paragraph("&nbsp;&nbsp; ".join(facts), small)]
            fix = f"<b>Fix:</b> {t(fix_text(f))}"
            if c.kev and c.kev_action:
                fix += f"&nbsp;&nbsp; <b>CISA:</b> {t(_truncate(c.kev_action, 220))}"
                if c.kev_due:
                    fix += f" (due {t(c.kev_due)})"
            body.append(Paragraph(f"{fix}<br/>{links_markup(f, 3)}", small))
            story.append(KeepTogether(body))
            heading = []

    # Not checked -----------------------------------------------------------
    skipped = [s for s in r.services if s.status in ("not_assessed", "error")]
    if skipped:
        story.append(Paragraph("Not checked", h2))
        story.append(Paragraph("Open ports that could not be matched to CVEs. They are not known to "
                               "be safe; review them by hand.", base))
        story.append(Spacer(1, 5))
        data = [[Paragraph(f"<b>{h}</b>", cell) for h in ("Endpoint", "Service", "Why it was not checked")]]
        data += [[Paragraph(t(s.endpoint), cell), Paragraph(t(s.label), cell), Paragraph(t(s.reason), cell)]
                 for s in skipped]
        table = Table(data, colWidths=[1.5 * inch, 1.6 * inch, width - 3.1 * inch], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), head_bg),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                   ("LINEBELOW", (0, 0), (-1, -1), 0.4, rule),
                                   ("BOX", (0, 0), (-1, -1), 0.4, rule)]))
        story.append(table)

    story.append(Paragraph("How this report was made", h2))
    story += [Paragraph(t(p), ParagraphStyle("mp", parent=base, spaceAfter=6)) for p in METHOD_PARAGRAPHS]

    def footer(canvas: Any, document: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(muted)
        canvas.drawString(document.leftMargin, 0.45 * inch, NVD_NOTICE)
        canvas.drawRightString(document.leftMargin + document.width, 0.45 * inch,
                               f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def render_json(r: Report) -> str:
    def svc_dict(s: Service) -> Dict[str, Any]:
        return {"endpoint": s.endpoint, "host": s.host, "hostname": s.hostname, "port": s.port,
                "protocol": s.protocol, "service": s.name, "product": s.product,
                "version": s.version, "version_raw": s.version_raw, "source": s.source,
                "cpe": s.cpe.to23() if s.cpe else None, "cpe_origin": s.cpe_origin or None,
                "status": s.status, "lookup_method": s.method or None,
                "reason": s.reason or None, "notes": s.notes,
                "distro": s.distro[0] if s.distro else None,
                "upgrade_guidance": upgrade_guidance(s) or None,
                "finding_count": len(s.findings)}

    def finding_dict(f: Finding) -> Dict[str, Any]:
        c = f.cve
        return {"priority": f.priority, "priority_label": PRIORITY_LABEL[f.priority],
                "cve": c.id, "severity": c.severity, "cvss_score": c.score,
                "cvss_version": c.cvss_version or None, "cvss_vector": c.vector or None,
                "kev": c.kev, "kev_required_action": c.kev_action or None,
                "kev_due": c.kev_due or None, "public_exploit_reference": c.exploit_ref,
                "cwes": c.cwes, "published": c.published or None, "status": c.status or None,
                "description": c.description, "endpoint": f.service.endpoint,
                "service": f.service.label, "match_method": f.method, "confidence": f.confidence,
                "fixed_in": f.fixed_in or None, "affected_through": f.affected_through or None,
                "remediation": fix_text(f),
                "remediation_links": [ref["url"] for ref in remediation_refs(c, 3)],
                "nvd_url": NVD_DETAIL_URL.format(c.id)}

    doc = {"tool": TOOL, "version": __version__, "generated": r.generated.isoformat(),
           "title": r.title, "demo": r.demo, "notice": NVD_NOTICE, "inputs": r.scans,
           "manual_entries": r.manual_count, "min_cvss": r.min_cvss,
           "summary": r.stats, "verdict": verdict_sentence(r.stats),
           "services": [svc_dict(s) for s in r.services],
           "findings": [finding_dict(f) for f in r.findings]}
    return json.dumps(doc, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Writing outputs and console summary
# ---------------------------------------------------------------------------

VALID_FORMATS = ("html", "pdf", "json")


def parse_formats(text: str) -> List[str]:
    wanted = [f.strip().lower() for f in (text or "").split(",") if f.strip()]
    bad = [f for f in wanted if f not in VALID_FORMATS]
    if bad or not wanted:
        raise InputError(f"unknown output format(s): {', '.join(bad) or text!r}. "
                         f"Choose from {', '.join(VALID_FORMATS)}.")
    return list(OrderedDict.fromkeys(wanted))


def output_base(path: str) -> str:
    root, ext = os.path.splitext(path)
    return root if ext.lower() in (".html", ".htm", ".pdf", ".json") else path


def write_outputs(r: Report, base: str, formats: Sequence[str], log: Log) -> List[str]:
    folder = os.path.dirname(os.path.abspath(base))
    os.makedirs(folder, exist_ok=True)
    written = []
    if "html" in formats:
        path = base + ".html"
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render_html(r))
        written.append(path)
    if "pdf" in formats:
        path = base + ".pdf"
        try:
            write_pdf(r, path)
            written.append(path)
        except ReportDependencyError as exc:
            log.warn(f"{exc}; skipping the PDF.")
    if "json" in formats:
        path = base + ".json"
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render_json(r))
        written.append(path)
    return written


def print_summary(r: Report, written: Sequence[str], log: Log) -> None:
    st = r.stats
    log.info("")
    log.info(f"Checked {st['assessed']} of {st['services']} services: {st['findings']} findings "
             f"({st['unique_cves']} unique CVEs), {st['kev']} known exploited.")
    log.info("  " + "   ".join(f"{k}: {v}" for k, v in st["severity"].items()
                               if v or k in ("Critical", "High", "Medium", "Low")))
    if r.findings:
        log.info("Top findings:")
        for f in r.findings[:10]:
            c = f.cve
            score = f"{c.score:4.1f}" if c.score is not None else " n/a"
            log.info(f"  P{f.priority}  {c.id:<16} {score} {c.severity:<8} "
                     f"{'KEV ' if c.kev else '    '}{f.service.endpoint}  {f.service.label}")
        if len(r.findings) > 10:
            log.info(f"  ... and {len(r.findings) - 10} more in the report")
    for s in r.services:
        if s.status == "error":
            log.warn(f"{s.endpoint} {s.label}: {s.reason}")
    if written:
        log.info("Reports written:")
        for path in written:
            log.info(f"  {path}")


# ---------------------------------------------------------------------------
# Offline demo: a synthetic scan and synthetic NVD responses
# ---------------------------------------------------------------------------
# Addresses are from 192.0.2.0/24 (TEST-NET-1, reserved for documentation),
# hostnames use the reserved .example TLD, and every CVE uses the made-up
# year 2099 so nobody mistakes the demo output for real findings.

DEMO_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX demo_scan.xml 192.0.2.10 192.0.2.20 192.0.2.30"
         start="4102444800" startstr="Fri Jan  1 00:00:00 2100" version="7.94" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<hostnames><hostname name="web01.lab.example" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="7.2p2 Ubuntu 4ubuntu2.8" extrainfo="Ubuntu Linux; protocol 2.0"
         ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:7.2p2</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="25"><state state="closed" reason="reset"/><service name="smtp" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="Apache httpd" version="2.4.49" extrainfo="(Unix)" method="probed" conf="10">
<cpe>cpe:/a:apache:http_server:2.4.49</cpe></service></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
<service name="https" product="nginx" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:igor_sysoev:nginx</cpe></service></port>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/>
<service name="http" product="Acme Widget Server" version="1.4" method="probed" conf="10"/></port>
</ports></host>
<host><status state="up" reason="echo-reply"/>
<address addr="192.0.2.20" addrtype="ipv4"/>
<hostnames><hostname name="db01.lab.example" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="21"><state state="open" reason="syn-ack"/>
<service name="ftp" product="vsftpd" version="3.0.3" ostype="Unix" method="probed" conf="10"><cpe>cpe:/a:vsftpd:vsftpd:3.0.3</cpe></service></port>
<port protocol="tcp" portid="3306"><state state="open" reason="syn-ack"/>
<service name="mysql" product="MySQL" version="5.7.33" method="probed" conf="10"><cpe>cpe:/a:mysql:mysql:5.7.33</cpe></service></port>
<port protocol="tcp" portid="3389"><state state="open" reason="syn-ack"/><service name="ms-wbt-server" method="table" conf="3"/></port>
<port protocol="tcp" portid="9999"><state state="open" reason="syn-ack"/><service name="tcpwrapped" method="probed" conf="8"/></port>
</ports></host>
<host><status state="down" reason="no-response"/><address addr="192.0.2.30" addrtype="ipv4"/></host>
<runstats><finished time="4102444860" timestr="Fri Jan  1 00:01:00 2100" elapsed="60.00" exit="success"/>
<hosts up="2" down="1" total="3"/></runstats>
</nmaprun>
"""

DEMO_MANUAL = ["192.0.2.40:6379/tcp Redis 6.0.9"]

_V31 = {
    9.8: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    8.8: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    7.8: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    7.5: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    6.5: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    5.4: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
    5.3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    4.9: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H",
    2.7: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L",
}


def _fx(cid: str, desc: str, score: Optional[float] = None, cvss: str = "3.1",
        cwe: str = "", matches: Sequence[Tuple[str, Dict[str, str]]] = (),
        refs: Sequence[Tuple[str, Sequence[str]]] = (), kev: bool = False,
        status: str = "Analyzed", published: str = "2099-01-15T12:00:00.000") -> Dict[str, Any]:
    """Build one NVD-shaped vulnerability item for the demo fixtures."""
    metrics: Dict[str, Any] = {}
    if score is not None:
        key = {"3.1": "cvssMetricV31", "3.0": "cvssMetricV30",
               "4.0": "cvssMetricV40", "2.0": "cvssMetricV2"}[cvss]
        vector = _V31.get(score, "") if cvss == "3.1" else "AV:N/AC:M/Au:N/C:P/I:P/A:P"
        metrics[key] = [{"source": "nvd@nist.gov", "type": "Primary",
                         "cvssData": {"version": cvss, "vectorString": vector, "baseScore": score}}]
    cve: Dict[str, Any] = {
        "id": cid, "sourceIdentifier": "demo@example.org", "published": published,
        "lastModified": published, "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": desc + " Synthetic demo record."}],
        "metrics": metrics,
        "weaknesses": ([{"source": "nvd@nist.gov", "type": "Primary",
                         "description": [{"lang": "en", "value": cwe}]}] if cwe else []),
        "configurations": ([{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
            dict({"vulnerable": True, "criteria": crit,
                  "matchCriteriaId": "00000000-0000-4000-8000-000000000000"}, **rng)
            for crit, rng in matches]}]}] if matches else []),
        "references": [{"url": u, "source": "demo@example.org", "tags": list(t)} for u, t in refs],
    }
    if kev:
        cve.update(cisaExploitAdd="2099-01-20", cisaActionDue="2099-02-10",
                   cisaRequiredAction="Apply updates per vendor instructions.",
                   cisaVulnerabilityName=f"Demo record {cid}")
    return {"cve": cve}


def _c23(vendor: str, product: str, version: str = "*", update: str = "*") -> str:
    return CPE("a", vendor, product, version, update).to23()


def demo_fixtures() -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """Synthetic NVD answers, keyed the way FixtureClient looks them up."""
    httpd, ssh = _c23("apache", "http_server"), _c23("openbsd", "openssh")
    exact = {
        _c23("apache", "http_server", "2.4.49"): [
            _fx("CVE-2099-0001", "Path traversal in Apache HTTP Server 2.4.49 lets a remote attacker "
                "read files outside the document root and, with CGI enabled, run code.",
                9.8, cwe="CWE-22", kev=True,
                matches=[(httpd, {"versionStartIncluding": "2.4.49", "versionEndExcluding": "2.4.51"})],
                refs=[("https://httpd.example/security/demo-0001", ["Vendor Advisory"]),
                      ("https://patches.example/httpd/2.4.51", ["Patch"]),
                      ("https://exploits.example/demo-0001", ["Exploit", "Third Party Advisory"])]),
            _fx("CVE-2099-0002", "HTTP request smuggling in the proxy module of Apache HTTP Server "
                "before 2.4.52 lets an attacker poison caches or bypass access rules.",
                7.5, cwe="CWE-444",
                matches=[(httpd, {"versionEndExcluding": "2.4.52"})],
                refs=[("https://httpd.example/security/demo-0002", ["Vendor Advisory", "Patch"])]),
            _fx("CVE-2099-0003", "A crafted script can exhaust memory in the embedded scripting "
                "module of Apache HTTP Server through 2.4.53.",
                5.3, cwe="CWE-770",
                matches=[(httpd, {"versionEndIncluding": "2.4.53"})],
                refs=[("https://lists.example/httpd-announce/demo-0003", ["Mailing List"])]),
            _fx("CVE-2099-0004", "A header parsing issue in Apache HTTP Server is awaiting analysis.",
                status="Awaiting Analysis",
                refs=[("https://httpd.example/security/demo-0004", ["Vendor Advisory"])]),
        ],
        _c23("oracle", "mysql", "5.7.33"): [
            _fx("CVE-2099-0201", "The optimizer component of MySQL Server 5.7.34 and earlier lets a "
                "low-privileged user read sensitive data.", 6.5,
                matches=[(_c23("oracle", "mysql"), {"versionStartIncluding": "5.7.0",
                                                     "versionEndIncluding": "5.7.34"})],
                refs=[("https://oracle.example/security-alerts/demo-cpu", ["Vendor Advisory", "Patch"])]),
            _fx("CVE-2099-0202", "The InnoDB component of MySQL Server 5.7.33 and earlier lets a "
                "high-privileged user crash the server.", 4.9,
                matches=[(_c23("oracle", "mysql"), {"versionStartIncluding": "5.7.0",
                                                     "versionEndIncluding": "5.7.33"})],
                refs=[("https://oracle.example/security-alerts/demo-cpu", ["Vendor Advisory", "Patch"])]),
            _fx("CVE-2099-0203", "The replication component of MySQL Server lets a high-privileged "
                "user cause a partial denial of service.", 2.7,
                matches=[(_c23("oracle", "mysql"), {"versionEndExcluding": "5.7.35"})],
                refs=[("https://oracle.example/security-alerts/demo-cpu", ["Vendor Advisory"])]),
        ],
        _c23("redis", "redis", "6.0.9"): [
            _fx("CVE-2099-0501", "An integer overflow in Redis before 6.0.10 lets a client crash the "
                "server with a crafted command.", 7.5, cwe="CWE-190",
                matches=[(_c23("redis", "redis"), {"versionEndExcluding": "6.0.10"})],
                refs=[("https://redis.example/releases/6.0.10", ["Release Notes", "Patch"])]),
        ],
    }
    product = {
        "openbsd:openssh": [
            _fx("CVE-2099-0101", "OpenSSH through 7.7 answers differently for valid and invalid "
                "user names, which lets a remote attacker enumerate accounts.", 5.3, cwe="CWE-203",
                matches=[(ssh, {"versionEndIncluding": "7.7"})],
                refs=[("https://exploits.example/demo-0101", ["Exploit"]),
                      ("https://openssh.example/txt/release-7.8", ["Release Notes"])]),
            _fx("CVE-2099-0102", "Privilege separation in OpenSSH before 7.4 lets a local user "
                "gain root through a shared memory manager flaw.", 7.8, cwe="CWE-119",
                matches=[(ssh, {"versionEndExcluding": "7.4"})],
                refs=[("https://openssh.example/security", ["Vendor Advisory"])]),
            _fx("CVE-2099-0103", "The sshd daemon in OpenSSH before 7.3 allows remote denial of "
                "service through long password strings.", 6.8, cvss="2.0",
                matches=[(ssh, {"versionEndExcluding": "7.3"})],
                refs=[("https://openssh.example/txt/release-7.3", ["Release Notes", "Patch"])]),
            _fx("CVE-2099-0104", "An agent forwarding flaw in OpenSSH 8.5 through 9.7 lets a remote "
                "attacker run code.", 9.8,
                matches=[(ssh, {"versionStartIncluding": "8.5", "versionEndExcluding": "9.8"})],
                refs=[("https://openssh.example/security", ["Vendor Advisory"])]),
            _fx("CVE-2099-0105", "A memory leak affects only OpenSSH 7.2p1.", 5.3,
                matches=[(_c23("openbsd", "openssh", "7.2", "p1"), {})],
                refs=[("https://openssh.example/security", ["Vendor Advisory"])]),
            _fx("CVE-2099-0106", "An X11 forwarding bypass affects OpenSSH 7.2p2.", 6.5, cwe="CWE-20",
                matches=[(_c23("openbsd", "openssh", "7.2", "p2"), {})],
                refs=[("https://openssh.example/txt/release-7.3", ["Release Notes"])]),
        ],
        "vsftpd_project:vsftpd": [
            _fx("CVE-2099-0301", "vsftpd before 3.0.3 allows remote attackers to bypass access "
                "restrictions.", 7.5,
                matches=[(_c23("vsftpd_project", "vsftpd"), {"versionEndExcluding": "3.0.3"})],
                refs=[("https://vsftpd.example/changelog", ["Release Notes"])]),
        ],
    }
    keyword = {
        "acme widget server 1.4": [
            _fx("CVE-2099-0401", "The admin console in Acme Widget Server before 1.6 lets an "
                "authenticated user run commands.", 8.8, cwe="CWE-78",
                refs=[("https://acme.example/advisories/demo-0401", ["Vendor Advisory"])]),
            _fx("CVE-2099-0402", "Cross-site scripting in the Acme Widget Server 1.x dashboard.",
                5.4, cwe="CWE-79",
                refs=[("https://acme.example/advisories/demo-0402", ["Vendor Advisory"])]),
            _fx("CVE-2099-0403", "An unrelated product whose description mentions version 1.4.", 9.8),
        ],
    }
    return {"exact": exact, "product": product, "keyword": keyword}


class FixtureClient:
    """Drop-in replacement for NVDClient that answers from local fixtures."""

    min_interval = 0.0
    api_key = None

    def __init__(self, fixtures: Optional[Dict[str, Dict[str, List[Dict[str, Any]]]]] = None,
                 fail: Sequence[str] = ()) -> None:
        self.fixtures = fixtures if fixtures is not None else demo_fixtures()
        self.fail = set(fail)
        self.requests_made = 0
        self.cache_hits = 0
        self.queries: List[Dict[str, str]] = []

    def search(self, params: Dict[str, str], flags: Sequence[str] = (),
               max_pages: int = 10) -> Tuple[List[Dict[str, Any]], int]:
        self.requests_made += 1
        self.queries.append(dict(params))
        if "cpeName" in params:
            key, table = params["cpeName"], "exact"
        elif "virtualMatchString" in params:
            cpe = parse_cpe(params["virtualMatchString"])
            key, table = (cpe.vendor_product if cpe else ""), "product"
        else:
            key, table = params.get("keywordSearch", "").lower(), "keyword"
        if key in self.fail:
            raise NVDError("HTTP 503: simulated outage")
        items = list(self.fixtures.get(table, {}).get(key, []))
        return items, len(items)


def demo_inputs() -> Tuple[List[Service], List[Dict[str, Any]], int]:
    services, meta = parse_nmap_xml_bytes(DEMO_NMAP_XML.encode("utf-8"), "demo_scan.xml")
    services.extend(parse_manual_entry(e) for e in DEMO_MANUAL)
    return services, [meta], len(DEMO_MANUAL)


# ---------------------------------------------------------------------------
# Self-test (offline)
# ---------------------------------------------------------------------------

def _silent_log() -> Log:
    log = Log(quiet=True)
    log.warn = log.warnings.append  # type: ignore[assignment]
    return log


def _expect(cond: bool, what: str) -> None:
    if not cond:
        raise AssertionError(what)


def _raises(exc: type, fn: Any, *args: Any) -> bool:
    try:
        fn(*args)
    except exc:
        return True
    return False


def _t_versions() -> None:
    order = ["2.0rc1", "2.0", "7.2", "7.2p1", "7.2p2", "7.3", "2.4.49", "2.4.51"]
    for a, b in (("2.0rc1", "2.0"), ("7.2", "7.2p1"), ("7.2p1", "7.2p2"), ("7.2p2", "7.3"),
                 ("2.4.49", "2.4.51"), ("1.0.2j", "1.0.2k"), ("3.0a1", "3.0"), ("3.0b2", "3.0rc1"),
                 ("9.9", "10.0"), ("1.0-beta", "1.0")):
        _expect(compare_versions(a, b) == -1, f"{a} < {b}")
        _expect(compare_versions(b, a) == 1, f"{b} > {a}")
    for a, b in (("1.0", "1.0.0"), ("v1.2", "1.2"), ("7.2P2", "7.2p2")):
        _expect(compare_versions(a, b) == 0, f"{a} == {b}")
    _expect(max_version(order) == "7.3", "max_version")
    _expect(clean_version("6.6.1p1 Ubuntu 2ubuntu2.13") == "6.6.1p1", "clean_version banner")
    _expect(clean_version("(2.4.7)") == "2.4.7" and clean_version("") == "", "clean_version edge")
    _expect(detect_distro("7.2p2 Ubuntu 4ubuntu2.8")[0] == "Ubuntu", "distro Ubuntu")
    _expect(detect_distro("8.4p1 Debian 5+deb11u1")[0] == "Debian", "distro Debian")
    _expect(detect_distro("2.4.49 (Unix)") is None, "no distro")


def _t_cpe() -> None:
    c = parse_cpe("cpe:/a:openbsd:openssh:7.2p2")
    _expect(c == CPE("a", "openbsd", "openssh", "7.2p2"), "CPE 2.2 URI")
    c = parse_cpe("cpe:2.3:a:openbsd:openssh:7.2:p2:*:*:*:*:*:*")
    _expect(c.full_version == "7.2p2", "CPE 2.3 update folded into version")
    tricky = CPE("a", "gnu", "g++", "4.8")
    _expect(r"g\+\+" in tricky.to23(), "CPE escaping")
    _expect(parse_cpe(tricky.to23()).product == "g++", "CPE round trip")
    _expect(parse_cpe("cpe:/a:igor_sysoev:nginx").has_version is False, "CPE without version")
    _expect(parse_cpe("not a cpe") is None and parse_cpe("cpe:/x:a:b") is None, "bad CPE")
    _expect(CPE("a", "apache", "http_server", "2.4.49").match_string()
            == "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "match string")
    _expect(alias_candidates("Apache httpd")[0] == ("apache", "http_server"), "alias httpd")
    _expect(alias_candidates("Apache Tomcat/Coyote JSP engine")[0] == ("apache", "tomcat"), "alias tomcat")
    _expect(alias_candidates("MySQL")[0] == ("oracle", "mysql"), "alias mysql")
    _expect(alias_candidates("bindshell") == [], "alias word boundary")


def _t_matching() -> None:
    ssh = CPE("a", "openbsd", "openssh", "7.2p2")

    def conf(crit: str, **rng: str) -> List[Dict[str, Any]]:
        return [{"nodes": [{"cpeMatch": [dict(vulnerable=True, criteria=crit, **rng)]}]}]

    any_ssh = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
    _expect(match_details(conf("cpe:2.3:a:openbsd:openssh:7.2:p2:*:*:*:*:*:*"), ssh, "7.2p2")[0],
            "7.2:p2 criteria matches 7.2p2")
    _expect(not match_details(conf("cpe:2.3:a:openbsd:openssh:7.2:p1:*:*:*:*:*:*"), ssh, "7.2p2")[0],
            "7.2:p1 criteria does not match 7.2p2")
    _expect(match_details(conf("cpe:2.3:a:openbsd:openssh:7.2:*:*:*:*:*:*:*"), ssh, "7.2p2")[0],
            "7.2 with wildcard update matches 7.2p2")
    _expect(not match_details(conf("cpe:2.3:a:openbsd:openssh:7.2.1:*:*:*:*:*:*:*"), ssh, "7.2")[0],
            "7.2.1 does not match 7.2")
    hit, fixed, _ = match_details(conf(any_ssh, versionEndExcluding="7.4"), ssh, "7.2p2")
    _expect(hit and fixed == "7.4", "range with fixed version")
    hit, _, through = match_details(conf(any_ssh, versionEndIncluding="7.7"), ssh, "7.2p2")
    _expect(hit and through == "7.7", "range through version")
    _expect(not match_details(conf(any_ssh, versionStartIncluding="8.5", versionEndExcluding="9.8"),
                              ssh, "7.2p2")[0], "range above target")
    _expect(not match_details(conf("cpe:2.3:a:other:openssh:*:*:*:*:*:*:*:*"), ssh, "7.2p2")[0],
            "other vendor ignored")
    _expect(not match_details([{"nodes": [{"cpeMatch": [{"vulnerable": False, "criteria": any_ssh}]}]}],
                              ssh, "7.2p2")[0], "non-vulnerable criteria ignored")


def _t_scoring() -> None:
    def m(t: str, s: float, v: str = "cvssMetricV31") -> Dict[str, Any]:
        return {v: [{"type": t, "source": t, "cvssData": {"baseScore": s, "vectorString": "x"}}]}

    both = {"cvssMetricV31": m("Secondary", 9.1)["cvssMetricV31"] + m("Primary", 7.5)["cvssMetricV31"]}
    _expect(pick_cvss(both)[:2] == (7.5, "3.1"), "prefer NVD primary score")
    _expect(pick_cvss(dict(m("Primary", 5.0, "cvssMetricV2"), **m("Primary", 6.1, "cvssMetricV30")))[:2]
            == (6.1, "3.0"), "prefer v3.0 over v2")
    _expect(pick_cvss({})[0] is None, "no metrics")
    _expect([severity_for(s) for s in (None, 0.0, 0.1, 4.0, 7.0, 9.0)]
            == ["Unscored", "None", "Low", "Medium", "High", "Critical"], "severity bands")
    rec = CVERecord(id="CVE-2099-1")
    for kw, want in ((dict(score=5.0, kev=True), 1), (dict(score=9.0), 1), (dict(score=7.5), 2),
                     (dict(score=4.5, exploit_ref=True), 2), (dict(score=5.0), 3),
                     (dict(score=3.9, exploit_ref=True), 4), (dict(score=None), 4)):
        _expect(priority_for(replace(rec, **kw)) == want, f"priority for {kw}")
    _expect(safe_url("javascript:alert(1)") == "" and safe_url("https://a.example/x y") == ""
            and safe_url("https://a.example/x?y=1") == "https://a.example/x?y=1", "safe_url")


def _t_inputs() -> None:
    services, meta = parse_nmap_xml_bytes(DEMO_NMAP_XML.encode(), "demo.xml")
    _expect((meta["hosts_total"], meta["hosts_up"], meta["open_ports"]) == (3, 2, 8), "demo XML counts")
    ssh = services[0]
    _expect((ssh.host, ssh.hostname, ssh.port, ssh.product) == ("192.0.2.10", "web01.lab.example",
                                                                22, "OpenSSH"), "demo XML service")
    _expect(ssh.cpes == ["cpe:/a:openbsd:openssh:7.2p2", "cpe:/o:linux:linux_kernel"], "demo XML CPEs")
    _expect(_raises(InputError, parse_nmap_xml_bytes, b"", "x"), "empty XML")
    _expect(_raises(InputError, parse_nmap_xml_bytes, b"<html></html>", "x"), "non-Nmap XML")
    _expect(_raises(InputError, parse_nmap_xml_bytes, DEMO_NMAP_XML.encode()[:900], "x"), "truncated XML")
    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>'
    _expect(_raises(InputError, parse_nmap_xml_bytes, bomb, "x"), "XML entities refused")

    s = parse_manual_entry("OpenSSH 7.2p2")
    _expect((s.product, s.version_raw, s.host) == ("OpenSSH", "7.2p2", ""), "manual plain")
    s = parse_manual_entry("10.0.0.5:80/tcp Apache httpd 2.4.49")
    _expect((s.host, s.port, s.product, s.version_raw) == ("10.0.0.5", 80, "Apache httpd", "2.4.49"),
            "manual with endpoint")
    s = parse_manual_entry("[2001:db8::1]:22 OpenSSH 8.9p1")
    _expect(s.host == "2001:db8::1" and s.endpoint == "[2001:db8::1]:22/tcp", "manual IPv6")
    s = parse_manual_entry("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    _expect(s.product == "http server" and s.version_raw == "2.4.49", "manual CPE")
    _expect(_raises(InputError, parse_manual_entry, "2.4.49"), "manual needs product")
    _expect(_raises(InputError, parse_manual_entry, "host:99999 Foo 1.0"), "manual port range")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "services.csv")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("host,port,product,version\n10.0.0.9,21,vsftpd,3.0.3\n# comment\n,,Redis,6.0.9\n")
        rows = parse_manual_file(path)
        _expect([(r.host, r.port, r.product) for r in rows]
                == [("10.0.0.9", 21, "vsftpd"), ("", None, "Redis")], "manual CSV")
        path = os.path.join(tmp, "services.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("OpenSSH 7.2p2\n\n10.0.0.5:80 Apache httpd 2.4.49\n")
        _expect(len(parse_manual_file(path)) == 2, "manual text file")


def _t_client() -> None:
    url = NVDClient.build_url({"cpeName": _c23("apache", "http_server", "2.4.49")}, ("isVulnerable",))
    _expect("cpeName=cpe:2.3:a:apache:http_server:2.4.49:*:*" in url and url.endswith("&isVulnerable"),
            "exact-CPE URL")
    _expect("keywordSearch=Acme%20Widget" in NVDClient.build_url({"keywordSearch": "Acme Widget"}),
            "keyword URL encoding")
    with tempfile.TemporaryDirectory() as tmp:
        cache = os.path.join(tmp, "cache.json")
        params = {"virtualMatchString": _c23("openbsd", "openssh"), "resultsPerPage": "2000",
                  "startIndex": "0"}
        items = demo_fixtures()["product"]["openbsd:openssh"]
        with open(cache, "w", encoding="utf-8") as fh:
            json.dump({NVDClient.build_url(params): {"ts": time.time(), "data": {
                "totalResults": len(items), "vulnerabilities": items}}}, fh)
        client = NVDClient(cache_file=cache, log=Log(quiet=True))
        got, total = client.search({"virtualMatchString": _c23("openbsd", "openssh")})
        _expect(total == len(items) == len(got) and client.cache_hits == 1
                and client.requests_made == 0, "cached NVD response reused without network")
    _expect(NVDClient(api_key="k").min_interval < 1 < NVDClient().min_interval, "rate limit spacing")
    calls = []

    def offline(*_a: Any, **_k: Any) -> Any:
        calls.append(1)
        raise urllib.error.URLError("simulated outage")

    real_urlopen = urllib.request.urlopen
    urllib.request.urlopen = offline  # type: ignore[assignment]
    try:
        silent = _silent_log()
        client = NVDClient(max_retries=1, log=silent)
        client.min_interval = 0.0
        for q in ("a", "b", "c"):
            _expect(_raises(NVDError, client.search, {"keywordSearch": q}), "outage raises NVDError")
    finally:
        urllib.request.urlopen = real_urlopen  # type: ignore[assignment]
    _expect(len(calls) == 2 and silent.warnings, "stops calling NVD after repeated failures")


def _demo_report(**kw: Any) -> Report:
    services, scans, manual = demo_inputs()
    return assess_and_build(services, scans, manual, kw.pop("client", FixtureClient()),
                            Log(quiet=True), title="Self-test", demo=True, **kw)


def _t_pipeline() -> None:
    r = _demo_report()
    by = {s.port: s for s in r.services}
    httpd, ssh, mysql, ftp, acme = by[80], by[22], by[3306], by[21], by[8080]
    _expect(httpd.method == "nvd-cpe" and len(httpd.findings) == 4, "httpd exact-CPE findings")
    _expect(httpd.findings[0].cve.id == "CVE-2099-0001" and httpd.findings[0].fixed_in == "2.4.51",
            "httpd top finding and fix")
    _expect(upgrade_guidance(httpd).startswith("Upgrading to 2.4.52 or later resolves 2 of 4")
            and "affected through 2.4.53" in upgrade_guidance(httpd), "httpd upgrade guidance")
    _expect("resolves 3 of 3" in upgrade_guidance(mysql), "affected-through counts as resolved")
    _expect(ssh.method == "local-range" and ssh.distro and ssh.distro[0] == "Ubuntu", "ssh local range")
    _expect(sorted(f.cve.id[-4:] for f in ssh.findings) == ["0101", "0102", "0103", "0106"],
            "ssh version-range filtering")
    _expect(mysql.cpe.vendor == "oracle" and mysql.cpe_origin == "alias"
            and any("mysql:mysql" in n for n in mysql.notes), "mysql alias fallback")
    _expect(ftp.status == "assessed" and not ftp.findings, "vsftpd clean")
    _expect(acme.method == "keyword" and len(acme.findings) == 2, "keyword fallback filtered")
    _expect(by[443].status == by[3389].status == by[9999].status == "not_assessed", "not assessed")
    _expect("port number" in by[3389].reason and "tcpwrapped" in by[9999].reason, "skip reasons")
    _expect(by[6379].source == "manual" and len(by[6379].findings) == 1, "manual Redis entry")
    st = r.stats
    _expect((st["services"], st["assessed"], st["not_assessed"], st["findings"], st["kev"])
            == (9, 6, 3, 14, 1), f"stats {st}")
    _expect(r.findings[0].cve.kev and r.findings[0].priority == 1, "KEV finding sorted first")
    _expect([f.priority for f in r.findings] == sorted(f.priority for f in r.findings), "priority order")
    high = _demo_report(min_cvss=7.0)
    _expect(high.findings and all(f.cve.score >= 7.0 for f in high.findings), "min CVSS filter")
    down = _demo_report(client=FixtureClient(fail={_c23("apache", "http_server", "2.4.49"),
                                                   "apache:http_server"}))
    _expect({s.port: s for s in down.services}[80].status == "error"
            and down.stats["errors"] == 1, "NVD failure reported per service")


def _t_outputs() -> None:
    r = _demo_report()
    evil = CVERecord(id="CVE-2099-9999", description='<script>alert("x")</script>', score=9.9,
                     references=[{"url": "javascript:alert(1)", "tags": ["Patch"], "source": ""}])
    svc = r.services[0]
    r.findings.append(Finding(cve=evil, service=svc, method="keyword", confidence="Low"))
    svc.findings.append(r.findings[-1])
    page = render_html(r)
    _expect(page.startswith("<!DOCTYPE html>") and "</html>" in page, "HTML document")
    _expect('<script>alert("x")' not in page and "javascript:alert" not in page, "HTML escaping")
    _expect("CVE-2099-0001" in page and "Offline demo" in page, "HTML content")
    doc = json.loads(render_json(r))
    _expect(doc["demo"] is True and doc["findings"][0]["cve"] == "CVE-2099-0001", "JSON output")
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "out", "report")
        written = write_outputs(r, base, ["html", "json", "pdf"], _silent_log())
        _expect(base + ".html" in written and base + ".json" in written, "outputs written")
        try:
            import reportlab  # noqa: F401  (only to decide whether the PDF must exist)
            with open(base + ".pdf", "rb") as fh:
                _expect(fh.read(5) == b"%PDF-", "PDF written")
        except ImportError:
            pass
    _expect(output_base("x/report.html") == "x/report" and parse_formats("PDF, html") == ["pdf", "html"],
            "output naming")
    _expect(_raises(InputError, parse_formats, "html,docx"), "bad format rejected")


SELF_TESTS = [("version comparison", _t_versions), ("CPE parsing", _t_cpe),
              ("version-range matching", _t_matching), ("CVSS and priority", _t_scoring),
              ("Nmap XML and manual input", _t_inputs), ("NVD client (offline)", _t_client),
              ("assessment pipeline", _t_pipeline), ("HTML/JSON/PDF output", _t_outputs)]


def run_self_test(log: Log) -> int:
    log.info(f"{TOOL} {__version__} self-test (offline, no network)")
    failed = 0
    for name, fn in SELF_TESTS:
        try:
            fn()
            log.info(f"  PASS  {name}")
        except Exception as exc:  # report every failure, keep going
            failed += 1
            log.info(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
    try:
        import reportlab  # noqa: F401
        pdf_note = "reportlab installed, PDF checked"
    except ImportError:
        pdf_note = "reportlab not installed, PDF skipped"
    log.info(f"{len(SELF_TESTS) - failed} of {len(SELF_TESTS)} checks passed ({pdf_note}; "
             f"XML parser: {'defusedxml' if SAFE_XML else 'standard library'}).")
    return 1 if failed else 0


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def _cvss_arg(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}")
    if not 0.0 <= value <= 10.0:
        raise argparse.ArgumentTypeError("CVSS scores run from 0.0 to 10.0")
    return value


def build_parser() -> argparse.ArgumentParser:
    doc = __doc__ or ""
    p = argparse.ArgumentParser(
        prog=TOOL, formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Match Nmap service versions to published CVEs (NVD API 2.0) and write a "
                    "prioritized HTML/PDF vulnerability report.",
        epilog=doc[doc.find("Examples"):doc.find("Requirements")].rstrip() if "Examples" in doc else None)
    src = p.add_argument_group("input (combine as needed)")
    src.add_argument("-x", "--xml", action="append", default=[], metavar="FILE",
                     help="Nmap XML output (nmap -sV -oX FILE). Repeatable.")
    src.add_argument("-m", "--manual", action="append", default=[], metavar="ENTRY",
                     help='a service typed by hand, e.g. "OpenSSH 7.2p2", '
                          '"10.0.0.5:80 Apache httpd 2.4.49" or a CPE. Repeatable.')
    src.add_argument("--manual-file", action="append", default=[], metavar="FILE",
                     help="one manual entry per line, or a CSV with host,port,product,version,cpe")
    src.add_argument("--demo", action="store_true",
                     help="run offline on a synthetic scan and synthetic CVE data")
    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", default="vuln_report", metavar="BASE",
                     help="output path without extension (default: vuln_report)")
    out.add_argument("-f", "--format", default="html,pdf", metavar="LIST",
                     help="comma-separated: html, pdf, json (default: html,pdf)")
    out.add_argument("--title", default="", help="report title")
    out.add_argument("--min-cvss", type=_cvss_arg, default=0.0, metavar="SCORE",
                     help="only report CVEs scoring at least SCORE (hides unscored CVEs)")
    out.add_argument("-q", "--quiet", action="store_true", help="only print warnings and errors")
    nvd = p.add_argument_group("NVD API")
    nvd.add_argument("--api-key", default=os.environ.get("NVD_API_KEY", ""), metavar="KEY",
                     help=f"NVD API key (default: $NVD_API_KEY). Free at {NVD_KEY_URL}")
    nvd.add_argument("--cache", default=".nvd_cache.json", metavar="FILE",
                     help="response cache file (default: .nvd_cache.json)")
    nvd.add_argument("--cache-hours", type=float, default=24.0, metavar="H",
                     help="reuse cached responses younger than H hours (default: 24)")
    nvd.add_argument("--no-cache", action="store_true", help="do not read or write the cache")
    nvd.add_argument("--timeout", type=float, default=45.0, metavar="SEC",
                     help="per-request timeout in seconds (default: 45)")
    nvd.add_argument("--no-keyword", action="store_true",
                     help="skip keyword searches for products without a CPE")
    p.add_argument("--self-test", action="store_true", help="run offline checks and exit")
    p.add_argument("--version", action="version", version=f"{TOOL} {__version__}")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    _configure_console()
    parser = build_parser()
    args = parser.parse_args(argv)
    log = Log(quiet=args.quiet)
    if args.self_test:
        return run_self_test(log)
    try:
        formats = parse_formats(args.format)
    except InputError as exc:
        parser.error(str(exc))
    has_input = bool(args.xml or args.manual or args.manual_file)
    if args.demo and has_input:
        parser.error("--demo uses its own synthetic input; drop -x/-m/--manual-file")
    if not (args.demo or has_input):
        parser.error("give an input: -x scan.xml, -m \"Product 1.2\", --manual-file FILE, or --demo")

    services: List[Service] = []
    scans: List[Dict[str, Any]] = []
    manual_count = 0
    try:
        if args.demo:
            services, scans, manual_count = demo_inputs()
        for path in args.xml:
            found, meta = parse_nmap_xml(path)
            log.info(f"{path}: {meta['hosts_up']} of {meta['hosts_total']} host(s) up, "
                     f"{meta['open_ports']} open port(s)")
            services.extend(found)
            scans.append(meta)
        for entry in args.manual:
            services.append(parse_manual_entry(entry))
            manual_count += 1
        for path in args.manual_file:
            found = parse_manual_file(path)
            log.info(f"{path}: {len(found)} manual entr{'y' if len(found) == 1 else 'ies'}")
            services.extend(found)
            manual_count += len(found)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not services:
        log.warn("the input contains no open ports; the report will be empty. "
                 "Check that the scan reached its target (try nmap -Pn).")

    if args.demo:
        client: Any = FixtureClient()
        log.info("Offline demo: synthetic scan, synthetic CVE data, no network access.")
    else:
        client = NVDClient(api_key=args.api_key, cache_file=None if args.no_cache else args.cache,
                           cache_hours=args.cache_hours, timeout=args.timeout, log=log)
        if not client.api_key:
            log.info(f"No NVD API key set; lookups are throttled. Get a free key at {NVD_KEY_URL}")
    title = args.title or ("Vulnerability report (offline demo)" if args.demo else "Vulnerability report")
    try:
        report = assess_and_build(services, scans, manual_count, client, log,
                                  keyword_fallback=not args.no_keyword, min_cvss=args.min_cvss,
                                  title=title, demo=args.demo)
        written = write_outputs(report, output_base(args.output), formats, log)
    except KeyboardInterrupt:
        print("\ninterrupted; no report written", file=sys.stderr)
        return 130
    except OSError as exc:
        print(f"error: could not write the report: {exc}", file=sys.stderr)
        return 1
    print_summary(report, written, log)
    if report.stats["errors"] and not report.stats["assessed"]:
        log.warn("every NVD lookup failed. Check the network connection and API key, then re-run.")
        return 1
    return 0 if written else 1


if __name__ == "__main__":
    sys.exit(main())
