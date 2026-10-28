#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fim.py - Secure File Integrity Monitor (FIM)

CSIT 2033 | Week 10 Lab | Cybersecurity Strategy: Defensive

A file integrity monitoring daemon. It baselines a directory by hashing every
file with SHA-256 into a SQLite database, then keeps checking the directory for
additions, deletions and modifications. Every alert goes to a tamper-evident,
append-only log: each entry is signed with HMAC-SHA256 and chained to the entry
before it, so editing, deleting, reordering, forging or truncating entries is
caught by `verify-log`.

Lab deliverables and where they live
  1. Baseline creation and hash database (SQLite) .... fim.py baseline
  2. Continuous monitoring loop, configurable interval  fim.py monitor --interval N
  3. Alerts in a tamper-evident log (HMAC-signed) ..... fim.py verify-log / tamper-test
  4. Demo: detect a simulated malware drop ............ fim.py demo  (or lab-setup + simulate)

Quick start
  python fim.py demo                          complete offline demonstration
  python fim.py lab-setup --dir lab_target    sample web-server directory to protect
  python fim.py baseline  --dir lab_target    SHA-256 baseline into fim_data/fim.db
  python fim.py monitor   --interval 5        the daemon (Ctrl+C stops it cleanly)
  python fim.py simulate  --dir lab_target    from a second terminal: inert malware drop
  python fim.py verify-log                    check every signature and the hash chain
  python fim.py report -o reports/fim_report  HTML + PDF + JSON report
  python fim.py self-test                     offline checks of the core logic

Requirements: Python 3.8+. The core uses only the standard library (hashlib,
hmac, sqlite3). Optional: watchdog (real-time file events between interval
scans) and reportlab (PDF report). Everything else degrades gracefully.

The HMAC key is read from the FIM_HMAC_KEY environment variable or from a key
file (default fim_data/fim.key, created with 0600 permissions on first use).
In production keep the key off the monitored host: whoever holds the key can
forge log entries.
"""

from __future__ import annotations

import argparse
import base64
import collections
import errno
import fnmatch
import hashlib
import hmac
import html
import io
import json
import math
import os
import platform
import posixpath
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import stat
import struct
import sys
import tempfile
import threading
import time
import traceback
import uuid
import zlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

__version__ = "1.0.0"
TOOL = "fim.py"

# ----------------------------------------------------------------------------
# Defaults and constants
# ----------------------------------------------------------------------------

DEFAULT_STATE_DIR = "fim_data"
DB_NAME = "fim.db"
LOG_NAME = "fim_alerts.log"
KEY_NAME = "fim.key"
MANIFEST_NAME = "simulation_manifest.json"
TAMPER_NAME = "tamper_test.json"
IOC_SAMPLE_NAME = "threat_intel_iocs.txt"
ENV_KEY = "FIM_HMAC_KEY"
ENV_COLOR = "FIM_COLOR"

SCHEMA_VERSION = 1
LOG_FORMAT = 1
GENESIS_PREV = "0" * 64
HASH_CHUNK = 1 << 20          # 1 MiB reads while hashing
SAMPLE_BYTES = 256 * 1024     # bytes sampled for entropy / type sniffing
ENTROPY_THRESHOLD = 7.2       # bits per byte; random or encrypted data is ~8.0
MIN_ENTROPY_SAMPLE = 1024

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2             # check found changes / verify-log found tampering
EXIT_BASELINE_TAMPERED = 3

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Alert events (integrity findings) versus lifecycle events (bookkeeping).
EVENT_LABELS = {
    "FILE_ADDED": "File added",
    "FILE_DELETED": "File deleted",
    "FILE_MODIFIED": "File modified",
    "FILE_MOVED": "File moved",
    "PERMISSIONS_CHANGED": "Permissions changed",
    "OWNER_CHANGED": "Owner changed",
    "TYPE_CHANGED": "File type changed",
    "SYMLINK_CHANGED": "Symlink target changed",
    "TIMESTAMP_CHANGED": "Timestamp changed",
    "FILE_UNREADABLE": "File unreadable",
    "DIRECTORY_UNREADABLE": "Directory unreadable",
    "BASELINE_TAMPERED": "Baseline tampered",
    "LOG_TAMPERED": "Alert log tampered",
    "LOG_CREATED": "Log created",
    "BASELINE_CREATED": "Baseline created",
    "BASELINE_UPDATED": "Baseline updated",
    "MONITOR_STARTED": "Monitor started",
    "MONITOR_STOPPED": "Monitor stopped",
    "HEARTBEAT": "Heartbeat",
    "INTEGRITY_CHECK": "Integrity check",
}
ALERT_EVENTS = {
    "FILE_ADDED", "FILE_DELETED", "FILE_MODIFIED", "FILE_MOVED",
    "PERMISSIONS_CHANGED", "OWNER_CHANGED", "TYPE_CHANGED", "SYMLINK_CHANGED",
    "TIMESTAMP_CHANGED", "FILE_UNREADABLE", "DIRECTORY_UNREADABLE",
    "BASELINE_TAMPERED", "LOG_TAMPERED",
}

# Known-bad SHA-256 values that ship with the tool. The EICAR entry is the
# industry-standard antivirus test file (only its hash is stored here).
BUILTIN_IOCS = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f":
        "EICAR antivirus test file",
}

ATTACK_NAMES = {
    "T1105": "Ingress Tool Transfer",
    "T1036.007": "Masquerading: Double File Extension",
    "T1036.008": "Masquerading: Masquerade File Type",
    "T1564.001": "Hide Artifacts: Hidden Files and Directories",
    "T1027.002": "Obfuscated Files or Information: Software Packing",
    "T1070": "Indicator Removal",
    "T1070.006": "Indicator Removal: Timestomp",
    "T1222.002": "Linux and Mac File and Directory Permissions Modification",
    "T1548.001": "Abuse Elevation Control Mechanism: Setuid and Setgid",
    "T1098.004": "Account Manipulation: SSH Authorized Keys",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1543.002": "Create or Modify System Process: Systemd Service",
    "T1037.004": "Boot or Logon Initialization Scripts: RC Scripts",
    "T1546.004": "Event Triggered Execution: Unix Shell Configuration Modification",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1505.003": "Server Software Component: Web Shell",
}


class FIMError(Exception):
    """An expected, user-facing error (bad input, missing baseline, ...)."""


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: Optional[datetime] = None) -> str:
    dt = dt or utc_now()
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def iso_from_ns(ns: Optional[int]) -> Optional[str]:
    if ns is None:
        return None
    return iso(datetime.fromtimestamp(ns / 1e9, tz=timezone.utc))


def parse_iso(text: Optional[str]) -> Optional[datetime]:
    if not text:
        return None
    try:
        t = text.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(t)
    except ValueError:
        return None


def short_time(text: Optional[str]) -> str:
    """HH:MM:SS.s (UTC) from an ISO timestamp."""
    dt = parse_iso(text)
    if not dt:
        return "-"
    return dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 100000}"


def human_ts(text: Optional[str]) -> str:
    dt = parse_iso(text)
    if not dt:
        return "-"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def human_size(n: Optional[int]) -> str:
    if n is None:
        return "-"
    units = ["B", "KB", "MB", "GB", "TB"]
    v = float(n)
    for u in units:
        if v < 1024 or u == units[-1]:
            return f"{int(v)} {u}" if u == "B" else f"{v:.1f} {u}"
        v /= 1024
    return f"{n} B"


def human_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "-"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    m, s = divmod(int(round(seconds)), 60)
    if m < 60:
        return f"{m} min {s} s"
    h, m = divmod(m, 60)
    return f"{h} h {m} min"


def mode_str(mode: Optional[int]) -> str:
    if mode is None:
        return "-"
    return f"{mode & 0o7777:04o}"


def rwx(mode: Optional[int]) -> str:
    if mode is None:
        return "-"
    return stat.filemode(stat.S_IFREG | (mode & 0o7777))[1:]


def plural(n: int, word: str, many: Optional[str] = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def canon(obj: Any) -> str:
    """Canonical JSON used for every signature: sorted keys, no spaces, ASCII."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def safe_text(s: str) -> str:
    """Make a string safe for UTF-8 storage (undecodable file names use surrogates)."""
    try:
        s.encode("utf-8")
        return s
    except UnicodeEncodeError:
        return s.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")


def hostname() -> str:
    try:
        return socket.gethostname() or "unknown-host"
    except OSError:
        return "unknown-host"


def platform_label() -> str:
    return f"{platform.system()} {platform.release()} / Python {platform.python_version()}"


def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_json(path: Path, data: Any) -> None:
    ensure_dir(path.parent)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def read_json(path: Optional[Path]) -> Optional[Any]:
    if not path or not Path(path).is_file():
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# ----------------------------------------------------------------------------
# Console output (ANSI colour where supported; ASCII-safe for Windows consoles)
# ----------------------------------------------------------------------------

def _prepare_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        enc = (getattr(stream, "encoding", None) or "").lower()
        if enc and "utf" not in enc and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except (ValueError, OSError):
                pass


def _enable_windows_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def want_color(choice: str = "auto") -> bool:
    env = os.environ.get(ENV_COLOR, "").lower()
    if choice == "never" or env in ("0", "never", "no") or os.environ.get("NO_COLOR"):
        return False
    if choice == "always" or env in ("1", "always", "yes"):
        return _enable_windows_ansi() or os.name != "nt"
    return sys.stdout.isatty() and _enable_windows_ansi()


class Console:
    SEV_STYLE = {
        "CRITICAL": "1;97;41",
        "HIGH": "1;91",
        "MEDIUM": "1;93",
        "LOW": "96",
        "INFO": "2",
    }

    def __init__(self, color: bool = False, quiet: bool = False, stream=None):
        self.color = color
        self.quiet = quiet
        self.stream = stream or sys.stdout
        self.lock = threading.Lock()

    def c(self, text: str, style: str) -> str:
        return f"\033[{style}m{text}\033[0m" if self.color and style else text

    def emit(self, text: str = "", force: bool = False) -> None:
        if self.quiet and not force:
            return
        with self.lock:
            try:
                print(text, file=self.stream, flush=True)
            except UnicodeEncodeError:
                print(text.encode("ascii", "replace").decode("ascii"), file=self.stream, flush=True)

    def heading(self, text: str) -> None:
        self.emit("")
        self.emit(self.c(text, "1"))

    def info(self, text: str) -> None:
        self.emit(text)

    def ok(self, text: str) -> None:
        self.emit(self.c("[+] ", "92") + text)

    def note(self, text: str) -> None:
        self.emit(self.c("[*] ", "96") + text)

    def warn(self, text: str) -> None:
        self.emit(self.c("[!] ", "93") + text, force=True)

    def error(self, text: str) -> None:
        self.emit(self.c("[x] ", "91") + text, force=True)

    def kv(self, key: str, value: str, width: int = 22) -> None:
        dots = "." * max(2, width - len(key))
        self.emit(f"  {key} {self.c(dots, '2')} {value}")

    def sev(self, severity: str) -> str:
        return self.c(f"{severity:<8}", self.SEV_STYLE.get(severity, ""))

    def alert(self, entry: Dict[str, Any]) -> None:
        data = entry.get("data") or {}
        sev = entry.get("sev", "INFO")
        label = EVENT_LABELS.get(entry.get("event", ""), entry.get("event", ""))
        path = entry.get("path") or ""
        if data.get("dest"):
            path = f"{path} -> {data['dest']}"
        when = short_time(entry.get("ts"))
        self.emit(f"{self.c(when, '2')}  {self.sev(sev)}  {label:<20} {path}", force=True)
        why = "; ".join(i.get("label", "") for i in data.get("indicators", [])[:4])
        if why:
            self.emit(f"            {self.c(why, '2')}", force=True)
        bits = []
        after = data.get("after") or {}
        if after.get("sha256"):
            bits.append(f"sha256 {after['sha256'][:16]}...")
        if data.get("source"):
            src = data["source"]
            if data.get("latency_ms") is not None:
                src += f" in {data['latency_ms'] / 1000:.2f} s"
            bits.append(f"detected by {src}")
        if bits:
            self.emit(f"            {self.c(' | '.join(bits), '2')}", force=True)


# ----------------------------------------------------------------------------
# HMAC keys
# ----------------------------------------------------------------------------

@dataclass
class Keys:
    master: bytes
    source: str

    def derive(self, label: str) -> bytes:
        return hmac.new(self.master, ("fim.py/" + label).encode(), hashlib.sha256).digest()

    @property
    def log_key(self) -> bytes:
        return self.derive("alert-log/v1")

    @property
    def baseline_key(self) -> bytes:
        return self.derive("baseline/v1")

    @property
    def anchor_key(self) -> bytes:
        return self.derive("log-anchor/v1")

    @property
    def key_id(self) -> str:
        """Public fingerprint of the key (safe to print; reveals nothing usable)."""
        return self.derive("key-id").hex()[:16]

    def sign(self, which: bytes, text: str) -> str:
        return hmac.new(which, text.encode("utf-8"), hashlib.sha256).hexdigest()


def _decode_key(text: str) -> bytes:
    t = text.strip()
    if re.fullmatch(r"[0-9a-fA-F]{32,}", t) and len(t) % 2 == 0:
        return bytes.fromhex(t)
    return t.encode("utf-8")


def load_keys(key_file: Path, create: bool = True) -> Keys:
    env = os.environ.get(ENV_KEY, "").strip()
    if env:
        key, source = _decode_key(env), f"environment variable {ENV_KEY}"
    elif key_file.is_file():
        key = _decode_key(key_file.read_text(encoding="ascii", errors="ignore"))
        source = f"key file {key_file}"
    elif create:
        ensure_dir(key_file.parent)
        material = secrets.token_hex(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(str(key_file), flags, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(material + "\n")
        key, source = bytes.fromhex(material), f"new key file {key_file}"
    else:
        raise FIMError(
            f"No HMAC key found. Set {ENV_KEY} or provide the key file used when the log was written "
            f"(looked for {key_file}).")
    if len(key) < 16:
        raise FIMError(f"The HMAC key is too short ({len(key)} bytes). Use at least 16 bytes, "
                       f"for example 64 hex characters from `python -c \"import secrets;print(secrets.token_hex(32))\"`.")
    return Keys(master=key, source=source)


# ----------------------------------------------------------------------------
# File records, hashing and scanning
# ----------------------------------------------------------------------------

INODE_MASK = (1 << 63) - 1        # keep inode numbers inside SQLite's signed 64-bit range
RECORD_FIELDS = ("path", "kind", "sha256", "size", "mtime_ns", "ctime_ns", "mode",
                 "uid", "gid", "inode", "link_target", "magic", "error")


@dataclass
class FileRecord:
    path: str                       # POSIX-style path relative to the monitored root
    kind: str                       # "file", "symlink" or "special"
    sha256: Optional[str] = None
    size: Optional[int] = None
    mtime_ns: Optional[int] = None
    ctime_ns: Optional[int] = None
    mode: Optional[int] = None      # permission bits incl. setuid/setgid/sticky
    uid: Optional[int] = None
    gid: Optional[int] = None
    inode: Optional[int] = None
    link_target: Optional[str] = None
    magic: Optional[str] = None     # detected content type, e.g. "ELF executable"
    error: Optional[str] = None     # why the file could not be hashed

    def to_row(self) -> tuple:
        return tuple(getattr(self, f) for f in RECORD_FIELDS)

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> "FileRecord":
        return cls(**dict(zip(RECORD_FIELDS, row)))

    def to_dict(self) -> Dict[str, Any]:
        return {f: getattr(self, f) for f in RECORD_FIELDS}

    def brief(self) -> Dict[str, Any]:
        """Compact view used inside alert entries."""
        d = {
            "kind": self.kind, "sha256": self.sha256, "size": self.size,
            "mode": mode_str(self.mode) if self.mode is not None else None,
            "uid": self.uid, "gid": self.gid, "mtime": iso_from_ns(self.mtime_ns),
            "type": self.magic, "target": self.link_target, "error": self.error,
        }
        return {k: v for k, v in d.items() if v is not None}


MAGIC_SIGNATURES = [
    (b"MZ", "Windows PE executable"),
    (b"\x7fELF", "ELF executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O executable"),
    (b"\xfe\xed\xfa\xcf", "Mach-O executable"),
    (b"\xce\xfa\xed\xfe", "Mach-O executable"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal binary or Java class"),
    (b"#!", "script (shebang)"),
    (b"<?php", "PHP script"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"SQLite format 3\x00", "SQLite database"),
]
EXEC_BINARY_TYPES = {"Windows PE executable", "ELF executable", "Mach-O executable",
                     "Mach-O universal binary or Java class"}
SCRIPT_TYPES = {"script (shebang)", "PHP script"}
COMPRESSED_TYPES = {"ZIP archive", "gzip archive", "7-Zip archive", "RAR archive", "PNG image",
                    "JPEG image", "GIF image", "PDF document", "SQLite database"}

# Extensions that legitimately hold native executables.
BINARY_EXT_OK = {"exe", "dll", "sys", "scr", "com", "ocx", "cpl", "msi", "efi", "bin", "so",
                 "dylib", "elf", "o", "ko", "out", "run", "app", "class", "node", "pyd", "drv"}
# Extensions that can run code when opened or served.
RISKY_EXT = {"exe", "dll", "scr", "com", "pif", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js",
             "jse", "wsf", "wsh", "hta", "jar", "msi", "lnk", "cpl", "sh", "elf", "so", "php",
             "phtml", "php5", "jsp", "jspx", "asp", "aspx", "cgi", "pl", "py"}
# Extensions that look like harmless documents (used for double-extension checks).
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg",
           "jpeg", "png", "gif", "bmp", "zip", "rar", "mp3", "mp4", "mov", "html", "htm", "odt"}
COMPRESSED_EXT = {"zip", "gz", "tgz", "bz2", "xz", "7z", "rar", "zst", "png", "jpg", "jpeg",
                  "gif", "webp", "mp3", "mp4", "mkv", "avi", "mov", "pdf", "docx", "xlsx",
                  "pptx", "jar", "apk", "whl", "woff", "woff2", "db", "sqlite"}
WEB_SCRIPT_EXT = {"php", "phtml", "php5", "phar", "jsp", "jspx", "asp", "aspx", "ashx", "cgi"}
WEB_DIR_NAMES = {"www", "htdocs", "public_html", "wwwroot", "html", "web", "webroot", "uploads"}


def sniff_type(head: Optional[bytes]) -> Optional[str]:
    if head is None:
        return None
    if not head:
        return "empty"
    for sig, label in MAGIC_SIGNATURES:
        if head.startswith(sig):
            return label
    if b"\x00" in head:
        return "binary data"
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start < len(head) - 3:
            return "binary data"
    return "text"


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 for empty input, 8.0 maximum)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in collections.Counter(data).values())


def name_suffixes(name: str) -> List[str]:
    """['pdf', 'exe'] for 'invoice.pdf.exe'; a leading dot marks a hidden file, not an extension."""
    parts = name.lstrip(".").lower().split(".")
    return [p for p in parts[1:] if p]


def is_hidden(rel: str) -> bool:
    return any(p.startswith(".") and p not in (".", "..") for p in rel.split("/"))


def special_kind(mode: int) -> str:
    if stat.S_ISFIFO(mode):
        return "named pipe (FIFO)"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character device"
    if stat.S_ISBLK(mode):
        return "block device"
    return "special file"


_OPEN_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
               | getattr(os, "O_BINARY", 0))


@dataclass
class HashResult:
    sha256: Optional[str]
    head: Optional[bytes]
    error: Optional[str]
    st: Optional[os.stat_result]
    bytes_read: int = 0


def hash_file(path: str, attempts: int = 3) -> HashResult:
    """Stream a file through SHA-256.

    The file is opened without following symlinks and without blocking (so a
    FIFO swapped in mid-scan cannot hang the daemon). If the file changes while
    it is being read, the hash is retried; after three tries it is reported as
    unstable rather than silently trusted.
    """
    last = HashResult(None, None, "not hashed", None)
    for attempt in range(attempts):
        try:
            fd = os.open(path, _OPEN_FLAGS)
        except FileNotFoundError:
            return HashResult(None, None, "vanished during scan", None)
        except PermissionError:
            return HashResult(None, None, "permission denied", None)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                return HashResult(None, None, "replaced by a symlink during scan", None)
            return HashResult(None, None, f"cannot open ({exc.strerror or exc})", None)
        try:
            st1 = os.fstat(fd)
            if not stat.S_ISREG(st1.st_mode):
                return HashResult(None, None, "not a regular file", st1)
            digest = hashlib.sha256()
            head = b""
            total = 0
            while True:
                chunk = os.read(fd, HASH_CHUNK)
                if not chunk:
                    break
                if total < 64:
                    head += chunk[:64 - total]
                digest.update(chunk)
                total += len(chunk)
            st2 = os.fstat(fd)
        except OSError as exc:
            return HashResult(None, None, f"read error ({exc.strerror or exc})", None)
        finally:
            os.close(fd)
        last = HashResult(digest.hexdigest(), head, None, st2, total)
        if st1.st_size == st2.st_size == total and st1.st_mtime_ns == st2.st_mtime_ns:
            return last
        time.sleep(0.05 * (attempt + 1))
    last.error = "changed while being hashed"
    return last


def read_sample(path: str, limit: int = SAMPLE_BYTES) -> Optional[bytes]:
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, total = [], 0
        while total < limit:
            chunk = os.read(fd, min(HASH_CHUNK, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


@dataclass
class ScanResult:
    records: Dict[str, FileRecord] = field(default_factory=dict)
    blind: Set[str] = field(default_factory=set)   # unreadable directories
    dirs: int = 0
    files_hashed: int = 0
    bytes_hashed: int = 0
    reused: int = 0
    duration: float = 0.0
    errors: List[str] = field(default_factory=list)


class Scanner:
    """Walks the monitored tree without following symlinks and records every entry."""

    def __init__(self, root: Path, excludes: Optional[Sequence[str]] = None,
                 skip_paths: Optional[Iterable[Path]] = None):
        self.root = Path(root).resolve()
        self.root_str = str(self.root)
        self.excludes = [e for e in (excludes or []) if e]
        self.skip = {os.path.normcase(os.path.abspath(str(p))) for p in (skip_paths or [])}

    # -- path helpers ------------------------------------------------------
    def rel(self, abs_path: str) -> Optional[str]:
        try:
            r = os.path.relpath(abs_path, self.root_str)
        except ValueError:
            return None
        if r == ".":
            return ""
        if r == ".." or r.startswith(".." + os.sep):
            return None
        return safe_text(r.replace(os.sep, "/"))

    def abs(self, rel: str) -> str:
        return os.path.join(self.root_str, *rel.split("/")) if rel else self.root_str

    def _match(self, rel: str) -> bool:
        name = rel.rsplit("/", 1)[-1]
        for pat in self.excludes:
            p = pat.rstrip("/")
            if "/" in p:
                if fnmatch.fnmatch(rel, p):
                    return True
            elif fnmatch.fnmatch(name, p):
                return True
        return False

    def excluded(self, rel: str) -> bool:
        """True if rel or any of its parent directories matches an exclude pattern."""
        if not rel:
            return False
        parts = rel.split("/")
        return any(self._match("/".join(parts[:i + 1])) for i in range(len(parts)))

    def skipped(self, abs_path: str) -> bool:
        """True for fim.py's own state files (and anything inside the state directory)."""
        if not self.skip:
            return False
        p = os.path.normcase(os.path.abspath(abs_path))
        return any(p == s or p.startswith(s + os.sep) for s in self.skip)

    # -- scanning ----------------------------------------------------------
    def scan(self, prev: Optional[Dict[str, FileRecord]] = None, fast: bool = False) -> ScanResult:
        t0 = time.monotonic()
        res = ScanResult()
        if not os.path.isdir(self.root_str):
            raise FIMError(f"The monitored directory no longer exists: {self.root_str}")
        self._walk(self.root_str, "", res, prev, fast)
        res.duration = time.monotonic() - t0
        return res

    def scan_paths(self, rels: Iterable[str], prev: Optional[Dict[str, FileRecord]] = None,
                   fast: bool = False) -> Tuple[ScanResult, List[str]]:
        """Rescan only the given paths (files or whole subtrees). Returns (result, scope)."""
        t0 = time.monotonic()
        res = ScanResult()
        scope: List[str] = []
        for rel in sorted(set(rels)):
            if not rel or self.excluded(rel):
                continue
            abs_p = self.abs(rel)
            if self.skipped(abs_p):
                continue
            scope.append(rel)
            try:
                st = os.lstat(abs_p)
            except FileNotFoundError:
                continue                      # deleted: the diff over `scope` reports it
            except OSError:
                res.blind.add(rel)
                continue
            if stat.S_ISDIR(st.st_mode):
                self._walk(abs_p, rel, res, prev, fast)
            else:
                rec = self.record(abs_p, rel, (prev or {}).get(rel), fast, res)
                if rec:
                    res.records[rel] = rec
        res.duration = time.monotonic() - t0
        return res, scope

    def _walk(self, abs_dir: str, rel_dir: str, res: ScanResult,
              prev: Optional[Dict[str, FileRecord]], fast: bool) -> None:
        stack = [(abs_dir, rel_dir)]
        while stack:
            d_abs, d_rel = stack.pop()
            try:
                with os.scandir(d_abs) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except FileNotFoundError:
                continue
            except OSError as exc:
                if d_rel == "":
                    raise FIMError(f"Cannot read the monitored directory {d_abs}: {exc}")
                res.blind.add(d_rel)
                res.errors.append(f"{d_rel}/: {exc.strerror or exc}")
                continue
            res.dirs += 1
            for entry in entries:
                if self.skipped(entry.path):
                    continue
                rel = safe_text(entry.name if not d_rel else f"{d_rel}/{entry.name}")
                if self._match(rel):
                    continue
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError:
                    is_dir = False
                if is_dir:
                    stack.append((entry.path, rel))
                    continue
                rec = self.record(entry.path, rel, (prev or {}).get(rel), fast, res)
                if rec:
                    res.records[rel] = rec

    def record(self, abs_p: str, rel: str, prev_rec: Optional[FileRecord] = None,
               fast: bool = False, res: Optional[ScanResult] = None) -> Optional[FileRecord]:
        try:
            st = os.lstat(abs_p)
        except FileNotFoundError:
            return None
        except OSError as exc:
            return FileRecord(path=rel, kind="file", error=f"cannot stat ({exc.strerror or exc})")
        common = dict(path=rel, size=st.st_size, mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns,
                      mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid,
                      inode=st.st_ino & INODE_MASK)
        if stat.S_ISLNK(st.st_mode):
            try:
                target = safe_text(os.readlink(abs_p))
            except OSError:
                target = None
            return FileRecord(kind="symlink", link_target=target, **common)
        if stat.S_ISDIR(st.st_mode):
            return None
        if not stat.S_ISREG(st.st_mode):
            return FileRecord(kind="special", magic=special_kind(st.st_mode), **common)
        if (fast and prev_rec is not None and prev_rec.kind == "file" and prev_rec.sha256
                and not prev_rec.error
                and (prev_rec.size, prev_rec.mtime_ns, prev_rec.ctime_ns, prev_rec.inode)
                == (st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino & INODE_MASK)):
            if res:
                res.reused += 1
            return FileRecord(kind="file", sha256=prev_rec.sha256, magic=prev_rec.magic, **common)
        h = hash_file(abs_p)
        if h.st is not None:
            common.update(size=h.st.st_size, mtime_ns=h.st.st_mtime_ns, ctime_ns=h.st.st_ctime_ns,
                          mode=stat.S_IMODE(h.st.st_mode), uid=h.st.st_uid, gid=h.st.st_gid,
                          inode=h.st.st_ino & INODE_MASK)
        if res:
            res.files_hashed += 1
            res.bytes_hashed += h.bytes_read
        if h.error == "vanished during scan":
            return None
        return FileRecord(kind="file", sha256=h.sha256, magic=sniff_type(h.head), error=h.error,
                          **common)


# ----------------------------------------------------------------------------
# Baseline database (SQLite)
# ----------------------------------------------------------------------------

SIGNED_META = ("schema_version", "algorithm", "root", "created_utc", "updated_utc", "excludes",
               "file_count", "total_bytes", "digest", "key_id")


def records_digest(records: Dict[str, FileRecord]) -> str:
    """One SHA-256 over every baseline row, in path order (a fingerprint of the whole baseline)."""
    h = hashlib.sha256()
    for path in sorted(records):
        h.update(canon(records[path].to_dict()).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


@dataclass
class BaselineCheck:
    ok: bool
    problem: Optional[str]
    meta: Dict[str, str]
    records: Dict[str, FileRecord]


class BaselineDB:
    """The hash database: baseline rows, a signed digest, session/scan history and the log anchor."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.conn: Optional[sqlite3.Connection] = None

    def open(self, create: bool = False) -> "BaselineDB":
        if not create and not self.path.is_file():
            raise FIMError(f"No baseline database at {self.path}. "
                           f"Run `{TOOL} baseline --dir <directory>` first.")
        ensure_dir(self.path.parent)
        try:
            self.conn = sqlite3.connect(str(self.path), timeout=30)
            self._schema()
        except sqlite3.DatabaseError as exc:
            raise FIMError(f"{self.path} is not a usable SQLite database ({exc}).")
        return self

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def __enter__(self) -> "BaselineDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _schema(self) -> None:
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS baseline (
                    path TEXT PRIMARY KEY, kind TEXT NOT NULL, sha256 TEXT, size INTEGER,
                    mtime_ns INTEGER, ctime_ns INTEGER, mode INTEGER, uid INTEGER, gid INTEGER,
                    inode INTEGER, link_target TEXT, magic TEXT, error TEXT);
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, started_utc TEXT NOT NULL,
                    stopped_utc TEXT, pid INTEGER, host TEXT, interval_s REAL, realtime INTEGER,
                    mode TEXT, cycles INTEGER DEFAULT 0, alerts INTEGER DEFAULT 0, stop_reason TEXT);
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER,
                    started_utc TEXT NOT NULL, trigger TEXT NOT NULL, files INTEGER,
                    hashed INTEGER, bytes_hashed INTEGER, duration_ms REAL, changes INTEGER);
                CREATE TABLE IF NOT EXISTS log_anchor (
                    log_id TEXT PRIMARY KEY, log_path TEXT, seq INTEGER NOT NULL,
                    hmac TEXT NOT NULL, updated_utc TEXT NOT NULL, sig TEXT NOT NULL);
            """)

    # -- meta / baseline -----------------------------------------------------
    def meta(self) -> Dict[str, str]:
        return dict(self.conn.execute("SELECT key, value FROM meta").fetchall())

    def has_baseline(self) -> bool:
        return "digest" in self.meta()

    def load_records(self) -> Dict[str, FileRecord]:
        cols = ", ".join(RECORD_FIELDS)
        rows = self.conn.execute(f"SELECT {cols} FROM baseline ORDER BY path").fetchall()
        return {r[0]: FileRecord.from_row(r) for r in rows}

    def write_baseline(self, root: Path, records: Dict[str, FileRecord], excludes: Sequence[str],
                       keys: Keys, keep_created: bool = False) -> Dict[str, str]:
        now = iso()
        old = self.meta()
        meta = {
            "schema_version": str(SCHEMA_VERSION),
            "tool_version": __version__,
            "algorithm": "sha256",
            "root": str(root),
            "created_utc": old.get("created_utc", now) if keep_created else now,
            "updated_utc": now,
            "host": hostname(),
            "platform": platform_label(),
            "excludes": json.dumps(list(excludes)),
            "file_count": str(len(records)),
            "total_bytes": str(sum((r.size or 0) for r in records.values() if r.kind == "file")),
            "digest": records_digest(records),
            "key_id": keys.key_id,
        }
        meta["signature"] = keys.sign(keys.baseline_key, canon({k: meta[k] for k in SIGNED_META}))
        with self.conn:
            self.conn.execute("DELETE FROM baseline")
            self.conn.executemany(
                f"INSERT INTO baseline ({', '.join(RECORD_FIELDS)}) VALUES "
                f"({', '.join('?' * len(RECORD_FIELDS))})",
                [records[p].to_row() for p in sorted(records)])
            self.conn.executemany("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                                  list(meta.items()))
        return meta

    def verify(self, keys: Keys) -> BaselineCheck:
        """Recompute the digest and HMAC so a doctored baseline cannot whitelist malware."""
        meta = self.meta()
        if "digest" not in meta:
            raise FIMError(f"{self.path} has no baseline yet. Run `{TOOL} baseline --dir <directory>`.")
        records = self.load_records()
        if records_digest(records) != meta.get("digest"):
            return BaselineCheck(False, "Baseline rows no longer match the signed digest: file hashes "
                                        "or entries were changed after the baseline was created.",
                                 meta, records)
        expected = keys.sign(keys.baseline_key, canon({k: meta.get(k) for k in SIGNED_META}))
        if not hmac.compare_digest(expected, meta.get("signature", "")):
            if meta.get("key_id") != keys.key_id:
                return BaselineCheck(False, f"The baseline signature does not verify with the current "
                                            f"HMAC key (key ID {keys.key_id}; baseline says "
                                            f"{meta.get('key_id')}). Either a different key is in use "
                                            f"or the baseline metadata was altered.", meta, records)
            return BaselineCheck(False, "The baseline metadata signature is invalid: the root, "
                                        "timestamps, counts or digest were altered.", meta, records)
        return BaselineCheck(True, None, meta, records)

    # -- monitoring history --------------------------------------------------
    def start_session(self, interval: float, realtime: bool, mode: str) -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO sessions (started_utc, pid, host, interval_s, realtime, mode) "
                "VALUES (?, ?, ?, ?, ?, ?)", (iso(), os.getpid(), hostname(), interval, int(realtime), mode))
        return int(cur.lastrowid)

    def update_session(self, sid: int, cycles: int, alerts: int,
                       stopped: Optional[str] = None, reason: Optional[str] = None) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE sessions SET cycles = ?, alerts = ?, stopped_utc = COALESCE(?, stopped_utc), "
                "stop_reason = COALESCE(?, stop_reason) WHERE id = ?",
                (cycles, alerts, stopped, reason, sid))

    def add_scan(self, sid: Optional[int], started: str, trigger: str, res: ScanResult,
                 changes: int) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO scans (session_id, started_utc, trigger, files, hashed, bytes_hashed, "
                "duration_ms, changes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (sid, started, trigger, len(res.records), res.files_hashed, res.bytes_hashed,
                 round(res.duration * 1000, 2), changes))

    def sessions(self) -> List[Dict[str, Any]]:
        cur = self.conn.execute("SELECT * FROM sessions ORDER BY id")
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def scans(self) -> List[Dict[str, Any]]:
        cur = self.conn.execute("SELECT * FROM scans ORDER BY id")
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    # -- log anchor (detects truncation of the alert log) ----------------------
    def set_anchor(self, keys: Keys, log_id: str, log_path: Path, seq: int, mac: str) -> None:
        sig = keys.sign(keys.anchor_key, canon({"log_id": log_id, "seq": seq, "hmac": mac}))
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO log_anchor (log_id, log_path, seq, hmac, updated_utc, sig) "
                "VALUES (?, ?, ?, ?, ?, ?)", (log_id, str(log_path), seq, mac, iso(), sig))

    def get_anchor(self, keys: Keys, log_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute("SELECT seq, hmac, updated_utc, sig FROM log_anchor WHERE log_id = ?",
                                (log_id,)).fetchone()
        if not row:
            return None
        seq, mac, updated, sig = row
        expected = keys.sign(keys.anchor_key, canon({"log_id": log_id, "seq": seq, "hmac": mac}))
        return {"seq": seq, "hmac": mac, "updated": updated,
                "valid_sig": hmac.compare_digest(expected, sig)}


# ----------------------------------------------------------------------------
# Change detection and assessment
# ----------------------------------------------------------------------------

BASE_SEVERITY = {
    "FILE_ADDED": "MEDIUM", "FILE_DELETED": "MEDIUM", "FILE_MODIFIED": "HIGH",
    "FILE_MOVED": "MEDIUM", "PERMISSIONS_CHANGED": "MEDIUM", "OWNER_CHANGED": "MEDIUM",
    "TYPE_CHANGED": "HIGH", "SYMLINK_CHANGED": "HIGH", "TIMESTAMP_CHANGED": "LOW",
    "FILE_UNREADABLE": "MEDIUM", "DIRECTORY_UNREADABLE": "MEDIUM",
}

SECURITY_CONFIG_NAMES = {"sshd_config", "ssh_config", "sudoers", "passwd", "shadow", "group",
                         "gshadow", "hosts", "resolv.conf", "pam.conf", "login.defs",
                         "nsswitch.conf", ".htaccess", "web.config", "php.ini", "my.cnf"}
SECURITY_CONFIG_DIRS = {"sudoers.d", "pam.d", "security"}
LOG_NAMES = {"syslog", "messages", "secure", "wtmp", "btmp", "lastlog", "auth", "kern"}

RESPONSES = [  # first matching indicator decides the advice
    ("known_bad_hash", "Quarantine the file, isolate the host and search other systems for this SHA-256."),
    ("masquerade", "Treat it as malware: quarantine it and find how it arrived (upload, e-mail or download)."),
    ("web_shell", "Remove the script, review web-server logs for requests to it and fix the upload path that allowed it."),
    ("ssh_keys", "Remove keys you do not recognise, rotate the account's credentials and review SSH logins."),
    ("setuid", "Remove the setuid/setgid bit and find out which account set it."),
    ("persistence", "Remove the added entry and investigate the program it launches."),
    ("timestomp", "Restore the file from a known-good copy; the untouched timestamp shows the edit was meant to stay hidden."),
    ("log_removed", "Recover the log from backup or the SIEM; deleted logs suggest someone covering their tracks."),
    ("log_truncated", "Compare with the SIEM copy to see which entries were removed."),
    ("executable", "Quarantine the executable and submit its hash to a malware sandbox or VirusTotal."),
    ("world_writable", "Restore the original permissions and find which account changed them."),
    ("exec_added", "Restore the original permissions and review what the file does."),
    ("security_config", "Diff against the known-good version and revert unauthorized settings."),
    ("high_entropy", "Analyse the file in a sandbox; packed or encrypted content hides its purpose."),
]
EVENT_RESPONSES = {
    "FILE_ADDED": "Confirm where the file came from; quarantine or delete it if it is not expected.",
    "FILE_MODIFIED": "Confirm the change was authorized; otherwise restore the file from a known-good copy.",
    "FILE_DELETED": "Confirm the deletion was authorized; otherwise restore the file from backup.",
    "FILE_MOVED": "Confirm the rename was expected; renamed files can hide in plain sight.",
    "PERMISSIONS_CHANGED": "Confirm the permission change was intended; otherwise restore the original mode.",
    "OWNER_CHANGED": "Confirm the ownership change was intended; otherwise restore the original owner.",
    "TYPE_CHANGED": "Find out why the file was replaced by a different kind of object, such as a symlink.",
    "SYMLINK_CHANGED": "Check where the link now points; a redirected link can expose or replace files.",
    "TIMESTAMP_CHANGED": "Usually benign (a touch or a copy); confirm nothing else about the file changed.",
    "FILE_UNREADABLE": "Restore read access so the file can be verified; removing access can blind integrity checks.",
    "DIRECTORY_UNREADABLE": "Restore read access so the directory can be verified.",
}


@dataclass
class Indicator:
    id: str
    label: str
    detail: str
    floor: Optional[str] = None     # minimum severity this indicator forces
    bump: bool = False              # raise severity one level
    attack: Tuple[str, ...] = ()


@dataclass
class Change:
    kind: str
    path: str
    old: Optional[FileRecord] = None
    new: Optional[FileRecord] = None
    dest: Optional[str] = None       # new path for FILE_MOVED
    severity: str = "MEDIUM"
    indicators: List[Indicator] = field(default_factory=list)
    attack: List[str] = field(default_factory=list)
    summary: str = ""
    response: str = ""
    notes: List[str] = field(default_factory=list)

    @property
    def target(self) -> str:
        return self.dest or self.path


@dataclass
class Policy:
    root: Path
    iocs: Dict[str, str] = field(default_factory=lambda: dict(BUILTIN_IOCS))
    critical: List[str] = field(default_factory=list)
    baseline: Dict[str, FileRecord] = field(default_factory=dict)


def _in_scope(key: str, scope: Optional[Sequence[str]]) -> bool:
    if scope is None:
        return True
    return any(key == s or key.startswith(s + "/") for s in scope)


def _compare(o: FileRecord, n: FileRecord) -> List[Change]:
    if o.kind != n.kind:
        return [Change("TYPE_CHANGED", o.path, old=o, new=n)]
    if o.kind == "symlink" and o.link_target != n.link_target:
        return [Change("SYMLINK_CHANGED", o.path, old=o, new=n)]
    if o.kind == "file":
        if n.error and not o.error and not n.sha256:
            return [Change("FILE_UNREADABLE", o.path, old=o, new=n)]
        if n.sha256 and n.sha256 != o.sha256:
            ch = Change("FILE_MODIFIED", o.path, old=o, new=n)
            if o.mode != n.mode:
                ch.notes.append(f"permissions also changed {mode_str(o.mode)} -> {mode_str(n.mode)}")
            if (o.uid, o.gid) != (n.uid, n.gid):
                ch.notes.append(f"owner also changed {o.uid}:{o.gid} -> {n.uid}:{n.gid}")
            return [ch]
    out = []
    if o.mode != n.mode:
        out.append(Change("PERMISSIONS_CHANGED", o.path, old=o, new=n))
    if (o.uid, o.gid) != (n.uid, n.gid):
        out.append(Change("OWNER_CHANGED", o.path, old=o, new=n))
    if not out and o.kind == "file" and o.mtime_ns != n.mtime_ns:
        out.append(Change("TIMESTAMP_CHANGED", o.path, old=o, new=n))
    return out


def diff_states(old: Dict[str, FileRecord], new: Dict[str, FileRecord],
                scope: Optional[Sequence[str]] = None, blind: Iterable[str] = ()) -> List[Change]:
    """Compare two snapshots. Identical content that disappears from one path and
    appears at another is reported once, as a move, instead of a delete plus an add."""
    blind = list(blind)
    old_keys = {k for k in old if _in_scope(k, scope)}
    new_keys = {k for k in new if _in_scope(k, scope)}
    added = sorted(new_keys - old_keys)
    deleted = sorted(k for k in old_keys - new_keys
                     if not any(k == b or k.startswith(b + "/") for b in blind))
    changes: List[Change] = []
    for k in sorted(old_keys & new_keys):
        changes.extend(_compare(old[k], new[k]))

    by_hash: Dict[str, List[str]] = collections.defaultdict(list)
    for k in deleted:
        r = old[k]
        if r.kind == "file" and r.sha256 and (r.size or 0) > 0:
            by_hash[r.sha256].append(k)
    moved_from, moved_to = set(), set()
    for k in added:
        r = new[k]
        if r.kind == "file" and r.sha256 and (r.size or 0) > 0 and by_hash.get(r.sha256):
            src = by_hash[r.sha256].pop(0)
            moved_from.add(src)
            moved_to.add(k)
            ch = Change("FILE_MOVED", src, old=old[src], new=r, dest=k)
            if old[src].mode != r.mode:
                ch.notes.append(f"permissions also changed {mode_str(old[src].mode)} -> {mode_str(r.mode)}")
            changes.append(ch)
    changes.extend(Change("FILE_ADDED", k, new=new[k]) for k in added if k not in moved_to)
    changes.extend(Change("FILE_DELETED", k, old=old[k]) for k in deleted if k not in moved_from)
    return changes


def _article(word: str) -> str:
    return "an" if word[:1].lower() in "aeiou" else "a"


def _persistence(lrel: str, lname: str) -> Optional[Tuple[str, str]]:
    parts = lrel.split("/")
    if any("cron" in p for p in parts[:-1]) or lname in ("crontab", "anacrontab"):
        return "T1053.003", "cron schedule"
    if "systemd" in parts and lname.endswith((".service", ".timer", ".socket")):
        return "T1543.002", "systemd unit"
    if lname == "rc.local" or "init.d" in parts or "rc.d" in parts:
        return "T1037.004", "boot-time RC script"
    if lname in (".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc",
                 ".zprofile", ".zlogin", "bash.bashrc") or (len(parts) > 1 and parts[-2] == "profile.d"):
        return "T1546.004", "shell start-up file"
    if "start menu/programs/startup" in lrel:
        return "T1547.001", "Windows Startup folder"
    return None


def _is_log(lrel: str, lname: str) -> bool:
    parts = lrel.split("/")
    stem = lname.split(".")[0]
    return (lname.endswith(".log") or ".log." in lname or stem in LOG_NAMES
            or any(p in ("log", "logs") for p in parts[:-1]))


def assess(ch: Change, pol: Policy) -> Change:
    """Attach indicators, a severity, ATT&CK techniques and response advice to a change."""
    tgt = ch.target
    name = tgt.rsplit("/", 1)[-1]
    lname, lrel = name.lower(), tgt.lower()
    parents = set(lrel.split("/")[:-1])
    exts = name_suffixes(name)
    last_ext = exts[-1] if exts else ""
    base = BASE_SEVERITY.get(ch.kind, "MEDIUM")
    if ch.kind == "FILE_MODIFIED" and ch.path not in pol.baseline:
        base = "MEDIUM"                 # a file that appeared after the baseline changed again
    inds: List[Indicator] = []

    def add(iid: str, label: str, detail: str, floor: Optional[str] = None,
            bump: bool = False, attack: Tuple[str, ...] = ()) -> None:
        inds.append(Indicator(iid, label, detail, floor, bump, tuple(attack)))

    new, old = ch.new, ch.old
    content_event = ch.kind in ("FILE_ADDED", "FILE_MODIFIED", "FILE_MOVED", "TYPE_CHANGED")
    if new is not None and new.kind == "file" and content_event:
        if new.sha256 and new.sha256 in pol.iocs:
            add("known_bad_hash", f"known-bad hash: {pol.iocs[new.sha256]}",
                f"This file's SHA-256 is on the threat-intelligence list as {pol.iocs[new.sha256]}.",
                floor="CRITICAL")
        sample = read_sample(os.path.join(str(pol.root), *tgt.split("/")))
        ftype = sniff_type(sample[:64]) if sample is not None else new.magic
        if ftype in EXEC_BINARY_TYPES:
            add("executable", ftype, f"The file starts with {_article(ftype)} {ftype} header.",
                floor="HIGH", attack=("T1105",) if ch.kind in ("FILE_ADDED", "FILE_MOVED") else ())
            if last_ext and last_ext not in BINARY_EXT_OK:
                add("masquerade", f"executable disguised as .{last_ext}",
                    f"The content is {_article(ftype)} {ftype}, but the name ends in .{last_ext}.",
                    floor="CRITICAL", attack=("T1036.008",))
        elif ftype in SCRIPT_TYPES and ch.kind in ("FILE_ADDED", "FILE_MOVED", "TYPE_CHANGED"):
            add("script", ftype, "A new script that can be run directly.", floor="HIGH")
        if len(exts) >= 2 and exts[-1] in RISKY_EXT and exts[-2] in DOC_EXT:
            add("double_extension", f"double extension (.{exts[-2]}.{exts[-1]})",
                "The name imitates a harmless document while the real extension runs code.",
                floor="HIGH", attack=("T1036.007",))
        elif (last_ext in RISKY_EXT and last_ext not in WEB_SCRIPT_EXT
              and ch.kind in ("FILE_ADDED", "FILE_MOVED")
              and not any(i.id in ("executable", "script") for i in inds)):
            add("risky_extension", f"executable file type (.{last_ext})",
                "Files of this type can run code when opened.", floor="HIGH")
        if last_ext in WEB_SCRIPT_EXT and ch.kind in ("FILE_ADDED", "FILE_MOVED") and parents & WEB_DIR_NAMES:
            uploads = "uploads" in parents
            add("web_shell", "server-side script in an upload folder" if uploads
                else "new server-side script in a web folder",
                "The web server would run this file when it is requested; this is how web shells are planted.",
                floor="CRITICAL" if uploads else "HIGH", attack=("T1505.003",))
        if (sample is not None and len(sample) >= MIN_ENTROPY_SAMPLE and ftype not in COMPRESSED_TYPES
                and last_ext not in COMPRESSED_EXT):
            ent = shannon_entropy(sample)
            if ent >= ENTROPY_THRESHOLD:
                add("high_entropy", f"high entropy ({ent:.2f} bits/byte)",
                    "Near-random content suggests a packed, encrypted or compressed payload.",
                    bump=True, attack=("T1027.002",))
        if ch.kind == "FILE_ADDED" and os.name != "nt" and new.mode is not None and new.mode & 0o111:
            add("exec_bit", f"executable permission ({rwx(new.mode)})",
                "The new file can be run directly.", floor="HIGH")

    if (ch.kind == "FILE_ADDED" and is_hidden(tgt)) or (
            ch.kind == "FILE_MOVED" and is_hidden(tgt) and not is_hidden(ch.path)):
        add("hidden", "hidden location", "The file sits in a dot-file or dot-directory that normal "
                                         "directory listings hide.", bump=True, attack=("T1564.001",))

    if ch.kind == "FILE_MODIFIED" and old is not None and new is not None and old.mtime_ns == new.mtime_ns:
        add("timestomp", "content changed but timestamp did not",
            "The modification time stayed at its earlier value after the content changed, which hides "
            "the edit from timestamp-based review.", floor="HIGH", attack=("T1070.006",))
    if ch.kind == "TIMESTAMP_CHANGED" and new is not None:
        b = pol.baseline.get(ch.path)
        if b is not None and b.mtime_ns == new.mtime_ns and b.sha256 and new.sha256 != b.sha256:
            add("timestomp", "timestamp reset to the baseline value",
                "The modification time was put back to its baseline value while the content still "
                "differs from the baseline.", floor="HIGH", attack=("T1070.006",))

    if (new is not None and new.mode is not None and os.name != "nt" and new.kind != "symlink"
            and ch.kind in ("FILE_ADDED", "PERMISSIONS_CHANGED", "FILE_MODIFIED", "FILE_MOVED")):
        old_mode = old.mode if (old is not None and old.mode is not None) else 0
        if new.mode & 0o002 and not old_mode & 0o002:
            add("world_writable", f"world-writable ({rwx(new.mode)})",
                "Any local account can now change this file.", floor="HIGH", attack=("T1222.002",))
        if new.mode & 0o6000 and not old_mode & 0o6000:
            add("setuid", "setuid/setgid bit set", "The file would run with its owner's or group's "
                                                   "privileges.", floor="CRITICAL", attack=("T1548.001",))
        if ch.kind == "PERMISSIONS_CHANGED" and new.mode & 0o111 and not old_mode & 0o111:
            add("exec_added", "made executable", "Execute permission was added.",
                floor="HIGH", attack=("T1222.002",))

    loc_events = ("FILE_ADDED", "FILE_MODIFIED", "FILE_MOVED", "PERMISSIONS_CHANGED",
                  "TYPE_CHANGED", "SYMLINK_CHANGED")
    if lname in ("authorized_keys", "authorized_keys2") and ch.kind in loc_events:
        add("ssh_keys", "SSH authorized_keys changed",
            "A key added here grants password-less SSH access to the account.",
            floor="CRITICAL", attack=("T1098.004",))
    pers = _persistence(lrel, lname)
    if pers and ch.kind in loc_events:
        add("persistence", f"persistence location ({pers[1]})",
            "Changes here make code run automatically on a schedule, at boot or at login.",
            floor="HIGH", attack=(pers[0],))
    if (lname in SECURITY_CONFIG_NAMES or parents & SECURITY_CONFIG_DIRS) and \
            ch.kind in loc_events + ("FILE_DELETED",):
        add("security_config", "security-sensitive configuration",
            "This file controls authentication, privileges or name resolution.", floor="HIGH")
    if _is_log(lrel, lname):
        if ch.kind == "FILE_DELETED":
            add("log_removed", "log file deleted", "Deleting logs is a common way to cover tracks.",
                floor="HIGH", attack=("T1070",))
        elif ch.kind == "FILE_MODIFIED" and old is not None and new is not None:
            if (new.size or 0) < (old.size or 0):
                add("log_truncated", "log file shrank",
                    f"The log lost {human_size((old.size or 0) - (new.size or 0))}; entries may have "
                    "been removed.", floor="HIGH", attack=("T1070",))
            elif (new.size or 0) > (old.size or 0) and not inds:
                base = "LOW"
                ch.notes.append("the log grew, which is normal append activity")
    if ch.kind == "FILE_UNREADABLE":
        add("unreadable", "read access removed",
            "The FIM can no longer hash this file; removing access is a way to blind integrity checks.")
    if pol.critical and any(fnmatch.fnmatch(tgt, g) or fnmatch.fnmatch(ch.path, g) for g in pol.critical):
        add("critical_path", "critical path", "The path matches a --critical pattern.", bump=True)

    rank = SEV_RANK[base]
    for ind in inds:
        if ind.floor:
            rank = max(rank, SEV_RANK[ind.floor])
    if any(ind.bump for ind in inds):
        rank = min(rank + 1, SEV_RANK["CRITICAL"])
    ch.severity = SEVERITIES[rank]
    ch.indicators = inds
    ch.attack = list(dict.fromkeys(t for ind in inds for t in ind.attack))

    facts = []
    if ch.kind == "FILE_MODIFIED" and old is not None and new is not None and old.size != new.size:
        facts.append(f"size {human_size(old.size)} -> {human_size(new.size)}")
    elif ch.kind == "PERMISSIONS_CHANGED" and old is not None and new is not None:
        facts.append(f"{mode_str(old.mode)} -> {mode_str(new.mode)}")
    elif ch.kind == "OWNER_CHANGED" and old is not None and new is not None:
        facts.append(f"{old.uid}:{old.gid} -> {new.uid}:{new.gid}")
    elif ch.kind == "SYMLINK_CHANGED" and old is not None and new is not None:
        facts.append(f"target {old.link_target} -> {new.link_target}")
    elif ch.kind == "TYPE_CHANGED" and old is not None and new is not None:
        facts.append(f"{old.kind} -> {new.kind}")
    ch.notes = facts + ch.notes
    where = f"{ch.path} -> {ch.dest}" if ch.dest else ch.path
    why = "; ".join(i.label for i in inds[:4])
    ch.summary = f"{EVENT_LABELS.get(ch.kind, ch.kind)}: {where}" + (f" ({why})" if why else "")
    ids = [i.id for i in inds]
    ch.response = next((text for iid, text in RESPONSES if iid in ids),
                       EVENT_RESPONSES.get(ch.kind, "Investigate the change."))
    return ch


def change_data(ch: Change, source: str, latency_ms: Optional[int] = None) -> Dict[str, Any]:
    data = {
        "source": source,
        "before": ch.old.brief() if ch.old else None,
        "after": ch.new.brief() if ch.new else None,
        "dest": ch.dest,
        "indicators": [{"id": i.id, "label": i.label, "detail": i.detail} for i in ch.indicators],
        "attack": [{"id": t, "name": ATTACK_NAMES.get(t, "")} for t in ch.attack],
        "notes": ch.notes,
        "response": ch.response,
        "latency_ms": latency_ms,
    }
    return {k: v for k, v in data.items() if v not in (None, [], "")}


def load_iocs(paths: Sequence[str]) -> Tuple[Dict[str, str], List[str]]:
    """Known-bad SHA-256 list. One hash per line, optionally followed by a name; # starts a comment."""
    iocs = dict(BUILTIN_IOCS)
    notes = []
    for p in paths or []:
        path = Path(p)
        if not path.is_file():
            raise FIMError(f"IOC file not found: {p}")
        count = 0
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([0-9a-fA-F]{64})(?:[\s,;|]+(.*))?$", line)
            if not m:
                notes.append(f"{path.name} line {line_no}: not a SHA-256 value, skipped")
                continue
            iocs[m.group(1).lower()] = (m.group(2) or "").strip() or f"listed in {path.name}"
            count += 1
        notes.append(f"{count} known-bad hashes loaded from {path.name}")
    return iocs, notes


# ----------------------------------------------------------------------------
# Tamper-evident, append-only alert log
# ----------------------------------------------------------------------------
#
# Every line is one JSON entry. Each entry carries:
#   seq   position in the log (1, 2, 3, ...)
#   prev  the HMAC of the entry before it (64 zeros for the first entry)
#   hmac  HMAC-SHA256 over the canonical JSON of every other field
# Changing any field breaks that entry's HMAC. Removing, inserting or
# reordering entries breaks the seq numbering and the prev links. Cutting
# entries off the end is caught by an anchor (last seq + HMAC) kept in the
# SQLite database, which is a separate file. Forging a replacement entry needs
# the HMAC key, which never appears in the log.

LOG_FIELD_ORDER = ("seq", "ts", "sev", "event", "path", "msg", "data", "v", "log", "kid", "prev", "hmac")
REQUIRED_LOG_FIELDS = {"seq", "ts", "event", "prev", "hmac", "log"}


def serialize_entry(entry: Dict[str, Any]) -> str:
    ordered = {k: entry[k] for k in LOG_FIELD_ORDER if k in entry}
    ordered.update({k: v for k, v in entry.items() if k not in ordered})
    return json.dumps(ordered, ensure_ascii=True, separators=(",", ":"))


def entry_mac(keys: Keys, entry: Dict[str, Any]) -> str:
    return keys.sign(keys.log_key, canon({k: v for k, v in entry.items() if k != "hmac"}))


def read_last_line(path: Path) -> Optional[str]:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return None
    if size == 0:
        return None
    with open(path, "rb") as fh:
        pos, buf = size, b""
        while pos > 0:
            step = min(65536, pos)
            pos -= step
            fh.seek(pos)
            buf = fh.read(step) + buf
            stripped = buf.rstrip(b"\r\n")
            cut = stripped.rfind(b"\n")
            if cut != -1:
                return stripped[cut + 1:].decode("ascii", "replace")
        return buf.rstrip(b"\r\n").decode("ascii", "replace")


class _FileLock:
    """Exclusive lock on a sidecar .lock file so several fim.py processes can share one log."""

    _thread_lock = threading.RLock()

    def __init__(self, path: Path):
        self.path = path
        self.fd: Optional[int] = None

    def __enter__(self) -> "_FileLock":
        self._thread_lock.acquire()
        ensure_dir(self.path.parent)
        self.fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            import fcntl
            fcntl.flock(self.fd, fcntl.LOCK_EX)
        except ImportError:
            try:
                import msvcrt
                for _ in range(400):
                    try:
                        msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        time.sleep(0.025)
            except ImportError:
                pass
        return self

    def __exit__(self, *exc) -> None:
        try:
            try:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except ImportError:
                import msvcrt
                os.lseek(self.fd, 0, 0)
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
        finally:
            os.close(self.fd)
            self.fd = None
            self._thread_lock.release()


@dataclass
class LogVerification:
    path: str
    status: str                    # VALID | TAMPERED | WRONG_KEY | EMPTY | MISSING
    summary: str = ""
    entries: int = 0
    valid: int = 0
    log_id: Optional[str] = None
    kid_log: Optional[str] = None
    kid_used: Optional[str] = None
    first_ts: Optional[str] = None
    last_ts: Optional[str] = None
    last_seq: int = 0
    head_hmac: str = GENESIS_PREV
    anchor: Optional[Dict[str, Any]] = None
    problems: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    lines: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "VALID"

    def first_finding(self) -> str:
        return self.problems[0]["message"] if self.problems else self.summary

    def to_dict(self, include_lines: bool = False) -> Dict[str, Any]:
        d = asdict(self)
        if not include_lines:
            d.pop("lines", None)
        return d


def verify_log(path: Path, keys: Keys, db: Optional[BaselineDB] = None,
               anchor: Optional[Dict[str, Any]] = None, keep_lines: bool = False) -> LogVerification:
    """Check every signature, the seq numbering, the prev chain and the anchor."""
    path = Path(path)
    v = LogVerification(path=str(path), status="VALID", kid_used=keys.key_id)
    if not path.is_file():
        v.status, v.summary = "MISSING", f"No alert log at {path}."
        return v
    raw = path.read_bytes()
    if not raw:
        v.status, v.summary = "EMPTY", "The alert log is empty."
        return v
    text = raw.decode("ascii", errors="replace")
    lines = text.split("\n")
    complete = text.endswith("\n")
    if complete:
        lines = lines[:-1]

    def problem(line_no: Optional[int], seq: Any, kind: str, message: str) -> None:
        v.problems.append({"line": line_no, "seq": seq, "kind": kind, "message": message})

    prev_mac: Optional[str] = GENESIS_PREV
    max_seq = 0
    seen: Set[int] = set()
    pending: Dict[int, int] = {}            # missing seq -> line where the gap appeared
    issues: Dict[int, List[Tuple[str, str]]] = collections.defaultdict(list)
    line_seq: Dict[int, Any] = {}
    seq_macs: Dict[int, str] = {}
    last_dt: Optional[datetime] = None
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            issues[line_no].append(("blank", "the line is blank; fim.py never writes blank lines, so an "
                                             "entry was erased here"))
            prev_mac = None
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            if line_no == len(lines) and not complete:
                issues[line_no].append(("torn", "the entry is incomplete (an interrupted write, or the end "
                                                "of the file was cut)"))
            else:
                issues[line_no].append(("bad_json", "the text is not a valid log entry (it was damaged or "
                                                    "edited)"))
            prev_mac = None
            continue
        if not isinstance(entry, dict) or not REQUIRED_LOG_FIELDS <= set(entry):
            issues[line_no].append(("malformed", "required fields are missing"))
            prev_mac = None
            continue
        v.entries += 1
        claimed = str(entry.get("hmac", ""))
        seq = entry.get("seq")
        line_seq[line_no] = seq
        if v.entries == 1:
            v.log_id, v.kid_log, v.first_ts = entry.get("log"), entry.get("kid"), entry.get("ts")
            if entry.get("event") != "LOG_CREATED" or entry.get("prev") != GENESIS_PREV:
                issues[line_no].append(("genesis", "this is not the log's opening entry, so the beginning "
                                                   "of the log is missing"))
        sig_ok = hmac.compare_digest(entry_mac(keys, entry), claimed)
        if sig_ok:
            v.valid += 1
        else:
            issues[line_no].append(("bad_signature", "signature mismatch: the entry was changed after it "
                                                     "was written, or forged without the key"))
        seq_issue = False
        if isinstance(seq, int):
            if seq in seen:
                issues[line_no].append(("duplicate", f"entry {seq} appears twice"))
                seq_issue = True
            elif seq > max_seq + 1:
                for missing in range(max_seq + 1, seq):
                    if missing not in seen:
                        pending[missing] = line_no
                seq_issue = True
            elif seq <= max_seq:
                if seq in pending:
                    gap_line = pending.pop(seq)
                    issues[line_no].append(("reorder", f"entry {seq} appears after entry {max_seq}, so "
                                                       "entries were reordered"))
                    issues[gap_line].append(("reorder", f"entry {line_seq.get(gap_line)} appears before "
                                                        f"entry {seq}, so entries were reordered"))
                else:
                    issues[line_no].append(("order", f"entry {seq} appears after entry {max_seq}"))
                seq_issue = True
            seen.add(seq)
            max_seq = max(max_seq, seq)
            seq_macs[seq] = claimed
            v.last_seq = seq
        if prev_mac is not None and entry.get("prev") != prev_mac and not seq_issue:
            issues[line_no].append(("chain", "the entry does not link to the one above it (an entry was "
                                             "removed, inserted or reordered here)"))
        if v.log_id and entry.get("log") != v.log_id:
            issues[line_no].append(("foreign", "the entry belongs to a different log"))
        dt = parse_iso(entry.get("ts"))
        if dt and last_dt and (last_dt - dt).total_seconds() > 2:
            v.warnings.append(f"Line {line_no}: timestamp is earlier than the entry before it.")
        last_dt = dt or last_dt
        if serialize_entry(entry) != line:
            v.warnings.append(f"Line {line_no}: formatting differs from what fim.py writes "
                              "(signed content unchanged).")
        prev_mac = claimed
        v.head_hmac = claimed
        v.last_ts = entry.get("ts")
        if keep_lines:
            v.lines.append({"line": line_no, "ok": sig_ok, "entry": entry})

    # Sequence numbers that never turned up were removed.
    by_line: Dict[int, List[int]] = collections.defaultdict(list)
    for missing, gap_line in pending.items():
        by_line[gap_line].append(missing)
    for gap_line, nums in by_line.items():
        nums.sort()
        what = (f"entry {nums[0]} is missing" if len(nums) == 1 else
                f"entries {nums[0]}-{nums[-1]} are missing" if nums[-1] - nums[0] == len(nums) - 1 else
                f"entries {', '.join(map(str, nums))} are missing")
        issues[gap_line].insert(0, ("gap", f"{what}, so {plural(len(nums), 'entry was', 'entries were')} "
                                           "removed before this line"))
    rank = {"bad_signature": 0, "gap": 1, "reorder": 2, "duplicate": 3, "order": 4, "genesis": 5,
            "chain": 6, "foreign": 7, "torn": 8, "bad_json": 9, "malformed": 10, "blank": 11}
    for line_no in sorted(issues):
        found = issues[line_no]
        kinds = [k for k, _ in found]
        seq = line_seq.get(line_no)
        head = f"Line {line_no}" + (f" (entry {seq})" if seq is not None else "")
        text = "; ".join(dict.fromkeys(msg for _, msg in found))
        v.problems.append({"line": line_no, "seq": seq,
                           "kind": min(kinds, key=lambda k: rank.get(k, 99)), "kinds": kinds,
                           "message": f"{head}: {text[0].upper()}{text[1:]}."})

    if v.entries and v.valid == 0 and v.kid_log and v.kid_log != keys.key_id:
        v.status = "WRONG_KEY"
        v.summary = (f"No entry verifies with the current key (key ID {keys.key_id}); the log was "
                     f"written with key ID {v.kid_log}. Load the original key to verify it.")
        return v

    if anchor is None and db is not None and v.log_id:
        try:
            anchor = db.get_anchor(keys, v.log_id)
        except sqlite3.Error:
            anchor = None
    if anchor:
        a = {"seq": anchor["seq"], "hmac": anchor["hmac"], "updated": anchor.get("updated")}
        if not anchor.get("valid_sig", True):
            a["status"] = "invalid"
            problem(None, None, "anchor", "The anchor stored in the database has an invalid signature.")
        elif v.last_seq < anchor["seq"]:
            a["status"] = "truncated"
            missing = anchor["seq"] - v.last_seq
            problem(None, anchor["seq"], "truncated",
                    f"The log ends at entry {v.last_seq}, but the database anchor recorded entry "
                    f"{anchor['seq']}: {plural(missing, 'entry', 'entries')} cut from the end.")
        elif seq_macs.get(anchor["seq"]) != anchor["hmac"]:
            a["status"] = "mismatch"
            problem(None, anchor["seq"], "anchor_mismatch",
                    f"Entry {anchor['seq']} does not match the database anchor, so the log was rewritten.")
        else:
            a["status"] = "match"
            if v.last_seq > anchor["seq"]:
                v.warnings.append(f"{plural(v.last_seq - anchor['seq'], 'entry', 'entries')} follow the "
                                  "database anchor.")
        v.anchor = a
    else:
        v.anchor = {"status": "absent"}

    if v.problems:
        v.status = "TAMPERED"
        more = f" ({len(v.problems)} problems in total.)" if len(v.problems) > 1 else ""
        v.summary = f"Verification failed. {v.problems[0]['message']}{more}"
    else:
        v.summary = (f"All {v.entries} entries carry valid HMAC-SHA256 signatures and form one "
                     "unbroken chain.")
    return v


class TamperEvidentLog:
    """Append-only writer. Verifies the log before extending it; a log that fails
    verification is set aside (kept as evidence) and a fresh chain is started."""

    def __init__(self, path: Path, keys: Keys, db: Optional[BaselineDB] = None,
                 console: Optional[Console] = None):
        self.path = Path(path)
        self.keys = keys
        self.db = db
        self.console = console
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.log_id: Optional[str] = None
        self.last_seq = 0
        self.last_mac = GENESIS_PREV
        self.set_aside: List[Dict[str, Any]] = []
        self._anchor_warned = False

    def open(self) -> "TamperEvidentLog":
        ensure_dir(self.path.parent)
        with _FileLock(self.lock_path):
            if self.path.is_file() and self.path.stat().st_size > 0:
                ver = verify_log(self.path, self.keys, self.db)
                if ver.ok:
                    self.log_id, self.last_seq, self.last_mac = ver.log_id, ver.last_seq, ver.head_hmac
                else:
                    self._set_aside_locked(ver)
            else:
                self._create_locked(None)
        return self

    def append(self, event: str, sev: str, msg: str, path: Optional[str] = None,
               data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with _FileLock(self.lock_path):
            self._sync_tail_locked()
            return self._append_locked(event, sev, msg, path, data)

    def recheck(self) -> LogVerification:
        """Full re-verification (used by the daemon's heartbeat); sets the log aside if it fails."""
        with _FileLock(self.lock_path):
            ver = verify_log(self.path, self.keys, self.db)
            if not ver.ok:
                self._set_aside_locked(ver)
            return ver

    # -- internals ---------------------------------------------------------------
    def _create_locked(self, previous: Optional[Dict[str, Any]]) -> None:
        self.log_id = uuid.uuid4().hex
        self.last_seq, self.last_mac = 0, GENESIS_PREV
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
        os.close(fd)
        data = {"tool": TOOL, "version": __version__, "host": hostname(), "platform": platform_label(),
                "key_id": self.keys.key_id, "signature": "HMAC-SHA256",
                "chain": "each entry includes the HMAC of the entry before it"}
        if previous:
            data["previous_log"] = previous
        self._append_locked("LOG_CREATED", "INFO", "Tamper-evident alert log created", None, data)

    def _set_aside_locked(self, ver: LogVerification) -> None:
        stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
        aside = self.path.with_name(f"{self.path.name}.untrusted-{stamp}")
        if self.path.exists():
            os.replace(self.path, aside)
            name = aside.name
        else:
            name = "(file missing)"
        finding = ver.first_finding() if ver.status != "MISSING" else "the log file was deleted"
        info = {"file": name, "status": ver.status, "entries": ver.entries,
                "problems": len(ver.problems), "finding": finding}
        self._create_locked(info)
        sev = "HIGH" if ver.status == "WRONG_KEY" else "CRITICAL"
        msg = (f"The alert log failed verification and was set aside as {name}: {finding}"
               if name != "(file missing)" else "The alert log was deleted while fim.py was using it.")
        self._append_locked("LOG_TAMPERED", sev, msg, None, {"previous_log": info, "source": "log check"})
        self.set_aside.append(info)
        if self.console:
            self.console.warn(msg)

    def _sync_tail_locked(self) -> None:
        """Adopt entries appended by other fim.py processes; detect a tampered or missing tail."""
        line = read_last_line(self.path)
        if line is None:
            if self.last_seq == 0 and self.log_id is None:
                self._create_locked(None)
            else:
                self._set_aside_locked(verify_log(self.path, self.keys, self.db))
            return
        try:
            entry = json.loads(line)
            good = (isinstance(entry, dict) and entry.get("log") == self.log_id
                    and hmac.compare_digest(entry_mac(self.keys, entry), str(entry.get("hmac", "")))
                    and isinstance(entry.get("seq"), int) and entry["seq"] >= self.last_seq
                    and not (entry["seq"] == self.last_seq and entry.get("hmac") != self.last_mac))
        except ValueError:
            good = False
        if good:
            self.last_seq, self.last_mac = entry["seq"], entry["hmac"]
        else:
            self._set_aside_locked(verify_log(self.path, self.keys, self.db))

    def _append_locked(self, event: str, sev: str, msg: str, path: Optional[str],
                       data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        entry: Dict[str, Any] = {"v": LOG_FORMAT, "seq": self.last_seq + 1, "ts": iso(),
                                 "log": self.log_id, "kid": self.keys.key_id, "event": event,
                                 "sev": sev, "msg": msg, "prev": self.last_mac}
        if path is not None:
            entry["path"] = path
        if data:
            entry["data"] = data
        entry["hmac"] = entry_mac(self.keys, entry)
        payload = (serialize_entry(entry) + "\n").encode("ascii")
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
        try:
            view = memoryview(payload)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        self.last_seq, self.last_mac = entry["seq"], entry["hmac"]
        if self.db is not None:
            try:
                self.db.set_anchor(self.keys, self.log_id, self.path, self.last_seq, self.last_mac)
            except sqlite3.Error as exc:
                if self.console and not self._anchor_warned:
                    self.console.warn(f"Could not update the log anchor in the database: {exc}")
                self._anchor_warned = True
        return entry


def read_log_entries(path: Path) -> List[Dict[str, Any]]:
    """Parse the log without judging it (verify_log does the judging)."""
    out = []
    if not Path(path).is_file():
        return out
    for line in Path(path).read_text(encoding="ascii", errors="replace").splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            out.append(entry)
    return out


def run_tamper_test(log_path: Path, keys: Keys, db: Optional[BaselineDB], work_dir: Path) -> Dict[str, Any]:
    """Attack copies of the log five ways and confirm verification catches every one.
    The original log is only read, never modified."""
    original = verify_log(log_path, keys, db)
    if not original.ok:
        raise FIMError(f"The original log must verify before it can be tamper-tested: {original.summary}")
    lines = Path(log_path).read_text(encoding="ascii").splitlines()
    entries = [json.loads(l) for l in lines]
    if len(entries) < 4:
        raise FIMError("The log needs at least four entries for a meaningful tamper test.")
    alert_idx = [i for i, e in enumerate(entries) if e.get("event") in ALERT_EVENTS]
    target = max(alert_idx, key=lambda i: (SEV_RANK.get(entries[i].get("sev"), 0), -i)) if alert_idx \
        else len(entries) // 2
    tgt = entries[target]
    ensure_dir(work_dir)
    scenarios = []

    def run(sid: str, title: str, change: str, new_lines: List[str], expected: str) -> None:
        copy = work_dir / f"{sid}.log"
        copy.write_text("\n".join(new_lines) + ("\n" if new_lines else ""), encoding="ascii")
        ver = verify_log(copy, keys, db)
        scenarios.append({
            "id": sid, "title": title, "change": change, "expected": expected,
            "detected": not ver.ok, "status": ver.status, "finding": ver.first_finding(),
            "problems": len(ver.problems), "copy": copy.name,
        })

    # 1. Edit: an attacker downgrades the most serious alert so it looks routine.
    edited = dict(tgt)
    edited["sev"] = "INFO"
    edited["msg"] = "Routine maintenance change"
    l1 = list(lines)
    l1[target] = serialize_entry(edited)
    run("edit", "Edit an alert",
        f"Line {target + 1}: severity changed from {tgt.get('sev')} to INFO and the message reworded to look routine",
        l1, "signature mismatch on the edited line")

    # 2. Delete: the attacker removes that alert entirely.
    l2 = lines[:target] + lines[target + 1:]
    what = EVENT_LABELS.get(tgt.get("event", ""), tgt.get("event", "")).lower()
    run("delete", "Delete an alert",
        f"Line {target + 1} removed (the '{what}' alert for {tgt.get('path') or 'the log'})",
        l2, "gap in entry numbers and a broken chain")

    # 3. Reorder: two neighbouring entries swap places.
    j = max(1, min(target, len(lines) - 3))
    l3 = list(lines)
    l3[j], l3[j + 1] = l3[j + 1], l3[j]
    run("reorder", "Reorder two entries", f"Lines {j + 1} and {j + 2} swapped", l3,
        "out-of-order entry numbers and a broken chain")

    # 4. Forge: a well-formed "all clear" entry, correctly numbered and linked, signed with a guessed key.
    last = entries[-1]
    fake = {"v": LOG_FORMAT, "seq": last["seq"] + 1, "ts": iso(), "log": last.get("log"),
            "kid": last.get("kid"), "event": "MONITOR_STOPPED", "sev": "INFO",
            "msg": "Monitor stopped: no integrity changes detected", "prev": last["hmac"]}
    fake["hmac"] = hmac.new(secrets.token_bytes(32), canon(fake).encode(), hashlib.sha256).hexdigest()
    run("forge", "Forge an entry", "A fake 'no changes detected' entry appended, numbered and linked "
                                   "correctly but signed without the real key",
        lines + [serialize_entry(fake)], "signature mismatch on the forged line")

    # 5. Truncate: the last entries are cut off, leaving a log that is internally consistent.
    cut = min(3, len(lines) - 2)
    run("truncate", "Truncate the end", f"Last {plural(cut, 'entry', 'entries')} removed",
        lines[:-cut], "missing entries compared with the database anchor")

    detected = sum(1 for s in scenarios if s["detected"])
    return {
        "generated": iso(), "log": str(log_path), "key_id": keys.key_id,
        "original": {"status": original.status, "entries": original.entries,
                     "head_hmac": original.head_hmac, "anchor": original.anchor},
        "scenarios": scenarios, "detected": detected, "total": len(scenarios),
        "note": "Each attack was made on a copy; the original log was not modified.",
    }


# ----------------------------------------------------------------------------
# State files, baseline creation, one-shot check
# ----------------------------------------------------------------------------

@dataclass
class StatePaths:
    dir: Path
    db: Path
    log: Path
    key: Path

    @classmethod
    def build(cls, state_dir: str = DEFAULT_STATE_DIR, db: Optional[str] = None,
              log: Optional[str] = None, key: Optional[str] = None) -> "StatePaths":
        d = Path(state_dir).resolve()
        return cls(dir=d,
                   db=Path(db).resolve() if db else d / DB_NAME,
                   log=Path(log).resolve() if log else d / LOG_NAME,
                   key=Path(key).resolve() if key else d / KEY_NAME)

    @property
    def manifest(self) -> Path:
        return self.dir / MANIFEST_NAME

    @property
    def tamper(self) -> Path:
        return self.dir / TAMPER_NAME

    def skip_paths(self) -> List[Path]:
        paths = [self.dir, self.db, self.log, self.key, self.log.with_name(self.log.name + ".lock")]
        paths += [self.db.with_name(self.db.name + s) for s in ("-journal", "-wal", "-shm")]
        return paths

    def inside(self, root: Path) -> bool:
        r = str(Path(root).resolve())
        return any(str(p) == r or str(p).startswith(r + os.sep) for p in (self.dir, self.db, self.log, self.key))


def create_baseline(root: Path, state: StatePaths, keys: Keys, console: Console,
                    excludes: Sequence[str] = (), update: bool = False, force: bool = False) -> Dict[str, Any]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise FIMError(f"Directory not found: {root}")
    if state.inside(root):
        console.warn("The state files (database, log, key) are inside the monitored directory. "
                     "They are excluded automatically, but keep them outside it in production.")
    db = BaselineDB(state.db).open(create=True)
    try:
        exists = db.has_baseline()
        old_meta = db.meta() if exists else {}
        if exists and not (update or force):
            raise FIMError(f"A baseline already exists in {state.db}. Use --update to approve the "
                           f"directory's current state, or --force to start a new baseline.")
        if update and not exists:
            raise FIMError("There is no baseline to update yet; run without --update first.")
        if update and old_meta.get("root") != str(root):
            raise FIMError(f"The existing baseline covers {old_meta.get('root')}, not {root}. "
                           f"Use --force to start a new baseline for a different directory.")
        if update and not excludes:
            excludes = json.loads(old_meta.get("excludes") or "[]")
        log = TamperEvidentLog(state.log, keys, db, console).open()
        old_records: Dict[str, FileRecord] = {}
        old_ok = True
        if update:
            check = db.verify(keys)
            old_ok, old_records = check.ok, check.records
            if not check.ok:
                console.warn(f"The previous baseline failed verification ({check.problem}). "
                             "It is being replaced by a fresh scan of the directory.")
        console.note(f"Hashing every file under {root} with SHA-256 ...")
        scanner = Scanner(root, excludes, skip_paths=state.skip_paths())
        res = scanner.scan()
        meta = db.write_baseline(root, res.records, excludes, keys, keep_created=update)
        data: Dict[str, Any] = {
            "root": str(root), "files": len(res.records), "bytes": int(meta["total_bytes"]),
            "directories": res.dirs, "digest": meta["digest"], "excludes": list(excludes),
            "database": str(state.db), "duration_ms": round(res.duration * 1000, 1),
        }
        if res.blind:
            data["unreadable_directories"] = sorted(res.blind)
        if update:
            accepted = diff_states(old_records, res.records)
            counts = collections.Counter(c.kind for c in accepted)
            data["accepted"] = {"counts": dict(counts),
                                "paths": [c.target for c in accepted][:25],
                                "previous_baseline_verified": old_ok}
            msg = (f"Baseline updated for {root}: {plural(len(accepted), 'change')} approved, "
                   f"{plural(len(res.records), 'file')} now trusted")
            log.append("BASELINE_UPDATED", "INFO", msg, None, data)
        else:
            log.append("BASELINE_CREATED", "INFO",
                       f"Baseline created for {root}: {plural(len(res.records), 'file')} hashed", None, data)
        data["meta"] = meta
        data["records"] = res.records
        data["scan"] = res
        return data
    finally:
        db.close()


def run_check(state: StatePaths, keys: Keys, console: Console, iocs: Dict[str, str],
              critical: Sequence[str] = ()) -> Tuple[int, List[Dict[str, Any]]]:
    """One-shot comparison of the directory against the baseline (Tripwire-style)."""
    db = BaselineDB(state.db).open()
    try:
        log = TamperEvidentLog(state.log, keys, db, console).open()
        check = db.verify(keys)
        if not check.ok:
            entry = log.append("BASELINE_TAMPERED", "CRITICAL", f"Baseline failed verification: {check.problem}",
                               None, {"source": "check"})
            console.alert(entry)
            return EXIT_BASELINE_TAMPERED, [entry]
        root = Path(check.meta["root"])
        excludes = json.loads(check.meta.get("excludes") or "[]")
        scanner = Scanner(root, excludes, skip_paths=state.skip_paths())
        policy = Policy(root=root, iocs=iocs, critical=list(critical), baseline=check.records)
        started = iso()
        res = scanner.scan()
        changes = diff_states(check.records, res.records, None, res.blind)
        changes += [Change("DIRECTORY_UNREADABLE", b) for b in sorted(res.blind)]
        entries = []
        for ch in changes:
            assess(ch, policy)
            entry = log.append(ch.kind, ch.severity, ch.summary, ch.path, change_data(ch, "check"))
            console.alert(entry)
            entries.append(entry)
        counts = collections.Counter(e["sev"] for e in entries)
        log.append("INTEGRITY_CHECK", "INFO",
                   f"Integrity check of {root}: {plural(len(res.records), 'file')} scanned, "
                   f"{plural(len(entries), 'change')} from the baseline",
                   None, {"files": len(res.records), "changes": len(entries), "by_severity": dict(counts),
                          "duration_ms": round(res.duration * 1000, 1)})
        db.add_scan(None, started, "check", res, len(entries))
        return (EXIT_FINDINGS if entries else EXIT_OK), entries
    finally:
        db.close()


# ----------------------------------------------------------------------------
# The monitoring daemon
# ----------------------------------------------------------------------------

class Monitor:
    """Interval scans (the authoritative check) plus optional watchdog events for
    near-real-time alerts in between. Every alert is written to the signed log."""

    def __init__(self, state: StatePaths, keys: Keys, console: Console, interval: float = 10.0,
                 realtime: bool = True, settle: float = 0.75, heartbeat: float = 60.0,
                 max_cycles: Optional[int] = None, duration: Optional[float] = None,
                 fast: bool = False, iocs: Optional[Dict[str, str]] = None,
                 critical: Sequence[str] = (), pidfile: Optional[Path] = None):
        if interval <= 0:
            raise FIMError("--interval must be greater than zero.")
        self.state, self.keys, self.console = state, keys, console
        self.interval, self.realtime, self.settle = float(interval), realtime, max(0.05, settle)
        self.max_settle = max(self.settle * 4, 3.0)
        self.heartbeat = float(heartbeat or 0)
        self.max_cycles, self.duration, self.fast = max_cycles, duration, fast
        self.iocs = iocs if iocs is not None else dict(BUILTIN_IOCS)
        self.critical = list(critical)
        self.pidfile = pidfile
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.ready = threading.Event()
        self.stop_reason = "stopped"
        self.exit_code = EXIT_OK
        self._dirty: Dict[str, float] = {}
        self._dirty_lock = threading.Lock()
        self._last_event = 0.0
        self._blind: Set[str] = set()
        self.cycles = 0
        self.interval_scans = 0
        self.alerts = 0
        self.by_sev: collections.Counter = collections.Counter()
        self.realtime_status = "off"

    # -- control -----------------------------------------------------------------
    def stop(self, reason: str = "stop requested") -> None:
        if not self.stop_event.is_set():
            self.stop_reason = reason
        self.stop_event.set()
        self.wake.set()

    def install_signal_handlers(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            return

        def handler(signum, _frame):
            try:
                name = signal.Signals(signum).name
            except ValueError:
                name = str(signum)
            self.stop(f"{name} received")

        for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
            sig = getattr(signal, name, None)
            if sig is not None:
                try:
                    signal.signal(sig, handler)
                except (ValueError, OSError):
                    pass

    # -- file-system events --------------------------------------------------------
    def _on_fs_event(self, rel: str) -> None:
        now = time.monotonic()
        with self._dirty_lock:
            self._dirty.setdefault(rel, now)
            self._last_event = now
        self.wake.set()

    def _dirty_due(self, now: float) -> Optional[float]:
        with self._dirty_lock:
            if not self._dirty:
                return None
            first = min(self._dirty.values())
            return min(self._last_event + self.settle, first + self.max_settle)

    def _take_dirty(self, now: float) -> Dict[str, float]:
        """Hand over the pending paths once events have settled (or waited long enough)."""
        with self._dirty_lock:
            if not self._dirty:
                return {}
            first = min(self._dirty.values())
            if now - self._last_event < self.settle and now - first < self.max_settle:
                return {}
            taken = dict(self._dirty)
            self._dirty.clear()
            return taken

    def _peek_dirty(self) -> Dict[str, float]:
        with self._dirty_lock:
            return dict(self._dirty)

    def _forget_dirty_before(self, t: float) -> None:
        """A full scan that started at t already covers every event seen before t."""
        with self._dirty_lock:
            for k in [k for k, v in self._dirty.items() if v <= t]:
                del self._dirty[k]

    @staticmethod
    def _event_time(t_map: Dict[str, float], ch: Change) -> Optional[float]:
        """When the file-system event behind this change arrived (checks the path, then its parents)."""
        for p in (ch.dest, ch.path):
            if not p:
                continue
            parts = p.split("/")
            for i in range(len(parts), 0, -1):
                t = t_map.get("/".join(parts[:i]))
                if t is not None:
                    return t
        return None

    def _start_observer(self, root: Path, scanner: Scanner):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except Exception as exc:
            return None, f"off (watchdog not available: {exc.__class__.__name__})"
        monitor = self

        class _Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                kind = getattr(event, "event_type", "")
                if kind not in ("created", "deleted", "modified", "moved", "closed"):
                    return
                if event.is_directory and kind == "modified":
                    return
                paths = [event.src_path]
                if kind == "moved":
                    paths.append(getattr(event, "dest_path", "") or "")
                for p in paths:
                    if not p:
                        continue
                    p = os.fsdecode(p)
                    if scanner.skipped(p):
                        continue
                    rel = scanner.rel(p)
                    if rel and not scanner.excluded(rel):
                        monitor._on_fs_event(rel)

        try:
            observer = Observer()
            observer.schedule(_Handler(), str(root), recursive=True)
            observer.start()
            return observer, f"on (watchdog {type(observer).__name__})"
        except Exception as exc:
            return None, f"off (watchdog failed to start: {exc})"

    # -- one scan cycle --------------------------------------------------------------
    def _cycle(self, ctx: Dict[str, Any], trigger: str, paths: Optional[List[str]] = None,
               t_map: Optional[Dict[str, float]] = None) -> None:
        db, log, scanner, policy = ctx["db"], ctx["log"], ctx["scanner"], ctx["policy"]
        observed: Dict[str, FileRecord] = ctx["observed"]
        started = iso()
        if paths is None:
            res = scanner.scan(prev=observed, fast=self.fast)
            scope = None
        else:
            res, scope = scanner.scan_paths(paths, prev=observed, fast=self.fast)
            if not scope:
                return
        changes = diff_states(observed, res.records, scope, res.blind | self._blind)
        if scope is None:
            new_blind = set(res.blind)
        else:
            new_blind = {b for b in self._blind if not _in_scope(b, scope)} | res.blind
        changes += [Change("DIRECTORY_UNREADABLE", b) for b in sorted(new_blind - self._blind)]
        for ch in changes:
            assess(ch, policy)
            t_ev = self._event_time(t_map, ch) if t_map else None
            latency = int((time.monotonic() - t_ev) * 1000) if t_ev is not None else None
            entry = log.append(ch.kind, ch.severity, ch.summary, ch.path, change_data(ch, trigger, latency))
            self.console.alert(entry)
            self.alerts += 1
            self.by_sev[ch.severity] += 1
        # observed state := what was just seen (keep entries hidden behind unreadable directories)
        keep_hidden = {k: v for k, v in observed.items()
                       if any(k == b or k.startswith(b + "/") for b in new_blind) and k not in res.records}
        if scope is None:
            observed.clear()
        else:
            for k in [k for k in observed if _in_scope(k, scope)]:
                del observed[k]
        observed.update(res.records)
        observed.update(keep_hidden)
        self._blind = new_blind
        self.cycles += 1
        db.add_scan(ctx["session"], started, trigger, res, len(changes))
        if paths is None and res.duration > self.interval and not ctx.get("slow_warned"):
            self.console.warn(f"A full scan took {res.duration:.1f} s, longer than the {self.interval:g} s "
                              "interval; consider a longer --interval or --fast.")
            ctx["slow_warned"] = True

    # -- main loop ---------------------------------------------------------------------
    def run(self) -> int:
        db = BaselineDB(self.state.db).open()
        observer = None
        session = None
        log = None
        started_mono = time.monotonic()
        try:
            log = TamperEvidentLog(self.state.log, self.keys, db, self.console).open()
            check = db.verify(self.keys)
            if not check.ok:
                entry = log.append("BASELINE_TAMPERED", "CRITICAL",
                                   f"Baseline failed verification; monitoring refused: {check.problem}",
                                   None, {"source": "startup"})
                self.console.alert(entry)
                self.console.error("The baseline cannot be trusted. Re-create it from a known-good state "
                                   f"(`{TOOL} baseline --force`) after investigating.")
                self.exit_code = EXIT_BASELINE_TAMPERED
                self.ready.set()
                return self.exit_code
            root = Path(check.meta["root"])
            excludes = json.loads(check.meta.get("excludes") or "[]")
            scanner = Scanner(root, excludes, skip_paths=self.state.skip_paths())
            policy = Policy(root=root, iocs=self.iocs, critical=self.critical, baseline=check.records)
            if self.realtime:
                observer, self.realtime_status = self._start_observer(root, scanner)
            else:
                self.realtime_status = "off (--no-watchdog)"
            mode = "interval scans + real-time events" if observer else "interval scans"
            session = db.start_session(self.interval, observer is not None, mode)
            if self.pidfile:
                ensure_dir(Path(self.pidfile).parent)
                Path(self.pidfile).write_text(str(os.getpid()), encoding="ascii")
            log.append("MONITOR_STARTED", "INFO",
                       f"Monitoring {root} every {self.interval:g} s ({mode})", None,
                       {"root": str(root), "interval_s": self.interval, "realtime": self.realtime_status,
                        "heartbeat_s": self.heartbeat, "fast": self.fast, "pid": os.getpid(),
                        "iocs": len(self.iocs), "critical": self.critical, "session": session,
                        "baseline_files": len(check.records), "baseline_digest": check.meta.get("digest")})
            ctx = {"db": db, "log": log, "scanner": scanner, "policy": policy,
                   "observed": dict(check.records), "session": session}
            self.console.ok(f"Baseline verified: {plural(len(check.records), 'file')}, signature OK "
                            f"(key ID {self.keys.key_id})")
            self.console.ok(f"Monitoring {root}: full scan every {self.interval:g} s, "
                            f"real-time events {self.realtime_status}")
            before = self.alerts
            self._cycle(ctx, "startup")
            drift = self.alerts - before
            self.console.ok("Startup check: " + ("every file matches the baseline" if not drift else
                                                  f"{plural(drift, 'difference')} from the baseline (see above)"))
            self.console.ok("Ready: watching for changes (Ctrl+C or SIGTERM stops the monitor cleanly)")
            self.ready.set()

            now = time.monotonic()
            next_full = now + self.interval
            next_hb = now + self.heartbeat if self.heartbeat > 0 else None
            deadline = now + self.duration if self.duration else None
            while not self.stop_event.is_set():
                now = time.monotonic()
                timers = [next_full] + [t for t in (next_hb, deadline, self._dirty_due(now)) if t]
                self.wake.wait(max(0.0, min(timers) - now))
                self.wake.clear()
                if self.stop_event.is_set():
                    break
                now = time.monotonic()
                taken = self._take_dirty(now)
                if taken:
                    self._cycle(ctx, "watchdog", list(taken), taken)
                if time.monotonic() >= next_full:
                    scan_start = time.monotonic()
                    self._cycle(ctx, "interval", None, self._peek_dirty())
                    self._forget_dirty_before(scan_start)
                    self.interval_scans += 1
                    next_full += self.interval
                    if next_full <= time.monotonic():
                        next_full = time.monotonic() + self.interval
                    db.update_session(session, self.cycles, self.alerts)
                if next_hb and time.monotonic() >= next_hb:
                    ver = log.recheck()
                    if ver.ok:
                        log.append("HEARTBEAT", "INFO",
                                   f"Monitor alive: {plural(self.cycles, 'scan')}, "
                                   f"{plural(self.alerts, 'alert')} so far; log verified "
                                   f"({ver.entries} entries)", None,
                                   {"uptime_s": round(time.monotonic() - started_mono, 1),
                                    "cycles": self.cycles, "alerts": self.alerts,
                                    "files": len(ctx["observed"]), "log_entries_verified": ver.entries})
                    else:
                        self.alerts += 1
                        self.by_sev["CRITICAL"] += 1
                    next_hb = time.monotonic() + self.heartbeat
                if self.max_cycles and self.interval_scans >= self.max_cycles:
                    self.stop(f"completed {plural(self.max_cycles, 'interval scan')}")
                elif deadline and time.monotonic() >= deadline:
                    self.stop(f"ran for {self.duration:g} s")
            # Final pass: nothing that happened right before the stop goes unrecorded.
            self._cycle(ctx, "shutdown")
            ver = log.recheck()
            uptime = time.monotonic() - started_mono
            stop_entry = log.append("MONITOR_STOPPED", "INFO",
                       f"Monitor stopped ({self.stop_reason}) after {plural(self.cycles, 'scan')} and "
                       f"{plural(self.alerts, 'alert')}", None,
                       {"reason": self.stop_reason, "cycles": self.cycles, "interval_scans": self.interval_scans,
                        "alerts": self.alerts, "by_severity": dict(self.by_sev),
                        "uptime_s": round(uptime, 1), "log_verified": ver.ok, "log_entries": ver.entries})
            db.update_session(session, self.cycles, self.alerts, stopped=iso(), reason=self.stop_reason)
            self.console.ok(f"Monitor stopped ({self.stop_reason}) after {human_duration(uptime)}: "
                            f"{plural(self.cycles, 'scan')}, {plural(self.alerts, 'alert')}; alert log "
                            f"{'verified' if ver.ok else 'FAILED verification'} and closed at entry "
                            f"{stop_entry['seq']}")
            self.exit_code = EXIT_OK
            return self.exit_code
        except FIMError:
            raise
        except Exception as exc:
            self.console.error(f"Monitor failed: {exc.__class__.__name__}: {exc}")
            if log is not None:
                try:
                    log.append("MONITOR_STOPPED", "HIGH", f"Monitor crashed: {exc.__class__.__name__}: {exc}",
                               None, {"reason": "error", "traceback": traceback.format_exc()[-2000:]})
                except Exception:
                    pass
            if session is not None:
                try:
                    db.update_session(session, self.cycles, self.alerts, stopped=iso(), reason="error")
                except Exception:
                    pass
            self.exit_code = EXIT_ERROR
            return self.exit_code
        finally:
            self.ready.set()
            if observer is not None:
                try:
                    observer.stop()
                    observer.join(timeout=5)
                except Exception:
                    pass
            if self.pidfile:
                try:
                    Path(self.pidfile).unlink()
                except OSError:
                    pass
            db.close()


# ----------------------------------------------------------------------------
# Lab directory, simulated malware drop, scorecard, demo
# ----------------------------------------------------------------------------

LAB_MARKER = "LAB_README.txt"
LAB_DROPPER_LABEL = "FIMLab.Dropper (simulated invoice dropper)"


def _lab_bytes(seed: str, n: int) -> bytes:
    """Deterministic pseudo-random filler (so lab artifacts hash the same on every run)."""
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:n])


def lab_dropper_bytes() -> bytes:
    """An inert stand-in for a dropped Windows executable: an MZ header and filler, no code."""
    header = bytearray(64)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = struct.pack("<I", 64)
    note = b"PE\x00\x00FIM-LAB SIMULATED DROPPER. Inert test artifact, not a working program.\n"
    return bytes(header) + note + _lab_bytes("fim-lab-dropper", 6144)


def lab_payload_bytes() -> bytes:
    """An inert stand-in for a packed Linux implant: an ELF magic number and random-looking bytes."""
    return (b"\x7fELF\x02\x01\x01" + bytes(9) + b"FIM-LAB SIMULATED PAYLOAD. Inert test artifact.\n"
            + _lab_bytes("fim-lab-payload", 48 * 1024))


def _fake_ssh_key(seed: str, comment: str) -> str:
    pub = hashlib.sha256(seed.encode()).digest()
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + pub
    return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}"


def _lab_png() -> bytes:
    w = h = 32

    def px(x: int, y: int) -> bytes:
        inside = (x - 15.5) ** 2 + (y - 15.5) ** 2 < 13.5 ** 2
        wave = inside and y > 17 and (y - 17) % 4 < 2
        return bytes((235, 242, 240) if wave else (18, 107, 93) if inside else (255, 255, 255))

    raw = b"".join(b"\x00" + b"".join(px(x, y) for x in range(w)) for y in range(h))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def lab_files() -> List[Tuple[str, bytes, int]]:
    deploy_key = _fake_ssh_key("fim-lab-deploy", "deploy@build-01")
    files = [
        (LAB_MARKER, "This directory was generated by fim.py lab-setup as a practice target for the\n"
                     "file integrity monitoring lab. It imitates part of a small web server and\n"
                     "contains no real data, credentials or programs.\n", 0o644),
        ("www/index.html", """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Lakeside Outdoor Supply</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <header><img src="/assets/logo.png" alt="" width="32" height="32"> Lakeside Outdoor Supply</header>
  <main>
    <h1>Gear for every season</h1>
    <p>Kayaks, tents and trail gear, shipped from our warehouse on the lake.</p>
    <p><a href="/login.php">Staff sign-in</a></p>
  </main>
  <footer>&copy; <span id="year"></span> Lakeside Outdoor Supply</footer>
  <script src="/assets/app.js"></script>
</body>
</html>
""", 0o644),
        ("www/login.php", """<?php
// Staff sign-in page (lab sample). The form posts to the application server.
$title = "Staff sign-in";
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title><?= htmlspecialchars($title) ?></title></head>
<body>
  <form method="post" action="/auth">
    <label>User <input name="user" autocomplete="username"></label>
    <label>Password <input name="pass" type="password" autocomplete="current-password"></label>
    <button>Sign in</button>
  </form>
</body>
</html>
""", 0o644),
        ("www/config.php", """<?php
// Storefront database settings (lab sample: placeholder values, not real credentials).
$db_host = "db.lakeside-outdoor.example";
$db_name = "storefront";
$db_user = "web_app";
$db_pass = "CHANGE-ME-lab-placeholder";
""", 0o640),
        ("www/assets/app.js", """// Storefront helpers
document.addEventListener("DOMContentLoaded", () => {
  const year = document.querySelector("#year");
  if (year) year.textContent = new Date().getFullYear();
});
""", 0o644),
        ("www/assets/style.css", """body { font-family: system-ui, sans-serif; margin: 0; color: #1d2b2f; }
header { display: flex; gap: .5rem; align-items: center; padding: 1rem 2rem; background: #126b5d; color: #fff; }
main { max-width: 40rem; padding: 2rem; }
footer { padding: 1rem 2rem; color: #5b6b70; }
""", 0o644),
        ("www/assets/logo.png", _lab_png(), 0o644),
        ("www/uploads/README.txt", "Customer photo uploads are stored here by the storefront.\n"
                                   "Only .jpg and .png files are accepted.\n", 0o644),
        ("etc/cron.d/maintenance", """# /etc/cron.d/maintenance - scheduled jobs for the storefront host
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# m  h  dom mon dow  user    command
30   2  *   *   *    root    /srv/bin/backup.sh >> /var/log/backup.log 2>&1
*/10 *  *   *   *    deploy  /srv/bin/healthcheck.py --quiet
""", 0o644),
        ("etc/nginx/nginx.conf", """user www-data;
worker_processes auto;
events { worker_connections 768; }
http {
    server_tokens off;
    server {
        listen 80;
        server_name lakeside-outdoor.example;
        root /srv/www;
        index index.html;
        location ~ ^/uploads/.*\\.php$ { deny all; }
        location ~ \\.php$ { include fastcgi_params; fastcgi_pass unix:/run/php/php-fpm.sock; }
    }
}
""", 0o644),
        ("etc/ssh/sshd_config", """# Hardened SSH settings (lab sample)
Port 22
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers deploy
MaxAuthTries 3
""", 0o644),
        ("home/deploy/.ssh/authorized_keys", deploy_key + "\n", 0o600),
        ("home/deploy/.bashrc", """# ~/.bashrc for the deploy account
export PATH="$HOME/bin:$PATH"
alias ll='ls -alF'
PS1='\\u@\\h:\\w\\$ '
""", 0o644),
        ("bin/backup.sh", """#!/bin/sh
# Nightly backup of the storefront (lab sample)
set -eu
STAMP=$(date +%Y%m%d)
tar -czf "/srv/backups/www-$STAMP.tar.gz" /srv/www
find /srv/backups -name 'www-*.tar.gz' -mtime +14 -delete
""", 0o755),
        ("bin/healthcheck.py", '''#!/usr/bin/env python3
"""Storefront health check (lab sample)."""
import sys
import urllib.request


def main() -> int:
    try:
        with urllib.request.urlopen("http://127.0.0.1/", timeout=5) as resp:
            return 0 if resp.status == 200 else 1
    except OSError:
        return 2


if __name__ == "__main__":
    sys.exit(main())
''', 0o755),
        ("var/log/auth.log", """Sep 28 06:12:01 web01 sshd[1123]: Accepted publickey for deploy from 192.0.2.10 port 51514 ssh2
Sep 28 06:12:01 web01 sshd[1123]: pam_unix(sshd:session): session opened for user deploy
Sep 28 06:40:17 web01 sshd[1123]: pam_unix(sshd:session): session closed for user deploy
Sep 29 06:10:44 web01 sshd[1388]: Accepted publickey for deploy from 192.0.2.10 port 50122 ssh2
Sep 29 22:51:09 web01 sshd[2051]: Invalid user admin from 198.51.100.23 port 41870
Sep 29 22:51:11 web01 sshd[2051]: Connection closed by invalid user admin 198.51.100.23 port 41870
""", 0o640),
        ("var/log/nginx/access.log", """192.0.2.44 - - [29/Sep/2026:14:02:11 +0000] "GET / HTTP/1.1" 200 742 "-" "Mozilla/5.0"
192.0.2.44 - - [29/Sep/2026:14:02:11 +0000] "GET /assets/style.css HTTP/1.1" 200 288 "/" "Mozilla/5.0"
198.51.100.23 - - [29/Sep/2026:22:49:30 +0000] "GET /login.php HTTP/1.1" 200 512 "-" "curl/8.5.0"
""", 0o644),
        ("data/customers.csv", """customer_id,name,email,city
1001,Ava Thompson,ava.thompson@example.com,Angola
1002,Marcus Lee,marcus.lee@example.com,Fort Wayne
1003,Priya Raman,priya.raman@example.com,Auburn
1004,Diego Alvarez,diego.alvarez@example.com,Coldwater
""", 0o640),
        ("docs/runbook.md", """# Storefront runbook

- Deploys happen from the `deploy` account over SSH (key-based only).
- Backups run nightly at 02:30 from `/srv/bin/backup.sh`.
- Uploads are images only; the web server refuses to run scripts from `/uploads/`.
""", 0o644),
    ]
    return [(p, c.encode("utf-8") if isinstance(c, str) else c, m) for p, c, m in files]


def lab_setup(target: Path, state: Optional[StatePaths], console: Console, force: bool = False) -> List[str]:
    target = Path(target).resolve()
    if target.exists() and any(target.iterdir()):
        if not force:
            raise FIMError(f"{target} already exists and is not empty. Use --force to rebuild the lab "
                           f"directory, or choose another --dir.")
        if not (target / LAB_MARKER).is_file():
            raise FIMError(f"{target} was not created by `{TOOL} lab-setup` (no {LAB_MARKER}); "
                           f"refusing to delete it. Choose another --dir.")
        shutil.rmtree(target)
    ensure_dir(target)
    base_time = time.time() - 30 * 86400
    written = []
    for i, (rel, content, mode) in enumerate(lab_files()):
        p = target.joinpath(*rel.split("/"))
        ensure_dir(p.parent)
        p.write_bytes(content)
        try:
            os.chmod(p, mode)
        except OSError:
            pass
        t = base_time + i * 3607
        os.utime(p, (t, t))
        written.append(rel)
    if state is not None:
        ensure_dir(state.dir)
        ioc = state.dir / IOC_SAMPLE_NAME
        ioc.write_text(
            "# Sample threat-intelligence hash list for the FIM lab: SHA-256, then a name.\n"
            "# In a SOC this list would come from a threat-intel platform or a VirusTotal hunt.\n"
            f"{hashlib.sha256(lab_dropper_bytes()).hexdigest()}  {LAB_DROPPER_LABEL}\n"
            f"{next(iter(BUILTIN_IOCS))}  EICAR antivirus test file\n", encoding="utf-8")
        console.ok(f"Sample threat-intel hash list written to {ioc}")
    console.ok(f"Lab directory ready: {target} ({plural(len(written), 'file')})")
    return written


def simulate_attack(root: Path, console: Console, delay: float = 1.5,
                    manifest_path: Optional[Path] = None) -> Dict[str, Any]:
    """Act out an intrusion on the directory using inert files, and record what was done
    and when (the ground truth used to score detection)."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise FIMError(f"Directory not found: {root}")
    steps: List[Dict[str, Any]] = []
    started = iso()

    def need(p: Path) -> None:
        if not p.is_file():
            raise FileNotFoundError(str(p))

    def drop(data: bytes, mode: Optional[int] = None) -> Callable[[Path], str]:
        def act(p: Path) -> str:
            ensure_dir(p.parent)
            p.write_bytes(data)
            if mode is not None and os.name != "nt":
                os.chmod(p, mode)
            return f"wrote {human_size(len(data))}, SHA-256 {hashlib.sha256(data).hexdigest()[:16]}..."
        return act

    def append(text: str) -> Callable[[Path], str]:
        def act(p: Path) -> str:
            need(p)
            with open(p, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            return f"appended: {text.strip()[:70]}"
        return act

    def deface(p: Path) -> str:
        need(p)
        st = os.stat(p)
        html_text = p.read_text(encoding="utf-8")
        tag = '  <script src="https://cdn-stats.attacker.example/collect.js"></script>\n'
        html_text = html_text.replace("</body>", tag + "</body>") if "</body>" in html_text else html_text + tag
        p.write_text(html_text, encoding="utf-8", newline="\n")
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
        return "injected a third-party <script> tag, then reset the modification time"

    def chmod_777(p: Path) -> str:
        need(p)
        os.chmod(p, 0o777)
        return "permissions set to 0777 (rwxrwxrwx)"

    def remove(p: Path) -> str:
        need(p)
        p.unlink()
        return "deleted"

    plan = [
        ("dropper", "Drop a disguised executable through the upload form",
         "www/uploads/invoice_8812.pdf.exe", "FILE_ADDED", "known_bad_hash", "T1105, T1036.007",
         drop(lab_dropper_bytes()), False),
        ("payload", "Unpack a hidden second-stage implant",
         "www/uploads/.cache/kworkerd", "FILE_ADDED", "hidden", "T1564.001, T1027.002",
         drop(lab_payload_bytes(), 0o755), False),
        ("webshell", "Plant a web shell next to the uploads",
         "www/uploads/thumb.php", "FILE_ADDED", "web_shell", "T1505.003",
         drop(b"<?php\n/* FIM LAB ARTIFACT: simulated web shell placeholder.\n"
                  b"   Inert by design; this file contains no executable PHP statements. */\n?>\n"), False),
        ("cron", "Add a cron job that relaunches the implant",
         "etc/cron.d/maintenance", "FILE_MODIFIED", "persistence", "T1053.003",
         append("*/5  *  *   *   *    root    /srv/www/uploads/.cache/kworkerd >/dev/null 2>&1\n"), False),
        ("sshkey", "Add the attacker's SSH key to the deploy account",
         "home/deploy/.ssh/authorized_keys", "FILE_MODIFIED", "ssh_keys", "T1098.004",
         append(_fake_ssh_key("fim-lab-attacker", "backup@203.0.113.66") + "\n"), False),
        ("deface", "Deface the home page and reset its timestamp",
         "www/index.html", "FILE_MODIFIED", "timestomp", "T1070.006", deface, False),
        ("perms", "Make the root-run backup script world-writable",
         "bin/backup.sh", "PERMISSIONS_CHANGED", "world_writable", "T1222.002", chmod_777, True),
        ("logs", "Delete the SSH authentication log",
         "var/log/auth.log", "FILE_DELETED", "log_removed", "T1070", remove, False),
    ]
    console.note(f"Simulating a malware drop on {root} (inert files only; {delay:g} s between steps)")
    for n, (sid, title, rel, expect, indicator, technique, action, posix_only) in enumerate(plan, 1):
        rec: Dict[str, Any] = {"id": sid, "n": n, "title": title, "path": rel, "expect": expect,
                               "expect_indicator": indicator, "technique": technique}
        if posix_only and os.name == "nt":
            rec.update(status="skipped", reason="permission bits are not meaningful on Windows")
        else:
            try:
                rec.update(status="done", detail=action(root.joinpath(*rel.split("/"))))
            except FileNotFoundError:
                rec.update(status="skipped", reason=f"{rel} does not exist in this directory")
            except OSError as exc:
                rec.update(status="failed", reason=str(exc))
        rec["at"] = iso()
        steps.append(rec)
        state_txt = {"done": console.c("done", "92"), "skipped": console.c("skipped", "93"),
                     "failed": console.c("failed", "91")}[rec["status"]]
        console.info(f"  {n}. {title:<56} {state_txt}")
        console.info(console.c(f"     {rel}: {rec.get('detail') or rec.get('reason')}", "2"))
        if delay and n < len(plan):
            time.sleep(delay)
    manifest = {"scenario": "Simulated malware drop on a small web server", "tool": f"{TOOL} {__version__}",
                "root": str(root), "host": hostname(), "started": started, "finished": iso(),
                "delay_s": delay, "steps": steps}
    if manifest_path:
        write_json(Path(manifest_path), manifest)
        console.ok(f"Ground-truth manifest written to {manifest_path}")
    return manifest


def build_scorecard(manifest: Optional[Dict[str, Any]], entries: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Match each simulated attacker action to the first alert that caught it."""
    if not manifest:
        return None
    alerts = sorted((e for e in entries if e.get("event") in ALERT_EVENTS), key=lambda e: e.get("seq", 0))
    rows = []
    for st in manifest.get("steps", []):
        row = {k: st.get(k) for k in ("n", "id", "title", "path", "expect", "expect_indicator",
                                      "technique", "status", "at", "reason")}
        if st.get("status") != "done":
            row["detected"] = None
            rows.append(row)
            continue
        at = parse_iso(st.get("at"))
        match = None
        for a in alerts:
            data = a.get("data") or {}
            if a.get("event") != st.get("expect"):
                continue
            if st.get("path") not in (a.get("path"), data.get("dest")):
                continue
            ts = parse_iso(a.get("ts"))
            if at and ts and ts < at - timedelta(seconds=1):
                continue
            match = a
            break
        if match is None:
            row["detected"] = False
        else:
            data = match.get("data") or {}
            ts = parse_iso(match.get("ts"))
            row.update(detected=True, alert_seq=match.get("seq"), severity=match.get("sev"),
                       source=data.get("source"),
                       latency_s=round(max(0.0, (ts - at).total_seconds()), 2) if (ts and at) else None,
                       classified=st.get("expect_indicator") in [i.get("id") for i in data.get("indicators", [])],
                       why="; ".join(i.get("label", "") for i in data.get("indicators", [])[:3]))
        rows.append(row)
    done = [r for r in rows if r.get("status") == "done"]
    hit = [r for r in done if r.get("detected")]
    lat = sorted(r["latency_s"] for r in hit if r.get("latency_s") is not None)
    median = (lat[len(lat) // 2] if len(lat) % 2 else (lat[len(lat) // 2 - 1] + lat[len(lat) // 2]) / 2) if lat else None
    return {"scenario": manifest.get("scenario"), "started": manifest.get("started"),
            "rows": rows, "performed": len(done), "detected": len(hit),
            "classified": sum(1 for r in hit if r.get("classified")),
            "median_latency_s": round(median, 2) if median is not None else None,
            "max_latency_s": max(lat) if lat else None}


# -- console printers shared by the CLI and the demo ---------------------------------

def print_verification(ver: LogVerification, console: Console) -> None:
    console.kv("Log file", ver.path)
    console.kv("Entries", str(ver.entries))
    if ver.entries:
        console.kv("Valid signatures", f"{ver.valid} / {ver.entries} (HMAC-SHA256, key ID {ver.kid_used})")
        console.kv("Log ID", f"{ver.log_id}")
        console.kv("Chain head", f"{ver.head_hmac}")
        a = ver.anchor or {}
        anchor_txt = {"match": f"matches the anchor in the database (entry {a.get('seq')})",
                      "truncated": "the log is SHORTER than the database anchor",
                      "mismatch": "does NOT match the database anchor",
                      "invalid": "anchor signature invalid",
                      "absent": "no anchor available (truncation cannot be checked)"}.get(a.get("status"), "-")
        console.kv("Anchor check", anchor_txt)
    for p in ver.problems[:12]:
        console.error(p["message"])
    if len(ver.problems) > 12:
        console.error(f"... and {len(ver.problems) - 12} more problems")
    for w in ver.warnings[:5]:
        console.warn(w)
    style = "1;92" if ver.ok else "1;91"
    console.emit(console.c(f"RESULT: {ver.status}", style) + f"  {ver.summary}", force=True)


def print_tamper(result: Dict[str, Any], console: Console) -> None:
    console.info(f"  {result['note']}")
    for i, s in enumerate(result["scenarios"], 1):
        mark = console.c("DETECTED", "1;92") if s["detected"] else console.c("MISSED", "1;91")
        console.info(f"  {i}. {s['title']:<22} {mark}  {s['change']}")
        console.info(console.c(f"     {s['finding']}", "2"))
    style = "1;92" if result["detected"] == result["total"] else "1;91"
    console.emit(console.c(f"RESULT: {result['detected']}/{result['total']} tampering attempts detected", style),
                 force=True)


def print_scorecard(card: Dict[str, Any], console: Console) -> None:
    for r in card["rows"]:
        if r.get("status") != "done":
            console.info(f"  {r['n']}. {r['title']:<56} {console.c('not run', '93')}")
            continue
        if r.get("detected"):
            lat = f"{r['latency_s']:.2f} s" if r.get("latency_s") is not None else "-"
            console.info(f"  {r['n']}. {r['title']:<56} {console.c('detected', '92')} {r['severity']:<8} "
                         f"in {lat} via {r.get('source')}")
        else:
            console.info(f"  {r['n']}. {r['title']:<56} {console.c('MISSED', '91')}")
    med = f"{card['median_latency_s']:.2f} s" if card.get("median_latency_s") is not None else "-"
    console.emit(console.c(f"RESULT: {card['detected']}/{card['performed']} attacker actions detected", "1")
                 + f" (median time to alert {med})", force=True)


def wait_for_detection(state: StatePaths, manifest: Dict[str, Any], timeout: float) -> Optional[Dict[str, Any]]:
    deadline = time.monotonic() + timeout
    card = None
    while time.monotonic() < deadline:
        card = build_scorecard(manifest, read_log_entries(state.log))
        if card and card["detected"] >= card["performed"]:
            return card
        time.sleep(0.25)
    return card


# ----------------------------------------------------------------------------
# Reports (JSON, HTML, PDF)
# ----------------------------------------------------------------------------

LIFECYCLE_IN_TIMELINE = {"BASELINE_CREATED", "BASELINE_UPDATED", "MONITOR_STARTED", "MONITOR_STOPPED",
                         "INTEGRITY_CHECK"}
SEV_WORD = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}
SOURCE_WORD = {"watchdog": "real-time event", "interval": "interval scan", "startup": "startup check",
               "shutdown": "final scan", "check": "manual check", "log check": "log check"}


def _join_words(items: List[str]) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def window_text(win: Dict[str, Any]) -> str:
    a, b = parse_iso(win.get("start")), parse_iso(win.get("end"))
    if not a or not b:
        return "-"
    span = f"{a:%Y-%m-%d %H:%M:%S} to " + (f"{b:%H:%M:%S}" if a.date() == b.date() else f"{b:%Y-%m-%d %H:%M:%S}")
    return f"{span} UTC ({human_duration(win.get('seconds'))})"


def response_plan(alerts: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    if not alerts:
        return []
    ids = {i.get("id") for a in alerts for i in a.get("indicators", [])}
    events = {a.get("event") for a in alerts}
    steps: List[Tuple[str, str]] = []
    if any(a.get("severity") == "CRITICAL" for a in alerts):
        steps.append(("Contain", "Isolate the host from the network and suspend the accounts involved "
                                 "until triage is complete."))
    steps.append(("Preserve evidence", "Copy the alert log, the baseline database and the files named in "
                                       "this report to write-once storage before anything is cleaned up, "
                                       "and record their SHA-256 values."))
    fix = []
    if "FILE_ADDED" in events:
        fix.append("quarantine the added files")
    if "web_shell" in ids:
        fix.append("remove the web shell")
    if "persistence" in ids:
        fix.append("remove the persistence entries")
    if "ssh_keys" in ids:
        fix.append("delete unauthorized SSH keys and rotate the account's credentials")
    if ids & {"world_writable", "exec_added", "setuid"} or "PERMISSIONS_CHANGED" in events:
        fix.append("restore the original permissions")
    if "FILE_MODIFIED" in events:
        fix.append("restore modified files from a known-good backup")
    if "FILE_DELETED" in events:
        fix.append("recover the deleted files")
    if fix:
        text = _join_words(fix)
        steps.append(("Eradicate", text[0].upper() + text[1:] + "."))
    if "web_shell" in ids or any("uploads/" in (a.get("path") or "") for a in alerts):
        steps.append(("Close the way in", "Review the web-server logs for the requests that delivered the "
                                          "files and fix the upload handler that accepted them."))
    if ids & {"known_bad_hash", "executable", "masquerade"}:
        steps.append(("Hunt", "Search other hosts and the mail and web proxies for the SHA-256 values of "
                              "the dropped files."))
    steps.append(("Re-baseline", f"After remediation, run `{TOOL} baseline --update` so the monitor "
                                 "trusts the clean state, and keep the daemon running."))
    return steps


def collect_report(state: StatePaths, keys: Keys, title: Optional[str] = None,
                   manifest_path: Optional[Path] = None, tamper_path: Optional[Path] = None) -> Dict[str, Any]:
    db = BaselineDB(state.db).open()
    try:
        meta = db.meta()
        bcheck = db.verify(keys) if "digest" in meta else None
        ver = verify_log(state.log, keys, db, keep_lines=True)
        sessions = db.sessions()
        scans = db.scans()
    finally:
        db.close()
    records = bcheck.records if bcheck else {}
    entries = [ln["entry"] for ln in ver.lines]
    alerts, timeline = [], []
    for ln in ver.lines:
        e, d = ln["entry"], ln["entry"].get("data") or {}
        ev = e.get("event")
        if ev in ALERT_EVENTS:
            a = {"seq": e.get("seq"), "line": ln["line"], "ts": e.get("ts"), "event": ev,
                 "label": EVENT_LABELS.get(ev, ev), "severity": e.get("sev", "INFO"), "path": e.get("path"),
                 "dest": d.get("dest"), "message": e.get("msg"), "source": d.get("source"),
                 "latency_ms": d.get("latency_ms"), "before": d.get("before"), "after": d.get("after"),
                 "indicators": d.get("indicators", []), "attack": d.get("attack", []),
                 "notes": d.get("notes", []), "response": d.get("response"), "verified": ln["ok"]}
            alerts.append(a)
            timeline.append(dict(a, kind="alert"))
        elif ev in LIFECYCLE_IN_TIMELINE:
            timeline.append({"seq": e.get("seq"), "ts": e.get("ts"), "event": ev,
                             "label": EVENT_LABELS.get(ev, ev), "message": e.get("msg"), "kind": "lifecycle",
                             "verified": ln["ok"]})
    counts = collections.Counter(a["severity"] for a in alerts)
    root = meta.get("root", "")
    manifest = read_json(manifest_path)
    scorecard = build_scorecard(manifest, entries) if manifest else None
    tamper = read_json(tamper_path)
    starts = [e.get("ts") for e in entries if e.get("event") == "MONITOR_STARTED"]
    stops = [e.get("ts") for e in entries if e.get("event") == "MONITOR_STOPPED"]
    window_start = starts[0] if starts else (ver.first_ts if ver.entries else None)
    window_end = stops[-1] if stops else (ver.last_ts if ver.entries else None)
    full = [s for s in scans if s.get("trigger") in ("startup", "interval", "shutdown", "check")]
    by_trigger = collections.Counter(s.get("trigger") for s in scans)
    durations = [s.get("duration_ms") or 0 for s in full]
    sources = collections.Counter(a.get("source") or "unknown" for a in alerts)

    n = len(alerts)
    crit = counts.get("CRITICAL", 0)
    if n:
        headline = (f"{plural(n, 'change')} to protected files {'was' if n == 1 else 'were'} detected"
                    + (f", {crit} of them critical." if crit and crit < n else
                       (", all critical." if crit == n and n > 1 else ".")))
        level = "violations" if (crit or counts.get("HIGH")) else "changes"
    else:
        headline, level = "No changes to protected files were detected.", "clean"
    if ver.status == "VALID":
        anchor_ok = (ver.anchor or {}).get("status") == "match"
        log_line = (f"The alert log verifies: all {ver.entries} entries are signed and chained"
                    + (", and it ends where the database anchor says it should." if anchor_ok else "."))
    elif ver.status == "WRONG_KEY":
        log_line = "The alert log could not be verified with the key in use, so its contents are unconfirmed."
    elif ver.status in ("MISSING", "EMPTY"):
        log_line = "There is no alert log to verify."
    else:
        log_line = f"The alert log failed verification and must be treated as compromised. {ver.first_finding()}"
    sim_line = None
    if scorecard and scorecard["performed"]:
        med = scorecard.get("median_latency_s")
        sim_line = (f"The simulated malware drop performed {plural(scorecard['performed'], 'attacker action')}; "
                    f"{scorecard['detected']} {'was' if scorecard['detected'] == 1 else 'were'} detected"
                    + (f", with a median time to alert of {med:.2f} s." if med is not None else "."))

    inventory = [{"path": r.path, "kind": r.kind, "size": r.size, "mode": mode_str(r.mode),
                  "type": r.magic or ("symlink" if r.kind == "symlink" else "-"), "sha256": r.sha256,
                  "mtime": iso_from_ns(r.mtime_ns), "target": r.link_target, "error": r.error}
                 for r in sorted(records.values(), key=lambda r: r.path)]
    return {
        "report": {"title": title or "File integrity monitoring report", "generated": iso(),
                   "tool": TOOL, "version": __version__, "host": hostname(), "platform": platform_label()},
        "target": {"root": root, "name": Path(root).name if root else "", "host": meta.get("host"),
                   "baseline_created": meta.get("created_utc"), "baseline_updated": meta.get("updated_utc"),
                   "files": int(meta.get("file_count") or 0), "bytes": int(meta.get("total_bytes") or 0),
                   "digest": meta.get("digest"), "excludes": json.loads(meta.get("excludes") or "[]"),
                   "signature_ok": bool(bcheck and bcheck.ok),
                   "signature_problem": bcheck.problem if bcheck else "no baseline found",
                   "key_id": meta.get("key_id")},
        "verdict": {"level": level, "headline": headline, "log_line": log_line, "sim_line": sim_line,
                    "counts": {s: counts.get(s, 0) for s in reversed(SEVERITIES)}, "alerts": n},
        "window": {"start": window_start, "end": window_end,
                   "seconds": ((parse_iso(window_end) - parse_iso(window_start)).total_seconds()
                               if window_start and window_end and parse_iso(window_end) and parse_iso(window_start)
                               else None)},
        "log": ver.to_dict(),
        "alerts": alerts,
        "timeline": timeline,
        "scorecard": scorecard,
        "tamper_test": tamper,
        "sessions": sessions,
        "scans": {"count": len(scans), "by_trigger": dict(by_trigger), "full_scans": len(full),
                  "mean_ms": round(sum(durations) / len(durations), 1) if durations else None,
                  "max_ms": round(max(durations), 1) if durations else None,
                  "bytes_hashed": sum(s.get("bytes_hashed") or 0 for s in scans)},
        "sources": dict(sources),
        "response": [{"step": t, "text": x} for t, x in response_plan(alerts)],
        "inventory": inventory,
        "entries": [{"line": ln["line"], "seq": ln["entry"].get("seq"), "ts": ln["entry"].get("ts"),
                     "event": ln["entry"].get("event"), "sev": ln["entry"].get("sev"),
                     "path": ln["entry"].get("path"), "msg": ln["entry"].get("msg"),
                     "prev": ln["entry"].get("prev"), "hmac": ln["entry"].get("hmac"), "ok": ln["ok"]}
                    for ln in ver.lines],
        "files": {"database": str(state.db), "log": str(state.log)},
    }


# -- the integrity seal: a guilloche rosette generated from the log's chain head ------------------

def seal_curves(head_hex: str, scale: float = 1.0) -> List[List[Tuple[float, float]]]:
    """Woven bands whose shape is derived from the final HMAC in the chain, so every
    report's seal is a visual fingerprint of the exact log it certifies."""
    if not re.fullmatch(r"[0-9a-f]{64}", head_hex or ""):
        head_hex = hashlib.sha256(b"fim.py seal").hexdigest()
    b = bytes.fromhex(head_hex)
    lobes = 9 + b[0] % 6
    bands = 12
    curves = []
    steps = 240
    for k in range(bands):
        base = 41 + k * 1.9
        amp = 5.5 + (b[1 + k] % 5) * 0.55
        phase = k * math.pi / bands + (b[20] / 255) * math.pi
        pts = []
        for i in range(steps + 1):
            t = 2 * math.pi * i / steps
            r = base + amp * math.sin(lobes * t + phase)
            pts.append((r * math.cos(t) * scale, r * math.sin(t) * scale))
        curves.append(pts)
    petals = 5 + b[30] % 4
    rose = []
    for i in range(steps + 1):
        t = 2 * math.pi * i / steps
        r = 22 + 7 * math.cos(petals * t)
        rose.append((r * math.cos(t) * scale, r * math.sin(t) * scale))
    curves.append(rose)
    return curves


def seal_svg(head_hex: str, ok: bool, log_id: str, entries: int, label: str) -> str:
    cx = cy = 100.0
    curves = seal_curves(head_hex)
    paths = []
    for idx, pts in enumerate(curves):
        d = "M" + " L".join(f"{cx + x:.1f} {cy + y:.1f}" for x, y in pts) + " Z"
        width = "0.45" if idx < len(curves) - 1 else "0.7"
        paths.append(f'<path d="{d}" fill="none" stroke="currentColor" stroke-width="{width}"/>')
    micro = (f"HMAC-SHA256 CHAIN HEAD {head_hex} \u00a0 LOG {(log_id or '')[:16]} \u00a0 "
             f"{entries} ENTRIES \u00a0 ")
    ring_r = 85.0
    circ = 2 * math.pi * ring_r
    void = ""
    mark = (f'<path d="M{cx - 11:.1f} {cy + 1:.1f} l8 8 l15 -17" fill="none" stroke="currentColor" '
            f'stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>')
    if not ok:
        mark = (f'<path d="M{cx - 10:.1f} {cy - 10:.1f} l20 20 M{cx + 10:.1f} {cy - 10:.1f} l-20 20" '
                f'fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round"/>')
        void = ('<defs><pattern id="void" width="34" height="16" patternUnits="userSpaceOnUse" '
                'patternTransform="rotate(-28)"><text x="0" y="12" font-family="Arial, sans-serif" '
                'font-weight="700" font-size="10" fill="currentColor">VOID</text></pattern></defs>'
                f'<circle cx="{cx}" cy="{cy}" r="78" fill="url(#void)" opacity="0.22"/>'
                f'<path d="M30 58 L78 92 L64 104 L122 128 L106 140 L172 150" fill="none" '
                f'stroke="currentColor" stroke-width="2.2"/>')
    return (
        f'<svg viewBox="0 0 200 200" role="img" aria-label="{html.escape(label, quote=True)}" '
        f'class="seal-art {"intact" if ok else "broken"}" xmlns="http://www.w3.org/2000/svg">'
        f'<defs><path id="ring" d="M {cx - ring_r} {cy} a {ring_r} {ring_r} 0 1 1 {2 * ring_r} 0 '
        f'a {ring_r} {ring_r} 0 1 1 {-2 * ring_r} 0"/></defs>'
        f'<circle cx="{cx}" cy="{cy}" r="97" fill="none" stroke="currentColor" stroke-width="1.6"/>'
        f'<circle cx="{cx}" cy="{cy}" r="92.5" fill="none" stroke="currentColor" stroke-width="0.6"/>'
        f'<circle cx="{cx}" cy="{cy}" r="78" fill="none" stroke="currentColor" stroke-width="0.6"/>'
        f'<text font-family="ui-monospace, Consolas, monospace" font-size="5.6" fill="currentColor" '
        f'letter-spacing="0.2"><textPath href="#ring" textLength="{circ - 6:.1f}" lengthAdjust="spacing">'
        f'{html.escape(micro)}</textPath></text>'
        + "".join(paths) +
        f'<circle cx="{cx}" cy="{cy}" r="15.5" class="seal-core" stroke="currentColor" stroke-width="0.8"/>'
        + mark + void + '</svg>')


# -- HTML ----------------------------------------------------------------------------------------

REPORT_CSS = """
:root{color-scheme:light dark;--paper:#f2f4f1;--sheet:#fbfcfa;--band:#e8ece9;--ink:#15232a;--ink-2:#4a5a60;
--rule:#cbd4d0;--seal:#116b5c;--seal-ink:#0e5a4d;--breach:#a3271d;--high:#9c4a10;--medium:#7d6200;
--low:#3c6185;--info:#66757a;--tint:#e3efea;--tint-bad:#f6e2df;
--serif:"Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua",Georgia,serif;
--sans:"Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,"SF Mono","Cascadia Mono",Consolas,"Liberation Mono",monospace}
@media (prefers-color-scheme:dark){:root{--paper:#0e1719;--sheet:#132023;--band:#182a2d;--ink:#dce6e3;
--ink-2:#9dafb2;--rule:#2b3d40;--seal:#5ec2aa;--seal-ink:#7fd3be;--breach:#f08377;--high:#efa168;
--medium:#dcbd57;--low:#91b6d8;--info:#8d9ca0;--tint:#173330;--tint-bad:#3a1f1c}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.55 var(--sans)}
.record{max-width:66rem;margin:0 auto;padding:2.75rem 1.5rem 4rem}
h1,h2{font-family:var(--serif);font-weight:600;line-height:1.2;letter-spacing:-.005em}
h1{font-size:2.3rem;margin:0 0 .4rem}
h2{font-size:1.55rem;margin:3.25rem 0 1rem;padding-bottom:.45rem;border-bottom:1px solid var(--rule)}
h3{font-size:1.05rem;margin:0;font-weight:600}
p{margin:.6rem 0;max-width:72ch}
a{color:inherit;text-decoration-color:var(--seal);text-underline-offset:.2em}
a:focus-visible{outline:2px solid var(--seal);outline-offset:3px}
code,.mono{font-family:var(--mono);font-size:.875em}
.subject{margin:0 0 1.5rem;color:var(--ink-2)}
.subject code{font-size:1.02rem;color:var(--ink)}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(10.5rem,1fr));gap:.8rem 2rem;margin:0;
padding:1rem 0;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule)}
.facts div{min-width:0}
.facts dt{font-size:.8125rem;color:var(--ink-2)}
.facts dd{margin:.1rem 0 0;font-weight:500;overflow-wrap:anywhere}
.verdict{display:grid;grid-template-columns:minmax(0,1fr) 15.5rem;gap:2.5rem;align-items:center;margin:2.25rem 0 0}
.headline{font-family:var(--serif);font-size:1.85rem;line-height:1.22;margin:0 0 .9rem;max-width:30ch}
.tally{list-style:none;display:flex;flex-wrap:wrap;gap:.4rem 1.4rem;padding:0;margin:0 0 1rem}
.seal{margin:0;text-align:center}
.seal-art{width:100%;max-width:15.5rem;height:auto;display:block;margin:0 auto}
.seal-art.intact{color:var(--seal)}
.seal-art.broken{color:var(--breach)}
.seal-core{fill:var(--paper)}
.seal figcaption{font-size:.875rem;color:var(--ink-2);margin-top:.45rem}
.seal figcaption strong{display:block;font-family:var(--serif);font-size:1.15rem;font-weight:600}
.seal figcaption strong.intact{color:var(--seal-ink)}
.seal figcaption strong.broken{color:var(--breach)}
nav.contents{margin:2.5rem 0 0;padding:.8rem 0;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule);
font-size:.875rem}
nav.contents ul{list-style:none;display:flex;flex-wrap:wrap;gap:.35rem 1.4rem;margin:0;padding:0}
.table-wrap{overflow-x:auto;margin:1rem 0;border:1px solid var(--rule);background:var(--sheet)}
table{border-collapse:collapse;width:100%;font-size:.875rem}
caption{text-align:left;padding:.6rem .8rem;color:var(--ink-2);caption-side:top}
th{text-align:left;font-weight:600;color:var(--ink-2);background:var(--band);padding:.5rem .8rem;
border-bottom:1px solid var(--rule);white-space:nowrap}
td{padding:.5rem .8rem;border-bottom:1px solid var(--rule);vertical-align:top}
tr:last-child td{border-bottom:0}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td.path{font-family:var(--mono);font-size:.82rem;overflow-wrap:break-word;min-width:11rem}
td.edge{border-left:4px solid var(--c,transparent)}
tr.quiet td{color:var(--ink-2)}
.sev{display:inline-flex;align-items:center;gap:.42em;font-weight:600;color:var(--c);white-space:nowrap}
.sev::before{content:"";width:.62em;height:.62em;background:var(--c);display:inline-block;flex:none}
.sev-critical{--c:var(--breach)}.sev-high{--c:var(--high)}.sev-medium{--c:var(--medium)}
.sev-low{--c:var(--low)}.sev-info{--c:var(--info)}
article.alert{background:var(--sheet);border:1px solid var(--rule);border-left:5px solid var(--c);
padding:1.1rem 1.3rem 1.2rem;margin:1.1rem 0}
article.alert header{display:flex;flex-wrap:wrap;gap:.35rem 1rem;align-items:baseline}
article.alert .where{font-family:var(--mono);font-size:.9rem;overflow-wrap:break-word;flex-basis:100%}
.kv{display:grid;grid-template-columns:8.5rem minmax(0,1fr);gap:.3rem 1rem;margin:.9rem 0 .6rem;font-size:.875rem}
.kv dt{color:var(--ink-2)}
.kv dd{margin:0;overflow-wrap:anywhere}
.hash{font-family:var(--mono);font-size:.78rem;word-break:break-all}
.why{margin:.4rem 0 .2rem;padding-left:1.15rem;font-size:.92rem}
.why li{margin:.25rem 0}
.attack{font-size:.85rem;color:var(--ink-2);margin:.5rem 0}
.advice{margin:.6rem 0 0;font-size:.92rem}
.ok{color:var(--seal-ink);font-weight:600}
.bad{color:var(--breach);font-weight:600}
.muted{color:var(--ink-2)}
.empty{background:var(--sheet);border:1px dashed var(--rule);padding:1rem 1.2rem}
.note{font-size:.875rem;color:var(--ink-2)}
ol.steps{padding-left:1.4rem}
ol.steps li{margin:.55rem 0;max-width:72ch}
.pill{display:inline-block;padding:.05rem .5rem;border:1px solid currentColor;font-size:.8rem;font-weight:600}
footer{margin-top:3.5rem;padding-top:1rem;border-top:1px solid var(--rule);color:var(--ink-2);font-size:.8125rem}
@media (max-width:760px){.record{padding:1.75rem 1rem 3rem}.verdict{grid-template-columns:1fr;gap:1.25rem}
.seal{order:-1}.seal-art{max-width:12rem}.headline{font-size:1.5rem}.kv{grid-template-columns:1fr}h1{font-size:1.85rem}}
@media print{body{background:#fff;color:#000}.record{max-width:none;padding:0}nav.contents{display:none}
article.alert,tr{break-inside:avoid}.table-wrap{overflow:visible;border:0}h2{break-after:avoid}}
"""


SCAN_WORD = {"watchdog": "event-triggered rescan", "interval": "interval scan", "startup": "startup check",
             "shutdown": "final scan", "check": "manual check"}


def _e(value: Any) -> str:
    """Escape for HTML; keep "SHA-256" from breaking across lines and show arrows as arrows."""
    text = html.escape("" if value is None else str(value), quote=True)
    return text.replace("SHA-256", "SHA&#8209;256").replace(" -&gt; ", " \u2192 ")


def _path(value: Any) -> str:
    """Escaped path that may wrap after each slash rather than mid-name."""
    return _e(value).replace("/", "/<wbr>")


def _prose(value: Any) -> str:
    """Escaped text where `backticks` become inline code."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", _e(value))


def _cap(text: Optional[str]) -> str:
    return (text[:1].upper() + text[1:]) if text else ""


def _source_phrase(sources: Dict[str, int]) -> str:
    names = {"watchdog": ("real-time event", "real-time events"), "interval": ("interval scan", "interval scans"),
             "startup": ("startup check", "startup checks"), "shutdown": ("final scan", "final scans"),
             "check": ("manual check", "manual checks"), "log check": ("log check", "log checks")}
    parts = []
    for k, n in sorted(sources.items(), key=lambda kv: -kv[1]):
        one, many = names.get(k, (k, k))
        parts.append(f"{n} by {one if n == 1 else many}")
    return _join_words(parts)


def _sev_html(sev: Optional[str]) -> str:
    sev = sev or "INFO"
    return f'<span class="sev sev-{sev.lower()}">{SEV_WORD.get(sev, sev.title())}</span>'


def _short_hash(h: Optional[str], n: int = 16) -> str:
    return (h[:n] + "\u2026") if h and len(h) > n else (h or "-")


def _kv(rows: List[Tuple[str, str]]) -> str:
    return '<dl class="kv">' + "".join(f"<dt>{_e(k)}</dt><dd>{v}</dd>" for k, v in rows if v) + "</dl>"


def _record_html(rec: Optional[Dict[str, Any]]) -> str:
    if not rec:
        return '<span class="muted">not present</span>'
    bits = []
    if rec.get("sha256"):
        bits.append(f'<span class="hash">{_e(rec["sha256"])}</span>')
    meta = []
    if rec.get("size") is not None:
        meta.append(human_size(rec["size"]))
    if rec.get("mode"):
        meta.append(f"mode {_e(rec['mode'])} ({_e(rwx(int(rec['mode'], 8)))})")
    if rec.get("type"):
        meta.append(_e(rec["type"]))
    if rec.get("mtime"):
        meta.append("modified " + _e(human_ts(rec["mtime"])))
    if rec.get("target"):
        meta.append("points to " + _e(rec["target"]))
    if rec.get("error"):
        meta.append(_e(rec["error"]))
    if meta:
        bits.append(f'<span class="muted">{"; ".join(meta)}</span>')
    return "<br>".join(bits)


def _detected_html(a: Dict[str, Any]) -> str:
    src = SOURCE_WORD.get(a.get("source") or "", a.get("source") or "-")
    lat = a.get("latency_ms")
    return f"{_e(src)}" + (f" ({lat / 1000:.2f} s after the change)" if lat is not None else "")


def render_html(rep: Dict[str, Any]) -> str:
    t, v, log = rep["target"], rep["verdict"], rep["log"]
    ok = log["status"] == "VALID"
    sc, tt = rep.get("scorecard"), rep.get("tamper_test")
    out: List[str] = []
    w = out.append
    w('<!doctype html><html lang="en"><head><meta charset="utf-8">')
    w('<meta name="viewport" content="width=device-width, initial-scale=1">')
    w('<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; '
      'img-src data:">')
    w(f"<title>{_e(rep['report']['title'])}: {_e(t['name'] or t['root'])}</title>")
    w(f"<style>{REPORT_CSS}</style></head><body><main class=\"record\">")

    # Masthead
    w(f"<header><h1>{_e(rep['report']['title'])}</h1>")
    w(f'<p class="subject">Protected directory <code>{_e(t["root"])}</code></p>')
    watched = window_text(rep["window"])
    facts = [("Host", t.get("host") or rep["report"]["host"]),
             ("Baseline taken", human_ts(t.get("baseline_created"))),
             ("Monitored", watched),
             ("Report generated", human_ts(rep["report"]["generated"])),
             ("Tool", f"{rep['report']['tool']} {rep['report']['version']}")]
    w('<dl class="facts">' + "".join(f"<div><dt>{_e(k)}</dt><dd>{_e(val)}</dd></div>" for k, val in facts)
      + "</dl></header>")

    # Verdict + seal
    w('<section class="verdict" aria-label="Summary"><div>')
    w(f'<p class="headline">{_e(v["headline"])}</p>')
    if v["alerts"]:
        w('<ul class="tally">' + "".join(
            f'<li>{_sev_html(s)} <span class="muted">{n}</span></li>' for s, n in v["counts"].items() if n)
          + "</ul>")
    w(f"<p>{_e(v['log_line'])}</p>")
    if v.get("sim_line"):
        w(f"<p>{_e(v['sim_line'])}</p>")
    if not t["signature_ok"]:
        w(f'<p class="bad">Baseline signature check failed: {_e(t["signature_problem"])}</p>')
    seal_label = ("Log seal intact" if ok else "Log seal broken")
    w('</div><figure class="seal">' + seal_svg(log.get("head_hmac") or "", ok, log.get("log_id") or "",
                                                 log.get("entries") or 0, seal_label))
    cap_detail = (f"{log['valid']} of {log['entries']} entries verified" if log.get("entries") else
                  "no entries")
    w(f'<figcaption><strong class="{"intact" if ok else "broken"}">{seal_label}</strong>{_e(cap_detail)}<br>'
      f'<span class="mono">{_e(_short_hash(log.get("head_hmac"), 20))}</span></figcaption></figure></section>')

    sections = [("timeline", "What happened")]
    if sc:
        sections.append(("simulation", "Simulated attack"))
    sections += [("alerts", "Alert details"), ("evidence", "Evidence log"), ("baseline", "Baseline"),
                 ("monitoring", "Monitoring"), ("response", "Response"), ("method", "How it works"),
                 ("entries", "Log entries")]
    w('<nav class="contents" aria-label="Sections"><ul>' +
      "".join(f'<li><a href="#{sid}">{_e(name)}</a></li>' for sid, name in sections) + "</ul></nav>")

    # Timeline
    w('<section id="timeline"><h2>What happened</h2>')
    if rep["timeline"]:
        w('<div class="table-wrap"><table><thead><tr><th>Time (UTC)</th><th>Severity</th><th>Event</th>'
          '<th>Path</th><th>Detected by</th></tr></thead><tbody>')
        for row in rep["timeline"]:
            if row["kind"] == "alert":
                where = row["path"] or ""
                if row.get("dest"):
                    where += " \u2192 " + row["dest"]
                why = "; ".join(i.get("label", "") for i in row.get("indicators", [])[:3])
                flag = "" if row.get("verified") else ' <span class="bad">(signature invalid)</span>'
                w(f'<tr><td class="edge sev-{row["severity"].lower()}">{_e(short_time(row["ts"]))}</td>'
                  f'<td>{_sev_html(row["severity"])}</td><td>{_e(row["label"])}{flag}'
                  + (f'<br><span class="note">{_e(why)}</span>' if why else "") +
                  f'</td><td class="path">{_path(where)}</td><td>{_detected_html(row)}</td></tr>')
            else:
                w(f'<tr class="quiet"><td class="edge">{_e(short_time(row["ts"]))}</td><td>-</td>'
                  f'<td>{_e(row["label"])}</td><td colspan="2">{_e(row.get("message"))}</td></tr>')
        w("</tbody></table></div>")
    else:
        w('<p class="empty">The alert log has no entries yet. Create a baseline and start the monitor.</p>')
    if not rep["alerts"] and rep["timeline"]:
        w('<p class="note">No alerts were raised: every scan matched the baseline.</p>')
    w("</section>")

    # Simulated attack scorecard
    if sc:
        med = sc.get("median_latency_s")
        w('<section id="simulation"><h2>Simulated attack</h2>')
        w(f"<p>{_e(sc.get('scenario'))}. Each attacker action below was performed with inert test files, "
          f"timed, and then matched to the alert that caught it. {sc['detected']} of {sc['performed']} "
          f"actions were detected"
          + (f"; the median time from action to signed alert was {med:.2f} s" if med is not None else "")
          + ".</p>")
        w('<div class="table-wrap"><table><thead><tr><th class="num">#</th><th>Attacker action</th>'
          '<th>Path</th><th>Result</th><th class="num">Time to alert</th><th>ATT&amp;CK</th></tr></thead><tbody>')
        for r in sc["rows"]:
            if r.get("status") != "done":
                res = f'<span class="muted">Not run: {_e(r.get("reason") or r.get("status"))}</span>'
                lat = "-"
            elif r.get("detected"):
                res = (_sev_html(r.get("severity")) + f' <span class="muted">via {_e(SOURCE_WORD.get(r.get("source") or "", r.get("source")))}</span>'
                       + (f'<br><span class="note">{_e(r.get("why"))}</span>' if r.get("why") else ""))
                lat = f"{r['latency_s']:.2f} s" if r.get("latency_s") is not None else "-"
            else:
                res, lat = '<span class="bad">Missed</span>', "-"
            w(f'<tr><td class="num">{_e(r.get("n"))}</td><td>{_e(r.get("title"))}</td>'
              f'<td class="path">{_path(r.get("path"))}</td><td>{res}</td><td class="num">{lat}</td>'
              f'<td class="mono">{_e(r.get("technique"))}</td></tr>')
        w("</tbody></table></div></section>")

    # Alert details
    w('<section id="alerts"><h2>Alert details</h2>')
    if not rep["alerts"]:
        w('<p class="empty">There are no alerts to describe.</p>')
    for a in rep["alerts"]:
        sev = a["severity"]
        where = a["path"] or ""
        if a.get("dest"):
            where += " \u2192 " + a["dest"]
        w(f'<article class="alert sev-{sev.lower()}" id="alert-{_e(a["seq"])}"><header>{_sev_html(sev)}'
          f'<h3>{_e(a["label"])}</h3><span class="muted">log entry {_e(a["seq"])}, '
          f'{_e(human_ts(a["ts"]))}</span><span class="where">{_path(where)}</span></header>')
        sig = '<span class="ok">valid</span>' if a.get("verified") else '<span class="bad">INVALID</span>'
        rows = [("Detected by", _detected_html(a)), ("Entry signature", sig)]
        if a["event"] not in ("FILE_ADDED",):
            rows.append(("Before", _record_html(a.get("before"))))
        if a["event"] not in ("FILE_DELETED", "DIRECTORY_UNREADABLE", "BASELINE_TAMPERED", "LOG_TAMPERED"):
            rows.append(("After", _record_html(a.get("after"))))
        if a.get("notes"):
            rows.append(("Also", _e("; ".join(a["notes"]))))
        if a["event"] in ("BASELINE_TAMPERED", "LOG_TAMPERED"):
            rows.append(("Finding", _e(a.get("message"))))
        w(_kv(rows))
        if a.get("indicators"):
            w('<ul class="why">' + "".join(
                f'<li><strong>{_e(_cap(i.get("label")))}.</strong> {_e(i.get("detail"))}</li>'
                for i in a["indicators"]) + "</ul>")
        if a.get("attack"):
            w('<p class="attack">MITRE ATT&amp;CK: ' + "; ".join(
                f'<span class="mono">{_e(x.get("id"))}</span> {_e(x.get("name"))}' for x in a["attack"]) + "</p>")
        if a.get("response"):
            w(f'<p class="advice"><strong>Response.</strong> {_prose(a["response"])}</p>')
        w("</article>")
    w("</section>")

    # Evidence log
    w('<section id="evidence"><h2>Evidence log</h2>')
    w("<p>Every alert above was appended to a JSON-lines log. Each entry is signed with HMAC-SHA256 under a "
      "key that never appears in the log, carries a sequence number, and includes the signature of the entry "
      "before it. Editing, deleting, reordering or forging an entry breaks the chain; the database keeps an "
      "anchor of the newest entry so a log that has been cut short is caught as well.</p>")
    anchor = log.get("anchor") or {}
    anchor_txt = {"match": f"matches the database anchor (entry {anchor.get('seq')})",
                  "truncated": "log is shorter than the database anchor",
                  "mismatch": "does not match the database anchor",
                  "invalid": "anchor signature is invalid",
                  "absent": "no anchor available"}.get(anchor.get("status"), "-")
    status_html = (f'<span class="ok">{_e(log["status"])}</span>' if ok
                   else f'<span class="bad">{_e(log["status"])}</span>')
    w(_kv([("Result", status_html + " " + _e(log.get("summary"))),
           ("Log file", f'<span class="mono">{_e(log.get("path"))}</span>'),
           ("Entries", f"{log.get('valid', 0)} of {log.get('entries', 0)} signatures valid"),
           ("Key ID", f'<span class="mono">{_e(log.get("kid_used"))}</span> (a fingerprint; the key itself '
                      'is never stored in the log or the report)'),
           ("Log ID", f'<span class="mono">{_e(log.get("log_id"))}</span>'),
           ("Chain head", f'<span class="hash">{_e(log.get("head_hmac"))}</span>'),
           ("Anchor check", _e(anchor_txt))]))
    for p in log.get("problems", [])[:20]:
        w(f'<p class="bad">{_e(p.get("message"))}</p>')
    if tt:
        w(f'<h3 style="margin-top:1.6rem">Tamper test</h3><p>To show that the log is tamper-evident, five '
          f'attacks were made on copies of it and each copy was verified. {tt["detected"]} of {tt["total"]} '
          f'were detected; the original log was only read.</p>')
        w('<div class="table-wrap"><table><thead><tr><th>Attack</th><th>What was changed</th>'
          '<th>Result</th><th>What verification reported</th></tr></thead><tbody>')
        for s in tt.get("scenarios", []):
            res = '<span class="ok">Detected</span>' if s.get("detected") else '<span class="bad">Missed</span>'
            w(f'<tr><td>{_e(s.get("title"))}</td><td>{_e(s.get("change"))}</td><td>{res}</td>'
              f'<td>{_e(s.get("finding"))}</td></tr>')
        w("</tbody></table></div>")
    w("</section>")

    # Baseline
    w('<section id="baseline"><h2>Baseline</h2>')
    sig_txt = ('<span class="ok">valid</span> (HMAC-SHA256 over every row)' if t["signature_ok"]
               else f'<span class="bad">failed</span> {_e(t["signature_problem"])}')
    w(_kv([("Directory", f'<span class="mono">{_e(t["root"])}</span>'),
           ("Created", _e(human_ts(t.get("baseline_created")))),
           ("Last approved", _e(human_ts(t.get("baseline_updated")))),
           ("Files", f"{t['files']} ({human_size(t['bytes'])})"),
           ("Excluded", _e(", ".join(t["excludes"])) if t["excludes"] else "nothing"),
           ("Baseline digest", f'<span class="hash">{_e(t.get("digest"))}</span>'),
           ("Signature", sig_txt),
           ("Database", f'<span class="mono">{_e(rep["files"]["database"])}</span>')]))
    inv = rep["inventory"]
    shown = inv[:500]
    w('<div class="table-wrap"><table><caption>Files in the baseline, with the SHA-256 recorded for each'
      '</caption><thead><tr><th>Path</th><th class="num">Size</th><th>Mode</th><th>Type</th>'
      '<th>SHA-256 (first 16 hex)</th></tr></thead><tbody>')
    for r in shown:
        w(f'<tr><td class="path">{_path(r["path"])}</td><td class="num">{_e(human_size(r["size"]))}</td>'
          f'<td class="mono">{_e(r["mode"])}</td><td>{_e(r["type"])}</td>'
          f'<td class="mono">{_e(_short_hash(r["sha256"]))}</td></tr>')
    w("</tbody></table></div>")
    if len(inv) > len(shown):
        w(f'<p class="note">Showing the first {len(shown)} of {len(inv)} files; the JSON report lists all.</p>')
    w("</section>")

    # Monitoring
    w('<section id="monitoring"><h2>Monitoring</h2>')
    scans = rep["scans"]
    if rep["sessions"]:
        w('<div class="table-wrap"><table><thead><tr><th>Started (UTC)</th><th>Stopped</th>'
          '<th class="num">Interval</th><th>Real-time events</th><th class="num">Scans</th>'
          '<th class="num">Alerts</th><th>How it stopped</th></tr></thead><tbody>')
        for s in rep["sessions"]:
            w(f'<tr><td>{_e(human_ts(s.get("started_utc")))}</td><td>{_e(short_time(s.get("stopped_utc")))}</td>'
              f'<td class="num">{_e(s.get("interval_s"))} s</td><td>{"yes" if s.get("realtime") else "no"}</td>'
              f'<td class="num">{_e(s.get("cycles"))}</td><td class="num">{_e(s.get("alerts"))}</td>'
              f'<td>{_e(s.get("stop_reason") or "still running or ended abruptly")}</td></tr>')
        w("</tbody></table></div>")
    else:
        w('<p class="note">No monitoring sessions are recorded in the database.</p>')
    trig = ", ".join(f"{n} {SCAN_WORD.get(k, k)}{'s' if n != 1 else ''}"
                     for k, n in sorted(scans["by_trigger"].items(), key=lambda kv: -kv[1]))
    w(_kv([("Scans", f"{scans['count']} in total" + (f" ({_e(trig)})" if trig else "")),
           ("Full-scan time", (f"{scans['mean_ms']:.1f} ms on average, {scans['max_ms']:.1f} ms at most"
                               if scans.get("mean_ms") is not None else "-")),
           ("Data hashed", human_size(scans.get("bytes_hashed"))),
           ("Alerts caught", _e(_source_phrase(rep["sources"])) or "-")]))
    w("</section>")

    # Response
    w('<section id="response"><h2>Recommended response</h2>')
    if rep["response"]:
        w('<ol class="steps">' + "".join(f'<li><strong>{_e(s["step"])}.</strong> {_prose(s["text"])}</li>'
                                         for s in rep["response"]) + "</ol>")
    else:
        w("<p>No action is needed. Keep the monitor running and re-baseline after approved changes.</p>")
    w("</section>")

    # Method and limits
    interval = rep["sessions"][-1]["interval_s"] if rep["sessions"] else None
    w('<section id="method"><h2>How it works</h2>')
    w("<p><strong>Baseline.</strong> Every regular file under the protected directory was read in full and "
      "hashed with SHA-256; symlinks are recorded but never followed. The rows are stored in SQLite together "
      "with a digest of every row, signed with HMAC-SHA256, so a baseline doctored to hide malware is rejected "
      "before monitoring starts.</p>")
    w("<p><strong>Monitoring.</strong> The daemon re-hashes the whole tree "
      + (f"every {interval:g} seconds " if interval else "on a fixed interval ")
      + "(the authoritative check) and uses watchdog file-system events to rescan changed paths within about "
        "a second. Each change is scored with indicators such as executable content behind a document "
        "extension, hidden locations, persistence locations, a timestamp left untouched after an edit, and "
        "known-bad hashes.</p>")
    w("<p><strong>Limits.</strong> Integrity monitoring detects changes; it does not prevent them. Anyone who "
      "obtains the HMAC key can write a convincing log, and someone able to roll back both the log and the "
      "database together can hide recent entries, so production systems should forward entries to a "
      "separate log server or write-once storage and keep the key off the monitored host. Without real-time "
      "events, a change that is made and reverted between two scans can go unseen.</p></section>")

    # Log entries appendix
    w('<section id="entries"><h2>Log entries</h2><p class="note">Each entry\u2019s <em>prev</em> value must '
      "equal the signature of the entry above it. Values are shortened to their first 12 hex digits.</p>")
    w('<div class="table-wrap"><table><thead><tr><th class="num">Line</th><th class="num">Seq</th>'
      '<th>Time (UTC)</th><th>Event</th><th>Path</th><th>prev</th><th>hmac</th><th>Signature</th></tr>'
      '</thead><tbody>')
    for en in rep["entries"]:
        w(f'<tr><td class="num">{_e(en["line"])}</td><td class="num">{_e(en["seq"])}</td>'
          f'<td>{_e(short_time(en["ts"]))}</td><td>{_e(EVENT_LABELS.get(en["event"], en["event"]))}</td>'
          f'<td class="path">{_path(en.get("path") or "")}</td><td class="mono">{_e((en.get("prev") or "")[:12])}</td>'
          f'<td class="mono">{_e((en.get("hmac") or "")[:12])}</td>'
          f'<td>{"<span class=ok>valid</span>" if en["ok"] else "<span class=bad>invalid</span>"}</td></tr>')
    w("</tbody></table></div></section>")
    w(f'<footer>Generated by {_e(TOOL)} {_e(__version__)} on {_e(rep["report"]["host"])} '
      f'({_e(rep["report"]["platform"])}), {_e(human_ts(rep["report"]["generated"]))}.</footer>')
    w("</main></body></html>")
    return "".join(out)


# -- PDF -----------------------------------------------------------------------------------------

def _pdf_fonts() -> Dict[str, Any]:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.lib.fonts import addMapping
    dirs = ["/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/dejavu", "/usr/share/fonts/TTF",
            "/usr/local/share/fonts", "/Library/Fonts",
            os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts")]
    try:
        import importlib.util
        spec = importlib.util.find_spec("matplotlib")
        if spec and spec.origin:
            dirs.append(os.path.join(os.path.dirname(spec.origin), "mpl-data", "fonts", "ttf"))
    except Exception:
        pass

    def find(name: str) -> Optional[str]:
        for d in dirs:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
        return None

    fonts = {"sans": "Helvetica", "bold": "Helvetica-Bold", "mono": "Courier", "head": "Times-Bold",
             "unicode": False}
    reg, bold, mono = find("DejaVuSans.ttf"), find("DejaVuSans-Bold.ttf"), find("DejaVuSansMono.ttf")
    try:
        if reg and bold:
            pdfmetrics.registerFont(TTFont("FIMSans", reg))
            pdfmetrics.registerFont(TTFont("FIMSans-Bold", bold))
            addMapping("FIMSans", 0, 0, "FIMSans")
            addMapping("FIMSans", 1, 0, "FIMSans-Bold")
            addMapping("FIMSans", 0, 1, "FIMSans")
            addMapping("FIMSans", 1, 1, "FIMSans-Bold")
            fonts.update(sans="FIMSans", bold="FIMSans-Bold", unicode=True)
        if mono:
            pdfmetrics.registerFont(TTFont("FIMMono", mono))
            fonts["mono"] = "FIMMono"
    except Exception:
        fonts.update(sans="Helvetica", bold="Helvetica-Bold", mono="Courier", unicode=False)
    return fonts


def render_pdf(rep: Dict[str, Any], out_path: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.platypus import (Flowable, KeepTogether, ListFlowable, ListItem, Paragraph,
                                    SimpleDocTemplate, Spacer, Table, TableStyle)

    F = _pdf_fonts()
    INK, INK2, RULE = colors.HexColor("#15232a"), colors.HexColor("#4a5a60"), colors.HexColor("#cbd4d0")
    BAND, SEAL, BREACH = colors.HexColor("#e8ece9"), colors.HexColor("#116b5c"), colors.HexColor("#a3271d")
    SEVC = {"CRITICAL": BREACH, "HIGH": colors.HexColor("#9c4a10"), "MEDIUM": colors.HexColor("#7d6200"),
            "LOW": colors.HexColor("#3c6185"), "INFO": colors.HexColor("#66757a")}

    def txt(s: Any) -> str:
        s = "" if s is None else str(s)
        if F["unicode"]:
            s = s.replace(" -> ", " \u2192 ")
        else:
            s = s.replace("\u2192", "->").replace("\u2026", "...").encode("cp1252", "replace").decode("cp1252")
        return html.escape(s, quote=False)

    def grouped(h: Optional[str]) -> str:
        return " ".join(h[i:i + 16] for i in range(0, len(h), 16)) if h else "-"

    st = {
        "title": ParagraphStyle("title", fontName=F["head"], fontSize=24, leading=28, textColor=INK, spaceAfter=4),
        "subject": ParagraphStyle("subject", fontName=F["sans"], fontSize=9.5, leading=13, textColor=INK2),
        "h2": ParagraphStyle("h2", fontName=F["head"], fontSize=15, leading=19, textColor=INK, spaceBefore=16,
                             spaceAfter=6),
        "h3": ParagraphStyle("h3", fontName=F["sans"], fontSize=10, leading=13, textColor=INK, spaceBefore=4),
        "body": ParagraphStyle("body", fontName=F["sans"], fontSize=9, leading=13, textColor=INK, spaceAfter=5),
        "headline": ParagraphStyle("headline", fontName=F["head"], fontSize=17, leading=21, textColor=INK,
                                   spaceAfter=6),
        "small": ParagraphStyle("small", fontName=F["sans"], fontSize=7.8, leading=10.2, textColor=INK),
        "muted": ParagraphStyle("muted", fontName=F["sans"], fontSize=7.8, leading=10.2, textColor=INK2),
        "mono": ParagraphStyle("mono", fontName=F["mono"], fontSize=7.2, leading=9.4, textColor=INK),
        "cellhead": ParagraphStyle("cellhead", fontName=F["bold"], fontSize=7.6, leading=9.8, textColor=INK2),
    }

    def P(s: str, style: str = "small") -> Paragraph:
        return Paragraph(s, st[style])

    def sev_p(sev: Optional[str]) -> Paragraph:
        sev = sev or "INFO"
        return P(f'<font color="{SEVC.get(sev, INK).hexval()}"><b>{SEV_WORD.get(sev, sev)}</b></font>')

    def table(rows: List[List[Any]], widths: List[float], head: bool = True, edge: Optional[List[Any]] = None) -> Table:
        tb = Table(rows, colWidths=widths, repeatRows=1 if head else 0)
        cmds = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("BOX", (0, 0), (-1, -1), 0.4, RULE)]  # edge bars are appended after the box
        if head:
            cmds.append(("BACKGROUND", (0, 0), (-1, 0), BAND))
        for i, c in enumerate(edge or []):
            if c is not None:
                cmds.append(("LINEBEFORE", (0, i), (0, i), 3, c))
        tb.setStyle(TableStyle(cmds))
        return tb

    class Seal(Flowable):
        def __init__(self, rep_log: Dict[str, Any], size: float = 150):
            super().__init__()
            self.log, self.size = rep_log, size
            self.width = self.height = size

        def draw(self):
            c = self.canv
            ok = self.log.get("status") == "VALID"
            col = SEAL if ok else BREACH
            s = self.size / 200.0
            cx = cy = self.size / 2
            c.saveState()
            c.setStrokeColor(col)
            c.setFillColor(col)
            for r, wdt in ((97, 1.6), (92.5, 0.6), (78, 0.6)):
                c.setLineWidth(wdt * s)
                c.circle(cx, cy, r * s, stroke=1, fill=0)
            curves = seal_curves(self.log.get("head_hmac") or "", scale=s)
            for idx, pts in enumerate(curves):
                c.setLineWidth((0.45 if idx < len(curves) - 1 else 0.7) * s)
                path = c.beginPath()
                path.moveTo(cx + pts[0][0], cy - pts[0][1])
                for x, y in pts[1:]:
                    path.lineTo(cx + x, cy - y)
                path.close()
                c.drawPath(path, stroke=1, fill=0)
            c.setFillColor(colors.white)
            c.setLineWidth(0.8 * s)
            c.circle(cx, cy, 15.5 * s, stroke=1, fill=1)
            c.setFillColor(col)
            head = self.log.get("head_hmac") or ""
            micro = (f"HMAC-SHA256 CHAIN HEAD {head}   LOG {(self.log.get('log_id') or '')[:16]}   "
                     f"{self.log.get('entries') or 0} ENTRIES   ")
            ring = 85 * s
            font_size = 5.0 * s * 1.1
            c.setFont(F["mono"], font_size)
            advance = 2 * math.pi * ring / len(micro)
            for i, ch in enumerate(micro):
                ang = math.pi - i * advance / ring
                c.saveState()
                c.translate(cx + ring * math.cos(ang), cy + ring * math.sin(ang))
                c.rotate(math.degrees(ang) - 90)
                c.drawCentredString(0, 0, ch)
                c.restoreState()
            c.setLineWidth(4 * s)
            c.setLineCap(1)
            c.setLineJoin(1)
            if ok:
                path = c.beginPath()
                path.moveTo(cx - 11 * s, cy - 1 * s)
                path.lineTo(cx - 3 * s, cy - 9 * s)
                path.lineTo(cx + 12 * s, cy + 8 * s)
                c.drawPath(path, stroke=1, fill=0)
            else:
                c.line(cx - 10 * s, cy + 10 * s, cx + 10 * s, cy - 10 * s)
                c.line(cx + 10 * s, cy + 10 * s, cx - 10 * s, cy - 10 * s)
                c.setFillAlpha(0.22)
                c.setFont("Helvetica-Bold", 10 * s)
                for gx in range(-80, 81, 30):
                    for gy in range(-80, 81, 15):
                        if gx * gx + gy * gy < 76 * 76:
                            c.saveState()
                            c.translate(cx + gx * s, cy + gy * s)
                            c.rotate(28)
                            c.drawCentredString(0, 0, "VOID")
                            c.restoreState()
            c.restoreState()

    root_label = rep["target"]["root"] or "-"

    class NumberedCanvas(rl_canvas.Canvas):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._pages = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self.saveState()
                self.setFont(F["sans"], 7.2)
                self.setFillColor(INK2)
                left = f"File integrity monitoring report: {root_label}"
                if len(left) > 95:
                    left = left[:92] + "..."
                self.drawString(0.75 * inch, 0.45 * inch, left)
                self.drawRightString(letter[0] - 0.75 * inch, 0.45 * inch, f"Page {self._pageNumber} of {total}")
                self.restoreState()
                super().showPage()
            super().save()

    t, v, log = rep["target"], rep["verdict"], rep["log"]
    ok = log["status"] == "VALID"
    width = letter[0] - 1.5 * inch - 12          # frame content width (frames pad 6 pt per side)
    story: List[Any] = []
    story.append(P(txt(rep["report"]["title"]), "title"))
    story.append(P("Protected directory " + f'<font name="{F["mono"]}">{txt(t["root"])}</font>', "subject"))
    story.append(Spacer(1, 8))
    watched = window_text(rep["window"])
    facts = [("Host", t.get("host") or rep["report"]["host"]), ("Baseline taken", human_ts(t.get("baseline_created"))),
             ("Monitored", watched), ("Report generated", human_ts(rep["report"]["generated"])),
             ("Tool", f"{rep['report']['tool']} {rep['report']['version']}")]
    frows = [[P(txt(k), "muted") for k, _ in facts[:3]], [P(txt(x), "small") for _, x in facts[:3]],
             [P(txt(k), "muted") for k, _ in facts[3:]] + [P("")], [P(txt(x), "small") for _, x in facts[3:]] + [P("")]]
    ft = Table(frows, colWidths=[width / 3] * 3)
    ft.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("LINEABOVE", (0, 0), (-1, 0), 0.5, RULE), ("LINEBELOW", (0, -1), (-1, -1), 0.5, RULE),
                            ("LEFTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 1),
                            ("BOTTOMPADDING", (0, 1), (-1, 1), 6), ("BOTTOMPADDING", (0, 3), (-1, 3), 6)]))
    story += [ft, Spacer(1, 14)]

    tally = "    ".join(f'<font color="{SEVC[s].hexval()}"><b>{SEV_WORD[s]}</b></font> {n}'
                        for s, n in v["counts"].items() if n)
    left = [P(txt(v["headline"]), "headline")]
    if tally:
        left.append(P(tally, "body"))
    left.append(P(txt(v["log_line"]), "body"))
    if v.get("sim_line"):
        left.append(P(txt(v["sim_line"]), "body"))
    if not t["signature_ok"]:
        left.append(P(f'<font color="{BREACH.hexval()}">Baseline signature check failed: '
                      f'{txt(t["signature_problem"])}</font>', "body"))
    seal_cap = [Seal(log, 132), Spacer(1, 4),
                P(f'<para alignment="center"><font name="{F["head"]}" size="11" color="'
                  f'{(SEAL if ok else BREACH).hexval()}">{"Log seal intact" if ok else "Log seal broken"}</font><br/>'
                  f'{log.get("valid", 0)} of {log.get("entries", 0)} entries verified</para>', "muted")]
    vt = Table([[left, seal_cap]], colWidths=[width - 150, 150])
    vt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                            ("RIGHTPADDING", (0, 0), (0, 0), 14)]))
    story.append(vt)

    def h2(text: str) -> Paragraph:
        return P(txt(text), "h2")

    # Timeline
    story.append(h2("What happened"))
    if rep["timeline"]:
        rows = [[P("Time (UTC)", "cellhead"), P("Severity", "cellhead"), P("Event", "cellhead"),
                 P("Path", "cellhead"), P("Detected by", "cellhead")]]
        edges: List[Any] = [None]
        for row in rep["timeline"]:
            if row["kind"] == "alert":
                where = (row["path"] or "") + ((" \u2192 " + row["dest"]) if row.get("dest") else "")
                why = "; ".join(i.get("label", "") for i in row.get("indicators", [])[:3])
                src = txt(SOURCE_WORD.get(row.get("source") or "", row.get("source") or "-"))
                if row.get("latency_ms") is not None:
                    src += f'<br/><font color="{INK2.hexval()}">after {row["latency_ms"] / 1000:.2f} s</font>'
                rows.append([P(short_time(row["ts"])), sev_p(row["severity"]),
                             P(txt(row["label"]) + (f'<br/><font color="{INK2.hexval()}">{txt(why)}</font>' if why else "")
                               + ("" if row.get("verified") else f' <font color="{BREACH.hexval()}">(signature invalid)</font>')),
                             P(txt(where), "mono"), P(src)])
                edges.append(SEVC.get(row["severity"]))
            else:
                rows.append([P(short_time(row["ts"]), "muted"), P("-", "muted"), P(txt(row["label"]), "muted"),
                             P(txt(row.get("message")), "muted"), P("")])
                edges.append(None)
        story.append(table(rows, [0.74 * inch, 0.66 * inch, 1.8 * inch, width - 4.5 * inch, 1.3 * inch], edge=edges))
    else:
        story.append(P("The alert log has no entries yet.", "body"))

    sc = rep.get("scorecard")
    if sc:
        story.append(h2("Simulated attack"))
        med = sc.get("median_latency_s")
        story.append(P(txt(f"{sc.get('scenario')}. Each attacker action was performed with inert test files, "
                           f"timed, and matched to the alert that caught it: {sc['detected']} of "
                           f"{sc['performed']} were detected"
                           + (f", median time to alert {med:.2f} s." if med is not None else ".")), "body"))
        rows = [[P("#", "cellhead"), P("Attacker action", "cellhead"), P("Path", "cellhead"),
                 P("Result", "cellhead"), P("Time to alert", "cellhead"), P("ATT&amp;CK", "cellhead")]]
        for r in sc["rows"]:
            if r.get("status") != "done":
                res, lat = P(txt("Not run: " + str(r.get("reason") or r.get("status"))), "muted"), "-"
            elif r.get("detected"):
                res = P(f'<font color="{SEVC.get(r.get("severity"), INK).hexval()}"><b>{SEV_WORD.get(r.get("severity"), "")}</b></font>'
                        f' via {txt(SOURCE_WORD.get(r.get("source") or "", r.get("source")))}')
                lat = f"{r['latency_s']:.2f} s" if r.get("latency_s") is not None else "-"
            else:
                res, lat = P(f'<font color="{BREACH.hexval()}"><b>Missed</b></font>'), "-"
            rows.append([P(str(r.get("n"))), P(txt(r.get("title"))), P(txt(r.get("path")), "mono"), res, P(lat),
                         P(txt(r.get("technique")), "mono")])
        story.append(table(rows, [0.25 * inch, 2.1 * inch, width - 5.15 * inch, 1.2 * inch, 0.75 * inch, 0.85 * inch]))

    # Alert details
    story.append(h2("Alert details"))
    if not rep["alerts"]:
        story.append(P("There are no alerts to describe.", "body"))
    for a in rep["alerts"]:
        where = (a["path"] or "") + ((" \u2192 " + a["dest"]) if a.get("dest") else "")
        block: List[Any] = []
        sevc = SEVC.get(a["severity"], INK)
        block.append(P(f'<font color="{sevc.hexval()}"><b>{SEV_WORD.get(a["severity"], "")}</b></font>  '
                       f'<b>{txt(a["label"])}</b>  <font color="{INK2.hexval()}">log entry {a["seq"]}, '
                       f'{txt(human_ts(a["ts"]))}</font>', "h3"))
        block.append(P(txt(where), "mono"))
        kv = [[P("Detected by", "muted"), P(txt(SOURCE_WORD.get(a.get("source") or "", a.get("source") or "-")
                                                 + (f" ({a['latency_ms'] / 1000:.2f} s after the change)"
                                                    if a.get("latency_ms") is not None else "")))],
              [P("Entry signature", "muted"), P("valid" if a.get("verified") else
                                                f'<font color="{BREACH.hexval()}"><b>INVALID</b></font>')]]

        def rec_cell(rec: Optional[Dict[str, Any]]) -> List[Any]:
            if not rec:
                return [P("not present", "muted")]
            meta = []
            if rec.get("size") is not None:
                meta.append(human_size(rec["size"]))
            if rec.get("mode"):
                meta.append(f"mode {rec['mode']} ({rwx(int(rec['mode'], 8))})")
            if rec.get("type"):
                meta.append(rec["type"])
            if rec.get("mtime"):
                meta.append("modified " + human_ts(rec["mtime"]))
            if rec.get("target"):
                meta.append("points to " + rec["target"])
            if rec.get("error"):
                meta.append(rec["error"])
            cell = []
            if rec.get("sha256"):
                cell.append(P(grouped(rec["sha256"]), "mono"))
            cell.append(P(txt("; ".join(meta)), "muted"))
            return cell

        if a["event"] != "FILE_ADDED":
            kv.append([P("Before", "muted"), rec_cell(a.get("before"))])
        if a["event"] not in ("FILE_DELETED", "DIRECTORY_UNREADABLE", "BASELINE_TAMPERED", "LOG_TAMPERED"):
            kv.append([P("After", "muted"), rec_cell(a.get("after"))])
        if a.get("notes"):
            kv.append([P("Also", "muted"), P(txt("; ".join(a["notes"])))])
        if a.get("indicators"):
            kv.append([P("Why it matters", "muted"),
                       [P(f"<b>{txt(_cap(i.get('label')))}.</b> {txt(i.get('detail'))}") for i in a["indicators"]]])
        if a.get("attack"):
            kv.append([P("MITRE ATT&amp;CK", "muted"),
                       P("; ".join(f'<font name="{F["mono"]}">{txt(x.get("id"))}</font> {txt(x.get("name"))}'
                                   for x in a["attack"]))])
        if a.get("response"):
            kv.append([P("Response", "muted"), P(txt(a["response"]))])
        kt = Table(kv, colWidths=[1.05 * inch, width - 1.05 * inch - 10])
        kt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5)]))
        block.append(kt)
        frame = Table([[block]], colWidths=[width])
        frame.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.4, RULE), ("LINEBEFORE", (0, 0), (0, 0), 3, sevc),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                                   ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
        story += [KeepTogether([frame]), Spacer(1, 7)]

    # Evidence log
    story.append(h2("Evidence log"))
    story.append(P(txt("Every alert was appended to a JSON-lines log. Each entry is signed with HMAC-SHA256 under "
                       "a key that never appears in the log, carries a sequence number, and includes the signature "
                       "of the entry before it. Editing, deleting, reordering or forging an entry breaks the chain; "
                       "an anchor of the newest entry, kept in the database, catches a log that was cut short."),
                   "body"))
    anchor = log.get("anchor") or {}
    anchor_txt = {"match": f"matches the database anchor (entry {anchor.get('seq')})",
                  "truncated": "log is shorter than the database anchor",
                  "mismatch": "does not match the database anchor", "invalid": "anchor signature is invalid",
                  "absent": "no anchor available"}.get(anchor.get("status"), "-")
    res_txt = (f'<font color="{(SEAL if ok else BREACH).hexval()}"><b>{txt(log["status"])}</b></font> '
               + txt(log.get("summary")))
    kv = [["Result", P(res_txt)], ["Log file", P(txt(log.get("path")), "mono")],
          ["Entries", P(f"{log.get('valid', 0)} of {log.get('entries', 0)} signatures valid")],
          ["Key ID", P(f'<font name="{F["mono"]}">{txt(log.get("kid_used"))}</font> (a fingerprint; the key itself is '
                       "never stored in the log or the report)")],
          ["Log ID", P(txt(log.get("log_id")), "mono")], ["Chain head", P(grouped(log.get("head_hmac")), "mono")],
          ["Anchor check", P(txt(anchor_txt))]]
    kt = Table([[P(k, "muted"), val] for k, val in kv], colWidths=[1.05 * inch, width - 1.05 * inch])
    kt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                            ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5)]))
    story.append(kt)
    for p in log.get("problems", [])[:20]:
        story.append(P(f'<font color="{BREACH.hexval()}">{txt(p.get("message"))}</font>', "body"))
    tt = rep.get("tamper_test")
    if tt:
        story.append(P("<b>Tamper test</b>", "h3"))
        story.append(P(txt(f"Five attacks were made on copies of the log and each copy was verified: "
                           f"{tt['detected']} of {tt['total']} were detected. The original log was only read."), "body"))
        rows = [[P("Attack", "cellhead"), P("What was changed", "cellhead"), P("Result", "cellhead"),
                 P("What verification reported", "cellhead")]]
        for s in tt.get("scenarios", []):
            rows.append([P(txt(s.get("title"))), P(txt(s.get("change"))),
                         P(f'<font color="{(SEAL if s.get("detected") else BREACH).hexval()}"><b>'
                           f'{"Detected" if s.get("detected") else "Missed"}</b></font>'), P(txt(s.get("finding")))])
        story.append(table(rows, [0.95 * inch, 1.95 * inch, 0.8 * inch, width - 3.7 * inch]))

    # Baseline
    story.append(h2("Baseline"))
    kv = [["Directory", P(txt(t["root"]), "mono")], ["Created", P(txt(human_ts(t.get("baseline_created"))))],
          ["Last approved", P(txt(human_ts(t.get("baseline_updated"))))],
          ["Files", P(f"{t['files']} ({human_size(t['bytes'])})")],
          ["Excluded", P(txt(", ".join(t["excludes"])) if t["excludes"] else "nothing")],
          ["Baseline digest", P(grouped(t.get("digest")), "mono")],
          ["Signature", P("valid (HMAC-SHA256 over every row)" if t["signature_ok"] else
                          f'<font color="{BREACH.hexval()}"><b>failed</b></font> {txt(t["signature_problem"])}')]]
    kt = Table([[P(k, "muted"), val] for k, val in kv], colWidths=[1.05 * inch, width - 1.05 * inch])
    kt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                            ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5)]))
    story += [kt, Spacer(1, 6)]
    inv = rep["inventory"][:150]
    rows = [[P("Path", "cellhead"), P("Size", "cellhead"), P("Mode", "cellhead"), P("Type", "cellhead"),
             P("SHA-256 (first 16 hex)", "cellhead")]]
    for r in inv:
        rows.append([P(txt(r["path"]), "mono"), P(human_size(r["size"])), P(txt(r["mode"]), "mono"),
                     P(txt(r["type"])), P(txt(_short_hash(r["sha256"])), "mono")])
    story.append(table(rows, [width - 4.35 * inch, 0.6 * inch, 0.45 * inch, 1.5 * inch, 1.8 * inch]))
    if len(rep["inventory"]) > len(inv):
        story.append(P(txt(f"Showing the first {len(inv)} of {len(rep['inventory'])} files; the JSON report "
                           "lists all of them."), "muted"))

    # Monitoring
    story.append(h2("Monitoring"))
    if rep["sessions"]:
        rows = [[P("Started (UTC)", "cellhead"), P("Stopped", "cellhead"), P("Interval", "cellhead"),
                 P("Real-time", "cellhead"), P("Scans", "cellhead"), P("Alerts", "cellhead"),
                 P("How it stopped", "cellhead")]]
        for s in rep["sessions"]:
            rows.append([P(txt(human_ts(s.get("started_utc")))), P(txt(short_time(s.get("stopped_utc")))),
                         P(f"{s.get('interval_s')} s"), P("yes" if s.get("realtime") else "no"),
                         P(str(s.get("cycles"))), P(str(s.get("alerts"))),
                         P(txt(s.get("stop_reason") or "still running or ended abruptly"))])
        story.append(table(rows, [1.58 * inch, 0.78 * inch, 0.6 * inch, 0.74 * inch, 0.5 * inch, 0.52 * inch,
                                  width - 4.72 * inch]))
    scans = rep["scans"]
    trig = ", ".join(f"{n} {SCAN_WORD.get(k, k)}{'s' if n != 1 else ''}"
                     for k, n in sorted(scans["by_trigger"].items(), key=lambda kv: -kv[1]))
    story.append(Spacer(1, 4))
    story.append(P(txt(f"{scans['count']} scans in total" + (f" ({trig})" if trig else "") + ". "
                       + (f"Full scans took {scans['mean_ms']:.1f} ms on average and {scans['max_ms']:.1f} ms at most; "
                          if scans.get("mean_ms") is not None else "")
                       + f"{human_size(scans.get('bytes_hashed'))} hashed in total."), "body"))

    # Response
    story.append(h2("Recommended response"))
    if rep["response"]:
        items = [ListItem(P(f"<b>{txt(s['step'])}.</b> " + re.sub(r"`([^`]+)`", r'<font name="%s">\1</font>' % F["mono"],
                                                                   txt(s["text"])), "body"), leftIndent=14)
                 for s in rep["response"]]
        story.append(ListFlowable(items, bulletType="1", bulletFontName=F["sans"], bulletFontSize=9, leftIndent=14))
    else:
        story.append(P("No action is needed. Keep the monitor running and re-baseline after approved changes.", "body"))

    # Method
    story.append(h2("How it works"))
    interval = rep["sessions"][-1]["interval_s"] if rep["sessions"] else None
    for para in (
        "<b>Baseline.</b> Every regular file under the protected directory was read in full and hashed with "
        "SHA-256; symlinks are recorded but never followed. The rows are stored in SQLite with a digest of every "
        "row, signed with HMAC-SHA256, so a baseline doctored to hide malware is rejected before monitoring starts.",
        "<b>Monitoring.</b> The daemon re-hashes the whole tree " + (f"every {interval:g} seconds " if interval else
        "on a fixed interval ") + "(the authoritative check) and uses watchdog file-system events to rescan changed "
        "paths within about a second. Each change is scored with indicators such as executable content behind a "
        "document extension, hidden locations, persistence locations, a timestamp left untouched after an edit, "
        "and known-bad hashes.",
        "<b>Limits.</b> Integrity monitoring detects changes; it does not prevent them. Anyone who obtains the HMAC "
        "key can write a convincing log, and someone able to roll back both the log and the database together can "
        "hide recent entries, so production systems should forward entries to a separate log server or write-once "
        "storage and keep the key off the monitored host. Without real-time events, a change that is made and "
        "reverted between two scans can go unseen."):
        story.append(P(para, "body"))

    # Appendix
    story.append(h2("Log entries"))
    story.append(P(txt("Each entry's prev value must equal the signature (hmac) of the entry above it. Values are "
                       "shortened to their first 12 hex digits."), "body"))
    rows = [[P("Line", "cellhead"), P("Seq", "cellhead"), P("Time", "cellhead"), P("Event", "cellhead"),
             P("Path", "cellhead"), P("prev", "cellhead"), P("hmac", "cellhead"), P("Sig.", "cellhead")]]
    for en in rep["entries"]:
        rows.append([P(str(en["line"])), P(str(en["seq"])), P(short_time(en["ts"])),
                     P(txt(EVENT_LABELS.get(en["event"], en["event"]))), P(txt(en.get("path") or ""), "mono"),
                     P(txt((en.get("prev") or "")[:12]), "mono"), P(txt((en.get("hmac") or "")[:12]), "mono"),
                     P("valid" if en["ok"] else f'<font color="{BREACH.hexval()}"><b>invalid</b></font>')])
    story.append(table(rows, [0.42 * inch, 0.4 * inch, 0.78 * inch, 1.12 * inch, width - 5.28 * inch,
                              0.86 * inch, 0.86 * inch, 0.44 * inch]))

    doc = SimpleDocTemplate(str(out_path), pagesize=letter, leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                            topMargin=0.7 * inch, bottomMargin=0.75 * inch,
                            title=f"{rep['report']['title']}: {t['name']}", author=f"{TOOL} {__version__}",
                            subject="File integrity monitoring report")
    doc.build(story, canvasmaker=NumberedCanvas)


def build_reports(state: StatePaths, keys: Keys, out_base: Path, formats: Sequence[str], console: Console,
                  title: Optional[str] = None, manifest: Optional[Path] = None,
                  tamper: Optional[Path] = None) -> Dict[str, Path]:
    out_base = Path(out_base)
    if out_base.suffix.lower() in (".html", ".pdf", ".json"):
        out_base = out_base.with_suffix("")
    ensure_dir(out_base.parent)
    if manifest is None and state.manifest.is_file():
        manifest = state.manifest
    if tamper is None and state.tamper.is_file():
        tamper = state.tamper
    rep = collect_report(state, keys, title, manifest, tamper)
    written: Dict[str, Path] = {}
    fmts = [f.strip().lower() for f in formats if f.strip()]
    if "json" in fmts:
        p = out_base.with_name(out_base.name + ".json")
        write_json(p, rep)
        written["json"] = p
    if "html" in fmts:
        p = out_base.with_name(out_base.name + ".html")
        p.write_text(render_html(rep), encoding="utf-8")
        written["html"] = p
    if "pdf" in fmts:
        p = out_base.with_name(out_base.name + ".pdf")
        try:
            render_pdf(rep, p)
            written["pdf"] = p
        except ImportError:
            console.warn("reportlab is not installed, so the PDF was skipped (pip install reportlab).")
    for kind, p in written.items():
        console.ok(f"{kind.upper():<4} report: {p}")
    return written


# ----------------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------------

def _state(args: argparse.Namespace) -> StatePaths:
    return StatePaths.build(args.state_dir, args.db, args.log, args.key_file)


def cmd_baseline(args: argparse.Namespace, con: Console) -> int:
    state = _state(args)
    keys = load_keys(state.key)
    con.note(f"HMAC key: {keys.source} (key ID {keys.key_id})")
    info = create_baseline(Path(args.dir), state, keys, con, args.exclude, args.update, args.force)
    res: ScanResult = info["scan"]
    con.ok(f"Baseline {'updated' if args.update else 'created'}: {plural(info['files'], 'file')} "
           f"({human_size(info['bytes'])}) in {plural(res.dirs, 'directory', 'directories')}, "
           f"hashed in {human_duration(res.duration)}")
    con.kv("Directory", info["root"])
    con.kv("Database", str(state.db))
    con.kv("Baseline digest", info["digest"])
    con.kv("Signature", f"HMAC-SHA256 over every row (key ID {keys.key_id})")
    con.kv("Alert log", str(state.log))
    if info.get("accepted"):
        acc = info["accepted"]
        counts = ", ".join(f"{n} {EVENT_LABELS.get(k, k).lower()}" for k, n in acc["counts"].items()) or "none"
        con.kv("Approved changes", counts)
    if res.blind:
        con.warn("Unreadable directories (their contents are not in the baseline): " + ", ".join(sorted(res.blind)))
    unreadable = [r.path for r in info["records"].values() if r.error]
    if unreadable:
        con.warn(f"{plural(len(unreadable), 'file')} could not be hashed: " + ", ".join(unreadable[:5]))
    if args.list:
        con.info("")
        for r in sorted(info["records"].values(), key=lambda r: r.path):
            con.info(f"  {(r.sha256 or '-')[:16]:<16}  {mode_str(r.mode)}  {human_size(r.size):>9}  {r.path}")
    return EXIT_OK


def cmd_check(args: argparse.Namespace, con: Console) -> int:
    state = _state(args)
    keys = load_keys(state.key, create=False)
    iocs, notes = load_iocs(args.ioc)
    for n in notes:
        con.note(n)
    con.heading(f"Integrity check against the baseline in {state.db}")
    code, entries = run_check(state, keys, con, iocs, args.critical)
    if code == EXIT_OK:
        con.ok("No changes: every file matches the baseline.")
    elif code == EXIT_FINDINGS:
        counts = collections.Counter(e["sev"] for e in entries)
        tally = ", ".join(f"{counts[s]} {s.lower()}" for s in reversed(SEVERITIES) if counts.get(s))
        con.warn(f"{plural(len(entries), 'change')} from the baseline ({tally}); each one is in {state.log}")
    return code


def cmd_monitor(args: argparse.Namespace, con: Console) -> int:
    state = _state(args)
    keys = load_keys(state.key, create=False)
    iocs, notes = load_iocs(args.ioc)
    for n in notes:
        con.note(n)
    mon = Monitor(state, keys, con, interval=args.interval, realtime=not args.no_watchdog, settle=args.settle,
                  heartbeat=args.heartbeat, max_cycles=args.cycles, duration=args.duration, fast=args.fast,
                  iocs=iocs, critical=args.critical, pidfile=Path(args.pidfile) if args.pidfile else None)
    mon.install_signal_handlers()
    try:
        return mon.run()
    except KeyboardInterrupt:
        mon.stop("keyboard interrupt")
        return EXIT_OK


def cmd_verify(args: argparse.Namespace, con: Console) -> int:
    state = _state(args)
    keys = load_keys(state.key, create=False)
    db = BaselineDB(state.db).open() if (not args.no_anchor and state.db.is_file()) else None
    try:
        ver = verify_log(state.log, keys, db)
    finally:
        if db is not None:
            db.close()
    if args.json:
        print(json.dumps(ver.to_dict(), indent=2))
    else:
        con.heading("Verifying the tamper-evident alert log")
        print_verification(ver, con)
    return EXIT_OK if ver.ok else EXIT_FINDINGS


def cmd_tamper(args: argparse.Namespace, con: Console) -> int:
    state = _state(args)
    keys = load_keys(state.key, create=False)
    db = BaselineDB(state.db).open() if state.db.is_file() else None
    try:
        result = run_tamper_test(state.log, keys, db, state.dir / "tamper_test")
    finally:
        if db is not None:
            db.close()
    out = Path(args.out) if args.out else state.tamper
    write_json(out, result)
    con.heading("Tamper test: five attacks on copies of the alert log")
    print_tamper(result, con)
    con.ok(f"Results saved to {out}")
    return EXIT_OK if result["detected"] == result["total"] else EXIT_FINDINGS


def cmd_report(args: argparse.Namespace, con: Console) -> int:
    state = _state(args)
    keys = load_keys(state.key, create=False)
    written = build_reports(state, keys, Path(args.output), args.formats.split(","), con, args.title,
                            Path(args.manifest) if args.manifest else None,
                            Path(args.tamper_results) if args.tamper_results else None)
    return EXIT_OK if written else EXIT_ERROR


def cmd_lab_setup(args: argparse.Namespace, con: Console) -> int:
    state = _state(args)
    lab_setup(Path(args.dir), state, con, args.force)
    con.info(f"  Next: python {TOOL} baseline --dir {args.dir}")
    return EXIT_OK


def cmd_simulate(args: argparse.Namespace, con: Console) -> int:
    state = _state(args)
    manifest = simulate_attack(Path(args.dir), con, args.delay,
                               Path(args.manifest) if args.manifest else state.manifest)
    done = sum(1 for s in manifest["steps"] if s["status"] == "done")
    con.ok(f"{done} of {len(manifest['steps'])} attacker actions performed. A running monitor should "
           "alert on each one; `report` scores the detections.")
    return EXIT_OK


def cmd_demo(args: argparse.Namespace, con: Console) -> int:
    work = Path(args.workdir).resolve()
    marker = work / ".fim-demo"
    if work.exists() and any(work.iterdir()):
        if not marker.is_file():
            raise FIMError(f"{work} exists and was not created by `{TOOL} demo`; choose another --workdir.")
        shutil.rmtree(work)
    ensure_dir(work)
    marker.write_text(f"created by {TOOL} demo\n", encoding="ascii")
    state = StatePaths.build(str(work / "fim_data"))
    target = work / "lab_target"
    total = 7

    def step(n: int, text: str) -> None:
        con.heading(f"Step {n} of {total}  {text}")

    con.emit(con.c(f"{TOOL} {__version__} demo: secure file integrity monitor", "1"))
    keys = load_keys(state.key)
    con.note(f"HMAC key: {keys.source} (key ID {keys.key_id})")
    step(1, "Build the lab directory to protect")
    lab_setup(target, state, con)
    step(2, "Baseline every file into SQLite (deliverable 1)")
    info = create_baseline(target, state, keys, con)
    con.ok(f"{plural(info['files'], 'file')} hashed; baseline digest {info['digest'][:16]}..., signed")
    step(3, f"Start the monitoring daemon, interval {args.interval:g} s (deliverable 2)")
    iocs, notes = load_iocs([str(state.dir / IOC_SAMPLE_NAME)])
    for n in notes:
        con.note(n)
    mon = Monitor(state, keys, con, interval=args.interval, realtime=not args.no_watchdog,
                  heartbeat=max(5.0, args.interval * 3), iocs=iocs)
    thread = threading.Thread(target=mon.run, name="fim-monitor", daemon=True)
    thread.start()
    mon.ready.wait(60)
    if not thread.is_alive():
        raise FIMError("The monitor did not start; see the messages above.")
    try:
        step(4, "Simulated malware drop (deliverable 4)")
        manifest = simulate_attack(target, con, args.delay, state.manifest)
        card = wait_for_detection(state, manifest, timeout=args.interval * 2 + 6)
    finally:
        mon.stop("demo finished")
        thread.join(60)
    step(5, "Verify the tamper-evident alert log (deliverable 3)")
    db = BaselineDB(state.db).open()
    try:
        ver = verify_log(state.log, keys, db)
        print_verification(ver, con)
        step(6, "Tamper test: attack copies of the log")
        result = run_tamper_test(state.log, keys, db, state.dir / "tamper_test")
    finally:
        db.close()
    write_json(state.tamper, result)
    print_tamper(result, con)
    step(7, "Detection scorecard and reports")
    card = build_scorecard(manifest, read_log_entries(state.log))
    if card:
        print_scorecard(card, con)
    written = build_reports(state, keys, work / "reports" / "fim_report", args.formats.split(","), con)
    con.heading("Demo complete")
    con.kv("Lab directory", str(target))
    con.kv("Baseline database", str(state.db))
    con.kv("Alert log", str(state.log))
    for kind, p in written.items():
        con.kv(f"{kind.upper()} report", str(p))
    ok = ver.ok and result["detected"] == result["total"] and card is not None and card["detected"] == card["performed"]
    return EXIT_OK if ok else EXIT_FINDINGS


# ----------------------------------------------------------------------------
# Self-test (offline, temporary directories only)
# ----------------------------------------------------------------------------

def run_self_test(con: Console) -> int:
    quiet = Console(color=False, quiet=True, stream=io.StringIO())
    keys = Keys(master=hashlib.sha256(b"fim self-test key").digest(), source="self-test")
    tests: List[Callable[[Path], None]] = []

    def test(fn: Callable[[Path], None]) -> Callable[[Path], None]:
        tests.append(fn)
        return fn

    def check(cond: bool, msg: str) -> None:
        if not cond:
            raise AssertionError(msg)

    def write(p: Path, data: bytes, mode: Optional[int] = None) -> Path:
        ensure_dir(p.parent)
        p.write_bytes(data)
        if mode is not None:
            os.chmod(p, mode)
        return p

    def new_state(tmp: Path) -> StatePaths:
        return StatePaths.build(str(tmp / "state"))

    @test
    def t_hash(tmp: Path) -> None:
        """SHA-256 streaming hash matches hashlib (multi-chunk file and a known vector)"""
        data = _lab_bytes("self-test", 2 * HASH_CHUNK + 12345)
        p = write(tmp / "big.bin", data)
        check(hash_file(str(p)).sha256 == hashlib.sha256(data).hexdigest(), "multi-chunk hash differs")
        q = write(tmp / "abc.txt", b"abc")
        check(hash_file(str(q)).sha256 ==
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "known vector differs")

    @test
    def t_baseline(tmp: Path) -> None:
        """Baseline hashes every file, honours excludes, records symlinks without following them"""
        root = tmp / "root"
        write(root / "a.txt", b"alpha")
        write(root / "sub" / "b.txt", b"bravo")
        write(root / "skip.tmp", b"temp")
        if hasattr(os, "symlink"):
            try:
                os.symlink("a.txt", root / "link")
            except (OSError, NotImplementedError):
                pass
        state = new_state(tmp)
        info = create_baseline(root, state, keys, quiet, excludes=["*.tmp"])
        recs = info["records"]
        check("a.txt" in recs and "sub/b.txt" in recs, "files missing from the baseline")
        check("skip.tmp" not in recs, "excluded file was baselined")
        if "link" in recs:
            check(recs["link"].kind == "symlink" and recs["link"].sha256 is None, "symlink was followed")
        with BaselineDB(state.db).open() as db:
            check(db.verify(keys).ok, "fresh baseline does not verify")

    @test
    def t_baseline_tamper(tmp: Path) -> None:
        """A doctored baseline (changed hash or metadata) is rejected"""
        root = tmp / "root"
        write(root / "a.txt", b"alpha")
        state = new_state(tmp)
        create_baseline(root, state, keys, quiet)
        conn = sqlite3.connect(str(state.db))
        conn.execute("UPDATE baseline SET sha256 = ? WHERE path = 'a.txt'", ("0" * 64,))
        conn.commit()
        conn.close()
        with BaselineDB(state.db).open() as db:
            res = db.verify(keys)
        check(not res.ok and "digest" in (res.problem or ""), "edited hash was not detected")
        create_baseline(root, state, keys, quiet, force=True)
        conn = sqlite3.connect(str(state.db))
        conn.execute("UPDATE meta SET value = '/elsewhere' WHERE key = 'root'")
        conn.commit()
        conn.close()
        with BaselineDB(state.db).open() as db:
            check(not db.verify(keys).ok, "edited metadata was not detected")

    @test
    def t_diff(tmp: Path) -> None:
        """Detects added, modified, deleted, moved, permission and type changes"""
        root = tmp / "root"
        for name in ("keep.txt", "edit.txt", "gone.txt", "move.txt", "perm.sh", "swap.txt"):
            write(root / name, f"content of {name}".encode())
        sc = Scanner(root)
        before = sc.scan().records
        write(root / "new.txt", b"new file")
        write(root / "edit.txt", b"changed")
        (root / "gone.txt").unlink()
        os.replace(root / "move.txt", root / "moved.txt")
        expected = {"FILE_ADDED", "FILE_MODIFIED", "FILE_DELETED", "FILE_MOVED"}
        if os.name != "nt":
            os.chmod(root / "perm.sh", 0o755)
            expected.add("PERMISSIONS_CHANGED")
            (root / "swap.txt").unlink()
            os.symlink("keep.txt", root / "swap.txt")
            expected.add("TYPE_CHANGED")
        kinds = {c.kind for c in diff_states(before, sc.scan().records)}
        check(expected <= kinds, f"missing {expected - kinds}")
        moved = [c for c in diff_states(before, sc.scan().records) if c.kind == "FILE_MOVED"]
        check(moved and moved[0].dest == "moved.txt", "rename was not paired as a move")

    @test
    def t_indicators(tmp: Path) -> None:
        """Flags masquerading executables, hidden packed payloads and timestomping"""
        root = tmp / "root"
        write(root / "index.html", b"<html>home</html>\n")
        sc = Scanner(root)
        before = sc.scan().records
        write(root / "report.pdf", lab_dropper_bytes())
        write(root / ".cache" / "agent", lab_payload_bytes(), 0o755 if os.name != "nt" else None)
        st = os.stat(root / "index.html")
        write(root / "index.html", b"<html>home<script src=x></script></html>\n")
        os.utime(root / "index.html", ns=(st.st_atime_ns, st.st_mtime_ns))
        pol = Policy(root=root, baseline=before)
        changes = {c.target: assess(c, pol) for c in diff_states(before, sc.scan().records)}
        pdf = changes["report.pdf"]
        check(pdf.severity == "CRITICAL" and any(i.id == "masquerade" for i in pdf.indicators),
              "PE file named .pdf was not flagged as masquerading")
        agent = changes[".cache/agent"]
        ids = {i.id for i in agent.indicators}
        check({"hidden", "high_entropy", "executable"} <= ids and agent.severity == "CRITICAL",
              f"hidden payload indicators incomplete: {ids}")
        check(any(i.id == "timestomp" for i in changes["index.html"].indicators), "timestomp missed")

    @test
    def t_simulation(tmp: Path) -> None:
        """Lab check catches all 8 simulated attacker actions and the scorecard matches them"""
        state = new_state(tmp)
        lab_setup(tmp / "lab", state, quiet)
        create_baseline(tmp / "lab", state, keys, quiet)
        manifest = simulate_attack(tmp / "lab", quiet, delay=0, manifest_path=state.manifest)
        iocs, _ = load_iocs([str(state.dir / IOC_SAMPLE_NAME)])
        code, entries = run_check(state, keys, quiet, iocs)
        check(code == EXIT_FINDINGS, "check did not report findings")
        card = build_scorecard(manifest, read_log_entries(state.log))
        check(card["detected"] == card["performed"], f"scorecard {card['detected']}/{card['performed']}")
        missing = [r["id"] for r in card["rows"] if r.get("status") == "done" and not r.get("classified")]
        check(not missing, f"actions detected without the expected indicator: {missing}")

    @test
    def t_log_tamper(tmp: Path) -> None:
        """Signed log verifies; editing, deleting, reordering, forging and truncating are all caught"""
        state = new_state(tmp)
        with BaselineDB(state.db).open(create=True) as db:
            log = TamperEvidentLog(state.log, keys, db, quiet).open()
            for i in range(6):
                log.append("FILE_ADDED", "HIGH" if i % 2 else "CRITICAL", f"test {i}", f"f{i}.txt", {"n": i})
            check(verify_log(state.log, keys, db).ok, "untouched log does not verify")
            result = run_tamper_test(state.log, keys, db, tmp / "copies")
        check(result["detected"] == result["total"] == 5, f"only {result['detected']}/5 attacks detected")

    @test
    def t_wrong_key(tmp: Path) -> None:
        """A different key is reported as WRONG_KEY rather than as tampering"""
        state = new_state(tmp)
        log = TamperEvidentLog(state.log, keys, None, quiet).open()
        log.append("HEARTBEAT", "INFO", "hello")
        other = Keys(master=b"another key, 32 bytes long......", source="test")
        check(verify_log(state.log, other).status == "WRONG_KEY", "wrong key not recognised")

    @test
    def t_set_aside(tmp: Path) -> None:
        """A tampered log is set aside as evidence and a new signed chain is started"""
        state = new_state(tmp)
        log = TamperEvidentLog(state.log, keys, None, quiet).open()
        log.append("FILE_ADDED", "CRITICAL", "dropper", "x.exe")
        lines = state.log.read_text(encoding="ascii").splitlines()
        lines[1] = lines[1].replace("CRITICAL", "INFO")
        state.log.write_text("\n".join(lines) + "\n", encoding="ascii")
        log2 = TamperEvidentLog(state.log, keys, None, quiet).open()
        check(len(log2.set_aside) == 1, "tampered log was not set aside")
        check(any(p.name.startswith(LOG_NAME + ".untrusted-") for p in state.dir.iterdir()), "evidence file missing")
        events = [e.get("event") for e in read_log_entries(state.log)]
        check("LOG_TAMPERED" in events and verify_log(state.log, keys).ok, "new chain missing or invalid")

    @test
    def t_monitor_interval(tmp: Path) -> None:
        """Monitoring loop (interval scans only) detects changes and stops cleanly"""
        root = tmp / "root"
        write(root / "a.txt", b"alpha")
        write(root / "b.txt", b"bravo")
        state = new_state(tmp)
        create_baseline(root, state, keys, quiet)
        mon = Monitor(state, keys, quiet, interval=0.3, realtime=False, heartbeat=0)
        th = threading.Thread(target=mon.run, daemon=True)
        th.start()
        check(mon.ready.wait(20), "monitor never became ready")
        write(root / "c.txt", b"charlie")
        write(root / "a.txt", b"ALPHA")
        (root / "b.txt").unlink()
        deadline = time.monotonic() + 10
        seen: Set[str] = set()
        while time.monotonic() < deadline and not {"FILE_ADDED", "FILE_MODIFIED", "FILE_DELETED"} <= seen:
            time.sleep(0.1)
            seen = {e.get("event") for e in read_log_entries(state.log)}
        mon.stop("self-test")
        th.join(20)
        check({"FILE_ADDED", "FILE_MODIFIED", "FILE_DELETED"} <= seen, f"events seen: {sorted(seen)}")
        check("MONITOR_STOPPED" in {e.get("event") for e in read_log_entries(state.log)}, "no stop entry")
        with BaselineDB(state.db).open() as db:
            check(db.sessions()[-1].get("stopped_utc") is not None, "session not closed")
            check(verify_log(state.log, keys, db).ok, "log does not verify after monitoring")

    @test
    def t_monitor_realtime(tmp: Path) -> None:
        """Real-time events (watchdog) raise an alert well before the next interval scan"""
        try:
            import watchdog  # noqa: F401
        except ImportError:
            con.info(con.c("        (watchdog not installed: real-time check skipped)", "2"))
            return
        root = tmp / "root"
        write(root / "a.txt", b"alpha")
        state = new_state(tmp)
        create_baseline(root, state, keys, quiet)
        mon = Monitor(state, keys, quiet, interval=60, realtime=True, settle=0.2, heartbeat=0)
        th = threading.Thread(target=mon.run, daemon=True)
        th.start()
        check(mon.ready.wait(20), "monitor never became ready")
        check(mon.realtime_status.startswith("on"), f"watchdog not active: {mon.realtime_status}")
        write(root / "dropped.exe", lab_dropper_bytes())
        deadline = time.monotonic() + 8
        hit = None
        while time.monotonic() < deadline and hit is None:
            time.sleep(0.1)
            hit = next((e for e in read_log_entries(state.log) if e.get("event") == "FILE_ADDED"), None)
        mon.stop("self-test")
        th.join(20)
        check(hit is not None and (hit.get("data") or {}).get("source") == "watchdog",
              "no real-time alert within 8 s")

    @test
    def t_reports(tmp: Path) -> None:
        """Reports render: hostile file names are escaped, JSON parses, PDF is produced"""
        root = tmp / "root"
        write(root / "a.txt", b"alpha")
        state = new_state(tmp)
        create_baseline(root, state, keys, quiet)
        hostile = "<img src=x onerror=alert(1)>.txt" if os.name != "nt" else "a&b'c.txt"
        write(root / hostile, b"x")
        run_check(state, keys, quiet, dict(BUILTIN_IOCS))
        written = build_reports(state, keys, tmp / "out" / "r", ["html", "json", "pdf"], quiet)
        page = written["html"].read_text(encoding="utf-8")
        check("<img src=x" not in page and "File added" in page, "hostile file name not escaped")
        check(json.loads(written["json"].read_text(encoding="utf-8"))["verdict"]["alerts"] == 1, "JSON wrong")
        if "pdf" in written:
            check(written["pdf"].read_bytes()[:5] == b"%PDF-", "PDF header missing")

    con.heading(f"{TOOL} {__version__} self-test")
    passed = 0
    for fn in tests:
        name = (fn.__doc__ or fn.__name__).strip()
        tmp = Path(tempfile.mkdtemp(prefix="fim-selftest-"))
        t0 = time.monotonic()
        try:
            fn(tmp)
            passed += 1
            con.info(f"  {con.c('PASS', '1;92')}  {name} {con.c(f'({time.monotonic() - t0:.1f} s)', '2')}")
        except Exception as exc:
            con.info(f"  {con.c('FAIL', '1;91')}  {name}")
            con.info(con.c(f"        {exc.__class__.__name__}: {exc}", "91"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    style = "1;92" if passed == len(tests) else "1;91"
    con.emit(con.c(f"{passed}/{len(tests)} checks passed", style), force=True)
    return EXIT_OK if passed == len(tests) else EXIT_ERROR


def cmd_self_test(args: argparse.Namespace, con: Console) -> int:
    return run_self_test(con)


# ----------------------------------------------------------------------------
# Command line
# ----------------------------------------------------------------------------

EPILOG = f"""
examples:
  python {TOOL} demo                              complete offline demonstration
  python {TOOL} lab-setup --dir lab_target        build the practice directory
  python {TOOL} baseline --dir lab_target         hash every file into fim_data/fim.db
  python {TOOL} monitor --interval 5              run the daemon (Ctrl+C stops it)
  python {TOOL} simulate --dir lab_target         (second terminal) inert malware drop
  python {TOOL} verify-log                        check every signature and the chain
  python {TOOL} tamper-test                       prove edits/deletions/forgeries are caught
  python {TOOL} report -o reports/fim_report      HTML + PDF + JSON report

The HMAC key comes from ${ENV_KEY} or <state-dir>/{KEY_NAME}. Exit codes: 0 OK,
1 error, 2 changes found or log failed verification, 3 baseline failed verification.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL, formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG,
        description="Secure file integrity monitor: SHA-256 baseline in SQLite, continuous monitoring, "
                    "and alerts in a tamper-evident HMAC-signed log.")
    parser.add_argument("--version", action="version", version=f"{TOOL} {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    def common(sp: argparse.ArgumentParser, state: bool = True) -> argparse.ArgumentParser:
        if state:
            g = sp.add_argument_group("state files")
            g.add_argument("--state-dir", default=DEFAULT_STATE_DIR,
                           help=f"folder for the database, log and key (default: {DEFAULT_STATE_DIR})")
            g.add_argument("--db", help=f"baseline database (default: <state-dir>/{DB_NAME})")
            g.add_argument("--log", help=f"alert log (default: <state-dir>/{LOG_NAME})")
            g.add_argument("--key-file", help=f"HMAC key file when ${ENV_KEY} is not set "
                                              f"(default: <state-dir>/{KEY_NAME})")
        o = sp.add_argument_group("output")
        o.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="coloured output")
        o.add_argument("--quiet", "-q", action="store_true", help="only print alerts, warnings and results")
        return sp

    b = common(sub.add_parser("baseline", help="hash a directory into the SQLite baseline (deliverable 1)"))
    b.add_argument("--dir", "-d", required=True, help="directory to protect")
    b.add_argument("--exclude", "-x", action="append", default=[], metavar="GLOB",
                   help="skip matching names or paths (repeatable), e.g. '*.tmp' or 'cache/*'")
    mx = b.add_mutually_exclusive_group()
    mx.add_argument("--update", action="store_true", help="approve the directory's current state")
    mx.add_argument("--force", action="store_true", help="replace the baseline with a new one")
    b.add_argument("--list", action="store_true", help="print every file with its hash")

    c = common(sub.add_parser("check", help="compare the directory with the baseline once"))
    c.add_argument("--ioc", action="append", default=[], metavar="FILE", help="known-bad SHA-256 list")
    c.add_argument("--critical", action="append", default=[], metavar="GLOB",
                   help="raise severity for matching paths (repeatable)")

    m = common(sub.add_parser("monitor", help="run the monitoring daemon (deliverable 2)"))
    m.add_argument("--interval", "-i", type=float, default=10.0, help="seconds between full scans (default 10)")
    m.add_argument("--no-watchdog", action="store_true", help="interval scans only, no real-time events")
    m.add_argument("--settle", type=float, default=0.75, help="quiet time before rescanning after an event")
    m.add_argument("--heartbeat", type=float, default=60.0,
                   help="seconds between heartbeat entries that re-verify the log (0 = off)")
    m.add_argument("--cycles", type=int, help="stop after this many interval scans")
    m.add_argument("--duration", type=float, help="stop after this many seconds")
    m.add_argument("--fast", action="store_true",
                   help="re-hash only files whose size, times or inode changed (large trees)")
    m.add_argument("--ioc", action="append", default=[], metavar="FILE", help="known-bad SHA-256 list")
    m.add_argument("--critical", action="append", default=[], metavar="GLOB",
                   help="raise severity for matching paths (repeatable)")
    m.add_argument("--pidfile", help="write the daemon's process ID here while it runs")

    v = common(sub.add_parser("verify-log", help="verify every signature and the chain (deliverable 3)"))
    v.add_argument("--json", action="store_true", help="print the result as JSON")
    v.add_argument("--no-anchor", action="store_true", help="skip the truncation check against the database")

    t = common(sub.add_parser("tamper-test", help="attack copies of the log; every attack must be caught"))
    t.add_argument("--out", help=f"results file (default: <state-dir>/{TAMPER_NAME})")

    r = common(sub.add_parser("report", help="write the HTML, PDF and JSON reports"))
    r.add_argument("-o", "--output", default="reports/fim_report", help="output path without extension")
    r.add_argument("--formats", default="html,pdf,json", help="comma-separated: html,pdf,json")
    r.add_argument("--title", help="report title")
    r.add_argument("--manifest", help=f"simulation manifest (default: <state-dir>/{MANIFEST_NAME} if present)")
    r.add_argument("--tamper-results", help=f"tamper-test results (default: <state-dir>/{TAMPER_NAME} if present)")

    ls = common(sub.add_parser("lab-setup", help="create the sample web-server directory to protect"))
    ls.add_argument("--dir", "-d", default="lab_target", help="where to build it (default lab_target)")
    ls.add_argument("--force", action="store_true", help="rebuild it if it already exists")

    s = common(sub.add_parser("simulate", help="act out a malware drop with inert files (deliverable 4)"))
    s.add_argument("--dir", "-d", default="lab_target", help="directory to attack (default lab_target)")
    s.add_argument("--delay", type=float, default=1.5, help="seconds between attacker actions")
    s.add_argument("--manifest", help=f"ground-truth file (default: <state-dir>/{MANIFEST_NAME})")

    d = common(sub.add_parser("demo", help="every step end to end in one command"), state=False)
    d.add_argument("--workdir", default="fim_demo", help="folder for the demo (default fim_demo)")
    d.add_argument("--interval", type=float, default=3.0, help="seconds between full scans (default 3)")
    d.add_argument("--delay", type=float, default=1.0, help="seconds between attacker actions (default 1)")
    d.add_argument("--no-watchdog", action="store_true", help="interval scans only")
    d.add_argument("--formats", default="html,pdf,json", help="report formats")

    common(sub.add_parser("self-test", help="offline checks of the core logic"), state=False)
    return parser


COMMANDS = {
    "baseline": cmd_baseline, "check": cmd_check, "monitor": cmd_monitor, "verify-log": cmd_verify,
    "tamper-test": cmd_tamper, "report": cmd_report, "lab-setup": cmd_lab_setup, "simulate": cmd_simulate,
    "demo": cmd_demo, "self-test": cmd_self_test,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    _prepare_streams()
    args = build_parser().parse_args(argv)
    con = Console(color=want_color(args.color), quiet=args.quiet)
    try:
        return COMMANDS[args.command](args, con)
    except FIMError as exc:
        con.error(str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        con.warn("Interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
