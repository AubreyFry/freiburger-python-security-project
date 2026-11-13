#!/usr/bin/env python3
"""
device_ping.py - Automated Device Ping Utility (CSIT 2033, Week 12, Lab 2)

Pings every address in one or more IPv4 networks, compares the devices that
answer with an organization's list of known devices, and sorts every address
into one of three types:

  AVAILABLE       negative ping - nothing answered; the address appears free
  VALID DEVICE    positive ping - the address belongs to a device in the inventory
  UNKNOWN DEVICE  positive ping - something answered that is NOT in the inventory

Examples
  python device_ping.py --init-inventory known_devices.csv
  python device_ping.py 192.168.1.0/24 -i known_devices.csv
  python device_ping.py 10.0.0.0/24 172.16.0.0/24 192.168.0.0/24 --lab -o report.pdf

--lab sweeps a built-in practice network instead of a real one. On Linux it runs
inside an isolated network namespace where the lab devices answer real ICMP and
no packets leave the machine; where that isn't permitted, replies are simulated
and the output says so.

Needs Python 3.8+ and the system ping command. PDF reports need reportlab
(pip install reportlab). Only sweep networks you own or are authorized to test.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

__version__ = "1.0.0"
TOOL_NAME = "Automated Device Ping Utility"

IPv4Address = ipaddress.IPv4Address
IPv4Network = ipaddress.IPv4Network

# The three address types the lab asks for.
AVAILABLE = "AVAILABLE"         # negative ping
VALID = "VALID DEVICE"          # positive ping, listed in the inventory
UNKNOWN = "UNKNOWN DEVICE"      # positive ping, NOT in the inventory

MODE_LIVE, MODE_LAB_NETNS, MODE_LAB_SIM = "live", "lab-namespace", "lab-simulated"
MODE_TEXT = {
    MODE_LIVE: "LIVE - real ICMP sweep",
    MODE_LAB_NETNS: "LAB - isolated virtual network, real ICMP (Linux namespace)",
    MODE_LAB_SIM: "LAB - simulated replies (no virtual network support here)",
}

DEFAULT_INVENTORY = "known_devices.csv"
LAB_NETWORKS = ("10.0.0.0/24", "172.16.0.0/24", "192.168.0.0/24")
NETNS_CHILD_FLAG = "--_inside-lab-namespace"   # internal: set when re-launched inside the lab namespace
WIDTH = 78
MAX_RANGES_SHOWN = 12

# ------------------------------------------------------------------------------
# Built-in lab organization
# Used by --init-inventory (writes the starter known_devices.csv) and by --lab
# (the practice network). Each entry: ip, device type, hostname, owner, powered on.
# ------------------------------------------------------------------------------
LAB_DEVICES = (
    # 10.0.0.0/24 - headquarters wired LAN
    ("10.0.0.1",      "Router",       "hq-core-rtr01", "IT Infrastructure", True),
    ("10.0.0.2",      "Switch",       "hq-core-sw01",  "IT Infrastructure", True),
    ("10.0.0.3",      "Switch",       "hq-acc-sw02",   "IT Infrastructure", True),
    ("10.0.0.10",     "Server",       "hq-dc01",       "IT Infrastructure", True),
    ("10.0.0.11",     "Server",       "hq-file01",     "IT Infrastructure", True),
    ("10.0.0.12",     "Server",       "hq-db01",       "IT Infrastructure", False),
    ("10.0.0.20",     "Printer",      "hq-prn01",      "Facilities",        True),
    ("10.0.0.101",    "Laptop",       "hq-lt-fin07",   "Finance",           True),
    ("10.0.0.102",    "Laptop",       "hq-lt-hr03",    "Human Resources",   True),
    # 172.16.0.0/24 - corporate Wi-Fi
    ("172.16.0.1",    "Router",       "wifi-gw01",     "IT Infrastructure", True),
    ("172.16.0.10",   "Access Point", "wifi-ap-fl1",   "IT Infrastructure", True),
    ("172.16.0.11",   "Access Point", "wifi-ap-fl2",   "IT Infrastructure", True),
    ("172.16.0.50",   "Mobile Phone", "mp-sales01",    "Sales",             True),
    ("172.16.0.51",   "Mobile Phone", "mp-sales02",    "Sales",             False),
    ("172.16.0.60",   "Tablet",       "tab-ops01",     "Operations",        True),
    ("172.16.0.61",   "Tablet",       "tab-ops02",     "Operations",        True),
    # 192.168.0.0/24 - branch office
    ("192.168.0.1",   "Router",       "br-rtr01",      "Branch Office",     True),
    ("192.168.0.2",   "Switch",       "br-sw01",       "Branch Office",     True),
    ("192.168.0.25",  "Server",       "br-nas01",      "Branch Office",     True),
    ("192.168.0.30",  "IP Camera",    "br-cam01",      "Facilities",        True),
    ("192.168.0.40",  "Laptop",       "br-lt01",       "Branch Office",     True),
    ("192.168.0.41",  "Laptop",       "br-lt02",       "Branch Office",     False),
    ("192.168.0.150", "Mobile Phone", "br-mp01",       "Branch Office",     True),
)
# Plugged into the lab network but missing from the inventory.
LAB_UNLISTED_HOSTS = ("10.0.0.45", "10.0.0.200", "172.16.0.77", "172.16.0.180", "192.168.0.88")


class InputError(Exception):
    """Bad input from the user (exit code 2)."""


class SetupError(Exception):
    """This machine can't run the sweep as requested (exit code 3)."""


class ReportError(Exception):
    """A report file could not be produced."""


# ------------------------------------------------------------------------------
# Console helpers
# ------------------------------------------------------------------------------
class Style:
    """Optional ANSI colors; plain text when disabled."""

    CODES = {"bold": "1", "red": "31", "green": "32", "yellow": "33",
             "blue": "34", "cyan": "36", "gray": "90"}

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, *names: str) -> str:
        if not self.enabled or not names:
            return text
        return "\033[%sm%s\033[0m" % (";".join(self.CODES[n] for n in names), text)


def _enable_windows_vt() -> bool:
    """Turn on ANSI escape processing in the Windows console."""
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


def _use_color(choice: str) -> bool:
    if choice == "never":
        return False
    if choice == "auto" and (os.environ.get("NO_COLOR") or not sys.stdout.isatty()):
        return False
    if os.name == "nt":
        return _enable_windows_vt() or choice == "always"
    return True


def _configure_stdio() -> None:
    # Never crash on characters a Windows console code page can't show, and
    # flush every line so output streams cleanly in Colab and pipes.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace", line_buffering=True)
        except (AttributeError, ValueError):
            pass


def _fit(text: object, width: int) -> str:
    text = str(text)
    return text if len(text) <= width else text[: max(0, width - 3)] + "..."


def _cols(values: Sequence[object], widths: Sequence[int]) -> str:
    return "  ".join(_fit(v, w).ljust(w) for v, w in zip(values, widths)).rstrip()


def _kv(label: str, value: str) -> None:
    lead = (" %-16s: " % label) if label else " " * 19
    lines = textwrap.wrap(value, width=WIDTH - len(lead), break_on_hyphens=False) or [""]
    print(lead + lines[0])
    for line in lines[1:]:
        print(" " * len(lead) + line)


def _plural(n: int, word: str, plural: Optional[str] = None) -> str:
    return "%d %s" % (n, word if n == 1 else (plural or word + "s"))


# ------------------------------------------------------------------------------
# Data model
# ------------------------------------------------------------------------------
@dataclass(frozen=True)
class Device:
    ip: IPv4Address
    device_type: str
    hostname: str = ""
    owner: str = ""


@dataclass
class Probe:
    alive: bool
    rtt_ms: Optional[float] = None
    rtt_below: bool = False          # Windows reports sub-millisecond replies as "<1ms"
    error: Optional[str] = None


@dataclass
class HostResult:
    ip: IPv4Address
    network: IPv4Network
    probe: Probe
    device: Optional[Device]

    @property
    def status(self) -> str:
        if not self.probe.alive:
            return AVAILABLE
        return VALID if self.device else UNKNOWN

    @property
    def rtt_text(self) -> str:
        p = self.probe
        if not p.alive:
            return "-"
        if p.rtt_ms is None:
            return "n/a"
        if p.rtt_below:
            return "<%g ms" % p.rtt_ms
        return ("%.2f ms" % p.rtt_ms) if p.rtt_ms < 100 else ("%.0f ms" % p.rtt_ms)

    @property
    def rtt_csv(self) -> str:
        p = self.probe
        if not p.alive or p.rtt_ms is None:
            return ""
        return ("<%g" % p.rtt_ms) if p.rtt_below else ("%.3f" % p.rtt_ms)

    @property
    def note(self) -> str:
        if self.probe.error:
            return "Probe error: %s" % self.probe.error
        if self.status == UNKNOWN:
            return "Not in inventory - investigate"
        if self.status == AVAILABLE and self.device:
            return "Inventory device did not reply"
        return ""


@dataclass
class SweepReport:
    networks: List[IPv4Network]
    address_count: int
    inventory: Dict[IPv4Address, Device]
    inventory_file: str
    mode: str
    started: datetime
    timeout_ms: int
    retries: int
    workers: int
    host: str
    analyst: str = ""
    results: List[HostResult] = field(default_factory=list)
    elapsed: float = 0.0
    lab_check: Optional[Tuple[int, int]] = None

    def by_status(self, status: str) -> List[HostResult]:
        return [r for r in self.results if r.status == status]

    @property
    def silent_known(self) -> List[HostResult]:
        return [r for r in self.results if r.status == AVAILABLE and r.device]

    @property
    def probe_errors(self) -> List[HostResult]:
        return [r for r in self.results if r.probe.error]


# ------------------------------------------------------------------------------
# Input: networks and the inventory file
# ------------------------------------------------------------------------------
def parse_networks(specs: Sequence[str]) -> Tuple[List[IPv4Network], List[str]]:
    """Parse CIDR strings such as '172.16.0.0/24' (commas or spaces may separate several)."""
    networks: List[IPv4Network] = []
    notes: List[str] = []
    for spec in specs:
        for token in re.split(r"[\s,;]+", spec.strip()):
            if not token:
                continue
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                raise InputError("'%s' is not a valid IPv4 network - use CIDR notation "
                                 "such as 172.16.0.0/24" % token) from None
            if net.version != 4:
                raise InputError("'%s' is an IPv6 network - this tool sweeps IPv4 only" % token)
            try:
                ipaddress.ip_network(token)
            except ValueError:
                notes.append("%s has host bits set - sweeping %s" % (token, net))
            if net not in networks:
                networks.append(net)
    if not networks:
        raise InputError("no network given")
    for i, a in enumerate(networks):
        if any(a.overlaps(b) for b in networks[i + 1:]):
            notes.append("overlapping networks given - each address is swept once")
            break
    return networks, notes


def _host_count(net: IPv4Network) -> int:
    return net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2


def enumerate_targets(networks: Sequence[IPv4Network]) -> List[Tuple[IPv4Address, IPv4Network]]:
    """Every usable host address (network and broadcast addresses skipped), each once."""
    seen: Set[IPv4Address] = set()
    targets: List[Tuple[IPv4Address, IPv4Network]] = []
    for net in networks:
        hosts = iter(net) if net.prefixlen >= 31 else net.hosts()
        for ip in hosts:
            if ip not in seen:
                seen.add(ip)
                targets.append((ip, net))
    targets.sort(key=lambda t: int(t[0]))
    return targets


_HEADER_NAMES = {
    "ip": {"ip_address", "ip", "address", "ipv4", "ipv4_address", "host_ip"},
    "type": {"device_type", "type", "device", "category", "kind"},
    "host": {"hostname", "host", "name", "device_name", "host_name"},
    "owner": {"owner", "department", "dept", "assigned_to", "location", "user"},
}


def _parse_single_ip(raw: str) -> Optional[IPv4Address]:
    try:
        if "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
            return net.network_address if net.version == 4 and net.num_addresses == 1 else None
        return IPv4Address(raw)
    except ValueError:
        return None


def load_inventory(path: str) -> Tuple[Dict[IPv4Address, Device], List[str]]:
    """Read the known-device list: CSV with ip_address and device_type (hostname, owner optional)."""
    if not os.path.isfile(path):
        raise InputError("inventory file '%s' not found - create a starter one with:  "
                         "python device_ping.py --init-inventory %s" % (path, path))
    warnings: List[str] = []
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:   # -sig: tolerate Excel's BOM
            raw_rows = list(csv.reader(fh))
    except UnicodeDecodeError:
        with open(path, newline="", encoding="latin-1") as fh:
            raw_rows = list(csv.reader(fh))
        warnings.append("%s is not UTF-8 - read it as Latin-1" % path)

    rows = [(n, [c.strip() for c in row]) for n, row in enumerate(raw_rows, start=1)
            if any(c.strip() for c in row) and not row[0].strip().startswith("#")]
    if not rows:
        raise InputError("inventory file '%s' is empty" % path)

    cols = {"ip": 0, "type": 1, "host": 2, "owner": 3}
    if _parse_single_ip(rows[0][1][0]) is None:            # first row is a header
        header = [re.sub(r"[\s\-]+", "_", h.lower()) for h in rows[0][1]]
        cols = {}
        for key, names in _HEADER_NAMES.items():
            for idx, name in enumerate(header):
                if name in names:
                    cols[key] = idx
                    break
        if "ip" not in cols or "type" not in cols:
            raise InputError("inventory header must include ip_address and device_type columns "
                             "(found: %s)" % ", ".join(rows[0][1]))
        rows = rows[1:]

    devices: Dict[IPv4Address, Device] = {}
    for line, row in rows:
        def cell(key: str) -> str:
            idx = cols.get(key)
            return row[idx] if idx is not None and idx < len(row) else ""

        ip = _parse_single_ip(cell("ip"))
        if ip is None:
            warnings.append("inventory line %d: '%s' is not a single IPv4 address - skipped"
                            % (line, cell("ip")))
            continue
        if not cell("type"):
            warnings.append("inventory line %d: %s has no device type - skipped" % (line, ip))
            continue
        if ip in devices:
            warnings.append("inventory line %d: duplicate entry for %s - kept the first" % (line, ip))
            continue
        devices[ip] = Device(ip, cell("type"), cell("host"), cell("owner"))

    if not devices:
        raise InputError("inventory file '%s' has no valid devices" % path)
    return devices, warnings


def write_sample_inventory(path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ip_address", "device_type", "hostname", "owner"])
        for ip, device_type, hostname, owner, _powered_on in LAB_DEVICES:
            writer.writerow([ip, device_type, hostname, owner])


# ------------------------------------------------------------------------------
# Probing: the system ping command (or simulated replies in lab mode)
# ------------------------------------------------------------------------------
_TTL_RE = re.compile(r"\bTTL[=:]\s*\d+", re.IGNORECASE)
_RTT_RE = re.compile(r"([=<])\s*(\d+(?:[.,]\d+)?)\s*ms\b", re.IGNORECASE)
_LOCAL_FAILURE_RE = re.compile(r"[^\r\n]*(?:operation not permitted|permission denied|"
                               r"access is denied|transmit failed|general failure)[^\r\n]*", re.IGNORECASE)
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)    # no console flash per ping on Windows


def parse_rtt(output: str) -> Tuple[Optional[float], bool]:
    match = _RTT_RE.search(output)
    if not match:
        return None, False
    return float(match.group(2).replace(",", ".")), match.group(1) == "<"


class Pinger:
    """Sends one ICMP echo request with the operating system's own ping command."""

    def __init__(self, timeout_ms: int):
        self.timeout_ms = timeout_ms
        self.system = platform.system()
        self.path = shutil.which("ping")
        if not self.path:
            hint = ("install it with:  apt-get install -y iputils-ping"
                    if self.system == "Linux" else "make sure ping is on your PATH")
            raise SetupError("the ping command was not found - " + hint)
        self.busybox = os.path.basename(os.path.realpath(self.path)).lower().startswith("busybox")

    def command(self, ip: str) -> List[str]:
        if self.system == "Windows":
            return [self.path, "-n", "1", "-w", str(self.timeout_ms), ip]
        if self.system in ("Darwin", "FreeBSD"):                 # BSD ping: -W is milliseconds
            return [self.path, "-n", "-c", "1", "-W", str(self.timeout_ms), ip]
        seconds = str(max(1, math.ceil(self.timeout_ms / 1000)))  # Linux ping: -W is seconds
        if self.busybox:
            return [self.path, "-c", "1", "-W", seconds, ip]
        return [self.path, "-n", "-c", "1", "-W", seconds, ip]

    def __call__(self, ip: object) -> Probe:
        try:
            proc = subprocess.run(self.command(str(ip)), stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                  timeout=self.timeout_ms / 1000 + 5, creationflags=_NO_WINDOW)
        except subprocess.TimeoutExpired:
            return Probe(False)
        except OSError as exc:
            return Probe(False, error=str(exc))
        output = proc.stdout.decode("utf-8", errors="replace")
        replied = proc.returncode == 0
        if self.system == "Windows":
            # Windows ping exits 0 for "Destination host unreachable" sent by a
            # router, so only a line carrying a TTL proves the host itself replied.
            replied = replied and _TTL_RE.search(output) is not None
        if not replied:
            # "No reply" must mean the network stayed silent. If this machine refused to
            # send the ping (local firewall, permissions), the address's state is unknown.
            failure = _LOCAL_FAILURE_RE.search(output)
            return Probe(False, error=failure.group(0).strip() if failure else None)
        rtt, below = parse_rtt(output)
        return Probe(True, rtt, below)


class SimulatedPinger:
    """Lab fallback: answers from the lab's list of powered-on devices."""

    def __init__(self, live: Set[IPv4Address]):
        self.live = live

    def __call__(self, ip: IPv4Address) -> Probe:
        return Probe(ip in self.live)


def preflight(pinger: Pinger) -> str:
    """Make sure ping works at all, so a broken ping can't report every address as free."""
    probe = pinger("127.0.0.1")
    if not probe.alive:
        raise SetupError("ping could not reach 127.0.0.1, so every address would wrongly show as "
                         "available. Check that ICMP is allowed on this machine. %s"
                         % (probe.error or ""))
    rtt = HostResult(IPv4Address("127.0.0.1"), IPv4Network("127.0.0.0/8"), probe, None).rtt_text
    return "ping 127.0.0.1 OK (%s)" % rtt


def sweep(addresses: Sequence[IPv4Address], prober: Callable[[IPv4Address], Probe],
          workers: int, retries: int) -> Dict[IPv4Address, Probe]:
    """Ping every address in parallel; addresses that stay silent are retried."""
    results: Dict[IPv4Address, Probe] = {}
    pending = list(addresses)
    for _attempt in range(retries + 1):
        if not pending:
            break
        pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(pending))))
        try:
            futures = {pool.submit(prober, ip): ip for ip in pending}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    results[ip] = future.result()
                except Exception as exc:          # a probe must never sink the whole sweep
                    results[ip] = Probe(False, error=str(exc))
        except KeyboardInterrupt:
            try:
                pool.shutdown(wait=False, cancel_futures=True)
            except TypeError:                     # Python < 3.9
                pool.shutdown(wait=False)
            raise
        pool.shutdown(wait=True)
        pending = [ip for ip in pending if not results[ip].alive]
    return results


# ------------------------------------------------------------------------------
# Lab network
# ------------------------------------------------------------------------------
def lab_live_hosts() -> Set[IPv4Address]:
    live = {IPv4Address(ip) for ip, _type, _host, _owner, powered_on in LAB_DEVICES if powered_on}
    live.update(IPv4Address(ip) for ip in LAB_UNLISTED_HOSTS)
    return live


def lab_namespace_launcher() -> Optional[List[str]]:
    """Return an `unshare` prefix that yields an isolated, configurable network
    namespace where ping works - or None if this machine doesn't allow one."""
    if not sys.platform.startswith("linux"):
        return None
    if not all(shutil.which(tool) for tool in ("unshare", "ip", "ping", "sh")):
        return None
    test = ("ip link set dev lo up && ip address add 192.0.2.1/32 dev lo "
            "&& ping -c 1 -W 1 192.0.2.1")
    for prefix in (["unshare", "--net"], ["unshare", "--net", "--user", "--map-root-user"]):
        try:
            proc = subprocess.run(prefix + ["sh", "-c", test], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return prefix
    return None


def _interfaces() -> List[str]:
    with open("/proc/self/net/dev") as fh:                 # per-namespace view
        lines = fh.read().splitlines()[2:]
    return [line.split(":", 1)[0].strip() for line in lines if ":" in line]


def build_lab_namespace(live: Iterable[IPv4Address]) -> None:
    """Bind every powered-on lab device to the loopback of a fresh namespace, so it
    answers real ICMP. Addresses with no device have no route and fail instantly."""
    try:
        interfaces = _interfaces()
    except OSError as exc:
        raise SetupError("cannot read interfaces: %s" % exc) from None
    if interfaces != ["lo"]:
        # Safety: only ever touch a brand-new, empty namespace - never the real host.
        raise SetupError("not inside an empty network namespace (found %s)" % ", ".join(interfaces))
    script = "link set dev lo up\n" + "".join(
        "address add %s/32 dev lo\n" % ip for ip in sorted(live, key=int))
    proc = subprocess.run(["ip", "-batch", "-"], input=script.encode(),
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        raise SetupError(proc.stdout.decode(errors="replace").strip() or "ip command failed")


def lab_self_check(results: Sequence[HostResult], live: Set[IPv4Address],
                   inventory: Dict[IPv4Address, Device]) -> Tuple[int, int]:
    """Compare every classification with the lab's ground truth."""
    correct = 0
    for r in results:
        if r.ip not in live:
            expected = AVAILABLE
        else:
            expected = VALID if r.ip in inventory else UNKNOWN
        correct += r.status == expected
    return correct, len(results)


# ------------------------------------------------------------------------------
# Console report
# ------------------------------------------------------------------------------
def collapse_ranges(ips: Sequence[IPv4Address]) -> List[Tuple[IPv4Address, IPv4Address]]:
    ordered = sorted(ips, key=int)
    if not ordered:
        return []
    ranges = []
    start = prev = ordered[0]
    for ip in ordered[1:]:
        if int(ip) != int(prev) + 1:
            ranges.append((start, prev))
            start = ip
        prev = ip
    ranges.append((start, prev))
    return ranges


def format_range(first: IPv4Address, last: IPv4Address) -> str:
    if first == last:
        return str(first)
    a, b = str(first).split("."), str(last).split(".")
    return "%s-%s" % (first, b[3]) if a[:3] == b[:3] else "%s-%s" % (first, last)


def _coverage_text(rep: SweepReport) -> str:
    parts = []
    for net in rep.networks[:4]:
        parts.append("%s: %d" % (net, sum(1 for ip in rep.inventory if ip in net)))
    if len(rep.networks) > 4:
        parts.append("...")
    outside = sum(1 for ip in rep.inventory if not any(ip in n for n in rep.networks))
    if outside:
        parts.append("outside targets: %d" % outside)
    return " | ".join(parts)


def print_header(rep: SweepReport, style: Style) -> None:
    print(style("=" * WIDTH, "cyan"))
    print(style(" " + TOOL_NAME.upper(), "bold") + style("  v" + __version__, "gray"))
    print(style("=" * WIDTH, "cyan"))
    _kv("Target networks", "%s  (%d addresses)"
        % (", ".join(str(n) for n in rep.networks), rep.address_count))
    _kv("Inventory", "%s - %s" % (rep.inventory_file, _plural(len(rep.inventory), "known device")))
    _kv("", _coverage_text(rep))
    _kv("Probe", "ICMP echo, %d ms timeout, %s, %d workers"
        % (rep.timeout_ms, _plural(rep.retries, "retry", "retries"), rep.workers))
    _kv("Mode", MODE_TEXT[rep.mode])
    _kv("Host", rep.host)
    if rep.analyst:
        _kv("Analyst", rep.analyst)
    _kv("Started", rep.started.strftime("%Y-%m-%d %H:%M:%S %Z").strip())
    print(style("-" * WIDTH, "cyan"))


def _section(title: str, count: int, color: str, style: Style) -> None:
    label = " %s " % title
    print(style("%s%s %d" % (label, "." * max(3, WIDTH - len(label) - len(str(count)) - 1), count),
                "bold", color))


def print_results(rep: SweepReport, style: Style) -> None:
    valid, unknown, avail = rep.by_status(VALID), rep.by_status(UNKNOWN), rep.by_status(AVAILABLE)
    pad = "     "

    print()
    _section("[+] VALID DEVICES - positive ping, in inventory", len(valid), "green", style)
    if valid:
        widths = (15, 15, 18, 10)
        print(pad + style(_cols(("IP ADDRESS", "DEVICE TYPE", "HOSTNAME", "RTT"), widths), "bold"))
        print(pad + _cols(["-" * w for w in widths], widths))
        for r in valid:
            print(pad + _cols((r.ip, r.device.device_type, r.device.hostname or "-", r.rtt_text), widths))
    else:
        print(pad + "(none)")

    print()
    _section("[!] UNKNOWN DEVICES - positive ping, NOT in inventory", len(unknown), "red", style)
    if unknown:
        widths = (15, 18, 10)
        print(pad + style(_cols(("IP ADDRESS", "NETWORK", "RTT"), widths), "bold"))
        print(pad + _cols(["-" * w for w in widths], widths))
        for r in unknown:
            print(pad + style(_cols((r.ip, r.network, r.rtt_text), widths), "red"))
        print(style(pad + "-> Identify each one (MAC address, switch port, DHCP lease). Add it to", "yellow"))
        print(style(pad + "   the inventory if authorized; otherwise isolate and remove it.", "yellow"))
    else:
        print(pad + "(none - every device that answered is in the inventory)")

    print()
    _section("[-] AVAILABLE - negative ping, no reply", len(avail), "blue", style)
    for net in rep.networks:
        ips = [r.ip for r in avail if r.network == net]
        lead = pad + "%-17s%4d free  " % (net, len(ips))
        ranges = collapse_ranges(ips)
        text = ", ".join(format_range(a, b) for a, b in ranges[:MAX_RANGES_SHOWN])
        if len(ranges) > MAX_RANGES_SHOWN:
            text += ", ... (+%d more ranges in the report)" % (len(ranges) - MAX_RANGES_SHOWN)
        lines = textwrap.wrap(text, width=WIDTH - len(lead), break_long_words=False,
                              break_on_hyphens=False) or ["-"]
        print(lead + lines[0])
        for line in lines[1:]:
            print(" " * len(lead) + line)
    silent = rep.silent_known
    if silent:
        print(style(pad + "Inventory devices that did not reply (offline, moved, or blocking ICMP):",
                    "gray"))
        for r in silent:
            print(pad + "  " + _cols((r.ip, r.device.device_type, r.device.hostname or "-"), (15, 15, 18)))


def print_summary(rep: SweepReport, saved: List[Tuple[str, Optional[str]]], style: Style) -> None:
    valid, unknown, avail = rep.by_status(VALID), rep.by_status(UNKNOWN), rep.by_status(AVAILABLE)
    print()
    print(style("=" * WIDTH, "cyan"))
    print(style(" SUMMARY  %d scanned | %d valid | %d unknown | %d available  (%.1f s)"
                % (len(rep.results), len(valid), len(unknown), len(avail), rep.elapsed), "bold"))
    if unknown:
        print(style(" [!] %s answering on the network - investigate before anything else."
                    % _plural(len(unknown), "unknown device"), "red", "bold"))
    else:
        print(style(" [+] No unknown devices - every reply matched the inventory.", "green"))
    if rep.probe_errors:
        print(style(" [!] %s could not run (e.g. %s) - those results are unreliable."
                    % (_plural(len(rep.probe_errors), "probe"), rep.probe_errors[0].probe.error),
                    "yellow"))
    if rep.lab_check:
        ok, total = rep.lab_check
        verdict = style("PASS", "green", "bold") if ok == total else style("FAIL", "red", "bold")
        print(" [*] Lab self-check: %d/%d addresses match the lab's ground truth - %s"
              % (ok, total, verdict))
    for path, error in saved:
        if error:
            print(style(" [x] Report not written - %s: %s" % (path, error), "red"))
        else:
            print(" [*] Report saved: %s" % path)
    print(style("=" * WIDTH, "cyan"))


# ------------------------------------------------------------------------------
# Report files: CSV, JSON, PDF
# ------------------------------------------------------------------------------
def write_csv(rep: SweepReport, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ip_address", "network", "result", "ping", "device_type",
                         "hostname", "owner", "rtt_ms", "note"])
        for r in rep.results:
            d = r.device
            writer.writerow([r.ip, r.network, r.status, "positive" if r.probe.alive else "negative",
                             d.device_type if d else "", d.hostname if d else "",
                             d.owner if d else "", r.rtt_csv, r.note])


def write_json(rep: SweepReport, path: str) -> None:
    data = {
        "tool": TOOL_NAME,
        "version": __version__,
        "generated": rep.started.isoformat(timespec="seconds"),
        "mode": rep.mode,
        "host": rep.host,
        "networks": [str(n) for n in rep.networks],
        "inventory_file": rep.inventory_file,
        "inventory_devices": len(rep.inventory),
        "probe": {"method": "ICMP echo", "timeout_ms": rep.timeout_ms,
                  "retries": rep.retries, "workers": rep.workers},
        "duration_seconds": round(rep.elapsed, 3),
        "summary": {"scanned": len(rep.results), "valid": len(rep.by_status(VALID)),
                    "unknown": len(rep.by_status(UNKNOWN)), "available": len(rep.by_status(AVAILABLE)),
                    "inventory_devices_without_reply": len(rep.silent_known)},
        "lab_self_check": ({"correct": rep.lab_check[0], "total": rep.lab_check[1]}
                           if rep.lab_check else None),
        "results": [{"ip": str(r.ip), "network": str(r.network), "result": r.status,
                     "ping": "positive" if r.probe.alive else "negative", "rtt_ms": r.probe.rtt_ms,
                     "device_type": r.device.device_type if r.device else None,
                     "hostname": r.device.hostname if r.device else None,
                     "owner": r.device.owner if r.device else None,
                     "note": r.note or None} for r in rep.results],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def write_pdf(rep: SweepReport, path: str) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        raise ReportError("PDF reports need reportlab - install it with: pip install reportlab") from None
    from xml.sax.saxutils import escape

    hexes = {"navy": "#1B2A41", "green": "#2E7D32", "red": "#C62828", "slate": "#546E7A",
             "ink": "#1F2328", "muted": "#5F6B7A", "zebra": "#F3F5F8", "grid": "#D8DEE6"}
    c = {name: colors.HexColor(value) for name, value in hexes.items()}

    def style(name: str, **kw: object) -> ParagraphStyle:
        base = {"fontName": "Helvetica", "fontSize": 9, "leading": 12, "textColor": c["ink"]}
        base.update(kw)
        return ParagraphStyle(name, **base)

    st_title = style("title", fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=c["navy"])
    st_sub = style("sub", fontSize=9.5, leading=13, textColor=c["muted"])
    st_h = style("h", fontName="Helvetica-Bold", fontSize=12.5, leading=16, spaceBefore=14, spaceAfter=5)
    st_body = style("body")
    st_note = style("note", fontSize=8.5, leading=11.5, textColor=c["muted"], spaceBefore=4)
    st_cell = style("cell", fontSize=8.5, leading=10.5)
    st_head = style("head", fontName="Helvetica-Bold", fontSize=8.5, leading=10.5, textColor=colors.white)
    st_label = style("label", fontName="Helvetica-Bold", fontSize=8.5, leading=11.5, textColor=c["muted"])
    st_num = style("num", fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=colors.white,
                   alignment=1)
    st_cap = style("cap", fontName="Helvetica-Bold", fontSize=7.5, leading=9, textColor=colors.white,
                   alignment=1)

    def esc(value: object) -> str:
        return escape(str(value))

    def heading(text: str, color: str) -> Paragraph:
        return Paragraph('<font color="%s">%s</font>' % (hexes[color], text), st_h)

    def grid_table(header: Sequence[str], rows: Sequence[Sequence[object]],
                   fractions: Sequence[float], accent: str) -> Table:
        data = [[Paragraph(esc(h), st_head) for h in header]]
        data += [[Paragraph(esc(v), st_cell) for v in row] for row in rows]
        table = Table(data, colWidths=[f * width for f in fractions], repeatRows=1)
        cmds = [("BACKGROUND", (0, 0), (-1, 0), c[accent]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LINEBELOW", (0, 1), (-1, -1), 0.4, c["grid"]),
                ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5)]
        cmds += [("BACKGROUND", (0, i), (-1, i), c["zebra"]) for i in range(2, len(data), 2)]
        table.setStyle(TableStyle(cmds))
        return table

    doc = SimpleDocTemplate(path, pagesize=letter, leftMargin=0.7 * inch, rightMargin=0.7 * inch,
                            topMargin=0.75 * inch, bottomMargin=0.8 * inch,
                            title="Network Device Sweep Report", author=rep.analyst or TOOL_NAME,
                            subject="ICMP sweep compared with the device inventory",
                            creator="device_ping.py %s" % __version__)
    width = doc.width
    valid, unknown, avail = rep.by_status(VALID), rep.by_status(UNKNOWN), rep.by_status(AVAILABLE)
    generated = rep.started.strftime("%Y-%m-%d %H:%M %Z").strip()

    story = [Paragraph("Network Device Sweep Report", st_title),
             Paragraph("%s v%s - ICMP sweep compared with the organization's device inventory"
                       % (TOOL_NAME, __version__), st_sub),
             Spacer(1, 12)]

    details = [("Generated", rep.started.strftime("%Y-%m-%d %H:%M:%S %Z").strip()),
               ("Target networks", ", ".join(str(n) for n in rep.networks)),
               ("Addresses scanned", str(len(rep.results))),
               ("Inventory", "%s (%s)" % (rep.inventory_file, _plural(len(rep.inventory), "device"))),
               ("Probe", "ICMP echo, %d ms timeout, %s, %d parallel workers"
                % (rep.timeout_ms, _plural(rep.retries, "retry", "retries"), rep.workers)),
               ("Mode", MODE_TEXT[rep.mode]),
               ("Sweep duration", "%.1f seconds" % rep.elapsed),
               ("Host", rep.host)]
    if rep.analyst:
        details.insert(1, ("Analyst", rep.analyst))
    detail_table = Table([[Paragraph(esc(k), st_label), Paragraph(esc(v), st_body)] for k, v in details],
                         colWidths=[1.45 * inch, width - 1.45 * inch])
    detail_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                      ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                      ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                                      ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5)]))
    story += [detail_table, Spacer(1, 14)]

    cards = [(len(rep.results), "ADDRESSES SCANNED", "navy"), (len(valid), "VALID DEVICES", "green"),
             (len(unknown), "UNKNOWN DEVICES", "red"), (len(avail), "AVAILABLE", "slate")]
    card_table = Table([[[Paragraph(str(n), st_num), Paragraph(label, st_cap)] for n, label, _ in cards]],
                       colWidths=[width / 4.0] * 4)
    cmds = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]
    cmds += [("BACKGROUND", (i, 0), (i, 0), c[color]) for i, (_, _, color) in enumerate(cards)]
    cmds += [("LINEAFTER", (i, 0), (i, 0), 5, colors.white) for i in range(3)]
    card_table.setStyle(TableStyle(cmds))
    story += [card_table, Spacer(1, 12)]

    if unknown:
        finding = ("<b>%s answered on the network but %s not in the inventory.</b> Treat each one as "
                   "unauthorized until it is identified: trace it by MAC address, switch port and DHCP "
                   "lease, then add it to the inventory or remove it from the network."
                   % (_plural(len(unknown), "unknown device"), "is" if len(unknown) == 1 else "are"))
        accent, tint = "red", "#FDECEA"
    else:
        finding = ("<b>No unknown devices.</b> Every address that answered belongs to a device "
                   "listed in the inventory.")
        accent, tint = "green", "#E8F5E9"
    box = Table([[Paragraph(finding, st_body)]], colWidths=[width])
    box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(tint)),
                             ("LINEBEFORE", (0, 0), (0, -1), 4, c[accent]),
                             ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                             ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story.append(box)

    story.append(heading("1. Unknown devices - positive ping, not in the inventory", "red"))
    if unknown:
        story.append(grid_table(("IP address", "Network", "Ping", "Round trip", "Finding"),
                                [(r.ip, r.network, "Positive", r.rtt_text, "Not in inventory - investigate")
                                 for r in unknown], (0.19, 0.2, 0.13, 0.15, 0.33), "red"))
    else:
        story.append(Paragraph("None - every device that answered is in the inventory.", st_body))

    story.append(heading("2. Valid devices - positive ping, listed in the inventory", "green"))
    if valid:
        story.append(grid_table(("IP address", "Device type", "Hostname", "Owner", "Round trip"),
                                [(r.ip, r.device.device_type, r.device.hostname or "-",
                                  r.device.owner or "-", r.rtt_text) for r in valid],
                                (0.18, 0.19, 0.23, 0.26, 0.14), "green"))
    else:
        story.append(Paragraph("None of the inventory devices answered.", st_body))

    story.append(heading("3. Available addresses - negative ping, no reply", "slate"))
    rows = []
    for net in rep.networks:
        ranges = collapse_ranges([r.ip for r in avail if r.network == net])
        text = ", ".join(format_range(a, b) for a, b in ranges[:150])
        if len(ranges) > 150:
            text += ", ... (+%d more ranges - see the CSV results)" % (len(ranges) - 150)
        rows.append((net, sum(1 for r in avail if r.network == net), text or "-"))
    story.append(grid_table(("Network", "Free", "Address ranges"), rows, (0.2, 0.09, 0.71), "slate"))
    if rep.silent_known:
        story.append(Paragraph("<b>Inventory devices that did not reply.</b> These addresses count as "
                               "available because nothing answered, but each is assigned to a known "
                               "device that may be offline, moved, or blocking ICMP.", st_note))
        story.append(Spacer(1, 4))
        story.append(grid_table(("IP address", "Device type", "Hostname", "Owner"),
                                [(r.ip, r.device.device_type, r.device.hostname or "-", r.device.owner or "-")
                                 for r in rep.silent_known], (0.2, 0.22, 0.26, 0.32), "slate"))

    story.append(heading("4. Method and limitations", "navy"))
    mode_note = {
        MODE_LIVE: "This was a live sweep: every address received real ICMP echo requests.",
        MODE_LAB_NETNS: "This sweep ran against the tool's built-in lab network inside an isolated Linux "
                        "network namespace. Each powered-on lab device was bound to the namespace's own "
                        "loopback interface and answered real ICMP echo requests; no packets left the "
                        "machine.",
        MODE_LAB_SIM: "This sweep ran against the tool's built-in lab network with simulated replies, "
                      "because the runtime does not allow virtual network interfaces. Classification and "
                      "reporting work exactly as in a live sweep.",
    }[rep.mode]
    paragraphs = [
        "<b>Method.</b> Each address received one ICMP echo request (ping) with a %d ms timeout; %s. "
        "Addresses that replied were matched against %s from %s."
        % (rep.timeout_ms, ("addresses that did not answer were tried %s" % _plural(rep.retries, "more time"))
           if rep.retries else "silent addresses were not retried",
           _plural(len(rep.inventory), "known device"), esc(rep.inventory_file)),
        "<b>Classification.</b> No reply = available. A reply from an address in the inventory = "
        "valid device. A reply from any other address = unknown device.",
        "<b>Limitations.</b> A negative ping only means no echo reply came back. Devices that are "
        "powered off, or that block ICMP (Windows PCs with the default firewall settings, for "
        "example), look available. Confirm with ARP tables or DHCP leases before reassigning an address.",
        "<b>Environment.</b> " + mode_note,
        "<b>Authorization.</b> Sweep only networks you own or have written permission to test.",
    ]
    if rep.lab_check:
        ok, total = rep.lab_check
        paragraphs.append("<b>Lab self-check.</b> %d of %d addresses matched the lab's ground truth (%s)."
                          % (ok, total, "PASS" if ok == total else "FAIL"))
    for text in paragraphs:
        story += [Paragraph(text, st_body), Spacer(1, 5)]

    def decorate(canvas, doc_) -> None:
        canvas.saveState()
        canvas.setFillColor(c["navy"])
        canvas.rect(0, letter[1] - 0.16 * inch, letter[0], 0.16 * inch, stroke=0, fill=1)
        canvas.setStrokeColor(c["grid"])
        canvas.setLineWidth(0.5)
        canvas.line(doc_.leftMargin, 0.56 * inch, doc_.leftMargin + doc_.width, 0.56 * inch)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(c["muted"])
        canvas.drawString(doc_.leftMargin, 0.4 * inch, "%s v%s  |  %s  |  Internal use - contains "
                          "network inventory data" % (TOOL_NAME, __version__, generated))
        canvas.drawRightString(doc_.leftMargin + doc_.width, 0.4 * inch, "Page %d" % doc_.page)
        canvas.restoreState()

    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)


REPORT_WRITERS = {".pdf": write_pdf, ".csv": write_csv, ".json": write_json}


def write_reports(rep: SweepReport, paths: Sequence[str]) -> List[Tuple[str, Optional[str]]]:
    saved = []
    for path in paths:
        try:
            REPORT_WRITERS[os.path.splitext(path)[1].lower()](rep, path)
            saved.append((path, None))
        except Exception as exc:
            saved.append((path, str(exc)))
    return saved


# ------------------------------------------------------------------------------
# Command line
# ------------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="device_ping.py",
        description="Ping every address in an IPv4 network and classify each one as AVAILABLE "
                    "(negative ping), VALID DEVICE (positive ping, in the inventory) or "
                    "UNKNOWN DEVICE (positive ping, not in the inventory).",
        epilog="examples:\n"
               "  python device_ping.py --init-inventory known_devices.csv\n"
               "  python device_ping.py 192.168.1.0/24 -i known_devices.csv -o report.pdf\n"
               "  python device_ping.py 10.0.0.0/24 172.16.0.0/24 192.168.0.0/24 --lab\n\n"
               "Only sweep networks you own or are authorized to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("networks", nargs="*", metavar="NETWORK",
                        help="IPv4 network(s) in CIDR notation, e.g. 172.16.0.0/24")
    parser.add_argument("-i", "--inventory", default=DEFAULT_INVENTORY, metavar="FILE",
                        help="CSV of known devices: ip_address, device_type[, hostname, owner] "
                             "(default: %(default)s)")
    parser.add_argument("-o", "--output", action="append", default=[], metavar="FILE",
                        help="write a report; format from the extension: .pdf .csv .json (repeatable)")
    parser.add_argument("-t", "--timeout", type=int, default=1000, metavar="MS",
                        help="wait per ping in milliseconds (default: %(default)s)")
    parser.add_argument("-r", "--retries", type=int, default=1, metavar="N",
                        help="extra pings for addresses that don't answer (default: %(default)s)")
    parser.add_argument("-w", "--workers", type=int, default=64, metavar="N",
                        help="pings in parallel (default: %(default)s)")
    parser.add_argument("--max-hosts", type=int, default=4096, metavar="N",
                        help="refuse sweeps larger than this (default: %(default)s)")
    parser.add_argument("--lab", action="store_true",
                        help="sweep the built-in practice network instead of a real one "
                             "(defaults to the three lab networks)")
    parser.add_argument("--init-inventory", metavar="FILE",
                        help="write the lab organization's device list to FILE (if missing) and exit")
    parser.add_argument("--analyst", default="", metavar="NAME", help="name to show on the reports")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                        help="colored console output (default: %(default)s)")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser


def _validate_args(args: argparse.Namespace) -> None:
    for name, low, high in (("timeout", 100, 60000), ("retries", 0, 5),
                            ("workers", 1, 512), ("max_hosts", 1, 1 << 24)):
        value = getattr(args, name)
        if not low <= value <= high:
            raise InputError("--%s must be between %d and %d" % (name.replace("_", "-"), low, high))
    for path in args.output:
        if os.path.splitext(path)[1].lower() not in REPORT_WRITERS:
            raise InputError("can't write '%s' - report files must end in .pdf, .csv or .json" % path)


def _prompt_for_network() -> str:
    if not sys.stdin.isatty():
        raise InputError("no network given - e.g.  python device_ping.py 192.168.1.0/24 "
                         "-i known_devices.csv   (or add --lab for the practice network)")
    try:
        value = input(" Network to sweep (CIDR, e.g. 192.168.1.0/24): ").strip()
    except EOFError:
        value = ""
    if not value:
        raise InputError("no network given")
    return value


def init_inventory(path: str, style: Style) -> int:
    if os.path.exists(path):
        try:
            count = "%s, " % _plural(len(load_inventory(path)[0]), "device")
        except InputError:
            count = ""
        print(" [*] %s already exists (%sleft unchanged)." % (path, count))
        return 0
    write_sample_inventory(path)
    print(style(" [+] Wrote %s - %d devices across %s" % (path, len(LAB_DEVICES), ", ".join(LAB_NETWORKS)),
                "green"))
    return 0


def run(args: argparse.Namespace, style: Style, in_namespace: bool) -> int:
    _validate_args(args)
    specs = list(args.networks) or (list(LAB_NETWORKS) if args.lab else [_prompt_for_network()])
    networks, notes = parse_networks(specs)
    total = sum(_host_count(n) for n in networks)
    if total > args.max_hosts:
        raise InputError("%d addresses is more than --max-hosts %d - narrow the network or raise "
                         "--max-hosts" % (total, args.max_hosts))
    targets = enumerate_targets(networks)
    inventory, inventory_warnings = load_inventory(args.inventory)
    notes += inventory_warnings

    live: Set[IPv4Address] = set()
    if args.lab:
        live = lab_live_hosts()
        mode = MODE_LAB_SIM
        if in_namespace:
            try:
                build_lab_namespace(live)
                mode = MODE_LAB_NETNS
            except SetupError as exc:
                notes.append("lab namespace setup failed (%s) - using simulated replies" % exc)
    else:
        mode = MODE_LIVE
        public = [str(n) for n in networks if not n.is_private]
        if public:
            notes.append("%s %s not private. Only sweep networks you own or are authorized to test."
                         % (", ".join(public), "is" if len(public) == 1 else "are"))
    prober = SimulatedPinger(live) if mode == MODE_LAB_SIM else Pinger(args.timeout)

    rep = SweepReport(networks=networks, address_count=len(targets), inventory=inventory,
                      inventory_file=args.inventory, mode=mode, started=datetime.now().astimezone(),
                      timeout_ms=args.timeout, retries=args.retries, workers=args.workers,
                      host="%s %s, Python %s" % (platform.system(), platform.release(),
                                                 platform.python_version()),
                      analyst=args.analyst)
    print_header(rep, style)
    for note in notes:
        print(style(" [!] " + note, "yellow"))
    if isinstance(prober, Pinger):
        print(" [*] Preflight: " + preflight(prober))
    if mode == MODE_LAB_NETNS:
        print(" [*] Lab network up: %d devices powered on (no traffic leaves this machine)" % len(live))
    elif mode == MODE_LAB_SIM:
        print(" [*] Lab network up: %d devices powered on (simulated replies)" % len(live))

    sys.stdout.write(" [*] Sweeping %d addresses ... " % len(targets))
    sys.stdout.flush()
    start = time.perf_counter()
    probes = sweep([ip for ip, _ in targets], prober, args.workers, args.retries)
    rep.elapsed = time.perf_counter() - start
    rep.results = [HostResult(ip, net, probes[ip], inventory.get(ip)) for ip, net in targets]
    replied = sum(1 for r in rep.results if r.probe.alive)
    print("done in %.1f s (%d replied, %d silent)" % (rep.elapsed, replied, len(rep.results) - replied))

    if args.lab:
        rep.lab_check = lab_self_check(rep.results, live, inventory)
    print_results(rep, style)
    saved = write_reports(rep, args.output)
    print_summary(rep, saved, style)
    failed = any(error for _, error in saved) or (rep.lab_check and rep.lab_check[0] != rep.lab_check[1])
    return 1 if failed else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    in_namespace = NETNS_CHILD_FLAG in argv
    argv = [a for a in argv if a != NETNS_CHILD_FLAG]
    args = build_parser().parse_args(argv)
    _configure_stdio()
    style = Style(_use_color(args.color))
    try:
        if args.init_inventory:
            return init_inventory(args.init_inventory, style)
        if args.lab and not in_namespace:
            launcher = lab_namespace_launcher()
            if launcher:   # re-run this script inside a private network namespace
                sys.stdout.flush()
                return subprocess.call(launcher + [sys.executable, os.path.abspath(__file__)]
                                       + argv + [NETNS_CHILD_FLAG])
        return run(args, style, in_namespace)
    except InputError as exc:
        print(style(" [x] Input error: %s" % exc, "red", "bold"), file=sys.stderr)
        return 2
    except SetupError as exc:
        print(style(" [x] Setup error: %s" % exc, "red", "bold"), file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\n [x] Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
