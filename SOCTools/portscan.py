#!/usr/bin/env python3
"""
portscan.py — Multi-threaded TCP port scanner with service banner grabbing and
automated exposure reporting.

CSIT 2033 Programming for Cybersecurity

A single-file tool. It discovers listening TCP services, identifies them from
their banners, and writes an assessment report that documents each exposure
with a remediation plan.

AUTHORISED USE ONLY
-------------------
Scan only systems you own or have written permission to test. Unauthorised
port scanning may violate the Computer Fraud and Abuse Act (18 U.S.C. § 1030),
equivalent legislation in other jurisdictions, and the acceptable use policy of
whatever network you are scanning from. Your institution's network is not
implicitly in scope. Practise against systems built for it: the built-in
``--lab`` mode, a virtual machine you created, a container you started, or a
public target that explicitly permits scanning such as ``scanme.nmap.org``.

QUICK START
-----------
    # Terminal 1: start fake services on loopback
    python3 portscan.py --lab

    # Terminal 2: scan them
    python3 portscan.py -t 127.0.0.1 --top-ports --authorize

    # A single host, explicit range, slower and gentler
    python3 portscan.py -t 192.168.56.101 -p 1-1024 --timeout 1.5 -w 100 --authorize

    # A lab subnet, only the ports that matter, with an audit trail
    python3 portscan.py -t 192.168.56.0/24 -p 21,22,23,80,443,3389 \\
        --assessor "J. Student" --scope-note "Lab 4, authorised 2026-09-03" \\
        --authorize

FILE LAYOUT
-----------
    Section 1   Severity model and remediation building blocks
    Section 2   Service knowledge base (ports -> risk and remediation plans)
    Section 3   Scan data model
    Section 4   Target and port specification parsing
    Section 5   Service fingerprinting
    Section 6   Banner grabbing and TLS inspection
    Section 7   The threaded scanner
    Section 8   Exposure analysis (results -> findings)
    Section 9   Report rendering (Markdown, JSON, CSV, console)
    Section 10  Lab target mode (fake loopback services for safe testing)
    Section 11  Command-line interface

DESIGN NOTES
------------
Scan technique
    This is a full TCP *connect* scan: it completes the three-way handshake via
    ``socket.connect_ex`` rather than sending raw SYN packets. Connect scanning
    needs no elevated privileges and no raw-socket support, which makes it
    portable across Windows, macOS, and Linux. The trade-off is that it is
    slower, noisier, and logged by the target application, so it is the correct
    choice for authorised assessment work and the wrong choice for stealth.

Concurrency model
    Port scanning is I/O-bound: each worker spends nearly all of its time
    blocked on a socket, not executing Python bytecode. The Global Interpreter
    Lock is released during blocking socket calls, so a thread pool gives a
    near-linear speed-up here and there is no reason to reach for
    multiprocessing. ``ThreadPoolExecutor`` bounds concurrency, which is what
    keeps the scan from exhausting local file descriptors or overwhelming the
    target.

Port state semantics
    open       The handshake completed.
    closed     The host actively refused the connection (RST / ECONNREFUSED),
               which proves the host is up but nothing is listening.
    filtered   No response before the timeout, or the network returned an
               unreachable error. A packet filter is the usual explanation, but
               a short timeout on a slow path produces the same result, so
               ``filtered`` is a statement about the scan, not about the host.

Dependencies
    None required; the standard library is enough. Installing ``cryptography``
    is optional and adds certificate detail (subject, issuer, expiry, key size,
    signature algorithm) to the TLS findings.

Exit codes
    0  scan completed, no CRITICAL or HIGH findings
    1  scan completed, CRITICAL or HIGH findings present
    2  usage or configuration error
    3  aborted by the operator
"""

from __future__ import annotations

import argparse
import csv
import errno
import io
import ipaddress
import json
import logging
import os
import re
import socket
import socketserver
import ssl
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import (Any, Callable, Dict, Iterable, List, Optional, Sequence,
                    Tuple)

log = logging.getLogger("portscan")

# Optional dependency. Present: full certificate detail. Absent: the scanner
# still records TLS protocol version and cipher, just not certificate fields.
try:  # pragma: no cover - environment dependent
    from cryptography import x509

    _HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTOGRAPHY = False


# ===========================================================================
# SECTION 1 — SEVERITY MODEL AND REMEDIATION BUILDING BLOCKS
# ===========================================================================
#
# The severity scale and the reusable remediation snippets that the
# knowledge base in section 2 is built from.


# ---------------------------------------------------------------------------
# Severity handling
# ---------------------------------------------------------------------------

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

SEVERITY_SLA: Dict[str, str] = {
    "CRITICAL": "Remediate within 24 hours",
    "HIGH": "Remediate within 7 days",
    "MEDIUM": "Remediate within 30 days",
    "LOW": "Remediate within 90 days",
    "INFO": "No action required; document only",
}

_SEVERITY_BY_RANK = {rank: name for name, rank in SEVERITY_ORDER.items()}


def severity_rank(severity: str) -> int:
    """Return a sortable integer for a severity label."""
    return SEVERITY_ORDER.get(severity.upper(), 0)


def escalate(severity: str, steps: int = 1) -> str:
    """Raise a severity label by `steps` levels, capped at CRITICAL."""
    rank = min(severity_rank(severity) + steps, SEVERITY_ORDER["CRITICAL"])
    return _SEVERITY_BY_RANK.get(rank, severity.upper())


def max_severity(*severities: str) -> str:
    """Return the highest of the supplied severity labels."""
    best = "INFO"
    for sev in severities:
        if severity_rank(sev) > severity_rank(best):
            best = sev.upper()
    return best


# ---------------------------------------------------------------------------
# Reusable remediation building blocks
# ---------------------------------------------------------------------------

FIREWALL_STEP = (
    "Restrict inbound access at the network edge and on the host firewall so the "
    "port is reachable only from named administrative subnets or a VPN/bastion "
    "range (default-deny, then allow-list)."
)

DECOMMISSION_STEP = (
    "Confirm with the system owner whether the service is still required. If it is "
    "not, stop and disable the service so it does not return after reboot, then "
    "remove the package."
)

PATCH_STEP = (
    "Bring the software to a vendor-supported release and enrol the host in the "
    "regular patch cycle."
)

MFA_STEP = (
    "Require multi-factor or key-based authentication for all interactive logins "
    "and disable any default, shared, or vendor-supplied accounts."
)

LOGGING_STEP = (
    "Forward authentication and connection logs to the central SIEM and alert on "
    "brute-force patterns and logins from unexpected source ranges."
)

VERIFY_CLOSED = (
    "Re-run this scanner from an untrusted network segment and confirm the port "
    "reports 'filtered' or 'closed' rather than 'open'."
)

VERIFY_TLS = (
    "Re-run this scanner and confirm the banner is only reachable over TLS, then "
    "validate the certificate chain and protocol versions with an external "
    "TLS configuration checker."
)

# Reference labels used across entries.
REF_NIST_800_41 = "NIST SP 800-41 Rev. 1 — Guidelines on Firewalls and Firewall Policy"
REF_NIST_800_123 = "NIST SP 800-123 — Guide to General Server Security"
REF_NIST_800_52 = "NIST SP 800-52 Rev. 2 — Guidelines for TLS Implementations"
REF_CIS = "CIS Benchmarks — platform-specific hardening guidance"
REF_CISA_SMB = "CISA guidance on blocking SMB at network boundaries"
REF_OWASP_ASVS = "OWASP Application Security Verification Standard (ASVS) v4"
REF_NIST_800_45 = "NIST SP 800-45 V2 — Guidelines on Electronic Mail Security"
REF_NIST_800_81 = "NIST SP 800-81-2 — Secure DNS Deployment Guide"
REF_NIST_800_92 = "NIST SP 800-92 — Guide to Computer Security Log Management"
REF_NIST_800_61 = "NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide"


# ===========================================================================
# SECTION 2 — SERVICE KNOWLEDGE BASE
# ===========================================================================
#
# Maps TCP ports and detected products to a risk rating, an impact
# statement, an ordered remediation plan, a verification step, and
# references. This is pure data plus a few lookup helpers, so the reporting
# logic can be reviewed and extended without touching the network code.


# ---------------------------------------------------------------------------
# Port-based knowledge base
# ---------------------------------------------------------------------------
# Each entry: name, severity, issue, impact, remediation[], verification, refs[]

SERVICE_KB: Dict[int, Dict[str, Any]] = {
    20: {
        "name": "FTP data",
        "severity": "HIGH",
        "issue": "FTP data channel is reachable, indicating an active FTP service.",
        "impact": "File contents transfer without encryption and can be read or "
                  "altered by anyone on the network path.",
        "remediation": [DECOMMISSION_STEP,
                        "Migrate transfers to SFTP (over SSH) or FTPS.",
                        FIREWALL_STEP],
        "verification": VERIFY_CLOSED,
        "refs": [REF_NIST_800_123, REF_CIS],
    },
    21: {
        "name": "FTP",
        "severity": "HIGH",
        "issue": "FTP control channel is exposed. FTP authenticates in cleartext.",
        "impact": "Usernames and passwords are recoverable by passive network "
                  "capture. Anonymous FTP may also allow unauthenticated file "
                  "access, and world-writable directories are a common malware "
                  "staging point.",
        "remediation": [
            "Replace FTP with SFTP (OpenSSH subsystem) or FTPS with TLS required "
            "on both the control and data channels.",
            "If FTP must remain, disable anonymous login, disable write access for "
            "anonymous users, and chroot every account to its own directory.",
            FIREWALL_STEP,
            LOGGING_STEP,
        ],
        "verification": "Attempt an anonymous login and a cleartext login from an "
                        "untrusted host; both should fail. Confirm the replacement "
                        "SFTP/FTPS path works for legitimate users.",
        "refs": [REF_NIST_800_123, REF_CIS],
    },
    22: {
        "name": "SSH",
        "severity": "MEDIUM",
        "issue": "SSH is reachable. SSH itself is encrypted, but an internet-facing "
                 "SSH port receives continuous automated credential-guessing traffic.",
        "impact": "Weak or reused passwords lead directly to remote shell access. "
                  "The banner also discloses the exact server version, which "
                  "narrows an attacker's exploit selection.",
        "remediation": [
            FIREWALL_STEP,
            "Set PasswordAuthentication no and PermitRootLogin no in "
            "/etc/ssh/sshd_config; use public-key or certificate authentication.",
            "Deploy fail2ban or equivalent rate limiting on repeated auth failures.",
            "Restrict allowed users/groups with AllowUsers or AllowGroups, and "
            "limit key exchange, cipher, and MAC algorithms to modern suites.",
            LOGGING_STEP,
        ],
        "verification": "Confirm `ssh -o PreferredAuthentications=password` is "
                        "rejected, and re-scan from outside the allow-list to "
                        "confirm the port is filtered.",
        "refs": [REF_CIS, REF_NIST_800_123],
    },
    23: {
        "name": "Telnet",
        "severity": "CRITICAL",
        "issue": "Telnet is exposed. All Telnet traffic, including credentials, is "
                 "transmitted in cleartext with no integrity protection.",
        "impact": "Credentials and full session contents can be captured or "
                  "hijacked by any party on the path. Telnet on network appliances "
                  "and embedded devices is a primary IoT botnet infection vector.",
        "remediation": [
            "Disable the Telnet daemon entirely and remove the package.",
            "Use SSH for all remote administration.",
            "On network hardware or embedded devices, apply the vendor's "
            "configuration to disable the Telnet line and enable SSH with a "
            "generated host key.",
            FIREWALL_STEP,
        ],
        "verification": VERIFY_CLOSED,
        "refs": [REF_NIST_800_123, REF_CIS],
    },
    25: {
        "name": "SMTP",
        "severity": "MEDIUM",
        "issue": "SMTP is reachable from an untrusted network.",
        "impact": "A misconfigured server may act as an open relay and be used to "
                  "send spam or phishing, damaging the organisation's sending "
                  "reputation. Cleartext submission also exposes credentials.",
        "remediation": [
            "Test for and eliminate open relay: reject mail that is neither from an "
            "authenticated user nor addressed to a local domain.",
            "Move user mail submission to port 587 with STARTTLS required and "
            "authentication enforced.",
            "Publish SPF, DKIM, and DMARC records for all sending domains.",
            "Suppress detailed version information in the SMTP greeting banner.",
            FIREWALL_STEP,
        ],
        "verification": "Use an external open-relay test and confirm relay attempts "
                        "are refused; confirm port 587 requires STARTTLS and AUTH.",
        "refs": [REF_NIST_800_45,
                 REF_NIST_800_52],
    },
    53: {
        "name": "DNS",
        "severity": "MEDIUM",
        "issue": "DNS over TCP is reachable.",
        "impact": "An open recursive resolver can be abused for DNS amplification "
                  "attacks against third parties, and unrestricted zone transfers "
                  "leak the internal host inventory.",
        "remediation": [
            "Separate authoritative and recursive roles; allow recursion only for "
            "internal client ranges.",
            "Restrict zone transfers with allow-transfer and TSIG keys.",
            "Enable response rate limiting (RRL) on authoritative servers.",
            PATCH_STEP,
        ],
        "verification": "Attempt `dig @target . NS` recursion and `dig @target "
                        "domain AXFR` from an external host; both should be refused.",
        "refs": [REF_NIST_800_81],
    },
    69: {
        "name": "TFTP",
        "severity": "HIGH",
        "issue": "TFTP is reachable. TFTP has no authentication of any kind.",
        "impact": "Anyone who can reach the port may read or overwrite files in the "
                  "TFTP root, which frequently holds network device configurations "
                  "and firmware images.",
        "remediation": [DECOMMISSION_STEP,
                        "If required for device provisioning, bind it to an isolated "
                        "provisioning VLAN and enable it only during maintenance windows.",
                        FIREWALL_STEP],
        "verification": VERIFY_CLOSED,
        "refs": [REF_NIST_800_123],
    },
    80: {
        "name": "HTTP",
        "severity": "MEDIUM",
        "issue": "Cleartext HTTP is exposed.",
        "impact": "Session cookies, form data, and credentials submitted over HTTP "
                  "can be intercepted or modified in transit. Server banners also "
                  "disclose the software stack and version.",
        "remediation": [
            "Redirect all HTTP traffic to HTTPS with a 301 and serve the "
            "application only over TLS 1.2+.",
            "Enable HTTP Strict Transport Security (HSTS) with a long max-age once "
            "HTTPS is confirmed working.",
            "Suppress version details in the Server header (for example nginx "
            "server_tokens off, or Apache ServerTokens Prod).",
            "Ensure administrative paths and management consoles are not reachable "
            "from the internet.",
            PATCH_STEP,
        ],
        "verification": "Confirm an HTTP request returns a redirect to HTTPS, "
                        "re-scan to confirm the Server header no longer includes a "
                        "version, and check HSTS is present on the HTTPS response.",
        "refs": [REF_OWASP_ASVS, REF_NIST_800_52],
    },
    110: {
        "name": "POP3",
        "severity": "HIGH",
        "issue": "Cleartext POP3 is exposed.",
        "impact": "Mailbox credentials and message contents are recoverable from "
                  "network capture.",
        "remediation": ["Require STARTTLS on 110 or move clients to POP3S on 995.",
                        "Disable plaintext AUTH mechanisms unless the session is "
                        "already TLS-protected.",
                        FIREWALL_STEP],
        "verification": VERIFY_TLS,
        "refs": [REF_NIST_800_52],
    },
    111: {
        "name": "rpcbind / portmapper",
        "severity": "HIGH",
        "issue": "RPC portmapper is exposed, enumerating other RPC services.",
        "impact": "Reveals NFS and other RPC endpoints and their ports, giving an "
                  "attacker a map of further attack surface. Also abusable for "
                  "reflection/amplification traffic.",
        "remediation": [DECOMMISSION_STEP,
                        FIREWALL_STEP,
                        "If NFS is required, restrict exports by host, use NFSv4 "
                        "with Kerberos, and never export with no_root_squash."],
        "verification": "Run `rpcinfo -p target` from an external host and confirm "
                        "the query is refused.",
        "refs": [REF_NIST_800_123],
    },
    135: {
        "name": "MSRPC endpoint mapper",
        "severity": "HIGH",
        "issue": "Windows RPC endpoint mapper is reachable from an untrusted network.",
        "impact": "Enables enumeration of Windows services and has repeatedly been "
                  "the entry point for remote code execution vulnerabilities and "
                  "lateral movement tooling.",
        "remediation": ["Block 135, 137-139, and 445 at all network boundaries.",
                        FIREWALL_STEP,
                        "Enable the Windows Defender Firewall domain/public profiles "
                        "with inbound default-deny.",
                        PATCH_STEP],
        "verification": VERIFY_CLOSED,
        "refs": [REF_CISA_SMB, REF_CIS],
    },
    139: {
        "name": "NetBIOS Session Service",
        "severity": "HIGH",
        "issue": "Legacy NetBIOS session service is exposed.",
        "impact": "Allows share and account enumeration and supports obsolete SMBv1 "
                  "dialects associated with worm propagation.",
        "remediation": ["Block at the network boundary and disable NetBIOS over "
                        "TCP/IP on adapters where it is not required.",
                        "Disable SMBv1 entirely.",
                        FIREWALL_STEP],
        "verification": VERIFY_CLOSED,
        "refs": [REF_CISA_SMB, REF_CIS],
    },
    143: {
        "name": "IMAP",
        "severity": "HIGH",
        "issue": "Cleartext IMAP is exposed.",
        "impact": "Mailbox credentials and message contents are recoverable from "
                  "network capture.",
        "remediation": ["Require STARTTLS on 143 or move clients to IMAPS on 993.",
                        "Disable plaintext AUTH before TLS is established.",
                        MFA_STEP,
                        FIREWALL_STEP],
        "verification": VERIFY_TLS,
        "refs": [REF_NIST_800_52],
    },
    161: {
        "name": "SNMP",
        "severity": "CRITICAL",
        "issue": "SNMP is reachable. SNMP v1/v2c authenticate with a cleartext "
                 "community string, and default strings are widely known.",
        "impact": "Read access discloses interface tables, routes, running "
                  "processes, and sometimes device configuration. Write access "
                  "permits reconfiguration of network equipment.",
        "remediation": [
            "Upgrade to SNMPv3 with authPriv (SHA authentication plus AES privacy).",
            "Remove default community strings such as public and private.",
            "Restrict polling to named management stations at both the ACL and "
            "firewall layers.",
            "Disable SNMP write access unless there is a documented requirement.",
        ],
        "verification": "Confirm v1/v2c queries with default community strings are "
                        "refused and only the SNMPv3 management station can poll.",
        "refs": [REF_NIST_800_123, REF_CIS],
    },
    389: {
        "name": "LDAP",
        "severity": "HIGH",
        "issue": "Cleartext LDAP is exposed.",
        "impact": "Directory bind credentials and query results, including the "
                  "organisation's user inventory, can be captured. Anonymous bind "
                  "may allow unauthenticated directory enumeration.",
        "remediation": ["Require LDAPS (636) or StartTLS and reject simple binds "
                        "over cleartext.",
                        "Disable anonymous bind and restrict directory read scope.",
                        FIREWALL_STEP],
        "verification": "Confirm a cleartext simple bind is rejected and anonymous "
                        "bind returns no data.",
        "refs": [REF_NIST_800_52, REF_CIS],
    },
    443: {
        "name": "HTTPS",
        "severity": "LOW",
        "issue": "HTTPS is exposed. This is normal for a public web service; the "
                 "risk depends on the TLS configuration and the application behind it.",
        "impact": "Weak protocol versions, expired certificates, or an exposed "
                  "administrative interface undermine the transport protection.",
        "remediation": [
            "Disable SSLv3, TLS 1.0, and TLS 1.1; serve TLS 1.2 and 1.3 only with "
            "forward-secret cipher suites.",
            "Maintain valid, non-expired certificates from a trusted CA and automate "
            "renewal.",
            "Suppress software version details in response headers.",
            "Confirm the application itself is in scope of authenticated "
            "application-layer testing; a port scan does not assess it.",
        ],
        "verification": VERIFY_TLS,
        "refs": [REF_NIST_800_52, REF_OWASP_ASVS],
    },
    445: {
        "name": "SMB over TCP",
        "severity": "CRITICAL",
        "issue": "SMB is directly exposed to an untrusted network.",
        "impact": "SMB is one of the most heavily targeted services in existence. "
                  "Exposure enables share enumeration, credential relay attacks, "
                  "ransomware propagation, and has been the vector for multiple "
                  "wormable remote code execution vulnerabilities.",
        "remediation": [
            "Block TCP 445 (and 137-139) inbound at every network boundary without "
            "exception; use a VPN for remote file access.",
            "Disable SMBv1 on all hosts.",
            "Require SMB signing and encryption, and audit share permissions to "
            "remove Everyone/Anonymous access.",
            PATCH_STEP,
            LOGGING_STEP,
        ],
        "verification": VERIFY_CLOSED,
        "refs": [REF_CISA_SMB, REF_CIS],
    },
    465: {
        "name": "SMTPS",
        "severity": "LOW",
        "issue": "Implicit-TLS SMTP submission is exposed.",
        "impact": "Acceptable when TLS and authentication are enforced; a weak TLS "
                  "configuration or unauthenticated relay would be exploitable.",
        "remediation": ["Require authentication for all submissions.",
                        "Enforce TLS 1.2+ and disable legacy ciphers.",
                        "Apply per-account rate limits to contain credential abuse."],
        "verification": VERIFY_TLS,
        "refs": [REF_NIST_800_52],
    },
    514: {
        "name": "syslog / rsh",
        "severity": "HIGH",
        "issue": "Port 514 is open, indicating syslog reception or the legacy rsh "
                 "service.",
        "impact": "Unauthenticated syslog accepts forged log entries, undermining "
                  "the integrity of the audit trail. rsh transmits credentials in "
                  "cleartext and trusts host-based authentication.",
        "remediation": ["Remove rsh/rlogin/rexec entirely; use SSH.",
                        "For log collection, move to TLS-protected syslog (6514) "
                        "with mutual authentication.",
                        FIREWALL_STEP],
        "verification": VERIFY_CLOSED,
        "refs": [REF_NIST_800_92],
    },
    587: {
        "name": "SMTP submission",
        "severity": "LOW",
        "issue": "Mail submission port is exposed.",
        "impact": "Expected for mail clients. Risk arises if STARTTLS is optional "
                  "or authentication is not enforced.",
        "remediation": ["Require STARTTLS before AUTH and reject cleartext "
                        "credentials.",
                        MFA_STEP,
                        "Rate-limit messages per authenticated account."],
        "verification": VERIFY_TLS,
        "refs": [REF_NIST_800_52],
    },
    623: {
        "name": "IPMI / BMC",
        "severity": "CRITICAL",
        "issue": "A baseboard management controller interface is exposed.",
        "impact": "BMCs provide out-of-band power control and console access below "
                  "the operating system. Compromise gives persistent, OS-independent "
                  "control of the server, and BMC firmware is rarely patched.",
        "remediation": ["Move all BMC/IPMI/iDRAC/iLO interfaces onto a dedicated, "
                        "isolated management network with no internet route.",
                        "Replace default credentials and disable cipher suite zero.",
                        PATCH_STEP],
        "verification": VERIFY_CLOSED,
        "refs": [REF_NIST_800_123],
    },
    636: {
        "name": "LDAPS",
        "severity": "LOW",
        "issue": "TLS-protected LDAP is exposed.",
        "impact": "Acceptable internally; directory services should generally not be "
                  "reachable from untrusted networks at all.",
        "remediation": [FIREWALL_STEP,
                        "Disable anonymous bind and enforce TLS 1.2+."],
        "verification": VERIFY_TLS,
        "refs": [REF_NIST_800_52],
    },
    873: {
        "name": "rsync",
        "severity": "CRITICAL",
        "issue": "An rsync daemon is exposed. rsync modules are frequently "
                 "configured without authentication.",
        "impact": "Anonymous listing and retrieval of entire directory trees, "
                  "including backups and configuration files, is a common source of "
                  "mass data exposure.",
        "remediation": ["Set auth users and a secrets file for every module, or run "
                        "rsync over SSH instead of the standalone daemon.",
                        "Set read only = yes and list = no where write access is "
                        "not required.",
                        FIREWALL_STEP],
        "verification": "Run `rsync target::` from an external host and confirm no "
                        "modules are listed without credentials.",
        "refs": [REF_NIST_800_123],
    },
    993: {
        "name": "IMAPS",
        "severity": "LOW",
        "issue": "TLS-protected IMAP is exposed.",
        "impact": "Expected for mail clients. Credential stuffing remains a risk.",
        "remediation": [MFA_STEP,
                        "Enforce TLS 1.2+ and monitor for impossible-travel logins."],
        "verification": VERIFY_TLS,
        "refs": [REF_NIST_800_52],
    },
    995: {
        "name": "POP3S",
        "severity": "LOW",
        "issue": "TLS-protected POP3 is exposed.",
        "impact": "Expected for mail clients. Credential stuffing remains a risk.",
        "remediation": [MFA_STEP, "Enforce TLS 1.2+."],
        "verification": VERIFY_TLS,
        "refs": [REF_NIST_800_52],
    },
    1433: {
        "name": "Microsoft SQL Server",
        "severity": "CRITICAL",
        "issue": "A database engine is directly reachable from an untrusted network.",
        "impact": "Databases should never be internet-facing. Exposure permits "
                  "brute-force against the sa account and direct access to stored "
                  "data if any credential is guessed or leaked.",
        "remediation": [
            "Remove all public exposure; databases should accept connections only "
            "from application subnets.",
            "Disable or rename the sa account and enforce Windows/AAD authentication "
            "with strong password policy.",
            "Require encrypted connections and validate server certificates.",
            "Apply least-privilege database roles to every application account.",
            LOGGING_STEP,
        ],
        "verification": VERIFY_CLOSED,
        "refs": [REF_CIS, REF_NIST_800_123],
    },
    1521: {
        "name": "Oracle TNS listener",
        "severity": "CRITICAL",
        "issue": "An Oracle database listener is reachable from an untrusted network.",
        "impact": "Permits SID enumeration and brute-force against database "
                  "accounts, and older listeners allow remote configuration.",
        "remediation": ["Remove public exposure and restrict to application subnets.",
                        "Set a listener password and enable valid node checking.",
                        "Change all default account passwords.",
                        PATCH_STEP],
        "verification": VERIFY_CLOSED,
        "refs": [REF_CIS],
    },
    2049: {
        "name": "NFS",
        "severity": "CRITICAL",
        "issue": "NFS is reachable from an untrusted network.",
        "impact": "Weak exports allow mounting of remote filesystems and, with "
                  "no_root_squash, direct root-level file manipulation.",
        "remediation": ["Restrict exports to specific hosts and never use "
                        "no_root_squash.",
                        "Move to NFSv4 with Kerberos (sec=krb5p).",
                        FIREWALL_STEP],
        "verification": "Run `showmount -e target` externally and confirm it fails.",
        "refs": [REF_NIST_800_123],
    },
    2375: {
        "name": "Docker Engine API (unencrypted)",
        "severity": "CRITICAL",
        "issue": "The Docker daemon API is exposed without TLS. This API is "
                 "unauthenticated by default.",
        "impact": "Equivalent to unauthenticated root on the host: an attacker can "
                  "start a privileged container that mounts the host filesystem.",
        "remediation": ["Stop exposing the daemon over TCP; use the local Unix "
                        "socket.",
                        "If remote access is genuinely required, enable TLS mutual "
                        "authentication on 2376 and restrict by firewall.",
                        "Audit for containers or images created while the port was "
                        "exposed, and treat the host as potentially compromised."],
        "verification": VERIFY_CLOSED,
        "refs": [REF_CIS],
    },
    3306: {
        "name": "MySQL / MariaDB",
        "severity": "CRITICAL",
        "issue": "A database engine is directly reachable from an untrusted network.",
        "impact": "Exposure permits credential brute-force and direct data access. "
                  "The handshake also discloses the exact server version.",
        "remediation": [
            "Bind the service to localhost or the application subnet only "
            "(bind-address) and remove public firewall exposure.",
            "Remove anonymous accounts and any user defined with host '%'.",
            "Require TLS for remote connections (require_secure_transport=ON).",
            "Grant least-privilege rights per application account.",
            PATCH_STEP,
        ],
        "verification": VERIFY_CLOSED,
        "refs": [REF_CIS, REF_NIST_800_123],
    },
    3389: {
        "name": "RDP",
        "severity": "CRITICAL",
        "issue": "Remote Desktop is exposed to an untrusted network.",
        "impact": "Exposed RDP is one of the most common initial-access vectors for "
                  "ransomware, through both credential guessing and pre-authentication "
                  "vulnerabilities in the protocol stack.",
        "remediation": [
            "Remove direct exposure; require VPN or an RD Gateway with MFA.",
            "Enable Network Level Authentication (NLA) and require TLS.",
            "Enforce account lockout thresholds and strong passwords, and restrict "
            "the Remote Desktop Users group.",
            PATCH_STEP,
            LOGGING_STEP,
        ],
        "verification": VERIFY_CLOSED,
        "refs": [REF_CIS, REF_NIST_800_41],
    },
    3632: {
        "name": "distccd",
        "severity": "CRITICAL",
        "issue": "A distributed compiler daemon is exposed.",
        "impact": "distccd is designed to execute compiler commands supplied by "
                  "clients and has historically permitted arbitrary command "
                  "execution when reachable.",
        "remediation": [DECOMMISSION_STEP,
                        "If required, bind to a trusted build subnet with "
                        "--allow and firewall restrictions."],
        "verification": VERIFY_CLOSED,
        "refs": [REF_NIST_800_123],
    },
    4444: {
        "name": "Unregistered service on 4444",
        "severity": "HIGH",
        "issue": "Port 4444 is open. This port has no standard assignment and is a "
                 "common default for reverse shells and post-exploitation tooling.",
        "impact": "May indicate a legitimate custom application, or may indicate an "
                  "active compromise or unauthorised listener.",
        "remediation": ["Identify the owning process immediately "
                        "(`ss -ltnp` / `netstat -anob`) and confirm it is expected.",
                        "If the process is not accounted for, treat the host as "
                        "potentially compromised and follow the incident response "
                        "process before making changes.",
                        FIREWALL_STEP],
        "verification": "Document the owning process and its business justification, "
                        "then confirm the port is filtered externally.",
        "refs": [REF_NIST_800_61],
    },
    5432: {
        "name": "PostgreSQL",
        "severity": "CRITICAL",
        "issue": "A database engine is directly reachable from an untrusted network.",
        "impact": "Permits credential brute-force and, with a weak pg_hba.conf, "
                  "direct data access.",
        "remediation": [
            "Set listen_addresses to localhost or the application subnet and remove "
            "public firewall exposure.",
            "Review pg_hba.conf: use scram-sha-256, never trust, and scope host "
            "entries to specific CIDRs.",
            "Require TLS (ssl = on) and reject non-TLS remote connections.",
            "Apply least-privilege roles; no application should connect as superuser.",
        ],
        "verification": VERIFY_CLOSED,
        "refs": [REF_CIS],
    },
    5900: {
        "name": "VNC",
        "severity": "CRITICAL",
        "issue": "VNC is exposed. VNC authentication is weak by design and many "
                 "deployments require no password at all.",
        "impact": "Direct interactive control of the desktop session, frequently "
                  "without any authentication. Publicly exposed VNC endpoints are "
                  "continuously indexed and probed.",
        "remediation": ["Remove public exposure; tunnel VNC through SSH or a VPN.",
                        "Set a strong password, or migrate to a remote access tool "
                        "with modern authentication.",
                        "Bind the server to localhost so only tunnelled connections "
                        "succeed."],
        "verification": VERIFY_CLOSED,
        "refs": [REF_NIST_800_41],
    },
    5984: {
        "name": "CouchDB",
        "severity": "CRITICAL",
        "issue": "A CouchDB HTTP interface is exposed.",
        "impact": "Historically shipped in an 'admin party' state allowing "
                  "unauthenticated administrative access and data modification.",
        "remediation": ["Create an admin account and disable anonymous access.",
                        "Bind to localhost or the application subnet.",
                        PATCH_STEP],
        "verification": VERIFY_CLOSED,
        "refs": [REF_NIST_800_123],
    },
    6379: {
        "name": "Redis",
        "severity": "CRITICAL",
        "issue": "Redis is exposed. Redis has no authentication enabled by default.",
        "impact": "Unauthenticated read and write access to all cached data. Write "
                  "access to Redis has well-documented paths to remote code "
                  "execution and host persistence.",
        "remediation": [
            "Bind to 127.0.0.1 and enable protected-mode.",
            "Set a long requirepass value, or configure ACL users on Redis 6+.",
            "Rename or disable administrative commands (CONFIG, FLUSHALL, "
            "SLAVEOF, MODULE) via rename-command.",
            "Audit stored keys and any authorized_keys or cron entries on the host, "
            "since exposed Redis is routinely used to plant them.",
        ],
        "verification": "Run `redis-cli -h target PING` externally and confirm it "
                        "fails or returns NOAUTH.",
        "refs": [REF_NIST_800_123],
    },
    8080: {
        "name": "HTTP alternate / application server",
        "severity": "MEDIUM",
        "issue": "A secondary HTTP service is exposed, often an application server, "
                 "proxy, or management console.",
        "impact": "These ports commonly host administrative interfaces, CI systems, "
                  "or app servers with default credentials and no TLS.",
        "remediation": ["Identify the application and confirm public exposure is "
                        "intended.",
                        "Place it behind the reverse proxy with TLS termination, or "
                        "restrict it to internal ranges.",
                        "Change all default credentials and disable default sample "
                        "or manager applications.",
                        PATCH_STEP],
        "verification": "Confirm the interface requires authentication over TLS and "
                        "re-scan from outside the allow-list.",
        "refs": [REF_OWASP_ASVS, REF_NIST_800_41],
    },
    8443: {
        "name": "HTTPS alternate / management console",
        "severity": "MEDIUM",
        "issue": "A secondary HTTPS service is exposed, frequently a device or "
                 "application management console.",
        "impact": "Management consoles reachable from untrusted networks are a "
                  "high-value target, especially with default credentials or "
                  "self-signed certificates that train users to ignore warnings.",
        "remediation": ["Restrict management interfaces to a management VLAN or VPN.",
                        "Replace default credentials and enable MFA where supported.",
                        "Install a certificate from a trusted CA.",
                        PATCH_STEP],
        "verification": VERIFY_TLS,
        "refs": [REF_NIST_800_41, REF_NIST_800_52],
    },
    9200: {
        "name": "Elasticsearch",
        "severity": "CRITICAL",
        "issue": "An Elasticsearch HTTP API is exposed. Older versions ship without "
                 "authentication.",
        "impact": "Unauthenticated read, write, and delete access to all indexed "
                  "data. Exposed clusters are a leading cause of large-scale data "
                  "leaks and 'ransom note' index wipes.",
        "remediation": [
            "Enable the security features (xpack.security.enabled) and configure "
            "users, roles, and TLS on both HTTP and transport layers.",
            "Bind to a private interface and remove public firewall exposure.",
            "Audit indices for evidence of unauthorised access or deletion.",
            PATCH_STEP,
        ],
        "verification": "Request /_cat/indices externally and confirm a 401 rather "
                        "than data.",
        "refs": [REF_NIST_800_123],
    },
    11211: {
        "name": "Memcached",
        "severity": "CRITICAL",
        "issue": "Memcached is exposed. It has no authentication and its UDP "
                 "counterpart is a severe amplification vector.",
        "impact": "Cached application data, which often includes session tokens, is "
                  "readable and writable by anyone. The service can also be abused "
                  "to launch very large reflected denial-of-service attacks.",
        "remediation": ["Bind to 127.0.0.1 with the -l option and disable UDP "
                        "with -U 0.",
                        "Restrict access to application hosts by firewall.",
                        "Enable SASL authentication if remote access is required."],
        "verification": "Send a `stats` command externally and confirm no response.",
        "refs": [REF_NIST_800_123],
    },
    27017: {
        "name": "MongoDB",
        "severity": "CRITICAL",
        "issue": "MongoDB is exposed. Older default configurations permit "
                 "unauthenticated connections.",
        "impact": "Unauthenticated read and write access to all collections. "
                  "Exposed MongoDB instances are routinely wiped and held for ransom.",
        "remediation": [
            "Enable authorization and create least-privilege users per application.",
            "Set bindIp to private interfaces only and remove public exposure.",
            "Require TLS for client connections.",
            "Audit collections and oplog for signs of unauthorised access.",
        ],
        "verification": VERIFY_CLOSED,
        "refs": [REF_NIST_800_123],
    },
}

# ---------------------------------------------------------------------------
# Cross-cutting classification sets
# ---------------------------------------------------------------------------

#: Protocols that carry credentials or data without transport encryption.
CLEARTEXT_PORTS = {20, 21, 23, 25, 69, 80, 110, 143, 161, 389, 514, 873, 2375,
                   5900, 8080, 11211}

#: Data stores that should never be reachable from an untrusted network.
DATA_STORE_PORTS = {1433, 1521, 3306, 5432, 5984, 6379, 9200, 11211, 27017,
                    9042, 5433, 7000, 8086}

#: Remote administration / management surfaces.
REMOTE_ADMIN_PORTS = {22, 23, 623, 2375, 3389, 5900, 5985, 5986, 8443, 10000}

#: Services that historically ship with no authentication at all.
UNAUTH_BY_DEFAULT_PORTS = {69, 873, 2375, 5984, 6379, 9200, 11211, 27017}

#: Ports commonly used by remote-access tooling and reverse shells.
SUSPICIOUS_PORTS = {1080, 1337, 4444, 4445, 5555, 6666, 6667, 8888, 9001,
                    9999, 31337, 12345, 54321}

#: Compact "top ports" list for the --top-ports convenience flag.
TOP_PORTS: Tuple[int, ...] = (
    21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389,
    443, 445, 464, 465, 514, 587, 623, 631, 636, 873, 902, 993, 995, 1080,
    1099, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 2375, 2376, 2483, 3000,
    3128, 3268, 3306, 3389, 3632, 4444, 4786, 4848, 5000, 5060, 5432, 5601,
    5672, 5900, 5901, 5984, 5985, 5986, 6379, 6443, 6667, 7001, 7077, 8000,
    8008, 8009, 8020, 8080, 8081, 8086, 8088, 8089, 8161, 8443, 8500, 8888,
    9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 10000, 11211, 15672,
    27017, 27018, 28017, 50000, 50070,
)

#: Fallback names for ports that are recognised but have no full KB entry.
EXTRA_PORT_NAMES: Dict[int, str] = {
    88: "Kerberos", 119: "NNTP", 179: "BGP", 427: "SLP", 464: "Kerberos passwd",
    500: "ISAKMP", 548: "AFP", 631: "IPP/CUPS", 902: "VMware auth",
    989: "FTPS data", 990: "FTPS control", 1080: "SOCKS proxy",
    1099: "Java RMI registry", 1723: "PPTP", 2082: "cPanel", 2083: "cPanel SSL",
    2181: "Apache ZooKeeper", 2376: "Docker API (TLS)", 3000: "Dev/app server",
    3128: "Squid proxy", 3268: "LDAP Global Catalog", 4786: "Cisco Smart Install",
    4848: "GlassFish admin", 5000: "Dev/app server", 5060: "SIP",
    5601: "Kibana", 5672: "AMQP/RabbitMQ", 5901: "VNC display 1",
    5985: "WinRM HTTP", 5986: "WinRM HTTPS", 6443: "Kubernetes API",
    6667: "IRC", 7001: "WebLogic", 7077: "Apache Spark",
    8000: "HTTP alternate", 8008: "HTTP alternate", 8009: "AJP13",
    8020: "Hadoop NameNode", 8081: "HTTP alternate", 8086: "InfluxDB",
    8088: "Hadoop/HTTP alternate", 8089: "Splunk management",
    8161: "ActiveMQ console", 8500: "HashiCorp Consul", 8888: "HTTP alternate",
    9000: "SonarQube/PHP-FPM", 9042: "Cassandra CQL", 9090: "Prometheus/admin",
    9092: "Apache Kafka", 9100: "Prometheus node exporter",
    9300: "Elasticsearch transport", 9418: "Git daemon",
    10000: "Webmin", 15672: "RabbitMQ console", 27018: "MongoDB shard",
    28017: "MongoDB HTTP status", 50000: "SAP/DB2", 50070: "Hadoop HDFS UI",
}

# ---------------------------------------------------------------------------
# Product lifecycle heuristics
# ---------------------------------------------------------------------------
# NOTE FOR THE READER: these thresholds are a coarse triage aid, not a
# vulnerability determination. A version below the threshold means "verify this
# against the vendor's supported-release list and the NVD", not "this host is
# exploitable". Do not report a version-based finding as confirmed without
# authenticated verification. Update these values each term; they age quickly.

MIN_TRIAGE_VERSION: Dict[str, str] = {
    "OpenSSH": "8.5",
    "nginx": "1.24",
    "Apache": "2.4.58",
    "Apache httpd": "2.4.58",
    "Microsoft-IIS": "10.0",
    "vsFTPd": "3.0.5",
    "ProFTPD": "1.3.8",
    "Pure-FTPd": "1.0.50",
    "MySQL": "8.0.35",
    "MariaDB": "10.6",
    "PostgreSQL": "13.0",
    "Postfix": "3.7",
    "Exim": "4.97",
    "Dovecot": "2.3.20",
    "Redis": "7.0",
    "MongoDB": "6.0",
    "Elasticsearch": "8.0",
    "Memcached": "1.6.20",
    "OpenSSL": "3.0",
    "PHP": "8.1",
    "Tomcat": "9.0.85",
    "Jetty": "10.0",
    "lighttpd": "1.4.74",
    "Werkzeug": "3.0",
}

_VERSION_TOKEN = re.compile(r"\d+")


def version_tuple(version: str) -> Tuple[int, ...]:
    """
    Convert a loose version string into a comparable tuple of integers.

    Non-numeric suffixes are ignored, so '9.6p1' -> (9, 6, 1) and
    '1.24.0-ubuntu' -> (1, 24, 0). Good enough for coarse triage, and
    deliberately tolerant of the many formats seen in real banners.
    """
    return tuple(int(tok) for tok in _VERSION_TOKEN.findall(version)[:4])


def is_triage_outdated(product: Optional[str], version: Optional[str]) -> bool:
    """True if `version` falls below the triage threshold for `product`."""
    if not product or not version:
        return False
    threshold = MIN_TRIAGE_VERSION.get(product)
    if threshold is None:
        # Try a case-insensitive match before giving up.
        for known, value in MIN_TRIAGE_VERSION.items():
            if known.lower() == product.lower():
                threshold = value
                break
    if threshold is None:
        return False
    observed = version_tuple(version)
    expected = version_tuple(threshold)
    if not observed or not expected:
        return False
    # Compare only the components both versions actually provide.
    width = min(len(observed), len(expected))
    return observed[:width] < expected[:width]


def lookup(port: int) -> Optional[Dict[str, Any]]:
    """Return the knowledge base entry for `port`, if one exists."""
    return SERVICE_KB.get(port)


def service_name(port: int) -> str:
    """Best-effort human-readable name for a port."""
    entry = SERVICE_KB.get(port)
    if entry:
        return str(entry["name"])
    if port in EXTRA_PORT_NAMES:
        return EXTRA_PORT_NAMES[port]
    if port in SUSPICIOUS_PORTS:
        return "Unregistered / commonly abused port"
    return "Unknown"


def generic_entry(port: int) -> Dict[str, Any]:
    """
    Build a finding template for an open port with no specific KB entry.

    An unidentified listener is still an exposure: it is attack surface nobody
    has justified. The remediation plan therefore centres on identification and
    justification rather than a specific hardening step.
    """
    suspicious = port in SUSPICIOUS_PORTS
    return {
        "name": service_name(port),
        "severity": "MEDIUM" if suspicious else "LOW",
        "issue": (
            f"TCP {port} is open but the service could not be positively "
            "identified from its banner."
            + (" This port is commonly used by remote-access tooling."
               if suspicious else "")
        ),
        "impact": "Unidentified listening services are unmanaged attack surface: "
                  "they are not patched on a known schedule, not covered by a "
                  "hardening baseline, and may not be known to the system owner.",
        "remediation": [
            "Identify the owning process and its business justification on the host "
            "(`ss -ltnp` on Linux, `netstat -anob` on Windows).",
            "If the service is not required, stop and disable it, then remove the "
            "software.",
            "If it is required, add it to the asset inventory with a named owner, "
            "a patch schedule, and an authentication requirement.",
            FIREWALL_STEP,
        ],
        "verification": "Record the owning process in the asset inventory and "
                        "re-scan to confirm the port is either justified or filtered.",
        "refs": [REF_NIST_800_123, REF_NIST_800_41],
    }


def all_referenced_standards() -> List[str]:
    """Every distinct reference label used in the knowledge base, sorted."""
    refs = set()
    for entry in SERVICE_KB.values():
        refs.update(entry.get("refs", []))
    refs.update([REF_NIST_800_123, REF_NIST_800_41])
    return sorted(refs)


# ===========================================================================
# SECTION 3 — SCAN DATA MODEL
# ===========================================================================
#
# The dataclasses that carry a scan from configuration through results.


MAX_BANNER_BYTES = 4096
MAX_RECV_ROUNDS = 4

#: Ports that speak TLS immediately on connect (implicit TLS).
TLS_PORTS = frozenset({443, 465, 563, 636, 989, 990, 993, 995, 1443, 2376,
                       4443, 5986, 6443, 6697, 8443, 9443, 9200, 10443})

#: Ports where an HTTP request is the right way to elicit a banner.
HTTP_PORTS = frozenset({80, 81, 88, 443, 591, 2082, 2083, 3000, 4848, 5000,
                        5601, 6443, 7001, 8000, 8008, 8080, 8081, 8086, 8088,
                        8089, 8161, 8443, 8500, 8888, 9000, 9090, 9200, 9300,
                        10000, 15672, 28017, 50070})

#: Ports whose service speaks first; read before writing anything.
PASSIVE_PORTS = frozenset({21, 22, 23, 25, 110, 119, 143, 194, 220, 465, 587,
                           993, 995, 1433, 3306, 5432, 5900, 5901, 6667, 11211,
                           27017})

#: Minimal, read-only application probes. Nothing here changes target state.
_HTTP_PROBE = (
    "GET / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: CSIT2033-portscan/1.0 (authorised assessment)\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n\r\n"
)
_GENERIC_PROBE = b"\r\n"

# ---------------------------------------------------------------------------
# errno classification
# ---------------------------------------------------------------------------

# ``connect_ex`` reports errors using the platform's native numbering, and the
# two families do not overlap: POSIX returns ECONNREFUSED (111 on Linux), while
# Windows returns WinSock codes in the 10000 range (WSAECONNREFUSED = 10061).
# Python does not translate between them, and the WSA* names exist in `errno`
# only on Windows, so both families are listed here by value. Without this, a
# closed port on Windows falls through to the catch-all branch and is reported
# as `filtered`, which would silently misrepresent a live host as firewalled.
_WSAECONNRESET, _WSAETIMEDOUT, _WSAECONNREFUSED = 10054, 10060, 10061
_WSAEACCES, _WSAENETDOWN, _WSAENETUNREACH = 10013, 10050, 10051
_WSAEHOSTDOWN, _WSAEHOSTUNREACH = 10064, 10065


def _errnos(*names: str, extra: Tuple[int, ...] = ()) -> frozenset:
    """Collect errno constants by name, skipping any absent on this platform."""
    codes = set(extra)
    for name in names:
        code = getattr(errno, name, None)
        if code is not None:
            codes.add(code)
    return frozenset(codes)


#: The host actively refused the connection: it is up, nothing is listening.
_CLOSED_ERRNOS = _errnos(
    "ECONNREFUSED", "ECONNRESET",
    extra=(_WSAECONNREFUSED, _WSAECONNRESET))
#: No usable response: a packet filter, a dead host, or a blocked local socket.
_FILTERED_ERRNOS = _errnos(
    "ETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH", "EHOSTDOWN", "ENETDOWN",
    "EACCES", "EPERM",
    extra=(_WSAETIMEDOUT, _WSAEHOSTUNREACH, _WSAENETUNREACH, _WSAEHOSTDOWN,
           _WSAENETDOWN, _WSAEACCES))


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Target:
    """A single resolved scan target."""

    ip: str
    hostname: Optional[str] = None

    @property
    def label(self) -> str:
        return f"{self.hostname} ({self.ip})" if self.hostname else self.ip

    @property
    def family(self) -> int:
        return socket.AF_INET6 if ":" in self.ip else socket.AF_INET


@dataclass
class TlsInfo:
    """TLS metadata captured during the handshake."""

    protocol: Optional[str] = None
    cipher: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_until_expiry: Optional[int] = None
    self_signed: Optional[bool] = None
    san: List[str] = field(default_factory=list)
    key_bits: Optional[int] = None
    signature_algorithm: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v not in (None, [], "")}


@dataclass
class PortResult:
    """The outcome of probing one TCP port on one target."""

    ip: str
    port: int
    state: str                      # open | closed | filtered
    hostname: Optional[str] = None
    latency_ms: Optional[float] = None
    banner: Optional[str] = None
    banner_bytes: int = 0
    probe: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    service: str = "Unknown"
    tls: Optional[TlsInfo] = None
    error: Optional[str] = None

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    @property
    def version_string(self) -> str:
        """Human-readable product/version, or an em dash when unidentified."""
        if self.product and self.version:
            return f"{self.product} {self.version}"
        if self.product:
            return self.product
        return "—"

    @property
    def confirmed_version(self) -> Optional[str]:
        """
        Product plus version, but only when an actual version was parsed.

        A product name with no version is an identification, not a version, and
        reporting it in a "detected version" column is misleading.
        """
        if self.product and self.version:
            return f"{self.product} {self.version}"
        return None

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "ip": self.ip,
            "hostname": self.hostname,
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "latency_ms": self.latency_ms,
            "probe": self.probe,
            "banner": self.banner,
            "banner_bytes": self.banner_bytes,
            "error": self.error,
        }
        if self.tls:
            data["tls"] = self.tls.to_dict()
        return {k: v for k, v in data.items() if v not in (None, "")}


@dataclass
class ScanConfig:
    """All tunable scan parameters, kept in one object for reproducibility."""

    ports: Sequence[int]
    timeout: float = 1.0
    banner_timeout: float = 2.0
    workers: int = 200
    delay: float = 0.0
    grab_banners: bool = True
    tls_probe: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port_count": len(self.ports),
            "port_range": summarize_ports(self.ports),
            "connect_timeout_s": self.timeout,
            "banner_timeout_s": self.banner_timeout,
            "worker_threads": self.workers,
            "inter_connection_delay_s": self.delay,
            "banner_grabbing": self.grab_banners,
            "tls_inspection": self.tls_probe,
        }


@dataclass
class ScanSession:
    """A completed scan: configuration, scope, results, and timing."""

    targets: List[Target]
    config: ScanConfig
    results: List[PortResult]
    started_at: datetime
    finished_at: datetime
    target_specs: List[str] = field(default_factory=list)
    assessor: str = "Unspecified"
    scope_note: str = ""
    errors: List[str] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def open_results(self) -> List[PortResult]:
        return sorted(
            (r for r in self.results if r.is_open),
            key=lambda r: (r.ip, r.port),
        )

    def hosts_with_open_ports(self) -> List[str]:
        return sorted({r.ip for r in self.results if r.is_open})

    def responsive_hosts(self) -> List[str]:
        """Hosts that proved they are up (open or actively closed ports)."""
        return sorted({r.ip for r in self.results if r.state in ("open", "closed")})


# ===========================================================================
# SECTION 4 — TARGET AND PORT SPECIFICATION PARSING
# ===========================================================================
#
# Hostnames, IP literals, CIDR networks, and address ranges in; resolved
# targets out. Malformed input raises rather than being silently dropped:
# a typo in a port range should stop the scan, not quietly change its scope.


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------

class TargetError(ValueError):
    """Raised when a target specification cannot be interpreted."""


_DASH_RANGE = re.compile(r"^(?P<start>[0-9.]+)\s*-\s*(?P<end>[0-9.]+)$")


def parse_target_spec(spec: str, resolve_all: bool = False) -> List[Target]:
    """
    Expand one target specification into a list of :class:`Target` objects.

    Accepted forms
    --------------
    ``example.com``             hostname (resolved via DNS)
    ``192.0.2.10``             single IPv4 or IPv6 address
    ``192.0.2.0/24``           CIDR network
    ``192.0.2.10-192.0.2.40``  explicit start-end range
    ``192.0.2.10-40``          shorthand range on the final octet

    Raises
    ------
    TargetError
        If the specification is malformed or a hostname does not resolve.
    """
    spec = spec.strip()
    if not spec:
        raise TargetError("empty target specification")

    # 1. CIDR notation.
    if "/" in spec:
        try:
            network = ipaddress.ip_network(spec, strict=False)
        except ValueError as exc:
            raise TargetError(f"{spec!r} is not a valid network: {exc}") from exc
        return [Target(ip=str(addr)) for addr in _network_addresses(network)]

    # 2. Explicit or shorthand dash range (IPv4 only).
    match = _DASH_RANGE.match(spec)
    if match:
        return _expand_dash_range(spec, match.group("start"), match.group("end"))

    # 3. Bare IP literal.
    try:
        ipaddress.ip_address(spec)
    except ValueError:
        pass
    else:
        return [Target(ip=spec)]

    # 4. Hostname.
    return _resolve_hostname(spec, resolve_all=resolve_all)


def _network_addresses(network: Any) -> List[Any]:
    """Usable addresses in a network, handling /31 and /32 correctly."""
    if network.num_addresses == 1:
        return [network.network_address]
    if network.prefixlen == network.max_prefixlen - 1:
        return list(network)          # /31 and /127 have no host/broadcast split
    return list(network.hosts())


def _expand_dash_range(spec: str, start_str: str, end_str: str) -> List[Target]:
    """Expand ``a.b.c.d-e.f.g.h`` or ``a.b.c.d-N`` into individual targets."""
    try:
        start = ipaddress.IPv4Address(start_str)
    except ValueError as exc:
        raise TargetError(f"{spec!r}: {start_str!r} is not a valid IPv4 address") from exc

    if "." in end_str:
        try:
            end = ipaddress.IPv4Address(end_str)
        except ValueError as exc:
            raise TargetError(f"{spec!r}: {end_str!r} is not a valid IPv4 address") from exc
    else:
        try:
            last_octet = int(end_str)
        except ValueError as exc:
            raise TargetError(f"{spec!r}: {end_str!r} is not a valid octet") from exc
        if not 0 <= last_octet <= 255:
            raise TargetError(f"{spec!r}: final octet {last_octet} out of range 0-255")
        octets = str(start).split(".")
        end = ipaddress.IPv4Address(".".join(octets[:3] + [str(last_octet)]))

    if int(end) < int(start):
        raise TargetError(f"{spec!r}: range end precedes range start")

    return [Target(ip=str(ipaddress.IPv4Address(value)))
            for value in range(int(start), int(end) + 1)]


def _resolve_hostname(name: str, resolve_all: bool = False) -> List[Target]:
    """Resolve a hostname to one target (default) or all of its addresses."""
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetError(f"could not resolve hostname {name!r}: {exc}") from exc

    seen: List[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)

    if not seen:
        raise TargetError(f"hostname {name!r} resolved to no addresses")

    chosen = seen if resolve_all else seen[:1]
    return [Target(ip=addr, hostname=name) for addr in chosen]


def parse_targets(specs: Iterable[str], resolve_all: bool = False) -> List[Target]:
    """Expand several specifications, preserving order and de-duplicating."""
    targets: List[Target] = []
    seen: set = set()
    for spec in specs:
        for target in parse_target_spec(spec, resolve_all=resolve_all):
            if target.ip in seen:
                continue
            seen.add(target.ip)
            targets.append(target)
    return targets


# ---------------------------------------------------------------------------
# Port parsing
# ---------------------------------------------------------------------------

class PortError(ValueError):
    """Raised when a port specification cannot be interpreted."""


def parse_ports(spec: str) -> List[int]:
    """
    Parse a port specification such as ``22,80,443`` or ``1-1024,8080-8090``.

    Returns a sorted list of unique ports. Raises :class:`PortError` on any
    out-of-range or non-numeric component rather than silently discarding it —
    a typo in the port range should stop the scan, not quietly change its scope.
    """
    ports: set = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            low_str, _, high_str = chunk.partition("-")
            low, high = _port_int(low_str, spec), _port_int(high_str, spec)
            if low > high:
                raise PortError(f"{spec!r}: range {chunk!r} is inverted")
            ports.update(range(low, high + 1))
        else:
            ports.add(_port_int(chunk, spec))

    if not ports:
        raise PortError(f"{spec!r} contained no ports")
    return sorted(ports)


def _port_int(value: str, spec: str) -> int:
    value = value.strip()
    try:
        port = int(value)
    except ValueError as exc:
        raise PortError(f"{spec!r}: {value!r} is not a number") from exc
    if not 1 <= port <= 65535:
        raise PortError(f"{spec!r}: port {port} is outside 1-65535")
    return port


def summarize_ports(ports: Sequence[int]) -> str:
    """Collapse a sorted port list back into compact ``1-1024,8080`` form."""
    if not ports:
        return "none"
    ordered = sorted(set(ports))
    parts: List[str] = []
    start = prev = ordered[0]
    for port in ordered[1:]:
        if port == prev + 1:
            prev = port
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = port
    parts.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(parts)


# ===========================================================================
# SECTION 5 — SERVICE FINGERPRINTING
# ===========================================================================
#
# Regular expressions that extract a product and version from a banner,
# tried most-specific-first.


# ---------------------------------------------------------------------------
# Service fingerprinting
# ---------------------------------------------------------------------------

# Ordered most-specific-first. Each pattern may supply named groups
# ``product``, ``version``, and ``extra``.
_FINGERPRINTS: Tuple[Tuple[str, re.Pattern, Optional[str]], ...] = (
    ("ssh-openssh",
     re.compile(r"SSH-(?P<proto>[\d.]+)-OpenSSH[_-](?P<version>[\w.]+)"
                r"(?:\s+(?P<extra>[^\r\n]+))?", re.I), "OpenSSH"),
    ("ssh-dropbear",
     re.compile(r"SSH-[\d.]+-dropbear[_-]?(?P<version>[\w.]*)", re.I), "Dropbear"),
    ("ssh-generic",
     re.compile(r"SSH-[\d.]+-(?P<product>[A-Za-z][\w.\-]*)[_\- ]?(?P<version>[\d][\w.]*)?"),
     None),
    ("ftp-vsftpd",
     re.compile(r"vsFTPd\s+(?P<version>[\d.]+)", re.I), "vsFTPd"),
    ("ftp-proftpd",
     re.compile(r"ProFTPD\s+(?P<version>[\w.]+)", re.I), "ProFTPD"),
    ("ftp-pureftpd",
     re.compile(r"Pure-FTPd\s*\[?(?P<version>[\d.]+)?", re.I), "Pure-FTPd"),
    ("ftp-filezilla",
     re.compile(r"FileZilla Server(?:\s+version)?\s+(?P<version>[\d.]+)", re.I),
     "FileZilla Server"),
    ("ftp-microsoft",
     re.compile(r"Microsoft FTP Service", re.I), "Microsoft FTP Service"),
    # Note the `[ \t\r]*$`: HTTP headers end with CRLF, and in MULTILINE mode
    # `$` matches immediately before the LF, so the CR must be consumed
    # explicitly or the anchor never matches.
    ("http-server-hdr",
     re.compile(r"^Server:[ \t]*(?P<product>[^/\r\n]+?)(?:/(?P<version>[\w.\-]+))?"
                r"(?:[ \t]+\((?P<extra>[^)\r\n]+)\))?[ \t\r]*$", re.I | re.M), None),
    ("http-powered-by",
     re.compile(r"^X-Powered-By:[ \t]*(?P<product>[^/\r\n]+?)(?:/(?P<version>[\w.\-]+))?"
                r"[ \t\r]*$", re.I | re.M), None),
    ("smtp-postfix",
     re.compile(r"220[^\r\n]*?Postfix(?:\s*\((?P<extra>[^)]+)\))?", re.I), "Postfix"),
    ("smtp-exim",
     re.compile(r"Exim\s+(?P<version>[\d.]+)", re.I), "Exim"),
    ("smtp-sendmail",
     re.compile(r"Sendmail\s+(?P<version>[\w.\-/]+)", re.I), "Sendmail"),
    ("smtp-exchange",
     re.compile(r"Microsoft ESMTP MAIL Service.*?Version:\s*(?P<version>[\d.]+)",
                re.I | re.S), "Microsoft Exchange"),
    ("imap-dovecot",
     re.compile(r"Dovecot(?:\s+(?P<extra>ready|v(?P<version>[\d.]+)))?", re.I),
     "Dovecot"),
    ("imap-courier",
     re.compile(r"Courier-IMAP", re.I), "Courier-IMAP"),
    ("mysql-mariadb",
     re.compile(r"(?P<version>\d+\.\d+\.\d+[\w.\-]*?)-MariaDB[\w.\-]*", re.I),
     "MariaDB"),
    ("redis-info",
     re.compile(r"redis_version:(?P<version>[\d.]+)", re.I), "Redis"),
    ("memcached",
     re.compile(r"^VERSION (?P<version>[\d.]+)", re.I | re.M), "Memcached"),
    ("elasticsearch-json",
     re.compile(r'"number"\s*:\s*"(?P<version>\d+\.\d+\.\d+[\w.\-]*)"'
                r'(?=.*(?:lucene_version|You Know, for Search|build_flavor))',
                re.I | re.S), "Elasticsearch"),
    ("mongodb",
     re.compile(r"MongoDB[^\r\n]*?(?P<version>\d+\.\d+\.\d+)", re.I), "MongoDB"),
    ("postgres",
     re.compile(r"PostgreSQL\s+(?P<version>[\d.]+)", re.I), "PostgreSQL"),
    ("telnet",
     re.compile(r"(?:\xff[\xfb-\xfe].)|(?:login:\s*$)", re.I | re.M),
     "Telnet service"),
    ("vnc",
     re.compile(r"RFB\s+(?P<version>\d{3}\.\d{3})", re.I), "VNC (RFB)"),
    ("irc",
     re.compile(r":(?P<extra>[\w.\-]+)\s+NOTICE\s+", re.I), "IRC"),
    ("smb",
     re.compile(r"SMB|\xffSMB", re.I), "SMB"),
    ("rsync",
     re.compile(r"@RSYNCD:\s*(?P<version>[\d.]+)", re.I), "rsync daemon"),
    ("nntp",
     re.compile(r"^20[01][^\r\n]*?(?P<product>INN|Leafnode)\s+(?P<version>[\w.]+)",
                re.I | re.M), None),
)

_MYSQL_HANDSHAKE = re.compile(
    r"^.{3}\x00\x0a(?P<version>\d+\.\d+\.\d+[\w.\-]*?)\x00", re.S
)


def fingerprint(banner: str, port: int) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Extract ``(product, version, extra_info, matched_rule)`` from a banner.

    Returns ``(None, None, None, None)`` when nothing matches. The caller is
    expected to fall back to the port-based service name, since a service that
    refuses to identify itself is still a service.
    """
    if not banner:
        return None, None, None, None

    # MySQL/MariaDB speak a binary handshake, not text; try it first on 3306.
    if port in (3306, 3307, 33060):
        match = _MYSQL_HANDSHAKE.match(banner)
        if match:
            version = match.group("version")
            product = "MariaDB" if "mariadb" in version.lower() else "MySQL"
            return product, version.split("-")[0], None, "mysql-handshake"

    for rule_name, pattern, product_override in _FINGERPRINTS:
        match = pattern.search(banner)
        if not match:
            continue
        groups = match.groupdict()
        product = product_override or (groups.get("product") or "").strip() or None
        version = (groups.get("version") or "").strip() or None
        extra = (groups.get("extra") or "").strip() or None
        if product or version:
            return product, version, extra, rule_name

    return None, None, None, None


def _merge_service_label(port_name: str, product: str) -> str:
    """
    Combine the port-based service name with the fingerprinted product.

    The fingerprint is the better evidence, but it should add information
    rather than repeat it: port 6379 with product "Redis" should read "Redis",
    not "Redis (Redis)". Only genuinely new detail earns the parenthetical.
    """
    if port_name in ("Unknown", ""):
        return product

    def normalise(text: str) -> str:
        return re.sub(r"[^a-z0-9]", "", text.lower())

    left, right = normalise(port_name), normalise(product)
    # Prefix matching, not plain substring matching: 'ftp' is a substring of
    # 'vsftpd' but "FTP (vsFTPd)" is still the more useful label, whereas
    # 'redis'/'redis' and 'vnc'/'vncrfb' genuinely are the same name.
    if left == right or left.startswith(right) or right.startswith(left):
        return port_name if len(port_name) >= len(product) else product
    return f"{port_name} ({product})"


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def sanitize_banner(raw: bytes, limit: int = 512) -> str:
    """
    Convert raw banner bytes into something safe to embed in a report.

    Banner content is attacker-controlled. Escaping control characters here
    prevents a hostile banner from injecting ANSI sequences into a terminal or
    breaking the structure of the generated Markdown.
    """
    text = raw.decode("utf-8", errors="replace")
    text = _CONTROL_CHARS.sub(lambda m: f"\\x{ord(m.group()):02x}", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    text = re.sub(r"\n{3,}", "\n\n", text)
    if len(text) > limit:
        text = text[:limit].rstrip() + " …[truncated]"
    return text


# ===========================================================================
# SECTION 6 — BANNER GRABBING AND TLS INSPECTION
# ===========================================================================
#
# All probes here are read-only. Nothing authenticates, writes, or
# modifies target state.


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

def _tls_context() -> ssl.SSLContext:
    """
    A deliberately permissive client context.

    The goal is to *observe* the server's TLS configuration, including weak or
    expired setups, so certificate validation must be disabled. This is correct
    for a scanner and would be a serious defect in an application client.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:  # pragma: no cover - depends on OpenSSL build
        pass
    try:
        ctx.minimum_version = ssl.TLSVersion.SSLv3
    except (ValueError, AttributeError):  # pragma: no cover
        pass
    return ctx


def _name_to_str(name: Any) -> str:
    """Render an x509 Name as a compact, human-readable string."""
    try:
        return ", ".join(f"{attr.rfc4514_attribute_name}={attr.value}"
                         for attr in name)
    except Exception:  # pragma: no cover - defensive
        return str(name)


def _inspect_certificate(der: bytes, info: TlsInfo) -> None:
    """Populate certificate fields on `info` from a DER-encoded certificate."""
    if not _HAVE_CRYPTOGRAPHY:
        info.error = "certificate detail unavailable (cryptography not installed)"
        return
    try:
        cert = x509.load_der_x509_certificate(der)
        info.subject = _name_to_str(cert.subject)
        info.issuer = _name_to_str(cert.issuer)
        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        info.not_before = not_before.isoformat()
        info.not_after = not_after.isoformat()
        info.days_until_expiry = (not_after - datetime.now(timezone.utc)).days
        info.self_signed = cert.subject == cert.issuer
        try:
            info.signature_algorithm = cert.signature_algorithm_oid._name
        except Exception:
            info.signature_algorithm = None
        try:
            info.key_bits = cert.public_key().key_size
        except Exception:
            info.key_bits = None
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info.san = [str(v) for v in ext.value.get_values_for_type(x509.DNSName)][:12]
        except x509.ExtensionNotFound:
            info.san = []
    except Exception as exc:  # pragma: no cover - malformed certs happen
        info.error = f"certificate parse failed: {exc.__class__.__name__}"


def _open(target: Target, port: int, timeout: float) -> socket.socket:
    """Open a connected TCP socket, raising OSError on failure."""
    sock = socket.socket(target.family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((target.ip, port))
    return sock


def _read_banner(sock: socket.socket, timeout: float,
                 limit: int = MAX_BANNER_BYTES) -> bytes:
    """Read up to `limit` bytes, tolerating a service that says nothing."""
    sock.settimeout(timeout)
    chunks: List[bytes] = []
    total = 0
    for _ in range(MAX_RECV_ROUNDS):
        try:
            data = sock.recv(min(2048, limit - total))
        except (socket.timeout, TimeoutError):
            break
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
        total += len(data)
        if total >= limit:
            break
        joined = b"".join(chunks)
        # Stop once we have a complete header block or a terminated greeting.
        if b"\r\n\r\n" in joined or b"\n\n" in joined:
            break
        if joined.endswith((b"\r\n", b"\n")) and total < 2048:
            break
    return b"".join(chunks)


def grab_banner(target: Target, port: int, timeout: float,
                tls_probe: bool = True) -> Tuple[bytes, Optional[str], Optional[TlsInfo]]:
    """
    Open a fresh connection and collect a service banner.

    A separate connection is used from the one that determined port state, so
    that a slow banner read cannot distort the recorded connect latency.

    Probe order
    -----------
    1. Wrap in TLS if the port is an implicit-TLS port.
    2. Read passively — most classic protocols greet the client first.
    3. If nothing arrived and the port looks like HTTP, send a GET.
    4. Otherwise send a bare CRLF to nudge a line-oriented service.

    All probes are read-only. Nothing here writes, deletes, or authenticates.

    Returns ``(raw_bytes, probe_name, tls_info)``.
    """
    tls_info: Optional[TlsInfo] = None
    probe_used: Optional[str] = None
    raw = b""
    sock: Optional[socket.socket] = None

    try:
        sock = _open(target, port, timeout)

        if tls_probe and port in TLS_PORTS:
            tls_info = TlsInfo()
            try:
                wrapped = _tls_context().wrap_socket(
                    sock, server_hostname=target.hostname or None)
                sock = wrapped
                tls_info.protocol = wrapped.version()
                cipher = wrapped.cipher()
                tls_info.cipher = cipher[0] if cipher else None
                der = wrapped.getpeercert(binary_form=True)
                if der:
                    _inspect_certificate(der, tls_info)
                probe_used = "tls-handshake"
            except (ssl.SSLError, OSError) as exc:
                tls_info.error = f"{exc.__class__.__name__}: {exc}"
                # Not a TLS service after all. The failed handshake leaves this
                # socket unusable — the server has already seen a ClientHello
                # and has either replied with an error or hung up — so it must
                # be discarded and replaced before probing in cleartext.
                # Elasticsearch on 9200 is the common case: TLS in 8.x, plain
                # HTTP in earlier versions.
                try:
                    sock.close()
                except OSError:
                    pass
                sock = _open(target, port, timeout)

        if port in PASSIVE_PORTS or probe_used is None:
            raw = _read_banner(sock, timeout)
            if raw:
                probe_used = probe_used or "passive-read"

        if not raw and port in HTTP_PORTS:
            request = _HTTP_PROBE.format(host=target.hostname or target.ip)
            try:
                sock.sendall(request.encode("ascii", errors="ignore"))
                raw = _read_banner(sock, timeout)
                if raw:
                    probe_used = "http-get"
            except OSError:
                pass

        if not raw:
            try:
                sock.sendall(_GENERIC_PROBE)
                raw = _read_banner(sock, timeout)
                if raw:
                    probe_used = "generic-crlf"
            except OSError:
                pass

    except (socket.timeout, TimeoutError):
        probe_used = probe_used or "timeout"
    except OSError as exc:
        log.debug("banner grab failed on %s:%s — %s", target.ip, port, exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    return raw, probe_used, tls_info


# ===========================================================================
# SECTION 7 — THE THREADED SCANNER
# ===========================================================================
#
# Bounded-concurrency TCP connect scanning.


# ---------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------

class TcpScanner:
    """
    A bounded-concurrency TCP connect scanner.

    Example
    -------
    >>> cfg = ScanConfig(ports=[22, 80, 443], timeout=0.5, workers=16)
    >>> scanner = TcpScanner(cfg)
    >>> session = scanner.scan(parse_targets(["127.0.0.1"]))   # doctest: +SKIP
    """

    def __init__(self, config: ScanConfig,
                 progress: Optional[Callable[[int, int], None]] = None) -> None:
        self.config = config
        self._progress = progress
        self._lock = threading.Lock()
        self._completed = 0
        self._errors: List[str] = []

    # -- single port ------------------------------------------------------

    def probe(self, target: Target, port: int) -> PortResult:
        """Probe one port and, if it is open, attempt a banner grab."""
        if self.config.delay:
            time.sleep(self.config.delay)

        result = PortResult(ip=target.ip, port=port, hostname=target.hostname,
                            state="filtered")
        sock = socket.socket(target.family, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout)
        start = time.perf_counter()

        try:
            code = sock.connect_ex((target.ip, port))
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            if code == 0:
                result.state = "open"
                result.latency_ms = round(elapsed_ms, 2)
            elif code in _CLOSED_ERRNOS:
                result.state = "closed"
                result.latency_ms = round(elapsed_ms, 2)
            elif code in _FILTERED_ERRNOS:
                result.state = "filtered"
                result.error = errno.errorcode.get(code, str(code))
            else:
                result.state = "filtered"
                result.error = errno.errorcode.get(code, str(code))
        except (socket.timeout, TimeoutError):
            result.state = "filtered"
            result.error = "timeout"
        except OSError as exc:
            result.state = "filtered"
            result.error = f"{exc.__class__.__name__}: {exc}"
        finally:
            try:
                sock.close()
            except OSError:
                pass

        if result.state == "open":
            result.service = service_name(port)
            if self.config.grab_banners:
                self._enrich(target, result)

        return result

    def _enrich(self, target: Target, result: PortResult) -> None:
        """Attach banner, fingerprint, and TLS metadata to an open-port result."""
        raw, probe_used, tls_info = grab_banner(
            target, result.port, self.config.banner_timeout,
            tls_probe=self.config.tls_probe)
        result.probe = probe_used
        result.tls = tls_info
        result.banner_bytes = len(raw)

        if not raw:
            return

        banner_text = sanitize_banner(raw)
        result.banner = banner_text
        product, version, extra, rule = fingerprint(
            raw.decode("utf-8", errors="replace"), result.port)
        result.product = product
        result.version = version
        result.extra_info = extra
        if rule:
            result.probe = f"{probe_used or 'unknown'}/{rule}"
        if product:
            result.service = _merge_service_label(
                service_name(result.port), product)

    # -- full scan --------------------------------------------------------

    def scan(self, targets: Sequence[Target], target_specs: Optional[List[str]] = None,
             assessor: str = "Unspecified", scope_note: str = "") -> ScanSession:
        """Scan every configured port on every target and return a session."""
        started = datetime.now(timezone.utc)
        total = len(targets) * len(self.config.ports)
        results: List[PortResult] = []
        self._completed = 0

        log.info("Scanning %d host(s) x %d port(s) = %d probes with %d threads",
                 len(targets), len(self.config.ports), total, self.config.workers)

        workers = max(1, min(self.config.workers, max(1, total)))
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix="scan") as pool:
            futures = {
                pool.submit(self.probe, target, port): (target, port)
                for target in targets
                for port in self.config.ports
            }
            for future in as_completed(futures):
                target, port = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:  # pragma: no cover - defensive
                    message = f"{target.ip}:{port} probe raised {exc!r}"
                    self._errors.append(message)
                    log.warning(message)
                    results.append(PortResult(ip=target.ip, port=port,
                                              hostname=target.hostname,
                                              state="filtered",
                                              error=str(exc)))
                with self._lock:
                    self._completed += 1
                    if self._progress:
                        self._progress(self._completed, total)

        finished = datetime.now(timezone.utc)
        results.sort(key=lambda r: (r.ip, r.port))
        return ScanSession(
            targets=list(targets),
            config=self.config,
            results=results,
            started_at=started,
            finished_at=finished,
            target_specs=target_specs or [],
            assessor=assessor,
            scope_note=scope_note,
            errors=list(self._errors),
        )


# ===========================================================================
# SECTION 8 — EXPOSURE ANALYSIS
# ===========================================================================
#
# The scanner answers 'what is listening?'. This section answers the two
# questions that matter to a system owner: 'why does that matter?' and
# 'what exactly do I change?'.
#
# Pass 1 produces one finding per open port, seeded from the knowledge base
# and then escalated by cross-cutting rules. Pass 2 derives findings from
# banner *content*: end-of-life software, TLS problems, version disclosure.


REPORT_TOOL = "CSIT 2033 portscan"
REPORT_VERSION = "1.0"

#: TLS protocol versions that should no longer be offered.
DEPRECATED_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

#: Certificate signature algorithms that no longer provide collision resistance.
WEAK_SIG_ALGS = {"md5WithRSAEncryption", "sha1WithRSAEncryption",
                 "md5", "sha1", "ecdsa-with-SHA1", "dsa-with-sha1"}

MIN_RSA_BITS = 2048
CERT_EXPIRY_WARN_DAYS = 30


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One documented exposure with its remediation plan."""

    finding_id: str
    severity: str
    title: str
    ip: str
    port: int
    hostname: Optional[str] = None
    service: str = "Unknown"
    detected_version: Optional[str] = None
    category: str = "Service exposure"
    issue: str = ""
    impact: str = ""
    evidence: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    verification: str = ""
    references: List[str] = field(default_factory=list)
    escalation_notes: List[str] = field(default_factory=list)
    confidence: str = "Confirmed"
    #: Short phrase for the roadmap table. Falls back to the first
    #: remediation step, which is usually but not always the headline action.
    primary_action: Optional[str] = None

    @property
    def asset(self) -> str:
        return f"{self.hostname} ({self.ip})" if self.hostname else self.ip

    @property
    def sla(self) -> str:
        return SEVERITY_SLA.get(self.severity, "Prioritise per policy")

    @property
    def rank(self) -> int:
        return severity_rank(self.severity)

    @property
    def headline_action(self) -> str:
        """The one-line action shown in the remediation roadmap."""
        if self.primary_action:
            return self.primary_action
        return self.remediation[0] if self.remediation else "See finding detail"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "title": self.title,
            "category": self.category,
            "asset": {"ip": self.ip, "hostname": self.hostname, "port": self.port},
            "service": self.service,
            "detected_version": self.detected_version,
            "confidence": self.confidence,
            "issue": self.issue,
            "impact": self.impact,
            "evidence": self.evidence,
            "remediation_plan": self.remediation,
            "verification": self.verification,
            "remediation_window": self.sla,
            "escalation_notes": self.escalation_notes,
            "references": self.references,
        }


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

class ExposureAnalyzer:
    """Turns :class:`PortResult` objects into :class:`Finding` objects."""

    def __init__(self, session: ScanSession) -> None:
        self.session = session
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"F-{self._counter:03d}"

    def analyze(self) -> List[Finding]:
        findings: List[Finding] = []
        for result in self.session.open_results:
            findings.append(self._service_finding(result))
            findings.extend(self._derived_findings(result))
        findings.extend(self._host_findings())

        # Highest severity first, then by host and port for a stable order.
        findings.sort(key=lambda f: (-f.rank, f.ip, f.port, f.finding_id))
        # Re-number after sorting so IDs read in priority order in the report.
        for index, finding in enumerate(findings, start=1):
            finding.finding_id = f"F-{index:03d}"
        return findings

    # -- pass 1: one finding per open port --------------------------------

    def _service_finding(self, result: PortResult) -> Finding:
        entry = lookup(result.port) or generic_entry(result.port)
        severity = str(entry["severity"])
        notes: List[str] = []

        if result.port in UNAUTH_BY_DEFAULT_PORTS:
            if severity_rank(severity) < severity_rank("CRITICAL"):
                notes.append("Escalated: service ships with no authentication by default.")
            severity = "CRITICAL"
        if result.port in DATA_STORE_PORTS:
            if severity_rank(severity) < severity_rank("HIGH"):
                notes.append("Escalated: data stores should never be reachable from "
                             "an untrusted network.")
                severity = "HIGH"
        if result.port in CLEARTEXT_PORTS and \
                severity_rank(severity) < severity_rank("HIGH"):
            notes.append("Escalated: protocol carries credentials or data without "
                         "transport encryption.")
            severity = escalate(severity)
        if result.port in SUSPICIOUS_PORTS and \
                severity_rank(severity) < severity_rank("HIGH"):
            notes.append("Escalated: port is commonly used by remote-access tooling; "
                         "verify the owning process before assuming it is benign.")
            severity = escalate(severity)
        if result.port in REMOTE_ADMIN_PORTS:
            notes.append("Administrative surface: successful authentication here "
                         "yields interactive or privileged control of the host.")

        evidence: List[str] = [
            f"TCP {result.port} responded to a full connect handshake"
            + (f" in {result.latency_ms:.0f} ms." if result.latency_ms else ".")
        ]
        if result.product:
            evidence.append(f"Banner fingerprint identified {result.version_string}.")
        if result.banner:
            evidence.append(f"Banner ({result.banner_bytes} bytes) captured via "
                            f"{result.probe or 'unknown probe'}.")
        elif result.probe:
            evidence.append(f"No banner returned (probe: {result.probe}).")
        if result.tls and result.tls.protocol:
            evidence.append(f"TLS handshake succeeded using {result.tls.protocol}"
                            + (f" / {result.tls.cipher}." if result.tls.cipher else "."))

        service_label = result.service if result.service != "Unknown" else str(entry["name"])
        title = f"{service_label} exposed on TCP {result.port}"

        return Finding(
            finding_id=self._next_id(),
            severity=severity,
            title=title,
            ip=result.ip,
            port=result.port,
            hostname=result.hostname,
            service=service_label,
            detected_version=result.confirmed_version,
            category="Service exposure",
            issue=str(entry["issue"]),
            impact=str(entry["impact"]),
            evidence=evidence,
            remediation=list(entry["remediation"]),
            verification=str(entry["verification"]),
            references=list(entry.get("refs", [])),
            escalation_notes=notes,
            confidence="Confirmed" if result.banner or result.product else "Port confirmed open",
        )

    # -- pass 2: findings derived from banner content ----------------------

    def _derived_findings(self, result: PortResult) -> List[Finding]:
        findings: List[Finding] = []

        if is_triage_outdated(result.product, result.version):
            threshold = MIN_TRIAGE_VERSION.get(result.product or "", "current")
            findings.append(Finding(
                finding_id=self._next_id(),
                severity="HIGH",
                title=f"{result.version_string} predates the current supported "
                      f"release baseline",
                ip=result.ip, port=result.port, hostname=result.hostname,
                service=result.service,
                detected_version=result.version_string,
                category="Patch management",
                confidence="Requires verification",
                primary_action=f"Verify the running version on the host, then "
                               f"upgrade {result.product} to a vendor-supported "
                               f"release.",
                issue=f"The banner advertises {result.version_string}, which is below "
                      f"the triage baseline of {result.product} {threshold} used by "
                      f"this assessment.",
                impact="Software behind the vendor's supported release line stops "
                       "receiving security fixes, so known vulnerabilities accumulate "
                       "with no remediation path other than upgrading. Publicly "
                       "advertised versions also let an attacker skip reconnaissance "
                       "and select known issues directly.",
                evidence=[f"Service banner reported {result.version_string}.",
                          f"Assessment triage baseline for {result.product} is "
                          f"{threshold}."],
                remediation=[
                    "Confirm the running version on the host itself; banners can be "
                    "stale, deliberately falsified, or reflect a backported "
                    "distribution build that is in fact patched.",
                    "Check the version against the vendor's supported-release list "
                    "and the NVD, and record the applicable advisories.",
                    "Schedule the upgrade through change management, testing in a "
                    "non-production environment first.",
                    "Enrol the host in the standing patch cycle so the gap does not "
                    "reopen, and add the service to the monthly vulnerability scan "
                    "scope.",
                ],
                verification="Re-scan and confirm the banner reports a supported "
                             "version, and confirm the authenticated vulnerability "
                             "scan no longer flags the host.",
                references=["Vendor security advisories for the affected product",
                            "NVD — https://nvd.nist.gov/",
                            REF_NIST_800_123],
                escalation_notes=[
                    "Version-based only. This finding is a triage signal from a "
                    "banner, not a confirmed vulnerability; it must be validated "
                    "against the host before it is reported as exploitable."
                ],
            ))

        if result.banner and result.version and result.port in (21, 22, 25, 80, 110,
                                                                143, 443, 587, 8080,
                                                                8443):
            findings.append(Finding(
                finding_id=self._next_id(),
                severity="LOW",
                title=f"Software version disclosed in the TCP {result.port} banner",
                ip=result.ip, port=result.port, hostname=result.hostname,
                service=result.service,
                detected_version=result.version_string,
                category="Information disclosure",
                issue="The service advertises its exact product and version to any "
                      "unauthenticated client.",
                impact="Version disclosure does not create a vulnerability by "
                       "itself, but it removes the reconnaissance step: an attacker "
                       "can match the banner against a vulnerability database and "
                       "select working exploits without probing. It also aids "
                       "automated mass-scanning tools in building target lists.",
                evidence=[f"Banner advertised {result.version_string} without "
                          "authentication."],
                remediation=[
                    "Suppress version detail in the service banner "
                    "(for example nginx `server_tokens off`, Apache "
                    "`ServerTokens Prod`, Postfix `smtpd_banner`).",
                    "Treat this as defence in depth only; do not substitute banner "
                    "suppression for patching, since it does not reduce actual "
                    "vulnerability.",
                ],
                verification="Re-run this scanner and confirm the banner no longer "
                             "contains a version number.",
                references=[REF_OWASP_ASVS, REF_CIS],
            ))

        if result.tls:
            findings.extend(self._tls_findings(result, result.tls))

        return findings

    def _tls_findings(self, result: PortResult, tls: TlsInfo) -> List[Finding]:
        findings: List[Finding] = []
        problems: List[str] = []
        remediation: List[str] = []
        severity = "INFO"

        if tls.protocol and tls.protocol in DEPRECATED_TLS:
            problems.append(f"the server negotiated {tls.protocol}, a deprecated "
                            "protocol version")
            remediation.append(
                f"Disable {tls.protocol} and every earlier version; offer TLS 1.2 "
                "and TLS 1.3 only.")
            severity = max_severity(severity, "HIGH")

        if tls.days_until_expiry is not None:
            if tls.days_until_expiry < 0:
                problems.append(f"the certificate expired "
                                f"{abs(tls.days_until_expiry)} days ago")
                remediation.append("Renew and install a current certificate "
                                   "immediately, then automate renewal (for example "
                                   "with ACME) so it cannot lapse again.")
                severity = max_severity(severity, "HIGH")
            elif tls.days_until_expiry <= CERT_EXPIRY_WARN_DAYS:
                problems.append(f"the certificate expires in "
                                f"{tls.days_until_expiry} days")
                remediation.append("Renew the certificate before expiry and "
                                   "automate future renewals.")
                severity = max_severity(severity, "MEDIUM")

        if tls.self_signed:
            problems.append("the certificate is self-signed")
            remediation.append(
                "Replace the self-signed certificate with one from a CA trusted by "
                "the client population, or from the internal PKI for internal "
                "services. Self-signed certificates on user-facing endpoints train "
                "users to click through warnings, which defeats the protection.")
            severity = max_severity(severity, "MEDIUM")

        if tls.key_bits and tls.key_bits < MIN_RSA_BITS:
            problems.append(f"the public key is only {tls.key_bits} bits")
            remediation.append(f"Reissue with at least {MIN_RSA_BITS}-bit RSA or a "
                               "256-bit elliptic curve key.")
            severity = max_severity(severity, "HIGH")

        if tls.signature_algorithm and tls.signature_algorithm in WEAK_SIG_ALGS:
            problems.append(f"the certificate is signed with "
                            f"{tls.signature_algorithm}")
            remediation.append("Reissue the certificate with a SHA-256 or stronger "
                               "signature algorithm.")
            severity = max_severity(severity, "MEDIUM")

        if not problems:
            return findings

        remediation.append("Re-test the endpoint with an external TLS configuration "
                           "scanner after each change, and add certificate expiry "
                           "monitoring with alerting at 30 and 7 days.")

        evidence = [f"TLS protocol: {tls.protocol or 'unknown'}"]
        if tls.cipher:
            evidence.append(f"Negotiated cipher: {tls.cipher}")
        if tls.subject:
            evidence.append(f"Certificate subject: {tls.subject}")
        if tls.issuer:
            evidence.append(f"Certificate issuer: {tls.issuer}")
        if tls.not_after:
            evidence.append(f"Certificate valid until: {tls.not_after}")
        if tls.san:
            evidence.append("SANs: " + ", ".join(tls.san))

        findings.append(Finding(
            finding_id=self._next_id(),
            severity=severity,
            title=f"Weak TLS configuration on TCP {result.port}",
            ip=result.ip, port=result.port, hostname=result.hostname,
            service=result.service,
            category="Cryptographic configuration",
            issue="The TLS endpoint has configuration weaknesses: "
                  + "; ".join(problems) + ".",
            impact="Deprecated protocol versions, weak keys, and invalid "
                   "certificates undermine the confidentiality and authenticity "
                   "guarantees that the rest of the application depends on, and can "
                   "enable downgrade or interception attacks against users.",
            evidence=evidence,
            remediation=remediation,
            verification="Re-run this scanner and an external TLS configuration "
                         "checker; confirm only TLS 1.2/1.3 are offered and the "
                         "certificate chain validates without warnings.",
            references=[REF_NIST_800_52, REF_CIS],
        ))
        return findings

    # -- host-level observations ------------------------------------------

    def _host_findings(self) -> List[Finding]:
        findings: List[Finding] = []
        by_host: Dict[str, List[PortResult]] = {}
        for result in self.session.open_results:
            by_host.setdefault(result.ip, []).append(result)

        for ip, results in sorted(by_host.items()):
            if len(results) < 10:
                continue
            ports = ", ".join(str(r.port) for r in sorted(results, key=lambda r: r.port))
            hostname = next((r.hostname for r in results if r.hostname), None)
            findings.append(Finding(
                finding_id=self._next_id(),
                severity="MEDIUM",
                title=f"Excessive network attack surface on {ip} "
                      f"({len(results)} open ports)",
                ip=ip, port=0, hostname=hostname,
                service="Multiple",
                category="Architecture / hardening",
                issue=f"{len(results)} TCP ports are reachable on this host within "
                      f"the scanned range, which suggests the host runs multiple "
                      f"roles or has not had a hardening baseline applied.",
                impact="A large listening footprint increases the probability that "
                       "at least one service is unpatched, misconfigured, or "
                       "forgotten. It also means a single service compromise "
                       "exposes every other role co-located on the host.",
                evidence=[f"Open ports observed: {ports}"],
                remediation=[
                    "Produce an inventory of every listening service on the host "
                    "with a named owner and a business justification.",
                    "Disable and remove every service without a current "
                    "justification (minimum necessary services principle).",
                    "Separate distinct roles onto separate hosts or containers so a "
                    "single compromise does not span functions.",
                    "Apply the relevant CIS Benchmark or organisational hardening "
                    "baseline and enforce it with configuration management.",
                    FIREWALL_STEP,
                ],
                verification="Re-scan after hardening and confirm only justified "
                             "services remain reachable; record the approved port "
                             "list as the baseline for future scan comparison.",
                references=[REF_NIST_800_123, REF_CIS],
            ))
        return findings


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------

def _plural(count: int, singular: str, plural: Optional[str] = None) -> str:
    """'1 host' / '3 hosts' — avoids the '1 host(s)' tell of generated text."""
    if count == 1:
        return f"{count} {singular}"
    return f"{count} {plural or singular + 's'}"


def severity_counts(findings: Sequence[Finding]) -> Dict[str, int]:
    counts = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def build_summary(session: ScanSession, findings: Sequence[Finding]) -> Dict[str, Any]:
    counts = severity_counts(findings)
    open_results = session.open_results
    return {
        "hosts_in_scope": len(session.targets),
        "hosts_responsive": len(session.responsive_hosts()),
        "hosts_with_open_ports": len(session.hosts_with_open_ports()),
        "ports_probed_per_host": len(session.config.ports),
        "total_probes": len(session.results),
        "open_ports": len(open_results),
        "banners_captured": sum(1 for r in open_results if r.banner),
        "services_identified": sum(1 for r in open_results if r.product),
        "findings_total": len(findings),
        "severity_counts": counts,
        "scan_duration_s": round(session.duration_s, 2),
        "probes_per_second": round(len(session.results) / session.duration_s, 1)
        if session.duration_s > 0 else None,
    }


# ===========================================================================
# SECTION 9 — REPORT RENDERING
# ===========================================================================
#
# Markdown for humans, JSON for tooling and scan-to-scan diffing, CSV for
# import into a tracker, and a compact console summary.


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def _md_escape(text: str) -> str:
    """Neutralise characters that would break a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")


def _fence(text: str) -> str:
    """Wrap untrusted text in a fence it cannot escape from."""
    cleaned = text.replace("```", "'''")
    return f"```text\n{cleaned}\n```"


_SEVERITY_MARK = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}


def render_markdown(session: ScanSession, findings: Sequence[Finding]) -> str:
    """Render the full assessment report as Markdown."""
    summary = build_summary(session, findings)
    counts = summary["severity_counts"]
    now = datetime.now(timezone.utc)
    scope_label = ", ".join(session.target_specs) or \
        ", ".join(t.label for t in session.targets[:5])

    out: List[str] = []
    add = out.append

    # ---- title block -----------------------------------------------------
    add(f"# Exposed Service Assessment — {_md_escape(scope_label)}")
    add("")
    add("**Handling:** Contains exploitable configuration detail. Treat as "
        "confidential and distribute only to the system owners and the security "
        "team.")
    add("")
    add("| Field | Value |")
    add("|---|---|")
    add(f"| Report generated | {now.strftime('%Y-%m-%d %H:%M:%S UTC')} |")
    add(f"| Scan window | {session.started_at.strftime('%Y-%m-%d %H:%M:%S')} – "
        f"{session.finished_at.strftime('%H:%M:%S UTC')} |")
    add(f"| Assessor | {_md_escape(session.assessor)} |")
    add(f"| Tool | {REPORT_TOOL} v{REPORT_VERSION} |")
    add("| Technique | TCP connect scan with service banner acquisition |")
    add(f"| Scope specification | `{_md_escape(scope_label)}` |")
    add(f"| Hosts in scope | {summary['hosts_in_scope']} |")
    port_range = session.config.to_dict()["port_range"]
    if len(port_range) > 60:
        port_range = port_range[:57].rsplit(",", 1)[0] + ", … (full list in 2.3)"
    add(f"| Ports probed per host | {summary['ports_probed_per_host']} "
        f"({_md_escape(port_range)}) |")
    add("")

    # ---- 1. executive summary -------------------------------------------
    add("## 1. Executive summary")
    add("")
    add(_executive_narrative(session, findings, summary))
    add("")
    add("| Severity | Findings | Remediation window |")
    add("|---|---|---|")
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if counts.get(name):
            add(f"| {_SEVERITY_MARK[name]} | {counts[name]} | "
                f"{SEVERITY_SLA[name]} |")
    add(f"| **Total** | **{summary['findings_total']}** | — |")
    add("")
    add("### Scan statistics")
    add("")
    add("| Metric | Value |")
    add("|---|---|")
    add(f"| Hosts in scope | {summary['hosts_in_scope']} |")
    add(f"| Hosts that responded | {summary['hosts_responsive']} |")
    add(f"| Hosts with at least one open port | {summary['hosts_with_open_ports']} |")
    add(f"| Total probes sent | {summary['total_probes']} |")
    add(f"| Open ports found | {summary['open_ports']} |")
    add(f"| Banners captured | {summary['banners_captured']} |")
    add(f"| Services positively identified | {summary['services_identified']} |")
    add(f"| Scan duration | {summary['scan_duration_s']} s |")
    if summary["probes_per_second"]:
        add(f"| Throughput | {summary['probes_per_second']} probes/s |")
    add("")

    # ---- 2. scope and methodology ---------------------------------------
    add("## 2. Scope and methodology")
    add("")
    add("### 2.1 Authorisation")
    add("")
    add("The operator confirmed authorisation to scan the systems listed below "
        "before the scan was permitted to run. Scanning systems without the "
        "owner's documented permission may violate the Computer Fraud and Abuse "
        "Act, equivalent legislation in other jurisdictions, and the acceptable "
        "use policy of the network being scanned.")
    if session.scope_note:
        add("")
        add(f"**Scope note from operator:** {session.scope_note}")
    add("")
    add("### 2.2 Targets")
    add("")
    add("| # | Hostname | IP address | Result |")
    add("|---|---|---|---|")
    open_by_ip: Dict[str, int] = {}
    for result in session.open_results:
        open_by_ip[result.ip] = open_by_ip.get(result.ip, 0) + 1
    responsive = set(session.responsive_hosts())
    for index, target in enumerate(session.targets, start=1):
        if open_by_ip.get(target.ip):
            verdict = f"{open_by_ip[target.ip]} open port(s)"
        elif target.ip in responsive:
            verdict = "Responded, no open ports in range"
        else:
            verdict = "No response (filtered or host down)"
        add(f"| {index} | {_md_escape(target.hostname or '—')} | `{target.ip}` | "
            f"{verdict} |")
    add("")
    add("### 2.3 Scan parameters")
    add("")
    add("| Parameter | Value |")
    add("|---|---|")
    for key, value in session.config.to_dict().items():
        add(f"| {key.replace('_', ' ').capitalize()} | {value} |")
    add("")
    add("### 2.4 Technique")
    add("")
    add("Each target port was probed with a full TCP connect (a completed "
        "three-way handshake). Ports are classified as follows.")
    add("")
    add("| State | Meaning |")
    add("|---|---|")
    add("| `open` | The handshake completed; a service is listening. |")
    add("| `closed` | The host actively refused the connection. The host is up, "
        "but nothing is bound to that port. |")
    add("| `filtered` | No response within the timeout, or a network unreachable "
        "error. Usually a packet filter, but a short timeout on a slow path "
        "produces the same result. |")
    add("")
    add("For every open port, a second connection was opened to acquire a service "
        "banner. Banner acquisition is read-only: the scanner reads whatever the "
        "service volunteers, sends an HTTP `GET /` on web ports, or sends a bare "
        "CRLF to prompt a line-oriented service. No authentication was attempted, "
        "no credentials were submitted, and no data was written or modified. "
        "Implicit-TLS ports were additionally inspected for protocol version, "
        "cipher, and certificate metadata.")
    add("")
    add("### 2.5 Limitations")
    add("")
    add("These constraints bound what the findings can support:")
    add("")
    add("- **TCP only.** UDP services (DNS, SNMP, NTP, TFTP, IKE, and others) were "
        "not assessed. A separate UDP scan is required for complete coverage.")
    add("- **Banners are self-reported.** A version string can be stale, "
        "deliberately falsified, or reflect a distribution build that has been "
        "patched without a version bump. Version-based findings are marked "
        "*Requires verification* and must be confirmed on the host.")
    add("- **No vulnerability validation.** This assessment reports exposure and "
        "configuration, not exploitability. No exploit was attempted against any "
        "service.")
    add("- **No application-layer testing.** A web service reported as open has "
        "not been assessed for application vulnerabilities such as injection, "
        "broken access control, or insecure deserialisation.")
    add("- **Point-in-time and path-dependent.** Results reflect one moment and "
        "one network vantage point. A host behind a load balancer, or protected "
        "by geo-blocking or rate limiting, may present differently to another "
        "source address.")
    add(f"- **Scoped port range.** Only {summary['ports_probed_per_host']} of "
        "65,535 TCP ports were probed. A service outside that range would not "
        "appear here.")
    add("")

    # ---- 3. findings summary --------------------------------------------
    add("## 3. Findings summary")
    add("")
    if not findings:
        add("No exposures were identified within the scanned scope. This is a "
            "statement about the scanned ports and protocols only; see the "
            "limitations above before treating it as an all-clear.")
        add("")
    else:
        add("| ID | Severity | Asset | Port | Category | Finding |")
        add("|---|---|---|---|---|---|")
        for finding in findings:
            port_label = str(finding.port) if finding.port else "—"
            add(f"| {finding.finding_id} | {_SEVERITY_MARK[finding.severity]} | "
                f"`{finding.ip}` | {port_label} | {_md_escape(finding.category)} | "
                f"{_md_escape(finding.title)} |")
        add("")

    # ---- 4. detailed findings -------------------------------------------
    if findings:
        add("## 4. Exposure detail and remediation plans")
        add("")
        for finding in findings:
            add(_render_finding(finding))
        add("")

    # ---- 5. roadmap ------------------------------------------------------
    add("## 5. Prioritised remediation roadmap")
    add("")
    add(_render_roadmap(findings))
    add("")

    # ---- 6. appendices ---------------------------------------------------
    add("## 6. Appendix A — Open port inventory")
    add("")
    if session.open_results:
        add("| Host | Port | State | Service | Detected version | Latency | Probe |")
        add("|---|---|---|---|---|---|---|")
        for result in session.open_results:
            latency = f"{result.latency_ms:.0f} ms" if result.latency_ms else "—"
            add(f"| `{result.ip}` | {result.port} | {result.state} | "
                f"{_md_escape(result.service)} | "
                f"{_md_escape(result.version_string)} | {latency} | "
                f"{_md_escape(result.probe or '—')} |")
    else:
        add("No open ports were observed.")
    add("")

    add("## 7. Appendix B — Captured banners")
    add("")
    banner_results = [r for r in session.open_results if r.banner]
    if banner_results:
        add("Banner content is supplied by the remote service and is therefore "
            "untrusted input. Control characters have been escaped.")
        add("")
        for result in banner_results:
            add(f"**`{result.ip}:{result.port}`** — {_md_escape(result.service)}")
            add("")
            add(_fence(result.banner or ""))
            add("")
    else:
        add("No banners were captured.")
    add("")

    add("## 8. Appendix C — Non-responsive and clean hosts")
    add("")
    quiet = [t for t in session.targets if not open_by_ip.get(t.ip)]
    if quiet:
        add("| Host | Status |")
        add("|---|---|")
        for target in quiet:
            status = "Responded, no open ports in scanned range" \
                if target.ip in responsive else "No response in scanned range"
            add(f"| `{target.ip}` | {status} |")
    else:
        add("Every host in scope had at least one open port.")
    add("")

    add("## 9. Appendix D — References")
    add("")
    used_refs = sorted({ref for finding in findings for ref in finding.references})
    for ref in used_refs or all_referenced_standards():
        add(f"- {ref}")
    add("")

    add("## 10. Recommended follow-up work")
    add("")
    add("1. Complete a UDP scan of the same scope; several high-risk services "
        "(SNMP, TFTP, DNS, NTP, IKE, and Memcached's UDP interface) are invisible "
        "to a TCP scan.")
    add("2. Run an authenticated vulnerability scan against the responsive hosts "
        "to convert the version-based triage findings in this report into "
        "confirmed or dismissed vulnerabilities.")
    add("3. Perform application-layer testing on the exposed web services.")
    add("4. Record the approved open-port list for each host as a baseline, then "
        "schedule this scan on a recurring basis and alert on any deviation from "
        "the baseline.")
    add("5. Re-scan after remediation and attach the output to the change record "
        "as closure evidence for each finding.")
    add("")

    if session.errors:
        add("## 11. Appendix E — Scan errors")
        add("")
        for message in session.errors:
            add(f"- `{_md_escape(message)}`")
        add("")

    add("---")
    add("")
    add(f"*Generated by {REPORT_TOOL} v{REPORT_VERSION}. Findings are derived from "
        "network-observable behaviour and service banners; version-based findings "
        "require host-level confirmation before they are treated as vulnerabilities.*")

    return "\n".join(out) + "\n"


def _executive_narrative(session: ScanSession, findings: Sequence[Finding],
                         summary: Dict[str, Any]) -> str:
    counts = summary["severity_counts"]
    scope_label = ", ".join(session.target_specs) or "the assessed scope"

    hosts = _plural(summary["hosts_in_scope"], "host")

    if not findings:
        return (
            f"A TCP connect scan covering {scope_label} ({hosts}, "
            f"{_plural(summary['ports_probed_per_host'], 'port')} per host) found "
            "no open ports and therefore no service exposures. This is a good "
            "result, but it is scoped: UDP services were not assessed, and the "
            "scan covered only part of the TCP port space. Review section 2.5 "
            "before treating this as a clean bill of health."
        )

    urgent = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    lead = (
        f"A TCP connect scan covering {scope_label} ({hosts}) identified "
        f"{_plural(summary['open_ports'], 'open port')} across "
        f"{_plural(summary['hosts_with_open_ports'], 'host')}, producing "
        f"{_plural(summary['findings_total'], 'finding')}. "
    )

    if counts["CRITICAL"]:
        lead += (
            f"{_plural(counts['CRITICAL'], 'finding')} "
            + ("is" if counts["CRITICAL"] == 1 else "are")
            + " rated CRITICAL and require"
            + ("s" if counts["CRITICAL"] == 1 else "")
            + " action within 24 hours. These are exposures where unauthenticated "
            "access or full host compromise is plausible without any special "
            "conditions. "
        )
    elif counts["HIGH"]:
        lead += (
            f"{_plural(counts['HIGH'], 'finding')} "
            + ("is" if counts["HIGH"] == 1 else "are")
            + " rated HIGH, meaning credentials or sensitive data traverse the "
            "network in cleartext or the service is a well-known initial-access "
            "target. "
        )
    else:
        lead += ("No critical or high-severity exposures were identified; the "
                 "findings are hardening and hygiene improvements. ")

    if urgent:
        top = urgent[:3]
        described = "; ".join(f"{f.service} on `{f.ip}:{f.port}`" for f in top)
        lead += f"The highest-priority items are: {described}. "

    lead += (
        "Section 4 documents each exposure with its impact, an ordered "
        "remediation plan, and a verification step. Section 5 sequences the work "
        "into phases by remediation window. The single highest-value control "
        "across most of these findings is the same: default-deny inbound "
        "filtering that allows each service only from the source ranges that "
        "legitimately need it."
    )
    return lead


def _render_finding(finding: Finding) -> str:
    lines: List[str] = []
    add = lines.append

    port_label = f":{finding.port}" if finding.port else ""
    add(f"### {finding.finding_id} — [{finding.severity}] {finding.title}")
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| **Severity** | {finding.severity} |")
    add(f"| **Remediation window** | {finding.sla} |")
    add(f"| **Affected asset** | `{finding.ip}{port_label}`"
        + (f" ({_md_escape(finding.hostname)})" if finding.hostname else "") + " |")
    add(f"| **Service** | {_md_escape(finding.service)} |")
    if finding.detected_version:
        add(f"| **Detected version** | {_md_escape(finding.detected_version)} |")
    add(f"| **Category** | {_md_escape(finding.category)} |")
    add(f"| **Confidence** | {_md_escape(finding.confidence)} |")
    add("")
    add(f"**Observation.** {finding.issue}")
    add("")
    add(f"**Why it matters.** {finding.impact}")
    add("")
    if finding.escalation_notes:
        add("**Rating notes.**")
        add("")
        for note in finding.escalation_notes:
            add(f"- {note}")
        add("")
    add("**Evidence.**")
    add("")
    for item in finding.evidence:
        add(f"- {item}")
    add("")
    add("**Remediation plan.**")
    add("")
    for index, step in enumerate(finding.remediation, start=1):
        add(f"{index}. {step}")
    add("")
    add(f"**Verification.** {finding.verification}")
    add("")
    if finding.references:
        add("**References.**")
        add("")
        for ref in finding.references:
            add(f"- {ref}")
        add("")
    add("---")
    add("")
    return "\n".join(lines)


def _render_roadmap(findings: Sequence[Finding]) -> str:
    phases: List[Tuple[str, str, List[str]]] = [
        ("Phase 1 — Immediate (within 24 hours)", ["CRITICAL"],
         "Contain first, then fix. For each item, apply firewall filtering to "
         "remove untrusted reachability immediately; that is usually faster than "
         "reconfiguring the service and it stops the bleeding while the permanent "
         "change goes through change management."),
        ("Phase 2 — Short term (within 7 days)", ["HIGH"],
         "Replace cleartext protocols with encrypted equivalents and harden the "
         "authentication path on services that must stay reachable."),
        ("Phase 3 — Planned (within 30 days)", ["MEDIUM"],
         "Restrict management interfaces to a management network, complete the "
         "patch and TLS configuration work, and produce the service inventory."),
        ("Phase 4 — Hygiene (within 90 days)", ["LOW", "INFO"],
         "Reduce information disclosure and finish documentation. These items do "
         "not reduce exploitability much on their own; schedule them so they do "
         "not displace the phases above."),
    ]

    lines: List[str] = []
    add = lines.append
    add("Work is sequenced by remediation window. Within each phase, address "
        "internet-facing hosts before internal ones.")
    add("")

    any_content = False
    for title, severities, guidance in phases:
        selected = [f for f in findings if f.severity in severities]
        if not selected:
            continue
        any_content = True
        add(f"### {title}")
        add("")
        add(guidance)
        add("")
        add("| ID | Asset | Finding | Primary action |")
        add("|---|---|---|---|")
        for finding in selected:
            port_label = f":{finding.port}" if finding.port else ""
            first_step = finding.headline_action
            if len(first_step) > 150:
                first_step = first_step[:147].rstrip() + "…"
            add(f"| {finding.finding_id} | `{finding.ip}{port_label}` | "
                f"{_md_escape(finding.title)} | {_md_escape(first_step)} |")
        add("")

    if not any_content:
        add("No remediation work is required for the scanned scope.")
        add("")

    add("### Cross-cutting controls")
    add("")
    add("These apply regardless of which individual findings are closed first, "
        "and they prevent the same findings from recurring:")
    add("")
    add("1. **Default-deny ingress.** Adopt an allow-list firewall posture at the "
        "perimeter and on each host, so a newly started service is not reachable "
        "from an untrusted network by accident.")
    add("2. **Minimum necessary services.** Build hosts from a hardened baseline "
        "with unneeded services absent rather than installed-and-disabled.")
    add("3. **Asset and port baseline.** Record the approved open-port list per "
        "host and alert on deviation; this converts scanning from a periodic "
        "project into a detection control.")
    add("4. **Management plane separation.** Move SSH, RDP, BMC/IPMI, and web "
        "management consoles onto a dedicated management network reachable only "
        "through a bastion or VPN with MFA.")
    add("5. **Patch and lifecycle management.** Enrol every exposed service in a "
        "documented patch cycle with a defined maximum age for security updates.")
    add("6. **Logging and monitoring.** Forward authentication and connection logs "
        "for exposed services to the SIEM and alert on brute-force patterns.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON and CSV rendering
# ---------------------------------------------------------------------------

def render_json(session: ScanSession, findings: Sequence[Finding]) -> str:
    """Machine-readable output for ticketing systems or diffing between scans."""
    document = {
        "report": {
            "tool": REPORT_TOOL,
            "tool_version": REPORT_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "assessor": session.assessor,
            "scope_note": session.scope_note,
        },
        "scan": {
            "target_specs": session.target_specs,
            "started_at": session.started_at.isoformat(),
            "finished_at": session.finished_at.isoformat(),
            "duration_s": round(session.duration_s, 2),
            "parameters": session.config.to_dict(),
            "targets": [{"ip": t.ip, "hostname": t.hostname} for t in session.targets],
            "errors": session.errors,
        },
        "summary": build_summary(session, findings),
        "findings": [f.to_dict() for f in findings],
        "open_ports": [r.to_dict() for r in session.open_results],
    }
    return json.dumps(document, indent=2, sort_keys=False)


def render_csv(findings: Sequence[Finding]) -> str:
    """Flat finding register, suitable for import into a tracker."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["finding_id", "severity", "remediation_window", "ip",
                     "hostname", "port", "service", "detected_version",
                     "category", "confidence", "title", "issue",
                     "remediation_steps", "verification"])
    for finding in findings:
        writer.writerow([
            finding.finding_id, finding.severity, finding.sla, finding.ip,
            finding.hostname or "", finding.port or "", finding.service,
            finding.detected_version or "", finding.category, finding.confidence,
            finding.title, finding.issue,
            " | ".join(finding.remediation), finding.verification,
        ])
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Console rendering
# ---------------------------------------------------------------------------

def render_console(session: ScanSession, findings: Sequence[Finding],
                   use_colour: bool = True) -> str:
    """A compact terminal summary printed at the end of a scan."""
    colours = {
        "CRITICAL": "\033[1;91m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
        "LOW": "\033[94m", "INFO": "\033[90m",
    }
    reset = "\033[0m" if use_colour else ""

    def paint(severity: str) -> str:
        if not use_colour:
            return severity.ljust(8)
        return f"{colours.get(severity, '')}{severity.ljust(8)}{reset}"

    summary = build_summary(session, findings)
    lines: List[str] = []
    add = lines.append

    add("")
    add("=" * 78)
    add(" OPEN PORTS")
    add("=" * 78)
    if session.open_results:
        add(f"{'HOST':<22}{'PORT':<8}{'SERVICE':<28}{'VERSION':<20}")
        add("-" * 78)
        for result in session.open_results:
            add(f"{result.ip:<22}{result.port:<8}{result.service[:27]:<28}"
                f"{result.version_string[:19]:<20}")
    else:
        add(" No open ports found in the scanned range.")

    add("")
    add("=" * 78)
    add(" FINDINGS")
    add("=" * 78)
    if findings:
        for finding in findings:
            port_label = f":{finding.port}" if finding.port else ""
            add(f" {finding.finding_id}  {paint(finding.severity)} "
                f"{finding.ip}{port_label}  {finding.title}")
    else:
        add(" No exposures identified.")

    counts = summary["severity_counts"]
    add("")
    add("-" * 78)
    tally = "  ".join(f"{name}: {counts[name]}" for name in
                      ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if counts[name])
    add(f" {tally or 'No findings'}")
    add(f" {summary['total_probes']} probes in {summary['scan_duration_s']}s "
        f"({summary['probes_per_second'] or 0} probes/s) · "
        f"{summary['open_ports']} open · "
        f"{summary['banners_captured']} banners captured")
    add("-" * 78)
    return "\n".join(lines)


# ===========================================================================
# SECTION 10 — LAB TARGET MODE
# ===========================================================================
#
# Deliberately unhardened fake services on loopback, so the scanner can be
# exercised without scanning anything you do not own. Every listener binds
# to 127.0.0.1 only, serves a canned banner, and closes. Nothing
# authenticates and nothing stores data.


HOST = "127.0.0.1"

# port -> (label, banner bytes, speaks_first)
SERVICES: Dict[int, Tuple[str, bytes, bool]] = {
    21: ("FTP (vsftpd)", b"220 (vsFTPd 2.3.4)\r\n", True),
    22: ("SSH (OpenSSH)", b"SSH-2.0-OpenSSH_7.4\r\n", True),
    23: ("Telnet", b"\xff\xfb\x01\xff\xfb\x03\r\nUbuntu 14.04 LTS\r\nlogin: ", True),
    25: ("SMTP (Postfix)", b"220 mail.lab.invalid ESMTP Postfix (Ubuntu)\r\n", True),
    80: ("HTTP (nginx)",
         b"HTTP/1.1 200 OK\r\n"
         b"Server: nginx/1.18.0 (Ubuntu)\r\n"
         b"Content-Type: text/html\r\n"
         b"Content-Length: 32\r\n"
         b"Connection: close\r\n\r\n"
         b"<html><body>lab</body></html>\r\n", False),
    3306: ("MySQL",
           b"\x4a\x00\x00\x00\x0a5.5.62-0ubuntu0.14.04.1\x00"
           b"\x36\x00\x00\x00\x2b\x4f\x5c\x3f\x1e\x36\x6b\x3a\x00\xff\xf7\x08"
           b"\x02\x00\x0f\x80\x15\x00", True),
    5900: ("VNC (RFB)", b"RFB 003.008\n", True),
    6379: ("Redis", b"redis_version:5.0.7\r\nrole:master\r\n", False),
    8080: ("HTTP alt (Apache)",
           b"HTTP/1.1 200 OK\r\n"
           b"Server: Apache/2.4.29 (Ubuntu)\r\n"
           b"X-Powered-By: PHP/7.0.33\r\n"
           b"Connection: close\r\n\r\n"
           b"manager\r\n", False),
    9200: ("Elasticsearch",
           b"HTTP/1.1 200 OK\r\n"
           b"Content-Type: application/json\r\n"
           b"Connection: close\r\n\r\n"
           b'{"version":{"number":"6.8.2"},"tagline":"You Know, for Search"}\r\n',
           False),
    11211: ("Memcached", b"VERSION 1.4.25\r\n", False),
}

TLS_PORT = 443
HIGH_PORT_OFFSET = 20000


class _BannerHandler(socketserver.BaseRequestHandler):
    """Serve one canned banner, optionally after reading a client probe."""

    banner: bytes = b""
    speaks_first: bool = True

    def handle(self) -> None:
        try:
            self.request.settimeout(3.0)
            if self.speaks_first:
                self.request.sendall(self.banner)
                try:
                    self.request.recv(1024)
                except (socket.timeout, OSError):
                    pass
            else:
                try:
                    self.request.recv(4096)
                except (socket.timeout, OSError):
                    pass
                self.request.sendall(self.banner)
        except OSError:
            pass


class _Server(socketserver.ThreadingTCPServer):
    # On POSIX this just skips the TIME_WAIT delay when restarting. On Windows
    # SO_REUSEADDR means something different and more dangerous: it lets a
    # second socket bind a port that is already in use, producing a listener
    # that silently never receives a connection. Better to fail loudly there
    # so a port conflict is reported instead of hidden.
    allow_reuse_address = os.name != "nt"
    daemon_threads = True


def _make_handler(banner: bytes, speaks_first: bool) -> type:
    return type("Handler", (_BannerHandler,),
                {"banner": banner, "speaks_first": speaks_first})


def _self_signed_cert() -> Optional[str]:
    """
    Generate an expired, self-signed certificate in a temporary file.

    Both properties are defects, which is exactly the point: they give the
    scanner's TLS analysis something to report. The key is 2048-bit because
    OpenSSL 3 refuses to load a smaller one regardless of security level.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        print("  [!] cryptography not installed; skipping the TLS listener",
              file=sys.stderr)
        return None

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "lab.invalid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSIT 2033 Lab"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)                       # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=400))
        .not_valid_after(now - timedelta(days=30))   # already expired
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("lab.invalid")]), critical=False)
        .sign(key, hashes.SHA256())
    )

    handle, path = tempfile.mkstemp(suffix=".pem")
    with os.fdopen(handle, "wb") as fh:
        fh.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return path


class _TlsServer(_Server):
    """HTTPS listener wrapping each accepted connection in TLS."""

    def __init__(self, address, handler, certfile: str) -> None:
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # The security level must be lowered *before* load_cert_chain: OpenSSL 3
        # enforces a minimum key size when the certificate is loaded, and this
        # lab certificate is deliberately weak.
        try:
            self._ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        self._ctx.load_cert_chain(certfile)
        super().__init__(address, handler)

    def get_request(self):
        sock, addr = self.socket.accept()
        try:
            return self._ctx.wrap_socket(sock, server_side=True), addr
        except (ssl.SSLError, OSError):
            sock.close()
            raise


def _start_lab_services(high_ports: bool = False) -> Tuple[List[_Server], List[int]]:
    """Start every listener. Returns the servers and the ports actually bound."""
    offset = HIGH_PORT_OFFSET if high_ports else 0
    servers: List[_Server] = []
    bound: List[int] = []

    for port, (label, banner, speaks_first) in sorted(SERVICES.items()):
        listen_port = port + offset if port < 1024 else port
        handler = _make_handler(banner, speaks_first)
        try:
            server = _Server((HOST, listen_port), handler)
        except OSError as exc:
            print(f"  [!] {listen_port:<6} {label}: {exc}", file=sys.stderr)
            continue
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        bound.append(listen_port)
        print(f"  [+] {listen_port:<6} {label}")

    certfile = _self_signed_cert()
    if certfile:
        tls_port = TLS_PORT + offset
        handler = _make_handler(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache/2.4.29 (Ubuntu)\r\n"
            b"Connection: close\r\n\r\nlab\r\n", False)
        try:
            server = _TlsServer((HOST, tls_port), handler, certfile)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
            bound.append(tls_port)
            print(f"  [+] {tls_port:<6} HTTPS (expired, self-signed)")
        except OSError as exc:
            print(f"  [!] {tls_port:<6} HTTPS: {exc}", file=sys.stderr)

    return servers, bound


def run_lab_mode(high_ports: bool = False) -> int:
    """
    Start the fake services and block until interrupted.

    Entered via ``--lab``. Run it in one terminal and scan 127.0.0.1 from
    another.
    """
    print("\n  Fake lab services (127.0.0.1 only, read-only banners)\n")
    servers, bound = _start_lab_services(high_ports=high_ports)

    if not servers:
        print("\n  No listeners started.", file=sys.stderr)
        return 1

    ports = ",".join(str(p) for p in sorted(bound))
    print(f"\n  {len(servers)} listener(s) up. Scan them from another terminal:\n")
    print(f"    python3 portscan.py -t 127.0.0.1 -p {ports} --authorize\n")
    print("  Ctrl-C to stop.\n")

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n  Shutting down.")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
    return 0


# ===========================================================================
# SECTION 11 — COMMAND-LINE INTERFACE
# ===========================================================================
#
# Argument parsing, the authorisation gate, safety limits, and orchestration.


LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
DEFAULT_PORTS = "1-1024"
MAX_WORKERS = 500
DEFAULT_MAX_HOSTS = 256


# ---------------------------------------------------------------------------
# CLI definition
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscan.py",
        description="Multi-threaded TCP port scanner with service banner "
                    "grabbing and automated exposure reporting.",
        epilog="Authorised use only. Scan only systems you own or have written\n"
               "permission to test. Use --lab to start safe local test targets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    scope = parser.add_argument_group("scope")
    scope.add_argument(
        "-t", "--target", dest="targets", action="append", metavar="SPEC",
        help="Target to scan. Accepts a hostname (example.com), an IP address "
             "(192.0.2.10), a CIDR network (192.0.2.0/24), or a range "
             "(192.0.2.10-40 or 192.0.2.10-192.0.2.40). Repeatable.")
    scope.add_argument(
        "-p", "--ports", default=DEFAULT_PORTS, metavar="SPEC",
        help=f"Ports to probe, e.g. '22,80,443' or '1-1024,8080-8090' "
             f"(default: {DEFAULT_PORTS}).")
    scope.add_argument(
        "--top-ports", action="store_true",
        help=f"Probe a curated list of {len(TOP_PORTS)} commonly "
             f"exposed ports instead of --ports.")
    scope.add_argument(
        "--all-ports", action="store_true",
        help="Probe all 65535 TCP ports. Slow; combine with a long timeout.")
    scope.add_argument(
        "--resolve-all", action="store_true",
        help="Scan every address a hostname resolves to, not just the first.")

    timing = parser.add_argument_group("timing and concurrency")
    timing.add_argument(
        "--timeout", type=float, default=1.0, metavar="SECONDS",
        help="Connect timeout per port (default: 1.0). Raise this on slow or "
             "high-latency links, or open ports will be misreported as filtered.")
    timing.add_argument(
        "--banner-timeout", type=float, default=2.0, metavar="SECONDS",
        help="Read timeout for banner acquisition (default: 2.0). Some services "
             "pause before greeting.")
    timing.add_argument(
        "-w", "--workers", type=int, default=200, metavar="N",
        help=f"Worker threads (default: 200, maximum: {MAX_WORKERS}). Lower this "
             f"if the target is fragile or the network drops connections.")
    timing.add_argument(
        "--delay", type=float, default=0.0, metavar="SECONDS",
        help="Delay before each connection, per worker. Use to throttle a scan "
             "that is tripping rate limits or IPS thresholds.")

    detection = parser.add_argument_group("detection")
    detection.add_argument(
        "--no-banner", action="store_true",
        help="Skip banner grabbing. Faster, quieter, and less informative: the "
             "report will fall back to port-number service guesses.")
    detection.add_argument(
        "--no-tls", action="store_true",
        help="Skip the TLS handshake and certificate inspection on TLS ports.")

    output = parser.add_argument_group("output")
    output.add_argument(
        "--report-dir", default="./reports", metavar="DIR",
        help="Directory for generated reports (default: ./reports).")
    output.add_argument(
        "--formats", default="md,json,csv", metavar="LIST",
        help="Comma-separated output formats from md, json, csv, or 'none' "
             "(default: md,json,csv).")
    output.add_argument(
        "--label", default=None, metavar="TEXT",
        help="Short label used in output filenames (default: derived from the "
             "first target).")
    output.add_argument(
        "--assessor",
        default=(os.environ.get("USER") or os.environ.get("USERNAME")
                 or "Unspecified"),
        metavar="NAME",
        help="Name recorded in the report as the assessor.")
    output.add_argument(
        "--scope-note", default="", metavar="TEXT",
        help="Free-text authorisation or scope note to embed in the report, "
             "e.g. a change ticket or engagement reference.")
    output.add_argument(
        "--no-colour", "--no-color", dest="no_colour", action="store_true",
        help="Disable ANSI colour in terminal output.")

    safety = parser.add_argument_group("safety")
    safety.add_argument(
        "--authorize", action="store_true",
        help="Assert that you are authorised to scan the specified targets. "
             "Without this flag the tool prompts for confirmation, and it will "
             "refuse to run unattended.")
    safety.add_argument(
        "--max-hosts", type=int, default=DEFAULT_MAX_HOSTS, metavar="N",
        help=f"Refuse to scan more than N hosts (default: {DEFAULT_MAX_HOSTS}). "
             f"Guards against a mistyped netmask turning into a /8.")

    lab = parser.add_argument_group("lab mode")
    lab.add_argument(
        "--lab", action="store_true",
        help="Start fake, deliberately unhardened services on 127.0.0.1 and "
             "block until interrupted, so the scanner can be tested without "
             "scanning anything you do not own. Run in a second terminal.")
    lab.add_argument(
        "--lab-high-ports", action="store_true",
        help=f"With --lab, shift privileged ports up by {HIGH_PORT_OFFSET} so "
             f"root is not required.")

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true",
                           help="Verbose logging.")
    verbosity.add_argument("-q", "--quiet", action="store_true",
                           help="Suppress progress and summary output.")

    return parser


# ---------------------------------------------------------------------------
# Safety gate
# ---------------------------------------------------------------------------

def confirm_authorisation(target_labels: Sequence[str], host_count: int,
                          port_count: int, pre_authorised: bool) -> bool:
    """
    Require an explicit authorisation assertion before any packet is sent.

    This is not security theatre and it is not a legal shield. It exists to
    interrupt the most common cause of an unauthorised scan, which is not
    malice but a mistyped target or a copy-pasted command run against the wrong
    network.
    """
    public = [label for label in target_labels if _is_public(label)]

    if pre_authorised:
        if public and not sys.stdin.isatty():
            log.warning("Scanning %d publicly routable address(es) under "
                        "--authorize.", len(public))
        return True

    if not sys.stdin.isatty():
        log.error("No terminal available for confirmation. Re-run with "
                  "--authorize if you are authorised to scan these targets.")
        return False

    print("", file=sys.stderr)
    print("  AUTHORISATION CHECK", file=sys.stderr)
    print(f"  Hosts:  {host_count}", file=sys.stderr)
    print(f"  Ports:  {port_count} per host "
          f"({host_count * port_count} probes total)", file=sys.stderr)
    if public:
        print(f"  Note:   {len(public)} target(s) are publicly routable "
              f"addresses.", file=sys.stderr)
    print("", file=sys.stderr)
    print("  Scan only systems you own or have written permission to test.",
          file=sys.stderr)
    print("", file=sys.stderr)

    try:
        answer = input("  Type YES to confirm you are authorised: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("", file=sys.stderr)
        return False
    return answer == "YES"


def _is_public(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Progress display
# ---------------------------------------------------------------------------

class ProgressPrinter:
    """Minimal single-line progress indicator written to stderr."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and sys.stderr.isatty()
        self._last_pct = -1

    def __call__(self, completed: int, total: int) -> None:
        if not self.enabled or not total:
            return
        pct = int(completed * 100 / total)
        if pct == self._last_pct:
            return
        self._last_pct = pct
        filled = pct // 4
        bar = "#" * filled + "." * (25 - filled)
        sys.stderr.write(f"\r  scanning [{bar}] {pct:3d}%  "
                         f"{completed}/{total} probes")
        sys.stderr.flush()

    def finish(self) -> None:
        if self.enabled:
            sys.stderr.write("\r" + " " * 70 + "\r")
            sys.stderr.flush()


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_reports(session, findings, report_dir: Path, formats: Sequence[str],
                  label: str) -> List[Path]:
    """Write the requested report formats and return the paths written."""
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    # Dots and slashes are stripped from the label: a target like
    # "192.168.1.0/24" would otherwise create a subdirectory, and Path.with_suffix
    # would treat ".1.0" as an existing extension and replace it.
    safe_label = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)[:40]
    stem = f"portscan_{safe_label}_{stamp}"

    renderers = {
        "md": (".md", lambda: render_markdown(session, findings)),
        "json": (".json", lambda: render_json(session, findings)),
        "csv": (".csv", lambda: render_csv(findings)),
    }

    written: List[Path] = []
    for fmt in formats:
        if fmt not in renderers:
            log.warning("Ignoring unknown output format %r", fmt)
            continue
        suffix, render = renderers[fmt]
        path = report_dir / (stem + suffix)
        path.write_text(render(), encoding="utf-8")
        written.append(path)
        log.info("Wrote %s", path)
    return written


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else
        (logging.ERROR if args.quiet else logging.INFO),
        format=LOG_FORMAT, stream=sys.stderr)

    # -- lab mode short-circuits everything else ---------------------------
    if args.lab:
        return run_lab_mode(high_ports=args.lab_high_ports)

    if not args.targets:
        parser.error("-t/--target is required (or use --lab to start the "
                     "built-in test services)")
        return 2

    # -- resolve ports -----------------------------------------------------
    try:
        if args.all_ports:
            ports = list(range(1, 65536))
        elif args.top_ports:
            ports = sorted(TOP_PORTS)
        else:
            ports = parse_ports(args.ports)
    except PortError as exc:
        parser.error(f"invalid --ports: {exc}")
        return 2

    # -- resolve targets ---------------------------------------------------
    try:
        targets = parse_targets(args.targets, resolve_all=args.resolve_all)
    except TargetError as exc:
        parser.error(f"invalid --target: {exc}")
        return 2

    if not targets:
        parser.error("no targets to scan")
        return 2

    if len(targets) > args.max_hosts:
        log.error("%d hosts exceeds the --max-hosts limit of %d. Narrow the "
                  "scope, or raise the limit deliberately if this is intended.",
                  len(targets), args.max_hosts)
        return 2

    if args.workers > MAX_WORKERS:
        log.warning("Clamping --workers from %d to %d", args.workers, MAX_WORKERS)
        args.workers = MAX_WORKERS
    if args.workers < 1:
        parser.error("--workers must be at least 1")
        return 2
    if args.timeout <= 0 or args.banner_timeout <= 0:
        parser.error("timeouts must be greater than zero")
        return 2

    # -- authorisation gate ------------------------------------------------
    if not confirm_authorisation([t.ip for t in targets], len(targets),
                                 len(ports), args.authorize):
        log.error("Authorisation not confirmed. Aborting without sending any "
                  "packets.")
        return 3

    # -- scan --------------------------------------------------------------
    config = ScanConfig(
        ports=ports,
        timeout=args.timeout,
        banner_timeout=args.banner_timeout,
        workers=args.workers,
        delay=args.delay,
        grab_banners=not args.no_banner,
        tls_probe=not args.no_tls,
    )

    if not args.quiet:
        print(f"\n  {len(targets)} host(s) · {len(ports)} port(s) "
              f"({summarize_ports(ports)}) · {args.workers} threads · "
              f"{args.timeout}s timeout", file=sys.stderr)

    progress = ProgressPrinter(enabled=not args.quiet)
    scanner = TcpScanner(config, progress=progress)

    try:
        session = scanner.scan(targets, target_specs=list(args.targets),
                               assessor=args.assessor, scope_note=args.scope_note)
    except KeyboardInterrupt:
        progress.finish()
        log.error("Interrupted by operator. No report was generated.")
        return 3
    finally:
        progress.finish()

    # -- analyse and report ------------------------------------------------
    findings = ExposureAnalyzer(session).analyze()

    if not args.quiet:
        print(render_console(session, findings, use_colour=not args.no_colour))

    formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
    if formats and formats != ["none"]:
        label = args.label or args.targets[0]
        try:
            written = write_reports(session, findings, Path(args.report_dir),
                                    formats, label)
        except OSError as exc:
            log.error("Could not write reports: %s", exc)
            return 2
        if not args.quiet and written:
            print("\n  Reports written:", file=sys.stderr)
            for path in written:
                print(f"    {path}", file=sys.stderr)
            print("", file=sys.stderr)

    counts = severity_counts(findings)
    return 1 if (counts["CRITICAL"] or counts["HIGH"]) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(3)
