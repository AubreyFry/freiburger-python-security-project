# Python Security Tools — CSIT 2033

Three defensive security tools written in Python for **CSIT 2033: Programming
for Cybersecurity** at Trine University.

> **Authorized use only.** These are defensive and diagnostic tools. Run them
> only against systems you own or are explicitly authorized to assess.
> Unauthorized scanning may violate the Computer Fraud and Abuse Act
> (18 U.S.C. § 1030) and equivalent laws elsewhere. A university or employer
> network is not implicitly in scope. `portscan.py` ships with a `--lab` mode
> that stands up fake local services so the tool can be exercised safely.

## The tools

### `SOCTools/portscan.py` — TCP port scanner and exposure reporter

Multi-threaded TCP scanner that discovers listening services, fingerprints them
from their banners, inspects TLS certificates, and writes an assessment report
documenting each exposure with a severity rating and a remediation plan. Reports
in Markdown, JSON, CSV, or console.

```bash
python portscan.py --lab                                   # safe local targets
python portscan.py -t 127.0.0.1 --top-ports --authorize
```

Two design decisions worth calling out:

- **The TLS inspection context is deliberately permissive** — certificate
  verification off, `SECLEVEL=0`, minimum version set as low as the build
  allows. A scanner that refuses to negotiate weak protocols cannot report that
  a server is offering them. The service knowledge base separately *recommends*
  disabling SSLv3, TLS 1.0 and 1.1, which is the opposite posture for the
  systems being assessed.
- **Windows socket behavior is handled explicitly.** WinSock returns error
  codes in the 10000 range rather than POSIX errno values, so connection
  results are mapped accordingly. The lab server sets `SO_REUSEADDR` on POSIX,
  where it just skips the `TIME_WAIT` delay on restart, but leaves it off on
  Windows, where it instead lets a second socket bind a port already in use —
  producing a listener that silently never receives a connection rather than a
  visible port conflict.

### `SOCTools/domain_recon.py` — passive OSINT domain reconnaissance

Aggregates publicly available information about a domain: WHOIS/RDAP records,
DNS records with SPF/DMARC/DKIM/CAA mail-security analysis, subdomains from
certificate transparency logs and passive DNS sources, and published contact
addresses. Outputs JSON or a formatted PDF report.

No port scanning, brute forcing, zone transfers, or exploitation. It does
retrieve the target's own published web pages to collect contact addresses.

```bash
python domain_recon.py example.com -f pdf
python domain_recon.py --self-test        # offline, no network
```

Three details in the analysis logic:

- **A failed SPF lookup is not a missing SPF record.** Treating a timeout as
  absence would report a mail-security finding that isn't real, so the two
  states are distinguished and a lookup failure reports as unknown rather than
  as absent. There's a regression test for it named
  `"SPF failure is not absence"`.
- **The obfuscated-address pattern requires bracketed or whitespace-delimited
  separators.** Matching `name (at) domain (dot) com` is the goal; without the
  delimiter requirement the same pattern fires inside ordinary words, turning
  `authentication.click` into `authentic@ion.click`.
- **Script, style and comment blocks are stripped before address extraction,**
  because minified JavaScript bundles produce a lot of convincing garbage.

### `SOCTools/log_parser.py` — LogSentry, multi-format log parser and detection engine

Normalizes security logs from many formats into a single event schema, runs
threshold-based detection analytics over the stream, and emits a report with
prioritized alerts, supporting evidence, IOCs, and remediation guidance.

Handles Apache/Nginx access and error logs, syslog (RFC 3164 and 5424), Linux
`auth.log`, Windows Event Log exports, and gzipped variants of any of them.
Standard library only — no third-party dependencies.

Detection runs as an eight-stage pipeline (read → detect format → parse →
normalize → enrich → detect → correlate → report). Thresholds are not
hard-coded: every number a detector compares against can be overridden through
a JSON file passed to `--config`, and the common ones also have their own
command-line flags, which take precedence.

```bash
python log_parser.py --lab     # offline demo, exercises the detectors
```

## Also in this repo

`main.py` is a short `requests` example kept from a different CSIT 2033
assignment, for reference. It is not part of the three tools above.

## Testing

All three tools carry built-in verification that runs without network access:

| | |
|---|---|
| `domain_recon.py --self-test` | Offline check of the analysis and reporting paths |
| `log_parser.py --lab` | Generates synthetic events and exercises the detectors |
| `portscan.py --lab` | Stands up local fake services to scan |

## Setup

```bash
git clone https://github.com/AubreyFry/freiburger-python-security-project.git
cd freiburger-python-security-project
pip install -r requirements.txt
```

`log_parser.py` and `portscan.py` both run on the standard library alone —
Python 3.8+ — though installing `cryptography` adds certificate detail
(subject, issuer, expiry, key size, signature algorithm) to `portscan.py`'s TLS
findings.

`domain_recon.py` is the one tool that requires third-party packages; it exits
with an install hint if they're missing, including under `--self-test`. The
pins in `requirements.txt` are current patched releases and need
**Python 3.10+**.

## Course context

CSIT 2033 — Programming for Cybersecurity, Trine University.
Aubrey Freiburger.
