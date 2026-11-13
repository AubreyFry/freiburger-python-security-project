# Python Security Tools — CSIT 2033

Defensive security tools written in Python for **CSIT 2033: Programming for
Cybersecurity** at Trine University. Each tool lives in `SOCTools/` and was
built for a lab in the course.

> **Authorized use only.** These are defensive and diagnostic tools. Run them
> only against systems you own or are explicitly authorized to assess.
> Unauthorized scanning may violate the Computer Fraud and Abuse Act
> (18 U.S.C. § 1030) and equivalent laws elsewhere. A university or employer
> network is not implicitly in scope. Most tools include a `--lab`, `--demo`,
> or self-test mode so they can be exercised safely, and `reconlite` refuses to
> run against anything other than `localhost` or `127.0.0.1`.

## Tools at a glance

| Tool | What it does |
|---|---|
| [`portscan.py`](#soctoolsportscanpy--tcp-port-scanner-and-exposure-reporter) | TCP port scanner with service fingerprinting, TLS inspection, and remediation reporting |
| [`domain_recon.py`](#soctoolsdomain_reconpy--passive-osint-domain-reconnaissance) | Passive OSINT recon: WHOIS/RDAP, DNS and mail security, subdomains, contacts |
| [`log_parser.py`](#soctoolslog_parserpy--logsentry-multi-format-log-parser-and-detection-engine) | Multi-format log parser with threshold-based detection |
| [`password_auditor.py`](#soctoolspassword_auditorpy--password-strength-auditor-and-policy-enforcer) | Password strength scoring, wordlist mutation, and policy enforcement |
| [`vuln_scanner.py`](#soctoolsvuln_scannerpy--nmap-to-nvd-vulnerability-reporter) | Matches Nmap results to NVD CVEs and prioritizes fixes |
| [`waf.py`](#soctoolswafpy--web-application-firewall) | Flask web application firewall with anomaly scoring |
| [`phish_detector.py`](#soctoolsphish_detectorpy--phishing-email-detector) | Scores emails for phishing with explained, per-feature reasoning |
| [`FIM.py`](#soctoolsfimpy--file-integrity-monitor) | File integrity monitor with a tamper-evident, signed alert log |
| [`device_ping.py`](#soctoolsdevice_pingpy--network-device-inventory-sweep) | Ping sweep that flags devices missing from the inventory |
| [`packet_analyzer.py`](#soctoolspacket_analyzerpy--packet-analyzer) | Packet analyzer |
| [`reconlite/`](#soctoolsreconlite--modular-web-recon-tool) | Modular, rate-limited web recon tool for local targets |

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

### `SOCTools/password_auditor.py` — password strength auditor and policy enforcer

Combines three pieces: a strength scorer built on `zxcvbn`, a mutation engine
that generates and detects common wordlist variations (leet substitutions,
appended digits and symbols, case changes), and a policy enforcer that
demonstrates a registration flow storing passwords as PBKDF2-HMAC-SHA256 hashes.
Produces terminal output, an offline HTML report, and JSON results. Passwords
and other sensitive values are never written to reports or logs.

One design decision: **the default policy has no composition rules**
(required uppercase, digit, symbol). Testing showed those rules rejected strong
passphrases while catching nothing weak, in line with NIST SP 800-63B. They're
still available with `--policy-profile composition`.

### `SOCTools/vuln_scanner.py` — Nmap-to-NVD vulnerability reporter

Parses Nmap XML scan output (or services entered manually or by CSV), looks up
known vulnerabilities through the NVD CVE API 2.0, and writes a prioritized
HTML/PDF/JSON report with CVSS scores, fixed versions, and remediation links.
Findings are ranked P1–P4, with entries on CISA's Known Exploited
Vulnerabilities list and CVSS 9.0+ scores ranked highest.

The NVD client handles rate limiting, retries, pagination, and caching, and
accepts an optional API key. A circuit breaker stops it from retrying
indefinitely if NVD is down, and an outage is reported rather than silently
masked by fallback searches.

```bash
python vuln_scanner.py --demo        # synthetic data, fictional CVE IDs
python vuln_scanner.py --self-test   # offline checks
```

### `SOCTools/waf.py` — web application firewall

A Flask-based web application firewall with a shared rule engine that detects
SQL injection, cross-site scripting, path traversal, and command injection.
Requests are scored with CRS-style anomaly scoring, and paranoia levels 1–4
trade detection coverage against false positives. Produces HTML and PDF reports.

### `SOCTools/phish_detector.py` — phishing email detector

Analyzes EML and MBOX files (including forwarded-as-attachment emails) and
scores each message for phishing. It checks SPF/DKIM/DMARC results, compares
links against the OpenPhish community feed (and VirusTotal, optionally), looks
for pressure and credential-request language, and catches Unicode tricks such
as zero-width characters and look-alike letters in sender names. Every point in
the score is shown with its reason, so a verdict can be checked rather than
trusted. Reports in HTML, PDF, and JSON, with links defanged.

```bash
python phish_detector.py --lab         # eight built-in fictional sample emails
python phish_detector.py --self-test   # offline checks
```

### `SOCTools/FIM.py` — file integrity monitor

Baselines a directory by hashing every file with SHA-256 into a SQLite
database, then monitors it on a configurable interval, with `watchdog`
catching changes between scans. Every alert goes into a tamper-evident log:
each entry is signed with HMAC-SHA256 and chained to the one before it, so an
edited, deleted, reordered, forged, or truncated entry fails verification. The
baseline is signed too, so the monitor won't start if someone edits a stored
hash to hide a change.

The demo stages a simulated eight-step malware drop (disguised dropper, web
shell, cron and SSH-key persistence, timestomped defacement, and more) against a
practice directory using harmless placeholder files, then scores what was
detected. Reports in HTML, PDF, and JSON.

```bash
python FIM.py self-test
python FIM.py demo
```

### `SOCTools/device_ping.py` — network device inventory sweep

Pings every address in one or more IPv4 networks and compares whatever answers
against a CSV inventory of known devices. Each address is classified as
**available** (no reply), **valid device** (replied and is in the inventory), or
**unknown device** (replied but isn't in the inventory — the one worth
investigating). Reports in PDF and CSV.

```bash
python device_ping.py --init-inventory known_devices.csv
python device_ping.py 192.168.1.0/24 -i known_devices.csv -o report.pdf
python device_ping.py 10.0.0.0/24 --lab -i known_devices.csv    # practice network
```

### `SOCTools/packet_analyzer.py` — packet analyzer

<!-- TODO: add a short description and an example command. -->

### `SOCTools/reconlite/` — modular web recon tool

A multi-module recon tool built for a local OWASP Juice Shop container. It
checks HTTP response headers, parses `robots.txt`, crawls same-origin links,
fingerprints the homepage, and probes a small path list, then writes
`findings.json`, `report.md`, and `dir_probe.csv`.

| Module | Role |
|---|---|
| `cli.py` | Argument parsing, orchestration, report writing |
| `headers.py` | Flags missing security headers separately from weak settings |
| `robots.py` | Retrieves and parses `robots.txt` |
| `spider.py` | Same-origin crawl with a depth limit; homepage fingerprint (SHA-256 + script URLs) |
| `dirs.py` | Probes `wordlist.txt`; exports results to CSV |
| `rate.py` | Shared rate limiter and request cap |
| `util.py` | URL handling, scope allowlist, logging, scoped HTTP client |

Safety is enforced in code, not left to the user:

- **Scope allowlist.** Only `localhost` and `127.0.0.1` are accepted, checked
  on every request, and redirects are never followed, so a redirect can't pull
  the tool off-target.
- **Rate limits.** At least 200 ms between requests and a hard cap of 500
  requests per run; lower values are rejected.
- **Tiny wordlists only.** Lists over 50 entries are refused.
- **Soft-404 detection.** Single-page apps like Juice Shop answer every unknown
  path with the homepage and a 200 status. One request to a random path sets a
  baseline, and probe results that match it are reported as not found rather
  than as discoveries.

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop     # in a separate terminal
python SOCTools/reconlite/cli.py --target http://localhost:3000 --json-out findings.json
```

## Also in this repo

`main.py` is a short `requests` example kept from a different CSIT 2033
assignment, for reference. It is not one of the tools above.

## Testing

Most tools carry built-in verification that runs without touching real systems:

| | |
|---|---|
| `portscan.py --lab` | Stands up local fake services to scan |
| `domain_recon.py --self-test` | Offline check of the analysis and reporting paths |
| `log_parser.py --lab` | Generates synthetic events and exercises the detectors |
| `vuln_scanner.py --self-test` / `--demo` | Offline checks; demo run on synthetic data |
| `phish_detector.py --self-test` / `--lab` | Offline checks; built-in sample emails |
| `FIM.py self-test` / `demo` | Offline checks; simulated malware drop |
| `device_ping.py --lab` | Sweeps a practice network instead of a real one |
| `reconlite/cli.py` | Runs against a local Juice Shop container only |

## Setup

```bash
git clone https://github.com/AubreyFry/freiburger-python-security-project.git
cd freiburger-python-security-project
pip install -r requirements.txt
```

`log_parser.py` and `portscan.py` run on the standard library alone, though
installing `cryptography` adds certificate detail (subject, issuer, expiry, key
size, signature algorithm) to `portscan.py`'s TLS findings. The other tools use
third-party packages, including `dnspython` and `reportlab` (`domain_recon.py`),
`zxcvbn` (`password_auditor.py`), `flask` (`waf.py`), `watchdog` and
`reportlab` (`FIM.py`), and `requests` and `beautifulsoup4` (`reconlite`).
The pins in `requirements.txt` are current patched releases and need
**Python 3.10+**.

Several labs were run in Google Colab; those notebooks were submitted with each
lab and aren't stored here. `reconlite` is the exception: it runs locally,
because it needs to reach a container on the same machine.

## Course context

CSIT 2033 — Programming for Cybersecurity, Trine University.
Aubrey Freiburger.
