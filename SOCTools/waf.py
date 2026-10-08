#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
waf.py - A lightweight Web Application Firewall (WAF) middleware and rule engine.

CSIT 2033 - Programming for Cybersecurity - Week 7 Lab (Defensive)

WHAT THIS TOOL DOES
-------------------
This is a signature-based WAF that inspects HTTP requests for the four
injection-style attack classes called out in the lab brief:

    * SQL Injection       (SQLi)
    * Cross-Site Scripting (XSS)
    * Path / Directory Traversal
    * OS Command Injection (CMDi)

The same rule engine powers three things, so there is exactly one place where
detection logic lives:

    1. A real Flask middleware (protect()) that blocks malicious live requests.
    2. A batch analyzer (--scan-file) that runs a file of payloads / HTTP
       requests through the engine and reports what would be blocked.
    3. A self-contained demo (--demo) that fires OWASP Web Security Testing
       Guide (WSTG) payloads at a deliberately vulnerable app, with the WAF
       off (to prove the app is vulnerable) and then on (to prove the WAF
       blocks the attack before it reaches the vulnerable code).

DESIGN NOTES
------------
The engine borrows two ideas from the OWASP ModSecurity Core Rule Set (CRS)
because they are exactly what the lab asks for when it says "tune false-positive
rates":

    * Anomaly scoring. A request is not blocked by a single rule; every matching
      rule adds a severity-weighted score, and the request is blocked only when
      the total crosses a threshold. This makes tuning a dial, not a rewrite.

    * Paranoia levels (1-4). Level 1 holds only high-confidence rules (very few
      false positives). Higher levels switch on more aggressive rules that catch
      more attacks but also flag more benign traffic. The false-positive write-up
      is produced by sweeping these levels (--demo prints the sweep).

Evasion resistance: every value is normalized (URL-decoded up to two passes,
HTML-entity-decoded, unicode-normalized, lower-cased) before matching, so
encoded payloads such as %2e%2e%2f or &lt;script&gt; are still caught.

USAGE
-----
    python waf.py --lab                 # offline self-test, no network
    python waf.py --demo                # vulnerable app + OWASP attacks + report
    python waf.py --scan-file tests.txt # analyze your own payloads / requests
    python waf.py --serve               # run the protected app on a real port
    python waf.py --serve --no-waf      # run it UNPROTECTED (to compare)

Common options:
    --paranoia {1,2,3,4}   rule aggressiveness           (default 2)
    --threshold N          anomaly score needed to block (default 5)
    --categories LIST      e.g. sqli,xss,traversal,cmdi  (default all)
    --mode {block,detect}  block requests, or only log   (default block)
    --report PATH          write a findings report to PATH(.html/.pdf)
    --format {html,pdf,both}                              (default both)

Author: Aubrey Freiburger
"""

import argparse
import html
import json
import os
import re
import sys
import threading
import unicodedata
import urllib.parse
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime, timezone

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Console encoding hardening.
#
# On Windows the console defaults to cp1252, which raised UnicodeEncodeError in
# earlier tools in this project. Force UTF-8 where the runtime allows it, and
# keep all console output ASCII-only regardless so nothing can crash a print.
# ---------------------------------------------------------------------------
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


# ===========================================================================
# SECTION 1 - SEVERITY MODEL
# ===========================================================================
# CRS-style severities, each worth a fixed number of anomaly points. A single
# CRITICAL match (5) therefore blocks at the default threshold of 5; it takes
# two WARNINGs or three NOTICEs to do the same. This is the knob the lab's
# false-positive tuning turns.

SEVERITY_SCORE = {
    "CRITICAL": 5,
    "HIGH": 4,
    "WARNING": 3,
    "NOTICE": 2,
}

# Order used when sorting / coloring, most severe first.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "WARNING", "NOTICE"]

# Human labels for the four attack categories.
CATEGORY_LABELS = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "traversal": "Path Traversal",
    "cmdi": "Command Injection",
}
ALL_CATEGORIES = list(CATEGORY_LABELS.keys())


# ===========================================================================
# SECTION 2 - RULE DEFINITIONS (the signature knowledge base)
# ===========================================================================
# Each rule carries everything the engine and the report need: a stable id, its
# attack category, a severity, the compiled patterns, the request parts it
# applies to, the minimum paranoia level that activates it, a plain-English
# description, and remediation advice the report can quote back to a developer.
#
# Patterns are written against the NORMALIZED (decoded, lower-cased) view of a
# value, so they are deliberately lower-case and do not try to account for URL
# or HTML encoding themselves - the normalizer handles that.

@dataclass
class Rule:
    id: str
    category: str
    severity: str
    description: str
    remediation: str
    patterns: list          # list of compiled regex
    paranoia: int = 1       # minimum paranoia level that enables this rule
    targets: tuple = ("path", "query", "body", "cookie", "header")

    @property
    def score(self) -> int:
        return SEVERITY_SCORE[self.severity]


def _c(pattern: str):
    """Compile a pattern case-insensitively with DOTALL for multiline bodies."""
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


def _build_rules():
    """Return the full rule set. Kept in a function so --lab can rebuild it."""
    rules = []

    # ----- SQL INJECTION ---------------------------------------------------
    rules += [
        Rule(
            id="SQLI-001",
            category="sqli",
            severity="CRITICAL",
            description="SQL boolean tautology or comment-based authentication "
                        "bypass (e.g. ' OR '1'='1, admin'-- -, \" or \"\"=\").",
            remediation="Use parameterized queries / prepared statements. Never "
                        "build SQL by string concatenation with user input.",
            patterns=[
                _c(r"('|\"|`)\s*(or|and)\s+('|\"|`)?\s*\d+\s*('|\"|`)?\s*=\s*('|\"|`)?\s*\d+"),
                _c(r"\b(or|and)\s+('|\")?[\w\s]+('|\")?\s*=\s*('|\")?[\w\s]+('|\")?\s*(--|#|/\*|$)"),
                _c(r"('|\")\s*(or|and)\s+('|\")[^'\"]*('|\")\s*=\s*('|\")"),
                # Classic auth bypass: a quote immediately closed by a line comment
                # (admin'--, ' or 1=1 #, foo'-- -). High-confidence SQLi signature.
                _c(r"('|\"|`)\s*(--|#)"),
            ],
            paranoia=1,
        ),
        Rule(
            id="SQLI-002",
            category="sqli",
            severity="CRITICAL",
            description="UNION-based SQL injection (UNION SELECT).",
            remediation="Parameterize queries and apply least-privilege DB "
                        "accounts so UNION reads are not possible.",
            patterns=[_c(r"\bunion\b\s+(all\s+)?\bselect\b")],
            paranoia=1,
        ),
        Rule(
            id="SQLI-003",
            category="sqli",
            severity="CRITICAL",
            description="Stacked / piggy-backed query that chains a second "
                        "statement (; DROP, ; DELETE, ; UPDATE, ; INSERT).",
            remediation="Disable multi-statement execution in the DB driver and "
                        "use parameterized queries.",
            patterns=[_c(r";\s*(drop|delete|insert|update|create|alter|truncate|exec|execute)\b")],
            paranoia=1,
        ),
        Rule(
            id="SQLI-004",
            category="sqli",
            severity="CRITICAL",
            description="Time-based blind SQLi function "
                        "(SLEEP, WAITFOR DELAY, BENCHMARK, pg_sleep).",
            remediation="Parameterize queries; set statement timeouts; alert on "
                        "slow queries from the app account.",
            patterns=[
                _c(r"\b(sleep|benchmark|pg_sleep|dbms_pipe\.receive_message)\s*\("),
                _c(r"\bwaitfor\s+delay\b"),
            ],
            paranoia=1,
        ),
        Rule(
            id="SQLI-005",
            category="sqli",
            severity="WARNING",
            description="Inline SQL comment (/* ... */) often used to split up "
                        "keywords and evade naive filters.",
            remediation="Parameterize queries; reject unbalanced quotes and "
                        "comment sequences at the input-validation layer.",
            patterns=[
                _c(r"/\*.*?\*/"),
            ],
            paranoia=2,
        ),
        Rule(
            id="SQLI-006",
            category="sqli",
            severity="WARNING",
            description="SQL metadata / injection helper functions and hex "
                        "literals (CONCAT, CHAR, 0x..., information_schema).",
            remediation="Parameterize queries; restrict access to "
                        "information_schema for the app DB account.",
            patterns=[
                _c(r"\b(concat|char|ascii|substring|group_concat|load_file|extractvalue|updatexml)\s*\("),
                _c(r"\binformation_schema\b"),
                _c(r"\b0x[0-9a-f]{4,}\b"),
            ],
            paranoia=3,
        ),
    ]

    # ----- CROSS-SITE SCRIPTING -------------------------------------------
    rules += [
        Rule(
            id="XSS-001",
            category="xss",
            severity="CRITICAL",
            description="HTML <script> tag in user input.",
            remediation="Context-aware output encoding (e.g. HTML-escape before "
                        "rendering). Add a strict Content-Security-Policy.",
            patterns=[_c(r"<\s*script\b"), _c(r"<\s*/\s*script\s*>")],
            paranoia=1,
        ),
        Rule(
            id="XSS-002",
            category="xss",
            severity="CRITICAL",
            description="Inline event handler used as an XSS vector "
                        "(onerror=, onload=, onclick=, onmouseover=, ...).",
            remediation="HTML-attribute-encode output; disallow user-supplied "
                        "HTML attributes; enforce CSP without inline handlers.",
            patterns=[_c(r"\bon[a-z]{3,15}\s*=\s*['\"]?[^'\"]*[\w(]")],
            paranoia=1,
        ),
        Rule(
            id="XSS-003",
            category="xss",
            severity="HIGH",
            description="javascript:/vbscript: URI scheme or data: URI carrying "
                        "script.",
            remediation="Validate URLs against an allow-list of schemes "
                        "(http/https/mailto); never reflect raw href/src values.",
            patterns=[
                _c(r"javascript\s*:"),
                _c(r"vbscript\s*:"),
                _c(r"data\s*:\s*text/html"),
            ],
            paranoia=1,
        ),
        Rule(
            id="XSS-004",
            category="xss",
            severity="HIGH",
            description="Dangerous HTML sink tag that commonly carries XSS "
                        "(<img>, <svg>, <iframe>, <object>, <embed>, <body>).",
            remediation="HTML-escape output; sanitize rich input with a vetted "
                        "library (e.g. DOMPurify) rather than a denylist.",
            patterns=[_c(r"<\s*(img|svg|iframe|object|embed|body|video|audio|details|marquee)\b")],
            paranoia=2,
        ),
        Rule(
            id="XSS-005",
            category="xss",
            severity="WARNING",
            description="Script execution / DOM sink keyword "
                        "(alert(, eval(, document.cookie, document.write, "
                        "String.fromCharCode).",
            remediation="Avoid eval and document.write; HTML-escape output; set "
                        "HttpOnly on session cookies so they are not readable.",
            patterns=[
                _c(r"\b(alert|prompt|confirm|eval)\s*\("),
                _c(r"document\s*\.\s*(cookie|write|location)"),
                _c(r"\bstring\s*\.\s*fromcharcode\s*\("),
            ],
            paranoia=2,
        ),
        Rule(
            id="XSS-006",
            category="xss",
            severity="NOTICE",
            description="Angle brackets around an unknown tag - possible HTML "
                        "injection probe.",
            remediation="HTML-escape all reflected output; this rule is a "
                        "low-confidence hint and is best used above paranoia 2.",
            patterns=[_c(r"<\s*[a-z][a-z0-9]*[\s/>]")],
            paranoia=3,
        ),
    ]

    # ----- PATH TRAVERSAL --------------------------------------------------
    rules += [
        Rule(
            id="LFI-001",
            category="traversal",
            severity="CRITICAL",
            description="Directory traversal sequence (../ or ..\\), including "
                        "encoded and nested-bypass forms once normalized.",
            remediation="Resolve the canonical path and confirm it stays inside "
                        "the intended base directory; never pass user input to "
                        "open()/fopen() directly.",
            patterns=[
                _c(r"\.\.[\\/]"),
                _c(r"\.\.(%2f|%5c)"),
                _c(r"(%2e){2}[\\/]"),
            ],
            paranoia=1,
            targets=("path", "query", "body", "cookie"),
        ),
        Rule(
            id="LFI-002",
            category="traversal",
            severity="HIGH",
            description="Reference to a known sensitive system file "
                        "(/etc/passwd, /etc/shadow, win.ini, boot.ini, "
                        "/proc/self, web.config).",
            remediation="Serve files by opaque id from an allow-list, not by "
                        "user-supplied name or path.",
            patterns=[
                _c(r"/etc/(passwd|shadow|hosts|group)"),
                _c(r"\b(boot\.ini|win\.ini|system32|web\.config|\.htaccess)\b"),
                _c(r"/proc/self/"),
            ],
            paranoia=1,
            targets=("path", "query", "body", "cookie"),
        ),
        Rule(
            id="LFI-003",
            category="traversal",
            severity="HIGH",
            description="Null-byte or stream wrapper used to bypass extension "
                        "checks (%00, php://, file://, expect://).",
            remediation="Reject null bytes and URI wrappers in file parameters; "
                        "validate on a canonical, decoded value.",
            patterns=[
                _c(r"%00"),
                _c(r"\x00"),
                _c(r"\b(php|file|expect|zip|phar|data)://"),
            ],
            paranoia=2,
            targets=("path", "query", "body", "cookie"),
        ),
    ]

    # ----- COMMAND INJECTION ----------------------------------------------
    rules += [
        Rule(
            id="CMDI-001",
            category="cmdi",
            severity="CRITICAL",
            description="Shell command separator followed by a common command "
                        "(; | & with ls, cat, id, whoami, nc, curl, wget, ...).",
            remediation="Never pass user input to a shell. Use argument-vector "
                        "APIs (subprocess with a list, no shell=True) and "
                        "validate against an allow-list.",
            patterns=[
                _c(r"[;&|]\s*(ls|cat|id|whoami|pwd|uname|nc|ncat|netcat|curl|wget|"
                   r"bash|sh|zsh|ksh|cmd|powershell|ping|nslookup|dir|type|more|"
                   r"net|systeminfo|ipconfig|ifconfig|rm|del|chmod|chown)\b"),
            ],
            paranoia=1,
        ),
        Rule(
            id="CMDI-002",
            category="cmdi",
            severity="CRITICAL",
            description="Command substitution via $(...), backticks, or ${...}.",
            remediation="Avoid shell invocation; if unavoidable, pass arguments "
                        "as a list and never interpolate user input.",
            patterns=[
                _c(r"\$\([^)]*\)"),
                _c(r"`[^`]+`"),
                _c(r"\$\{[^}]*\}"),
            ],
            paranoia=1,
        ),
        Rule(
            id="CMDI-003",
            category="cmdi",
            severity="HIGH",
            description="Logical command chaining (&&, ||) or a pipe into a "
                        "shell interpreter.",
            remediation="Do not build shell strings from input; use parameterized "
                        "process execution.",
            patterns=[
                _c(r"(&&|\|\|)\s*\w"),
                _c(r"\|\s*(sh|bash|cmd|powershell|python|perl)\b"),
            ],
            paranoia=2,
        ),
        Rule(
            id="CMDI-004",
            category="cmdi",
            severity="WARNING",
            description="Reference to a shell environment variable or Windows "
                        "system path often seen in CMDi payloads "
                        "(%SYSTEMROOT%, $PATH, $IFS).",
            remediation="Validate input against an allow-list; strip shell "
                        "metacharacters before any OS call.",
            patterns=[
                _c(r"%(systemroot|windir|comspec|path)%"),
                _c(r"\$\{?(ifs|path|home)\b"),
            ],
            paranoia=3,
        ),
    ]

    return rules


RULES = _build_rules()


# ===========================================================================
# SECTION 3 - INPUT NORMALIZATION (evasion resistance)
# ===========================================================================
# Attackers hide payloads behind layers of encoding. Before a value is matched
# against any rule, it is expanded into a set of "views": the raw value plus
# progressively decoded forms. A rule matches if ANY view matches, so
# %2e%2e%2f, ..%2f, and &lt;script&gt; are all caught by the plain patterns.

def normalize_views(value: str) -> list:
    """Return a de-duplicated list of decoded views of a single value."""
    if value is None:
        return [""]
    views = []
    seen = set()

    def add(v):
        if v is None:
            return
        low = v.lower()
        if low not in seen:
            seen.add(low)
            views.append(low)

    add(value)

    # URL decode, up to two passes to defeat double-encoding (%252e -> %2e -> .)
    current = value
    for _ in range(2):
        try:
            decoded = urllib.parse.unquote(current)
        except Exception:
            break
        if decoded == current:
            break
        add(decoded)
        current = decoded

    # HTML entity decode (&lt; &#60; &#x3c; -> <)
    try:
        add(html.unescape(value))
        add(html.unescape(current))
    except Exception:
        pass

    # Unicode normalization (NFKC folds full-width and compatibility chars)
    try:
        add(unicodedata.normalize("NFKC", current))
    except Exception:
        pass

    # Collapse backslashes to forward slashes so ..\ and ../ look alike,
    # and strip common no-op obfuscation whitespace sequences.
    add(current.replace("\\", "/"))

    return views


# ===========================================================================
# SECTION 4 - THE WAF ENGINE
# ===========================================================================

@dataclass
class Detection:
    """A single rule firing against a single request value."""
    rule_id: str
    category: str
    severity: str
    score: int
    location: str          # where it matched: "query:id", "body", "path", ...
    matched: str           # the snippet that matched (truncated, for the report)
    description: str
    remediation: str


@dataclass
class InspectionResult:
    """The engine's verdict for one request."""
    decision: str                      # "allow" | "block"
    score: int
    detections: list
    request_label: str = ""            # human label, e.g. "GET /search?q=..."
    mode: str = "block"

    @property
    def blocked(self) -> bool:
        return self.decision == "block"

    @property
    def top_severity(self) -> str:
        for sev in SEVERITY_ORDER:
            if any(d.severity == sev for d in self.detections):
                return sev
        return "NONE"

    @property
    def categories_hit(self) -> list:
        out = []
        for d in self.detections:
            if d.category not in out:
                out.append(d.category)
        return out


@dataclass
class WAFConfig:
    enabled_categories: tuple = tuple(ALL_CATEGORIES)
    paranoia: int = 2
    anomaly_threshold: int = 5
    mode: str = "block"                # "block" or "detect"
    max_value_len: int = 20000         # guard against pathological inputs

    def normalized(self):
        cats = tuple(c for c in self.enabled_categories if c in ALL_CATEGORIES)
        pl = min(4, max(1, int(self.paranoia)))
        return WAFConfig(
            enabled_categories=cats or tuple(ALL_CATEGORIES),
            paranoia=pl,
            anomaly_threshold=max(1, int(self.anomaly_threshold)),
            mode=self.mode if self.mode in ("block", "detect") else "block",
            max_value_len=self.max_value_len,
        )


class WAFEngine:
    """Stateless rule engine. Build once, inspect many requests."""

    def __init__(self, config: WAFConfig = None):
        self.config = (config or WAFConfig()).normalized()
        self.active_rules = [
            r for r in RULES
            if r.category in self.config.enabled_categories
            and r.paranoia <= self.config.paranoia
        ]

    # -- low level: inspect one string value --------------------------------
    def inspect_value(self, value, location: str) -> list:
        if not value:
            return []
        value = str(value)
        if len(value) > self.config.max_value_len:
            value = value[: self.config.max_value_len]

        views = normalize_views(value)
        found = []
        seen_rule_here = set()

        for rule in self.active_rules:
            # Only apply the rule to the request parts it declares.
            loc_kind = location.split(":", 1)[0]
            if loc_kind not in rule.targets:
                continue
            if rule.id in seen_rule_here:
                continue
            for pattern in rule.patterns:
                hit = None
                for view in views:
                    m = pattern.search(view)
                    if m:
                        hit = m
                        break
                if hit:
                    snippet = hit.group(0)
                    if len(snippet) > 120:
                        snippet = snippet[:117] + "..."
                    found.append(Detection(
                        rule_id=rule.id,
                        category=rule.category,
                        severity=rule.severity,
                        score=rule.score,
                        location=location,
                        matched=snippet,
                        description=rule.description,
                        remediation=rule.remediation,
                    ))
                    seen_rule_here.add(rule.id)
                    break
        return found

    # -- high level: inspect a whole request --------------------------------
    def inspect_request(self, req: dict) -> InspectionResult:
        """
        `req` is a plain dict describing a request, so the engine never depends
        on Flask:
            {
              "method": "GET",
              "path": "/search",
              "query": {"q": "..."},          # or a raw query string
              "headers": {"User-Agent": "..."},
              "cookies": {"sid": "..."},
              "body": {"field": "..."} or "raw body string",
            }
        """
        detections = []

        # Path
        detections += self.inspect_value(req.get("path", ""), "path")

        # Query parameters
        detections += self._inspect_mapping(req.get("query"), "query")

        # Body (form fields or a raw string)
        body = req.get("body")
        if isinstance(body, dict):
            detections += self._inspect_mapping(body, "body")
        elif body:
            detections += self.inspect_value(body, "body")

        # Cookies
        detections += self._inspect_mapping(req.get("cookies"), "cookie")

        # Headers (only the ones attackers actually abuse, to limit FPs)
        headers = req.get("headers") or {}
        risky = ("user-agent", "referer", "x-forwarded-for", "cookie", "x-api-version")
        for name, val in headers.items():
            if name.lower() in risky:
                detections += self.inspect_value(val, f"header:{name}")

        total = sum(d.score for d in detections)
        if detections and total >= self.config.anomaly_threshold:
            decision = "block" if self.config.mode == "block" else "allow"
        else:
            decision = "allow"

        label = f"{req.get('method', 'GET')} {req.get('path', '/')}".strip()
        return InspectionResult(
            decision=decision,
            score=total,
            detections=detections,
            request_label=label,
            mode=self.config.mode,
        )

    def _inspect_mapping(self, mapping, kind: str) -> list:
        out = []
        if not mapping:
            return out
        if isinstance(mapping, str):
            # raw query string: inspect whole thing plus each decoded param
            out += self.inspect_value(mapping, kind)
            try:
                for k, vals in urllib.parse.parse_qs(mapping, keep_blank_values=True).items():
                    for v in vals:
                        out += self.inspect_value(v, f"{kind}:{k}")
            except Exception:
                pass
            return out
        for k, v in mapping.items():
            if isinstance(v, (list, tuple)):
                for item in v:
                    out += self.inspect_value(item, f"{kind}:{k}")
            else:
                out += self.inspect_value(v, f"{kind}:{k}")
        return out


# ===========================================================================
# SECTION 5 - FLASK MIDDLEWARE INTEGRATION
# ===========================================================================
# protect(app, config) installs the WAF as a before_request hook. If a request
# is blocked it never reaches your view function - the WAF returns 403 first.
# All of this is import-guarded so the file still runs with no Flask installed
# (e.g. for --scan-file on a bare Python).

try:
    from flask import Flask, request, Response, abort, g
    _HAVE_FLASK = True
except Exception:
    _HAVE_FLASK = False


BLOCK_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Request blocked</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#1b1f27;
color:#e7e9ee;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.box{max-width:30rem;padding:2rem;border:1px solid #39404d;border-radius:10px;background:#232832}
h1{margin:0 0 .5rem;font-size:1.3rem;color:#ff6b6b}code{background:#14181f;padding:.1rem .35rem;border-radius:4px}
p{line-height:1.5;color:#b9bfca}</style></head><body><div class="box">
<h1>403 - Request blocked by WAF</h1>
<p>Your request was flagged by the web application firewall and was not processed.</p>
<p>Reference: <code>{ref}</code></p></div></body></html>"""


def protect(app, config: WAFConfig = None, log: bool = True):
    """Attach the WAF engine to a Flask app as inbound middleware."""
    if not _HAVE_FLASK:
        raise RuntimeError("Flask is not installed; cannot attach middleware.")
    engine = WAFEngine(config)
    app.config["WAF_ENGINE"] = engine
    app.config.setdefault("WAF_LOG", [])

    def _describe():
        try:
            raw_body = request.get_data(cache=True, as_text=True) or ""
        except Exception:
            raw_body = ""
        form = request.form.to_dict(flat=False) if request.form else {}
        return {
            "method": request.method,
            "path": request.path,
            "query": request.args.to_dict(flat=False),
            "headers": dict(request.headers),
            "cookies": request.cookies.to_dict(),
            "body": form if form else raw_body,
        }

    @app.before_request
    def _waf_before_request():
        result = engine.inspect_request(_describe())
        g.waf_result = result
        if log:
            app.config["WAF_LOG"].append(result)
        if result.blocked:
            ref = f"WAF-{len(app.config['WAF_LOG']):04d}"
            page = BLOCK_PAGE.replace("{ref}", ref)
            return Response(page, status=403, mimetype="text/html")
        return None

    return engine


# ===========================================================================
# SECTION 6 - DELIBERATELY VULNERABLE DEMO APP
# ===========================================================================
# The lab says "test it against a deliberately vulnerable local app." This is
# that app - a tiny intentionally-insecure Flask app, DVWA-in-miniature.
#
# SAFETY: SQLi and reflected XSS are exploited for real because they are safe in
# a sandbox (in-memory SQLite, reflected text). Path traversal is real but
# sandboxed to a throwaway temp directory seeded with decoy files, so it cannot
# touch the real filesystem. Command injection uses a SIMULATED shell that
# returns the command string it WOULD run but never executes it - demonstrating
# the flaw without any real remote-code-execution risk.

import sqlite3
import tempfile


def _seed_traversal_sandbox() -> str:
    """Create a temp dir with a public file and decoy 'secret' files."""
    base = tempfile.mkdtemp(prefix="waf_demo_")
    public = os.path.join(base, "public")
    os.makedirs(public, exist_ok=True)
    with open(os.path.join(public, "readme.txt"), "w", encoding="utf-8") as fh:
        fh.write("Public file. Nothing secret here.\n")
    # Decoy "sensitive" files one level up from the public dir.
    with open(os.path.join(base, "secret.txt"), "w", encoding="utf-8") as fh:
        fh.write("TOP SECRET (decoy): flag{path_traversal_succeeded}\n")
    etc = os.path.join(base, "etc")
    os.makedirs(etc, exist_ok=True)
    with open(os.path.join(etc, "passwd"), "w", encoding="utf-8") as fh:
        fh.write("root:x:0:0:(decoy) demo passwd file:/root:/bin/bash\n")
    return base


def build_vulnerable_app(with_waf: bool = False, config: WAFConfig = None):
    """Return a Flask app that is intentionally vulnerable (optionally WAF-protected)."""
    if not _HAVE_FLASK:
        raise RuntimeError("Flask is not installed; cannot build the demo app.")

    app = Flask(__name__)
    app.config["WAF_LOG"] = []

    # In-memory user table for the SQLi demo.
    def _db():
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT, role TEXT)")
        conn.executemany(
            "INSERT INTO users VALUES (?,?,?,?)",
            [(1, "admin", "s3cr3t!", "admin"), (2, "alice", "hunter2", "user")],
        )
        return conn

    sandbox = _seed_traversal_sandbox()
    public_dir = os.path.join(sandbox, "public")

    @app.route("/")
    def index():
        return (
            "<h1>Vulnerable Demo App</h1><ul>"
            "<li>GET /login?username=admin&amp;password=x (SQLi)</li>"
            "<li>GET /search?q=hello (reflected XSS)</li>"
            "<li>GET /download?name=readme.txt (path traversal)</li>"
            "<li>GET /ping?host=127.0.0.1 (command injection, simulated)</li>"
            "</ul>"
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        src = request.form if request.method == "POST" else request.args
        username = src.get("username", "")
        password = src.get("password", "")
        # VULNERABLE: query built by string formatting.
        query = (
            "SELECT username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        conn = _db()
        try:
            row = conn.execute(query).fetchone()
        except sqlite3.Error as exc:
            return f"<p>SQL error: {html.escape(str(exc))}</p>", 200
        finally:
            conn.close()
        if row:
            return f"<p>Welcome {html.escape(row[0])}! Role: {html.escape(row[1])}</p>"
        return "<p>Invalid credentials.</p>", 401

    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        # VULNERABLE: user input reflected into HTML without escaping.
        return f"<h2>Search</h2><p>Results for: {q}</p>"

    @app.route("/download")
    def download():
        name = request.args.get("name", "readme.txt")
        # VULNERABLE: path joined with user input, no canonicalization check.
        target = os.path.join(public_dir, name)
        try:
            with open(target, "r", encoding="utf-8", errors="replace") as fh:
                data = fh.read()
            return f"<pre>{html.escape(data)}</pre>"
        except OSError as exc:
            return f"<p>Could not read file: {html.escape(str(exc))}</p>", 404

    @app.route("/ping")
    def ping():
        host = request.args.get("host", "127.0.0.1")
        # VULNERABLE PATTERN: this string would be passed to a shell. We build
        # it to show the injection, but we DO NOT execute it (safety). A real
        # vulnerable app would call os.system(cmd) here.
        cmd = f"ping -c 1 {host}"
        return (
            "<p>(simulated) would run shell command:</p>"
            f"<pre>{html.escape(cmd)}</pre>"
        )

    if with_waf:
        protect(app, config)

    return app


# ===========================================================================
# SECTION 7 - OWASP TEST CORPUS (WSTG) + BENIGN CORPUS
# ===========================================================================
# Representative payloads drawn from the OWASP Web Security Testing Guide
# categories WSTG-INPV-05 (SQLi), WSTG-INPV-01 (XSS), WSTG-ATHZ-01 (traversal),
# and WSTG-INPV-12 (command injection). Each entry: (name, payload, category,
# where it should be placed when synthesizing a request).

OWASP_PAYLOADS = [
    # --- SQL injection (WSTG-INPV-05) ---
    ("SQLi tautology", "' OR '1'='1", "sqli", "login"),
    ("SQLi auth bypass comment", "admin'-- -", "sqli", "login"),
    ("SQLi UNION select", "' UNION SELECT username, password FROM users-- -", "sqli", "login"),
    ("SQLi stacked drop", "'; DROP TABLE users;-- -", "sqli", "login"),
    ("SQLi time-based", "1' AND SLEEP(5)-- -", "sqli", "login"),
    ("SQLi boolean numeric", "1 OR 1=1", "sqli", "login"),
    # --- Cross-site scripting (WSTG-INPV-01) ---
    ("XSS script tag", "<script>alert(1)</script>", "xss", "search"),
    ("XSS img onerror", "<img src=x onerror=alert(document.cookie)>", "xss", "search"),
    ("XSS svg onload", "<svg/onload=alert(1)>", "xss", "search"),
    ("XSS javascript uri", "javascript:alert(1)", "xss", "search"),
    ("XSS encoded", "%3Cscript%3Ealert(1)%3C%2Fscript%3E", "xss", "search"),
    ("XSS entity encoded", "&lt;script&gt;alert(1)&lt;/script&gt;", "xss", "search"),
    # --- Path traversal (WSTG-ATHZ-01) ---
    ("Traversal unix passwd", "../../../../etc/passwd", "traversal", "download"),
    ("Traversal to secret", "../secret.txt", "traversal", "download"),
    ("Traversal encoded", "..%2f..%2f..%2fetc%2fpasswd", "traversal", "download"),
    ("Traversal double-encoded", "..%252f..%252fsecret.txt", "traversal", "download"),
    ("Traversal windows", "..\\..\\..\\windows\\win.ini", "traversal", "download"),
    ("Traversal null byte", "../secret.txt%00.png", "traversal", "download"),
    # --- Command injection (WSTG-INPV-12) ---
    ("CMDi semicolon", "127.0.0.1; cat /etc/passwd", "cmdi", "ping"),
    ("CMDi pipe", "127.0.0.1 | whoami", "cmdi", "ping"),
    ("CMDi substitution", "127.0.0.1 $(id)", "cmdi", "ping"),
    ("CMDi backticks", "127.0.0.1 `uname -a`", "cmdi", "ping"),
    ("CMDi logical and", "127.0.0.1 && dir", "cmdi", "ping"),
]

# Benign inputs that naive WAFs flag by mistake. These drive the false-positive
# analysis: a good rule set lets most of these through, especially at low PL.
BENIGN_PAYLOADS = [
    ("Name with apostrophe", "O'Brien", "login"),
    ("Search for a book", "SQL injection explained for beginners", "search"),
    ("Boolean search text", "cats and dogs", "search"),
    ("Comparison in search", "price < 100 and rating > 4", "search"),
    ("Code talk", "how do I use the SELECT statement in SQL", "search"),
    ("HTML snippet question", "what does <b>bold</b> mean in html", "search"),
    ("File name", "quarterly-report-2026.pdf", "download"),
    ("Nested folder legit", "images/products/logo.png", "download"),
    ("Hostname", "server-01.internal.example.com", "ping"),
    ("Math expression", "result = (a + b) * c", "search"),
    ("Windows path legit", "Documents\\report.docx", "download"),
    ("Email address", "alice@example.com", "login"),
    # The following are legitimate but "technical" inputs - the kind a developer
    # forum, CMS, or docs-site search really receives. They mix a SQL/shell term
    # with an HTML tag, so they trip two aggressive (PL3+) rules each and cross
    # the block threshold only at high paranoia. These are the classic source of
    # WAF false positives and are what make the paranoia sweep show a real
    # detection-vs-false-positive tradeoff.
    ("Dev Q: concat in span", "how do I wrap CONCAT(first, last) output in a <span> element", "search"),
    ("Dev Q: substring in div", "use SUBSTRING(title, 1, 20) then render it inside a <div>", "search"),
    ("Dev Q: env var in pre", "echo the %PATH% variable into a <pre> block for the docs", "search"),
    ("Dev Q: schema in table", "select from information_schema and show results in a <table>", "search"),
]


def _synthesize_request(payload: str, where: str) -> dict:
    """Place a raw payload where a real attacker would put it."""
    where = (where or "search").lower()
    if where == "login":
        return {"method": "POST", "path": "/login",
                "body": {"username": payload, "password": "x"}}
    if where == "search":
        return {"method": "GET", "path": "/search", "query": {"q": payload}}
    if where == "download":
        return {"method": "GET", "path": "/download", "query": {"name": payload}}
    if where == "ping":
        return {"method": "GET", "path": "/ping", "query": {"host": payload}}
    # default: drop it in a generic query param
    return {"method": "GET", "path": "/", "query": {"input": payload}}


# ===========================================================================
# SECTION 8 - FALSE-POSITIVE / DETECTION ANALYSIS
# ===========================================================================

def paranoia_sweep(threshold: int, categories) -> list:
    """
    For each paranoia level 1-4, measure detection rate on the OWASP corpus and
    false-positive rate on the benign corpus. This is the raw material for the
    'false-positive analysis and rule refinement' write-up.
    """
    rows = []
    for pl in (1, 2, 3, 4):
        cfg = WAFConfig(enabled_categories=tuple(categories), paranoia=pl,
                        anomaly_threshold=threshold, mode="block")
        engine = WAFEngine(cfg)

        caught = 0
        for _name, payload, _cat, where in OWASP_PAYLOADS:
            res = engine.inspect_request(_synthesize_request(payload, where))
            if res.blocked:
                caught += 1

        false_pos = 0
        for _name, payload, where in BENIGN_PAYLOADS:
            res = engine.inspect_request(_synthesize_request(payload, where))
            if res.blocked:
                false_pos += 1

        total_mal = len(OWASP_PAYLOADS)
        total_ben = len(BENIGN_PAYLOADS)
        rows.append({
            "paranoia": pl,
            "active_rules": len(engine.active_rules),
            "detected": caught,
            "total_malicious": total_mal,
            "detection_rate": round(100.0 * caught / total_mal, 1),
            "false_positives": false_pos,
            "total_benign": total_ben,
            "false_positive_rate": round(100.0 * false_pos / total_ben, 1),
        })
    return rows


# ===========================================================================
# SECTION 9 - REPORT MODEL + RENDERERS (HTML and PDF)
# ===========================================================================

@dataclass
class ReportModel:
    title: str
    generated: str
    config: WAFConfig
    source_label: str                 # what was tested
    results: list                     # list of (meta_name, InspectionResult)
    sweep: list = field(default_factory=list)   # paranoia sweep rows (optional)
    notes: list = field(default_factory=list)

    # ---- derived summary numbers ----
    @property
    def total(self):
        return len(self.results)

    @property
    def blocked(self):
        return sum(1 for _n, r in self.results if r.blocked)

    @property
    def allowed(self):
        return self.total - self.blocked

    @property
    def total_detections(self):
        return sum(len(r.detections) for _n, r in self.results)

    def category_counts(self):
        counts = {c: 0 for c in ALL_CATEGORIES}
        for _n, r in self.results:
            for cat in r.categories_hit:
                counts[cat] = counts.get(cat, 0) + 1
        return counts

    def severity_counts(self):
        counts = {s: 0 for s in SEVERITY_ORDER}
        for _n, r in self.results:
            for d in r.detections:
                counts[d.severity] = counts.get(d.severity, 0) + 1
        return counts


def _ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ----- HTML report ---------------------------------------------------------
# Design brief: a security-operations findings report. Severity color carries
# information (it is the point of the report), so the palette is driven by the
# four severities; the brand furniture (header rule, section markers) stays
# quiet slate. Body/UI in IBM Plex Sans; payloads, rule ids and patterns in IBM
# Plex Mono, because those are literal code and monospacing is meaningful here,
# not decoration. Prints cleanly.

_SEV_COLOR = {
    "CRITICAL": "#b4232a",
    "HIGH": "#c2410c",
    "WARNING": "#a16207",
    "NOTICE": "#4b5563",
    "NONE": "#15803d",
}


def _esc(s):
    return html.escape(str(s), quote=True)


def render_html_report(model: ReportModel) -> str:
    cfg = model.config
    cat_counts = model.category_counts()
    sev_counts = model.severity_counts()

    verdict_clean = model.blocked == 0 and model.total_detections == 0
    verdict_color = "#15803d" if verdict_clean else "#b4232a"
    verdict_text = (
        "No attacks detected in this sample"
        if verdict_clean else
        f"{model.blocked} of {model.total} requests blocked"
    )

    # --- category coverage strip ---
    cat_cells = []
    for cat in ALL_CATEGORIES:
        enabled = cat in cfg.enabled_categories
        n = cat_counts.get(cat, 0)
        state = "on" if enabled else "off"
        cat_cells.append(f"""
        <div class="cat {state}">
          <div class="cat-count">{n}</div>
          <div class="cat-name">{_esc(CATEGORY_LABELS[cat])}</div>
          <div class="cat-state">{'enabled' if enabled else 'disabled'}</div>
        </div>""")

    # --- severity chips ---
    sev_chips = []
    for sev in SEVERITY_ORDER:
        n = sev_counts.get(sev, 0)
        if n == 0:
            continue
        sev_chips.append(
            f'<span class="chip" style="--sev:{_SEV_COLOR[sev]}">'
            f'<b>{n}</b> {sev.title()}</span>'
        )
    sev_chips_html = "".join(sev_chips) or '<span class="chip ok">No rule matches</span>'

    # --- findings rows ---
    rows = []
    for name, res in model.results:
        if res.blocked:
            decision = '<span class="pill block">BLOCKED</span>'
        elif res.detections:
            decision = '<span class="pill warn">FLAGGED</span>'
        else:
            decision = '<span class="pill pass">ALLOWED</span>'

        if res.detections:
            det_bits = []
            for d in sorted(res.detections, key=lambda x: SEVERITY_ORDER.index(x.severity)):
                det_bits.append(
                    f'<div class="det">'
                    f'<span class="rid" style="--sev:{_SEV_COLOR[d.severity]}">{_esc(d.rule_id)}</span>'
                    f'<span class="dloc">{_esc(d.location)}</span>'
                    f'<code class="match">{_esc(d.matched)}</code>'
                    f'</div>'
                )
            det_html = "".join(det_bits)
        else:
            det_html = '<span class="muted">no rules matched</span>'

        rows.append(f"""
      <tr>
        <td class="c-name">{_esc(name)}<div class="req">{_esc(res.request_label)}</div></td>
        <td class="c-det">{det_html}</td>
        <td class="c-score">{res.score}</td>
        <td class="c-dec">{decision}</td>
      </tr>""")
    rows_html = "".join(rows) if rows else (
        '<tr><td colspan="4" class="muted">No requests were inspected.</td></tr>'
    )

    # --- paranoia sweep table (optional) ---
    sweep_html = ""
    if model.sweep:
        srows = []
        for r in model.sweep:
            current = " current" if r["paranoia"] == cfg.paranoia else ""
            srows.append(f"""
        <tr class="sweep{current}">
          <td>PL{r['paranoia']}{' &larr; this run' if current else ''}</td>
          <td>{r['active_rules']}</td>
          <td>{r['detected']}/{r['total_malicious']}</td>
          <td><span class="bar"><span style="width:{r['detection_rate']}%;background:#15803d"></span></span>{r['detection_rate']}%</td>
          <td>{r['false_positives']}/{r['total_benign']}</td>
          <td><span class="bar"><span style="width:{r['false_positive_rate']}%;background:#b4232a"></span></span>{r['false_positive_rate']}%</td>
        </tr>""")
        sweep_html = f"""
    <section>
      <h2><span class="mark"></span>False-positive analysis</h2>
      <p class="lead">Each paranoia level was run against {model.sweep[0]['total_malicious']} OWASP
      WSTG attack payloads and {model.sweep[0]['total_benign']} benign inputs at anomaly threshold
      {cfg.anomaly_threshold}. Raising the level catches more attacks but flags more legitimate
      traffic &mdash; pick the level and threshold that keep detection high while false positives stay
      acceptable for the app.</p>
      <table class="sweep-table">
        <thead><tr>
          <th>Paranoia</th><th>Active rules</th><th>Detected</th><th>Detection rate</th>
          <th>False positives</th><th>FP rate</th>
        </tr></thead>
        <tbody>{''.join(srows)}</tbody>
      </table>
    </section>"""

    # --- rules reference (only rules that were active) ---
    engine = WAFEngine(cfg)
    ref_rows = []
    for rule in sorted(engine.active_rules, key=lambda r: r.id):
        ref_rows.append(f"""
      <tr>
        <td><code>{_esc(rule.id)}</code></td>
        <td>{_esc(CATEGORY_LABELS[rule.category])}</td>
        <td><span class="sev-tag" style="--sev:{_SEV_COLOR[rule.severity]}">{rule.severity}</span> ({rule.score})</td>
        <td>{_esc(rule.description)}</td>
        <td class="rem">{_esc(rule.remediation)}</td>
      </tr>""")
    ref_html = "".join(ref_rows)

    notes_html = ""
    if model.notes:
        items = "".join(f"<li>{_esc(n)}</li>" for n in model.notes)
        notes_html = f'<section><h2><span class="mark"></span>Notes</h2><ul class="notes">{items}</ul></section>'

    cats_on = ", ".join(CATEGORY_LABELS[c] for c in cfg.enabled_categories)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(model.title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{{
    --ink:#1b1f27; --ink-2:#4b5563; --muted:#8b93a1;
    --paper:#ffffff; --panel:#f6f7f9; --panel-2:#eef0f3;
    --line:#e2e5ea; --line-strong:#cfd4dc;
    --brand:#44506b;
    --mono:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
    --sans:'IBM Plex Sans',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  }}
  *{{box-sizing:border-box}}
  html{{-webkit-text-size-adjust:100%}}
  body{{margin:0;background:var(--panel);color:var(--ink);font-family:var(--sans);
    font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}}
  .wrap{{max-width:1040px;margin:0 auto;padding:40px 28px 72px}}

  /* header */
  header.doc{{border-bottom:3px solid var(--brand);padding-bottom:20px;margin-bottom:28px}}
  .eyebrow{{font-family:var(--mono);font-size:12px;color:var(--brand);letter-spacing:.02em;margin:0 0 6px}}
  header.doc h1{{font-size:28px;font-weight:700;letter-spacing:-.01em;margin:0 0 14px;line-height:1.15}}
  .meta{{display:flex;flex-wrap:wrap;gap:4px 28px;font-size:13.5px;color:var(--ink-2)}}
  .meta div span{{color:var(--ink);font-weight:500}}
  .meta code{{font-family:var(--mono);font-size:12.5px;background:var(--panel-2);padding:1px 6px;border-radius:4px}}

  /* verdict */
  .verdict{{display:flex;align-items:center;gap:16px;margin:0 0 26px;padding:16px 20px;
    border-radius:10px;background:var(--paper);border:1px solid var(--line);
    border-left:6px solid var(--vc)}}
  .verdict .big{{font-size:30px;font-weight:700;color:var(--vc);line-height:1;font-variant-numeric:tabular-nums}}
  .verdict .vtext{{font-size:15px;color:var(--ink-2)}}
  .verdict .vtext b{{color:var(--ink)}}
  .chips{{margin-left:auto;display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end}}
  .chip{{font-size:12.5px;padding:4px 10px;border-radius:999px;background:var(--panel);
    border:1px solid var(--line-strong);color:var(--ink-2)}}
  .chip b{{color:var(--sev,var(--ink));font-variant-numeric:tabular-nums}}
  .chip.ok{{color:#15803d;border-color:#bbe5c6;background:#f0faf2}}

  /* category strip */
  .cats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:0 0 30px}}
  .cat{{background:var(--paper);border:1px solid var(--line);border-radius:10px;padding:14px 16px}}
  .cat.off{{background:var(--panel);opacity:.62}}
  .cat-count{{font-size:26px;font-weight:700;line-height:1;font-variant-numeric:tabular-nums}}
  .cat-name{{font-size:13.5px;font-weight:600;margin-top:6px}}
  .cat-state{{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:2px}}
  .cat.on .cat-state{{color:var(--brand)}}

  /* sections */
  section{{margin:0 0 34px}}
  h2{{font-size:18px;font-weight:600;margin:0 0 14px;display:flex;align-items:center;gap:10px}}
  h2 .mark{{width:10px;height:10px;background:var(--brand);border-radius:2px;flex:none}}
  .lead{{color:var(--ink-2);max-width:72ch;margin:-4px 0 16px}}

  /* findings table */
  table{{width:100%;border-collapse:collapse;background:var(--paper);
    border:1px solid var(--line);border-radius:10px;overflow:hidden}}
  thead th{{text-align:left;font-size:12px;font-weight:600;color:var(--ink-2);
    background:var(--panel);padding:10px 14px;border-bottom:1px solid var(--line-strong)}}
  tbody td{{padding:12px 14px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}}
  tbody tr:last-child td{{border-bottom:none}}
  .c-name{{width:26%;font-weight:600}}
  .req{{font-family:var(--mono);font-size:12px;color:var(--muted);font-weight:400;margin-top:3px;word-break:break-all}}
  .c-score{{width:7%;text-align:center;font-variant-numeric:tabular-nums;font-weight:600}}
  .c-dec{{width:12%;text-align:center}}
  .det{{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:7px}}
  .det:last-child{{margin-bottom:0}}
  .rid{{font-family:var(--mono);font-size:11.5px;font-weight:600;color:#fff;background:var(--sev);
    padding:2px 7px;border-radius:5px;flex:none}}
  .dloc{{font-family:var(--mono);font-size:11.5px;color:var(--ink-2);background:var(--panel-2);
    padding:2px 6px;border-radius:4px}}
  .match{{font-family:var(--mono);font-size:12px;color:#86202a;background:#fcecec;
    padding:2px 7px;border-radius:4px;word-break:break-all;max-width:100%}}
  .muted,.c-det .muted{{color:var(--muted);font-size:13px}}

  .pill{{font-family:var(--mono);font-size:11px;font-weight:600;padding:3px 9px;border-radius:999px;white-space:nowrap}}
  .pill.block{{color:#fff;background:#b4232a}}
  .pill.warn{{color:#7a4a00;background:#fdeccb;border:1px solid #f3cf8a}}
  .pill.pass{{color:#15803d;background:#edf8f0;border:1px solid #bbe5c6}}

  /* sweep */
  .sweep-table td{{font-size:14px}}
  .sweep.current td{{background:#f3f6fb;font-weight:600}}
  .bar{{display:inline-block;width:88px;height:7px;border-radius:4px;background:var(--panel-2);
    margin-right:8px;vertical-align:middle;overflow:hidden}}
  .bar span{{display:block;height:100%}}

  .sev-tag{{font-family:var(--mono);font-size:11px;font-weight:600;color:#fff;background:var(--sev);
    padding:1px 6px;border-radius:4px}}
  .rem{{color:var(--ink-2);font-size:13px}}
  .notes li{{margin-bottom:6px;color:var(--ink-2)}}

  footer{{margin-top:48px;padding-top:16px;border-top:1px solid var(--line);
    font-size:12.5px;color:var(--muted);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}}
  footer code{{font-family:var(--mono)}}

  @media (max-width:720px){{
    .cats{{grid-template-columns:repeat(2,1fr)}}
    .verdict{{flex-wrap:wrap}} .chips{{margin-left:0;justify-content:flex-start}}
    .c-name,.c-score,.c-dec{{width:auto}}
    thead{{display:none}}
    tbody td{{display:block;border-bottom:none}}
    tbody tr{{display:block;border-bottom:1px solid var(--line-strong);padding:6px 0}}
  }}
  @media print{{
    body{{background:#fff;font-size:11.5px}}
    .wrap{{max-width:none;padding:0}}
    .cat,.verdict,table,.chip{{break-inside:avoid}}
    a[href]:after{{content:""}}
  }}
</style>
</head>
<body>
<div class="wrap">

  <header class="doc">
    <p class="eyebrow">WAF inspection report &middot; waf.py v{__version__}</p>
    <h1>{_esc(model.title)}</h1>
    <div class="meta">
      <div>Source: <span>{_esc(model.source_label)}</span></div>
      <div>Generated: <span>{_esc(model.generated)}</span></div>
      <div>Mode: <code>{cfg.mode}</code></div>
      <div>Paranoia: <code>PL{cfg.paranoia}</code></div>
      <div>Threshold: <code>{cfg.anomaly_threshold}</code></div>
    </div>
  </header>

  <div class="verdict" style="--vc:{verdict_color}">
    <div class="big">{model.blocked}/{model.total}</div>
    <div class="vtext"><b>{_esc(verdict_text)}.</b><br>
      {model.total_detections} total rule matches across {model.total} inspected request(s).
      Rule sets active: {_esc(cats_on)}.</div>
    <div class="chips">{sev_chips_html}</div>
  </div>

  <div class="cats">{''.join(cat_cells)}</div>

  <section>
    <h2><span class="mark"></span>Detailed findings</h2>
    <p class="lead">Every inspected request, the rules it tripped, the part of the request each
    match was found in, the accumulated anomaly score, and the resulting decision. A request is
    blocked when its score reaches the threshold ({cfg.anomaly_threshold}).</p>
    <table>
      <thead><tr>
        <th>Request</th><th>Rule matches (id &middot; location &middot; matched text)</th>
        <th>Score</th><th>Decision</th>
      </tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </section>

  {sweep_html}

  {notes_html}

  <section>
    <h2><span class="mark"></span>Active rule reference</h2>
    <p class="lead">The {len(engine.active_rules)} rules enabled for this run (category filter and
    paranoia level PL{cfg.paranoia}). Remediation is the fix for the vulnerable application &mdash; a
    WAF buys time, but the underlying code should still be fixed.</p>
    <table>
      <thead><tr><th>Rule</th><th>Category</th><th>Severity</th><th>Detects</th><th>Remediation</th></tr></thead>
      <tbody>{ref_html}</tbody>
    </table>
  </section>

  <footer>
    <span>Generated by waf.py v{__version__} &mdash; CSIT 2033 Week 7 Lab</span>
    <span><code>defensive &middot; signature-based &middot; anomaly-scored</code></span>
  </footer>

</div>
</body>
</html>"""


# ----- PDF report ----------------------------------------------------------
# Optional: uses reportlab if present, degrades gracefully if not.

def render_pdf_report(model: ReportModel, path: str) -> bool:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.units import inch
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable)
    except Exception as exc:
        print(f"[!] PDF report skipped (reportlab unavailable): {exc}")
        return False

    cfg = model.config
    styles = getSampleStyleSheet()
    H1 = ParagraphStyle("H1", parent=styles["Heading1"], fontName="Helvetica-Bold",
                        fontSize=19, spaceAfter=4, textColor=colors.HexColor("#1b1f27"))
    EY = ParagraphStyle("EY", parent=styles["Normal"], fontName="Courier",
                        fontSize=8.5, textColor=colors.HexColor("#44506b"), spaceAfter=2)
    H2 = ParagraphStyle("H2", parent=styles["Heading2"], fontName="Helvetica-Bold",
                        fontSize=13, spaceBefore=16, spaceAfter=6,
                        textColor=colors.HexColor("#1b1f27"))
    BODY = ParagraphStyle("BODY", parent=styles["Normal"], fontName="Helvetica",
                          fontSize=9.5, leading=13, textColor=colors.HexColor("#333a45"))
    SMALL = ParagraphStyle("SMALL", parent=styles["Normal"], fontName="Helvetica",
                           fontSize=8, leading=10, textColor=colors.HexColor("#4b5563"))
    MONO = ParagraphStyle("MONO", parent=styles["Normal"], fontName="Courier",
                          fontSize=7.5, leading=9.5, textColor=colors.HexColor("#86202a"))
    CELL = ParagraphStyle("CELL", parent=styles["Normal"], fontName="Helvetica",
                          fontSize=8, leading=10, textColor=colors.HexColor("#1b1f27"))

    def P(text, style=BODY):
        return Paragraph(text, style)

    story = []
    story.append(P(f"WAF INSPECTION REPORT &middot; waf.py v{__version__}", EY))
    story.append(P(_esc(model.title), H1))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#44506b"),
                            spaceBefore=4, spaceAfter=8))
    meta = (f"Source: <b>{_esc(model.source_label)}</b> &nbsp;|&nbsp; "
            f"Generated: {_esc(model.generated)}<br/>"
            f"Mode: {cfg.mode} &nbsp;|&nbsp; Paranoia: PL{cfg.paranoia} &nbsp;|&nbsp; "
            f"Threshold: {cfg.anomaly_threshold} &nbsp;|&nbsp; "
            f"Rule sets: {_esc(', '.join(CATEGORY_LABELS[c] for c in cfg.enabled_categories))}")
    story.append(P(meta, SMALL))
    story.append(Spacer(1, 10))

    # verdict line
    verdict_clean = model.blocked == 0 and model.total_detections == 0
    vcolor = colors.HexColor("#15803d" if verdict_clean else "#b4232a")
    vtxt = ("No attacks detected in this sample"
            if verdict_clean else f"{model.blocked} of {model.total} requests blocked")
    vtbl = Table([[P(f"{model.blocked}/{model.total}",
                     ParagraphStyle("V", parent=H1, fontSize=22, textColor=vcolor)),
                   P(f"<b>{_esc(vtxt)}.</b><br/>{model.total_detections} total rule matches "
                     f"across {model.total} inspected request(s).", BODY)]],
                 colWidths=[1.2 * inch, 5.3 * inch])
    vtbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f6f7f9")),
        ("LINEBEFORE", (0, 0), (0, -1), 4, vcolor),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(vtbl)

    # findings
    story.append(P("Detailed findings", H2))
    data = [[P("<b>Request</b>", CELL), P("<b>Rule matches</b>", CELL),
             P("<b>Score</b>", CELL), P("<b>Decision</b>", CELL)]]
    for name, res in model.results:
        if res.detections:
            bits = []
            for d in sorted(res.detections, key=lambda x: SEVERITY_ORDER.index(x.severity)):
                bits.append(f"{_esc(d.rule_id)} [{_esc(d.location)}]: "
                            f"<font face='Courier'>{_esc(d.matched)}</font>")
            det = "<br/>".join(bits)
        else:
            det = "<i>no rules matched</i>"
        decision = ("BLOCKED" if res.blocked else
                    ("FLAGGED" if res.detections else "ALLOWED"))
        dcolor = ("#b4232a" if res.blocked else
                  ("#a16207" if res.detections else "#15803d"))
        data.append([
            P(f"<b>{_esc(name)}</b><br/><font face='Courier' size=7 color='#8b93a1'>"
              f"{_esc(res.request_label)}</font>", CELL),
            P(det, CELL),
            P(str(res.score), CELL),
            P(f"<b><font color='{dcolor}'>{decision}</font></b>", CELL),
        ])
    ftbl = Table(data, colWidths=[1.7 * inch, 3.5 * inch, 0.5 * inch, 0.85 * inch], repeatRows=1)
    ftbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0f3")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e5ea")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(ftbl)

    # sweep
    if model.sweep:
        story.append(P("False-positive analysis", H2))
        story.append(P(
            f"Each paranoia level run against {model.sweep[0]['total_malicious']} OWASP WSTG "
            f"attack payloads and {model.sweep[0]['total_benign']} benign inputs at threshold "
            f"{cfg.anomaly_threshold}. Higher levels detect more but flag more legitimate traffic.",
            BODY))
        sdata = [[P(f"<b>{h}</b>", CELL) for h in
                  ["Paranoia", "Active rules", "Detected", "Detection %",
                   "False positives", "FP %"]]]
        for r in model.sweep:
            tag = "PL%d%s" % (r["paranoia"], "  <- this run" if r["paranoia"] == cfg.paranoia else "")
            sdata.append([P(tag, CELL),
                          P(str(r["active_rules"]), CELL),
                          P(f"{r['detected']}/{r['total_malicious']}", CELL),
                          P(f"{r['detection_rate']}%", CELL),
                          P(f"{r['false_positives']}/{r['total_benign']}", CELL),
                          P(f"{r['false_positive_rate']}%", CELL)])
        stbl = Table(sdata, colWidths=[1.3*inch, 1.0*inch, 0.9*inch, 1.0*inch, 1.3*inch, 0.8*inch],
                     repeatRows=1)
        stbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0f3")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e5ea")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(stbl)

    # notes
    if model.notes:
        story.append(P("Notes", H2))
        for n in model.notes:
            story.append(P("&bull; " + _esc(n), BODY))

    # rules reference
    engine = WAFEngine(cfg)
    story.append(P("Active rule reference", H2))
    rdata = [[P(f"<b>{h}</b>", CELL) for h in
              ["Rule", "Category", "Severity", "Detects", "Remediation"]]]
    for rule in sorted(engine.active_rules, key=lambda r: r.id):
        rdata.append([
            P(f"<font face='Courier' size=7>{_esc(rule.id)}</font>", CELL),
            P(_esc(CATEGORY_LABELS[rule.category]), CELL),
            P(f"{rule.severity} ({rule.score})", CELL),
            P(_esc(rule.description), CELL),
            P(_esc(rule.remediation), CELL),
        ])
    rtbl = Table(rdata, colWidths=[0.7*inch, 1.1*inch, 0.9*inch, 2.3*inch, 2.3*inch], repeatRows=1)
    rtbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0f3")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e5ea")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(rtbl)

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e5ea")))
    story.append(P(f"Generated by waf.py v{__version__} - CSIT 2033 Week 7 Lab - "
                   f"defensive, signature-based, anomaly-scored.", SMALL))

    doc = SimpleDocTemplate(path, pagesize=LETTER,
                            leftMargin=0.6*inch, rightMargin=0.6*inch,
                            topMargin=0.6*inch, bottomMargin=0.6*inch,
                            title=model.title, author="waf.py")
    doc.build(story)
    return True


def write_reports(model: ReportModel, base: str, fmt: str) -> list:
    """Write report(s) and return the list of paths written."""
    written = []
    root, ext = os.path.splitext(base)
    if ext.lower() in (".html", ".pdf"):
        base = root  # treat as a base name, we add extensions ourselves
    if fmt in ("html", "both"):
        p = base + ".html"
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(render_html_report(model))
        written.append(p)
        print(f"[+] HTML report written: {p}")
    if fmt in ("pdf", "both"):
        p = base + ".pdf"
        if render_pdf_report(model, p):
            written.append(p)
            print(f"[+] PDF report written:  {p}")
    return written


# ===========================================================================
# SECTION 10 - FILE LOADING FOR --scan-file
# ===========================================================================
# The Colab notebook lets the user upload their own test-case file. We accept
# three shapes and auto-detect:
#   * .json  - a list of strings, OR a list of objects with keys like
#              {"name","payload","target"} or a full request
#              {"method","path","query","body",...}
#   * .http  - one or more raw HTTP requests (request line + headers + body)
#   * .txt / anything else - one payload per line (# comments ignored)

def load_test_cases(path: str) -> list:
    """Return a list of (name, request_dict) to inspect."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()

    ext = os.path.splitext(path)[1].lower()
    stripped = raw.strip()

    # Try JSON first if it looks like JSON or has a .json extension.
    if ext == ".json" or stripped[:1] in "[{":
        try:
            return _load_json_cases(json.loads(raw))
        except Exception:
            pass  # fall through to other parsers

    # Raw HTTP request(s)?
    if ext in (".http", ".req") or re.match(
            r"^(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)\s+\S+\s+HTTP/",
            stripped, re.IGNORECASE):
        cases = _load_http_cases(raw)
        if cases:
            return cases

    # Default: one payload per line.
    cases = []
    for i, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cases.append((f"line {i}", _synthesize_request(line, "search")))
    return cases


def _load_json_cases(data) -> list:
    cases = []
    if isinstance(data, dict):
        data = [data]
    for i, item in enumerate(data, 1):
        if isinstance(item, str):
            cases.append((f"payload {i}", _synthesize_request(item, "search")))
        elif isinstance(item, dict):
            name = item.get("name") or item.get("id") or f"case {i}"
            # Full request descriptor?
            if any(k in item for k in ("method", "path", "query", "body", "headers", "cookies")):
                req = {
                    "method": item.get("method", "GET"),
                    "path": item.get("path", "/"),
                    "query": item.get("query"),
                    "headers": item.get("headers"),
                    "cookies": item.get("cookies"),
                    "body": item.get("body"),
                }
                cases.append((name, req))
            else:
                payload = item.get("payload") or item.get("input") or item.get("value") or ""
                target = item.get("target") or item.get("where") or "search"
                cases.append((name, _synthesize_request(payload, target)))
    return cases


def _load_http_cases(raw: str) -> list:
    """Parse one or more raw HTTP requests separated by blank 'request-line' boundaries."""
    # Split on a line that looks like a new request line.
    blocks, current = [], []
    for line in raw.splitlines():
        if re.match(r"^(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)\s+\S+\s+HTTP/",
                    line, re.IGNORECASE) and current:
            blocks.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append("\n".join(current))

    cases = []
    for i, block in enumerate(blocks, 1):
        lines = block.splitlines()
        if not lines:
            continue
        m = re.match(r"^(\w+)\s+(\S+)\s+HTTP/", lines[0], re.IGNORECASE)
        if not m:
            continue
        method, target = m.group(1).upper(), m.group(2)
        path, _, query = target.partition("?")
        headers, cookies = {}, {}
        body_lines, in_body = [], False
        for ln in lines[1:]:
            if in_body:
                body_lines.append(ln)
                continue
            if ln.strip() == "":
                in_body = True
                continue
            if ":" in ln:
                k, _, v = ln.partition(":")
                k, v = k.strip(), v.strip()
                headers[k] = v
                if k.lower() == "cookie":
                    for part in v.split(";"):
                        if "=" in part:
                            ck, _, cv = part.strip().partition("=")
                            cookies[ck] = cv
        body = "\n".join(body_lines).strip()
        req = {"method": method, "path": path, "query": query or None,
               "headers": headers or None, "cookies": cookies or None,
               "body": body or None}
        cases.append((f"{method} {path} (req {i})", req))
    return cases


# ===========================================================================
# SECTION 11 - RUN MODES
# ===========================================================================

def _print_result_line(name, res):
    if res.blocked:
        tag = "BLOCK"
    elif res.detections:
        tag = "FLAG "
    else:
        tag = "ALLOW"
    cats = ",".join(res.categories_hit) if res.categories_hit else "-"
    print(f"  [{tag}] score={res.score:<3} {name[:42]:<42} {cats}")


def run_scan_file(path: str, config: WAFConfig, report_base, report_fmt) -> int:
    print(f"\n=== Scanning file: {path} ===")
    try:
        cases = load_test_cases(path)
    except FileNotFoundError:
        print(f"[!] File not found: {path}")
        return 2
    except Exception as exc:
        print(f"[!] Could not read test cases: {exc}")
        return 2

    if not cases:
        print("[!] No test cases found in the file.")
        return 1

    engine = WAFEngine(config)
    results = []
    print(f"[*] Loaded {len(cases)} test case(s). Inspecting with "
          f"PL{engine.config.paranoia}, threshold {engine.config.anomaly_threshold}...\n")
    for name, req in cases:
        res = engine.inspect_request(req)
        results.append((name, res))
        _print_result_line(name, res)

    blocked = sum(1 for _n, r in results if r.blocked)
    flagged = sum(1 for _n, r in results if r.detections and not r.blocked)
    print(f"\n[=] {blocked} blocked, {flagged} flagged-but-allowed, "
          f"{len(results) - blocked - flagged} clean of {len(results)} total.")

    if report_base:
        model = ReportModel(
            title="WAF Scan - Uploaded Test Cases",
            generated=_ts(),
            config=engine.config,
            source_label=os.path.basename(path),
            results=results,
            notes=[
                "These results come from a user-supplied test file.",
                "A WAF is defense-in-depth; fix the underlying input handling too.",
            ],
        )
        write_reports(model, report_base, report_fmt)
    return 0


def run_demo(config: WAFConfig, report_base, report_fmt) -> int:
    print("\n=== OWASP WSTG demo against the deliberately vulnerable app ===")
    if not _HAVE_FLASK:
        print("[!] Flask is required for --demo. Install it with: pip install flask")
        return 2

    # Build two apps: unprotected (to prove vulnerability) and protected.
    vuln = build_vulnerable_app(with_waf=False)
    guarded = build_vulnerable_app(with_waf=True, config=config)
    vc = vuln.test_client()
    gc = guarded.test_client()
    engine = WAFEngine(config)

    def _fire(client, req):
        if req["path"] == "/login":
            return client.post("/login", data=req["body"])
        qs = req.get("query") or {}
        return client.get(req["path"], query_string=qs)

    print(f"[*] Firing {len(OWASP_PAYLOADS)} OWASP payloads at each app "
          f"(PL{engine.config.paranoia}, threshold {engine.config.anomaly_threshold}).\n")
    print(f"  {'PAYLOAD':<26} {'UNPROTECTED':<14} {'WITH WAF':<10}")
    print(f"  {'-'*26} {'-'*14} {'-'*10}")

    results = []
    leaked_unprotected = 0
    blocked_by_waf = 0
    for name, payload, cat, where in OWASP_PAYLOADS:
        req = _synthesize_request(payload, where)

        # Unprotected response (demonstrates the flaw).
        r_un = _fire(vc, req)
        body = r_un.get_data(as_text=True)
        reached = _vuln_reached(where, body, r_un.status_code)
        if reached:
            leaked_unprotected += 1

        # Protected response (WAF should intercept).
        r_g = _fire(gc, req)
        waf_blocked = r_g.status_code == 403
        if waf_blocked:
            blocked_by_waf += 1

        print(f"  {name[:26]:<26} "
              f"{('EXPLOITED' if reached else 'no effect'):<14} "
              f"{('BLOCKED' if waf_blocked else 'passed'):<10}")

        # Engine detail for the report.
        results.append((f"{name}  ({CATEGORY_LABELS[cat]})", engine.inspect_request(req)))

    print(f"\n  Unprotected app: {leaked_unprotected}/{len(OWASP_PAYLOADS)} payloads reached "
          f"the vulnerable code.")
    print(f"  WAF-protected:   {blocked_by_waf}/{len(OWASP_PAYLOADS)} payloads blocked with 403.")

    # Confirm benign traffic still works through the WAF.
    print("\n[*] Sanity check: benign requests through the WAF ...")
    benign_ok = 0
    for name, payload, where in BENIGN_PAYLOADS:
        req = _synthesize_request(payload, where)
        r = _fire(gc, req)
        if r.status_code != 403:
            benign_ok += 1
    print(f"  {benign_ok}/{len(BENIGN_PAYLOADS)} benign requests passed "
          f"(the rest are false positives at this setting).")

    # False-positive sweep for the write-up.
    print("\n[*] Running paranoia sweep for the false-positive write-up ...")
    sweep = paranoia_sweep(engine.config.anomaly_threshold, engine.config.enabled_categories)
    for r in sweep:
        print(f"  PL{r['paranoia']}: detection {r['detection_rate']}% "
              f"({r['detected']}/{r['total_malicious']}), "
              f"false-positive {r['false_positive_rate']}% "
              f"({r['false_positives']}/{r['total_benign']}), "
              f"{r['active_rules']} rules")

    if report_base:
        model = ReportModel(
            title="WAF Demo - OWASP WSTG Attack Simulation",
            generated=_ts(),
            config=engine.config,
            source_label="Built-in OWASP WSTG payload corpus vs. vulnerable demo app",
            results=results,
            sweep=sweep,
            notes=[
                f"Unprotected app: {leaked_unprotected}/{len(OWASP_PAYLOADS)} payloads reached "
                f"the vulnerable code path.",
                f"WAF-protected app: {blocked_by_waf}/{len(OWASP_PAYLOADS)} payloads returned 403.",
                f"Benign traffic at PL{engine.config.paranoia}/threshold "
                f"{engine.config.anomaly_threshold}: {benign_ok}/{len(BENIGN_PAYLOADS)} passed.",
                "Command-injection sink is simulated (the command is built but never executed).",
            ],
        )
        write_reports(model, report_base, report_fmt)
    return 0


def _vuln_reached(where, body, status) -> bool:
    """Heuristic: did the attack visibly reach the vulnerable code in the unprotected app?"""
    b = body.lower()
    if where == "login":
        return "welcome" in b or "sql error" in b
    if where == "search":
        return "<script" in b or "onerror" in b or "<svg" in b or "javascript:" in b
    if where == "download":
        return "secret" in b or "root:x:" in b or "decoy" in b
    if where == "ping":
        return "would run shell command" in b and (";" in body or "|" in body
                                                    or "$(" in body or "`" in body or "&&" in body)
    return status == 200


def run_serve(config: WAFConfig, port: int, with_waf: bool) -> int:
    if not _HAVE_FLASK:
        print("[!] Flask is required for --serve. Install it with: pip install flask")
        return 2
    app = build_vulnerable_app(with_waf=with_waf, config=config)
    state = "PROTECTED by the WAF" if with_waf else "UNPROTECTED (no WAF)"
    print(f"\n=== Vulnerable demo app [{state}] ===")
    print(f"[*] Listening on http://127.0.0.1:{port}")
    print("[*] Try:  /login?username=admin'--+  |  /search?q=<script>alert(1)</script>")
    print("[*]       /download?name=../secret.txt  |  /ping?host=127.0.0.1;id")
    print("[*] Ctrl+C to stop.\n")
    try:
        app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    return 0


# ===========================================================================
# SECTION 12 - SELF TEST (--lab)
# ===========================================================================

def run_lab() -> int:
    print("=== waf.py self-test (offline) ===\n")
    passed, failed = 0, 0

    def check(desc, cond):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  [PASS] {desc}")
        else:
            failed += 1
            print(f"  [FAIL] {desc}")

    full = WAFConfig(paranoia=2, anomaly_threshold=5)
    engine = WAFEngine(full)

    # 1. Each OWASP payload is detected in the right category.
    print("-- OWASP payload detection --")
    for name, payload, cat, where in OWASP_PAYLOADS:
        res = engine.inspect_request(_synthesize_request(payload, where))
        hit_cat = cat in res.categories_hit
        check(f"detect {name} -> {cat}", hit_cat and res.blocked)

    # 2. Encoding evasion is defeated by the normalizer.
    print("\n-- evasion / normalization --")
    enc = engine.inspect_request(_synthesize_request("..%252f..%252fetc%252fpasswd", "download"))
    check("double-URL-encoded traversal is caught", enc.blocked)
    ent = engine.inspect_request(_synthesize_request("&lt;script&gt;alert(1)&lt;/script&gt;", "search"))
    check("HTML-entity-encoded XSS is caught", ent.blocked)

    # 3. Benign inputs mostly pass at PL1 (low false positives).
    print("\n-- false-positive floor (PL1) --")
    pl1 = WAFEngine(WAFConfig(paranoia=1, anomaly_threshold=5))
    fp = sum(1 for _n, p, w in BENIGN_PAYLOADS if pl1.inspect_request(_synthesize_request(p, w)).blocked)
    check(f"PL1 false positives <= 2 (got {fp})", fp <= 2)

    # 4. Anomaly threshold behaves monotonically.
    print("\n-- anomaly scoring --")
    strict = WAFEngine(WAFConfig(paranoia=2, anomaly_threshold=3))
    loose = WAFEngine(WAFConfig(paranoia=2, anomaly_threshold=99))
    payload = "O'Brien"
    check("very high threshold allows a borderline input",
          not loose.inspect_request(_synthesize_request(payload, "login")).blocked)
    check("a clear attack still blocks at a strict threshold",
          strict.inspect_request(_synthesize_request("' OR '1'='1", "login")).blocked)

    # 5. Category filtering works.
    print("\n-- category filtering --")
    only_xss = WAFEngine(WAFConfig(enabled_categories=("xss",), paranoia=2))
    r = only_xss.inspect_request(_synthesize_request("' OR '1'='1", "login"))
    check("SQLi ignored when only XSS is enabled", not r.blocked)
    r2 = only_xss.inspect_request(_synthesize_request("<script>alert(1)</script>", "search"))
    check("XSS still caught when only XSS is enabled", r2.blocked)

    # 6. detect mode never blocks but still records detections.
    print("\n-- detect vs block mode --")
    detect = WAFEngine(WAFConfig(paranoia=2, mode="detect", anomaly_threshold=5))
    rd = detect.inspect_request(_synthesize_request("' OR '1'='1", "login"))
    check("detect mode does not block", not rd.blocked)
    check("detect mode still records detections", len(rd.detections) > 0)

    # 7. Report renders without error.
    print("\n-- reporting --")
    try:
        results = [("test", engine.inspect_request(_synthesize_request("<script>alert(1)</script>", "search")))]
        model = ReportModel("Self-test", _ts(), full, "self-test", results,
                            sweep=paranoia_sweep(5, ALL_CATEGORIES))
        htmlout = render_html_report(model)
        check("HTML report renders", "<html" in htmlout.lower() and len(htmlout) > 2000)
    except Exception as exc:
        check(f"HTML report renders (error: {exc})", False)

    # 8. Flask demo app builds and the WAF blocks a live request.
    if _HAVE_FLASK:
        print("\n-- live middleware (test client) --")
        try:
            guarded = build_vulnerable_app(with_waf=True, config=full)
            c = guarded.test_client()
            resp = c.get("/search", query_string={"q": "<script>alert(1)</script>"})
            check("WAF returns 403 on a live XSS request", resp.status_code == 403)
            ok = c.get("/search", query_string={"q": "hello world"})
            check("WAF allows a benign live request", ok.status_code == 200)
        except Exception as exc:
            check(f"live middleware test (error: {exc})", False)
    else:
        print("\n-- live middleware -- (skipped, Flask not installed)")

    print(f"\n=== {passed} passed, {failed} failed ===")
    return 0 if failed == 0 else 1


# ===========================================================================
# SECTION 13 - CLI
# ===========================================================================

def parse_categories(value: str):
    if not value:
        return tuple(ALL_CATEGORIES)
    aliases = {
        "sql": "sqli", "sqli": "sqli", "injection": "sqli",
        "xss": "xss",
        "traversal": "traversal", "lfi": "traversal", "path": "traversal",
        "cmd": "cmdi", "cmdi": "cmdi", "rce": "cmdi", "command": "cmdi",
    }
    cats = []
    for part in value.split(","):
        key = part.strip().lower()
        if key in ("all", "*"):
            return tuple(ALL_CATEGORIES)
        if key in aliases and aliases[key] not in cats:
            cats.append(aliases[key])
    return tuple(cats) if cats else tuple(ALL_CATEGORIES)


def build_parser():
    p = argparse.ArgumentParser(
        prog="waf.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Lightweight signature-based Web Application Firmware (WAF) "
                    "middleware and rule engine for SQLi / XSS / path traversal / "
                    "command injection.",
        epilog="Examples:\n"
               "  python waf.py --lab\n"
               "  python waf.py --demo --report report --format both\n"
               "  python waf.py --scan-file payloads.txt --report out\n"
               "  python waf.py --serve --no-waf --port 5000\n",
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--lab", action="store_true",
                      help="run the offline self-test and exit")
    mode.add_argument("--demo", action="store_true",
                      help="fire OWASP payloads at the vulnerable app (WAF off, then on)")
    mode.add_argument("--scan-file", metavar="PATH",
                      help="analyze a file of payloads / HTTP requests (txt/json/http)")
    mode.add_argument("--serve", action="store_true",
                      help="run the vulnerable demo app on a real port")

    p.add_argument("--no-waf", action="store_true",
                   help="with --serve: run the app UNPROTECTED (for comparison)")
    p.add_argument("--port", type=int, default=5000, help="port for --serve (default 5000)")

    p.add_argument("--paranoia", type=int, default=2, choices=[1, 2, 3, 4],
                   help="rule aggressiveness, 1=fewest FPs .. 4=most aggressive (default 2)")
    p.add_argument("--threshold", type=int, default=5,
                   help="anomaly score required to block (default 5)")
    p.add_argument("--categories", default="all",
                   help="comma list of sqli,xss,traversal,cmdi (default all)")
    p.add_argument("--mode", default="block", choices=["block", "detect"],
                   help="block requests or only detect/log them (default block)")

    p.add_argument("--report", metavar="PATH",
                   help="write a findings report to PATH (.html/.pdf added automatically)")
    p.add_argument("--format", default="both", choices=["html", "pdf", "both"],
                   help="report format (default both)")
    p.add_argument("--open", action="store_true",
                   help="open the HTML report in a browser when done")

    p.add_argument("--version", action="version", version=f"waf.py {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    config = WAFConfig(
        enabled_categories=parse_categories(args.categories),
        paranoia=args.paranoia,
        anomaly_threshold=args.threshold,
        mode=args.mode,
    ).normalized()

    report_base = args.report
    report_fmt = args.format

    if args.lab:
        return run_lab()

    if args.serve:
        return run_serve(config, args.port, with_waf=not args.no_waf)

    if args.scan_file:
        rc = run_scan_file(args.scan_file, config, report_base, report_fmt)
    elif args.demo:
        rc = run_demo(config, report_base, report_fmt)
    else:
        # No mode selected: run the demo if nothing else was asked, but hint at help.
        print("No mode selected. Running --demo. (Use --help to see all options.)\n")
        rc = run_demo(config, report_base, report_fmt)

    if args.open and report_base:
        htmlp = os.path.splitext(report_base)[0] + ".html"
        if os.path.exists(htmlp):
            try:
                webbrowser.open("file://" + os.path.abspath(htmlp))
            except Exception:
                pass
    return rc


if __name__ == "__main__":
    sys.exit(main())
