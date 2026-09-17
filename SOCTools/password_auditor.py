#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""password_auditor.py -- Week 4 lab: password auditing tool and policy enforcer.

CSIT 2033 -- Cybersecurity strategy: offensive (audit) and defensive (enforce).

WHAT THIS TOOL DOES
-------------------
Offensive half (auditing):
  1. Strength scorer     -- zxcvbn scoring plus explicit checks against a
                            rockyou-style wordlist, with an educational entropy
                            estimate in bits.
  2. Mutation engine     -- generates wordlist variations (capitalization, leet
                            substitutions, appended digits/years/symbols, and
                            combinations such as P@ssw0rd2026!) and, in reverse,
                            detects when a candidate password is one of them.

Defensive half (enforcement):
  3. Policy enforcer     -- a reusable module that accepts or rejects a password
                            against configurable requirements and returns
                            specific improvement advice. Includes a registration
                            demonstration that rejects a weak password, lets the
                            user try again, and hashes the accepted password with
                            hashlib.pbkdf2_hmac using a unique random salt.

Reporting: results are printed to the terminal, exported as JSON, and exported as
a self-contained offline HTML report that is laid out for printing to PDF.

PRIVACY RULE ENFORCED THROUGHOUT
--------------------------------
Passwords, password hashes, salts, and revealing matched wordlist fragments are
never written to the JSON report, the HTML report, or any log. Report content is
built from a separate "public record" structure that the secret values never
enter (see build_public_record). A leak check (assert_no_leak) runs before every
report is written, and test_report_safety_* covers this behaviour.

QUICK START
-----------
    pip install zxcvbn                      # optional but recommended
    python password_auditor.py --demo       # non-interactive demonstration
    python password_auditor.py --check      # audit a password, hidden entry
    python password_auditor.py --register   # registration demo, hidden entry
    python password_auditor.py --self-test  # run the built-in test suite
    python password_auditor.py --mutations password

On Windows PowerShell use `py` instead of `python`:
    py password_auditor.py --demo
    Select-String -Path .\password_auditor.py -Pattern '__version__ = "1.0.0"' -Quiet

In Google Colab, use three separate cells. A %%writefile magic has to be the
first line of its own cell, and running the script as a subprocess keeps
argparse and sys.exit() from fighting the notebook kernel:
    cell 1:  !pip install zxcvbn -q
    cell 2:  %%writefile password_auditor.py
             ... paste this entire file below the magic ...
    cell 3:  !python password_auditor.py --demo
             from google.colab import files
             files.download('reports/password_audit.html')

SUPPLYING THE ROCKYOU SAMPLE LIST
---------------------------------
The assignment's rockyou sample is loaded from a configurable path. Resolution
order (first hit wins):
    1. --wordlist PATH
    2. the PASSWORD_AUDITOR_WORDLIST environment variable
    3. ./wordlists/rockyou-sample.txt          (DEFAULT_WORDLIST_PATH)
Format: one password per line, UTF-8 or latin-1, blank lines and lines starting
with '#' ignored, decoding errors replaced rather than fatal. Only the first
--wordlist-limit lines are loaded (default 200000) so a full rockyou.txt does not
exhaust memory. Example setup:
    mkdir wordlists
    copy rockyou-sample.txt wordlists\\rockyou-sample.txt     (Windows)
    cp rockyou-sample.txt wordlists/rockyou-sample.txt        (macOS/Linux)
If the file is absent the tool still runs: it falls back to DEMO_WORDLIST, a
small clearly labelled demonstration list defined below, and says so in the
terminal output and in both reports.

Python 3.9+ (argparse.BooleanOptionalAction). Standard library only, except for
the optional zxcvbn package; without zxcvbn a documented built-in heuristic
scorer is used instead and every report records which engine ran.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import html
import itertools
import json
import logging
import math
import os
import random
import re
import string
import sys
import textwrap
import unittest
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

__version__ = "1.0.0"
TOOL_NAME = "password_auditor"
REPORT_SCHEMA_VERSION = "1.0"

# --------------------------------------------------------------------------- #
# Optional dependency: zxcvbn                                                  #
# --------------------------------------------------------------------------- #
try:  # pragma: no cover - depends on the machine the lab is run on
    from zxcvbn import zxcvbn as _zxcvbn_score

    ZXCVBN_AVAILABLE = True
except Exception:  # pragma: no cover
    _zxcvbn_score = None
    ZXCVBN_AVAILABLE = False


# =========================================================================== #
# SECTION 1 -- CONFIGURATION AND DEFAULT SETTINGS                             #
# =========================================================================== #

# --- Wordlist settings ----------------------------------------------------- #
DEFAULT_WORDLIST_PATH = "wordlists/rockyou-sample.txt"
WORDLIST_ENV_VAR = "PASSWORD_AUDITOR_WORDLIST"
DEFAULT_WORDLIST_LIMIT = 200_000  # max lines read from the rockyou sample
MIN_BASE_WORD_LENGTH = 4  # ignore wordlist hits shorter than this

# --- DEMONSTRATION WORDLIST ------------------------------------------------ #
# THIS IS NOT ROCKYOU. It is a tiny, hand-written stand-in (the 80 or so base
# words that dominate every leaked-password study) so the tool is fully
# functional before the assignment's rockyou sample file is supplied. Every
# report states whether findings came from this demo list or from a real file.
DEMO_WORDLIST: Tuple[str, ...] = (
    "password", "passwords", "123456", "12345678", "123456789",
    "1234567890", "qwerty", "qwertyuiop", "abc123", "111111", "iloveyou",
    "admin", "administrator", "welcome", "monkey", "dragon", "letmein",
    "football", "baseball", "basketball", "soccer", "hockey", "sunshine",
    "princess", "flower", "shadow", "master", "superman", "batman", "trustno1",
    "michael", "jennifer", "jordan", "hunter", "harley", "ranger", "daniel",
    "ashley", "nicole", "thomas", "summer", "winter", "spring", "autumn",
    "chocolate", "cookie", "coffee", "whatever", "freedom", "starwars",
    "pokemon", "computer", "internet", "secret", "cheese", "banana", "purple",
    "orange", "silver", "golden", "tigger", "charlie", "buster", "maggie",
    "bailey", "lucky", "ginger", "pepper", "peanut", "samsung", "google",
    "facebook", "yahoo", "linkedin", "amazon", "netflix", "chicago", "boston",
    "dallas", "denver", "phoenix", "trine", "indiana",
)

# --- Mutation engine settings ---------------------------------------------- #
# Forward leet substitutions: plaintext letter -> characters attackers use.
LEET_FORWARD: Dict[str, Tuple[str, ...]] = {
    "a": ("@", "4"),
    "b": ("8",),
    "e": ("3",),
    "g": ("9",),
    "i": ("1", "!"),
    "l": ("1",),
    "o": ("0",),
    "s": ("$", "5"),
    "t": ("7",),
    "z": ("2",),
}

# Forward generation uses one primary substitution per letter (the first entry
# above) so the generated space stays small enough to enumerate completely.
# MutationEngine(leet_alternates=True) adds the secondary forms (a->4, s->5).
LEET_PRIMARY: Dict[str, str] = {plain: subs[0] for plain, subs in LEET_FORWARD.items()}

# Reverse map used for detection, which always considers every substitution.
# '1' is ambiguous (i or l), so detection has to try both -- that ambiguity is
# why detection enumerates variants.
LEET_REVERSE: Dict[str, Tuple[str, ...]] = {}
for _plain, _subs in LEET_FORWARD.items():
    for _sub in _subs:
        LEET_REVERSE.setdefault(_sub, ())
        if _plain not in LEET_REVERSE[_sub]:
            LEET_REVERSE[_sub] = LEET_REVERSE[_sub] + (_plain,)

DEFAULT_APPEND_DIGITS: Tuple[str, ...] = ("", "1", "12", "123", "1234", "007", "99")
DEFAULT_APPEND_SYMBOLS: Tuple[str, ...] = ("", "!", "!!", "@", "#", "$", "?")
# Prefixes are rarer than suffixes in real cracking rules, so the default keeps
# the generated space small. Pass prepend=("", "1", "!") to include them.
DEFAULT_PREPEND: Tuple[str, ...] = ("",)
DEFAULT_YEAR_RANGE: Tuple[int, int] = (2018, 2027)  # inclusive, --years to change
EXTRA_YEARS: Tuple[str, ...] = ("1990", "1999", "2000")


@dataclass(frozen=True)
class MutationLimits:
    """Caps that keep mutation work bounded. All are configurable from the CLI."""

    max_case_variants: int = 4        # lower, Capitalized, UPPER, tOGGLE
    max_leet_positions: int = 10      # letters considered for substitution
    max_leet_variants: int = 64       # leet forms kept per case variant
    max_variants_per_word: int = 8000  # hard cap on generate() output
    max_unleet_variants: int = 512    # reverse (detection) enumeration cap
    max_affix_peels: int = 4          # how many trailing/leading runs to strip
    max_affix_run: int = 6            # longest digit/symbol run treated as affix
    max_cores: int = 48               # candidate stems examined per password
    min_base_length: int = MIN_BASE_WORD_LENGTH


# --- Entropy and crack-time model settings --------------------------------- #
POOL_SIZES: Dict[str, int] = {
    "lowercase": 26,
    "uppercase": 26,
    "digit": 10,
    "symbol": 33,   # 32 ASCII punctuation characters plus the space
    "other": 100,   # accented/unicode characters, deliberately conservative
}
AXIS_MAX_BITS = 128.0  # full width of the bit scale drawn in the reports
# Documented attacker rates used for the illustrative guess-time column.
GUESS_RATES: Tuple[Tuple[str, float], ...] = (
    ("online service, throttled (100 guesses/s)", 1e2),
    ("offline, fast unsalted hash on GPUs (10 billion guesses/s)", 1e10),
    ("offline, against this tool's PBKDF2 settings (~100k guesses/s)", 1e5),
)
SCORE_LABELS: Tuple[str, ...] = ("Very weak", "Weak", "Moderate", "Strong", "Very strong")
# zxcvbn score boundaries expressed in log10(guesses); used by the fallback
# scorer so both engines produce comparable scores.
SCORE_LOG10_BOUNDS: Tuple[float, ...] = (3.0, 6.0, 8.0, 10.0)

# --- Password hashing settings (defensive storage) ------------------------- #
# PBKDF2-HMAC-SHA256 with 600,000 iterations follows the OWASP Password Storage
# Cheat Sheet recommendation for PBKDF2-SHA256. 16 random bytes of salt per
# password (os.urandom is the CSPRNG; secrets.token_bytes is the same source) is
# the NIST SP 800-132 minimum, and a 32-byte derived key matches the SHA-256
# output size so no security is lost to truncation.
PBKDF2_HASH_NAME = "sha256"
PBKDF2_ITERATIONS = 600_000
PBKDF2_SALT_BYTES = 16
PBKDF2_KEY_BYTES = 32
PBKDF2_TEST_ITERATIONS = 1_000  # tests only, keeps the suite fast

# --- Report settings ------------------------------------------------------- #
# Batch input defaults: how many candidates a file-driven audit reads, and how
# many get a full detail block in the HTML. The JSON always contains every one.
DEFAULT_AUDIT_LIMIT = 250
DEFAULT_MAX_DETAIL = 25

DEFAULT_REPORT_DIR = "reports"
DEFAULT_JSON_NAME = "password_audit.json"
DEFAULT_HTML_NAME = "password_audit.html"

# --- Fictional test passwords used by --demo ------------------------------- #
# Every string below is invented for this lab. Never feed a real password into a
# demonstration whose output you intend to share.
DEMO_CANDIDATES: Tuple[Tuple[str, str], ...] = (
    ("demo-1 plain wordlist entry", "password"),
    ("demo-2 capitalized plus digit", "Password1"),
    ("demo-3 combined leet, year, symbol", "P@ssw0rd2026!"),
    ("demo-4 season plus year", "Summer2026!"),
    ("demo-5 keyboard run", "qwerty123!"),
    ("demo-6 short but varied", "Xk7$q!"),
    ("demo-7 four-word passphrase", "brisk-lantern-quarry-clove"),
    ("demo-8 passphrase with variety", "Vp9!tundra-Kestrel-thicket"),
)
DEMO_REGISTRATION_ATTEMPTS: Tuple[str, ...] = (
    "Summer2026!",                 # rejected: wordlist mutation
    "Tr1ne2026",                   # rejected: wordlist mutation, no symbol
    "orchid-canyon-verdict-7731",  # accepted
)

LOGGER = logging.getLogger(TOOL_NAME)


# =========================================================================== #
# SECTION 2 -- SAFE OUTPUT, LOGGING, AND LEAK PROTECTION                      #
# =========================================================================== #

class AuditError(Exception):
    """Raised for user-correctable problems (bad paths, unusable input)."""


class ReportSafetyError(Exception):
    """Raised if a report about to be written still contains a secret value."""


class _Palette:
    """ANSI colours, disabled unless the terminal can be trusted."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t: str) -> str:
        return self._wrap("1", t)

    def dim(self, t: str) -> str:
        return self._wrap("2", t)

    def red(self, t: str) -> str:
        return self._wrap("31", t)

    def green(self, t: str) -> str:
        return self._wrap("32", t)

    def yellow(self, t: str) -> str:
        return self._wrap("33", t)

    def blue(self, t: str) -> str:
        return self._wrap("34", t)


def _colour_supported(no_colour: bool) -> bool:
    if no_colour or os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":  # try to switch on virtual terminal processing
        try:  # pragma: no cover - Windows only
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:  # pragma: no cover
            return False
    return True


def out(text: str = "") -> None:
    """Print a line, surviving Windows cp1252 consoles.

    All of this tool's output is ASCII by design, but a wordlist path or a
    zxcvbn message could contain something else, and PowerShell raises
    UnicodeEncodeError rather than degrading. Replace instead of crashing.
    """
    try:
        sys.stdout.write(text + "\n")
    except UnicodeEncodeError:  # pragma: no cover - console dependent
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        safe = (text + "\n").encode(encoding, errors="replace").decode(encoding, "replace")
        sys.stdout.write(safe)


# --- Secret tracking ------------------------------------------------------- #
# Values registered here are scrubbed from log records and checked against
# report text before it is written. This is defence in depth: the primary
# guarantee is structural, because reports are rendered from public records that
# secrets never enter.
_ACTIVE_SECRETS: List[str] = []


def register_secret(value: str) -> None:
    """Track a value that must never reach a log line or a report."""
    if value and value not in _ACTIVE_SECRETS:
        _ACTIVE_SECRETS.append(value)


def forget_secrets() -> None:
    """Drop all tracked secrets (called when a run finishes)."""
    _ACTIVE_SECRETS.clear()


def scrub(text: str) -> str:
    """Replace any tracked secret inside text with a redaction marker."""
    for secret in _ACTIVE_SECRETS:
        if secret and secret in text:
            text = text.replace(secret, "[REDACTED]")
    return text


class RedactingFilter(logging.Filter):
    """Scrub tracked secrets out of log records before they are emitted."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            record.msg = scrub(str(record.getMessage()))
            record.args = ()
        except Exception:  # pragma: no cover - never break logging
            record.msg = "[log record suppressed]"
            record.args = ()
        return True


def configure_logging(verbose: bool, log_file: Optional[str]) -> None:
    LOGGER.handlers.clear()
    LOGGER.setLevel(logging.DEBUG if verbose else logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s")
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(formatter)
    stream.addFilter(RedactingFilter())
    stream.setLevel(logging.DEBUG if verbose else logging.WARNING)
    LOGGER.addHandler(stream)
    if log_file:
        try:
            handler = logging.FileHandler(log_file, encoding="utf-8")
        except OSError as exc:
            raise AuditError(f"cannot open log file {log_file!r}: {exc}") from exc
        handler.setFormatter(formatter)
        handler.addFilter(RedactingFilter())
        LOGGER.addHandler(handler)
    LOGGER.propagate = False


def assert_no_leak(text: str, where: str) -> None:
    """Fail loudly if report text contains a tracked secret.

    Only secrets that are at least 8 characters long AND contain something other
    than lowercase letters are scanned. A dictionary-word password such as
    "password" cannot be scanned this way, because the report's own explanatory
    text legitimately contains that word; those cases are covered structurally
    instead (secrets never enter a public record) and by the report-safety tests.
    """
    for secret in _ACTIVE_SECRETS:
        if len(secret) < 8:
            continue
        if secret.isalpha() and secret.islower():
            continue
        if secret in text:
            raise ReportSafetyError(
                f"refusing to write {where}: it still contains a tracked secret value"
            )


# =========================================================================== #
# SECTION 3 -- WORDLIST LOADING                                               #
# =========================================================================== #

@dataclass
class Wordlist:
    """A set of known-bad passwords, lowercased for case-insensitive lookups."""

    entries: frozenset
    source_path: Optional[str]
    file_lines: int
    demo_entries: int
    truncated: bool
    limit: int
    notes: List[str] = field(default_factory=list)

    @property
    def file_loaded(self) -> bool:
        return self.source_path is not None

    def contains(self, word: str) -> bool:
        return word.lower() in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def describe(self) -> str:
        if self.file_loaded:
            base = (
                f"{len(self):,} unique entries "
                f"({self.file_lines:,} line{'' if self.file_lines == 1 else 's'} "
                f"read from {self.source_path}"
            )
            if self.demo_entries:
                base += f", plus {self.demo_entries:,} built-in demonstration entries"
            base += ")"
            if self.truncated:
                base += f" [truncated at --wordlist-limit {self.limit:,}]"
            return base
        return (
            f"{len(self):,} entries from the built-in DEMONSTRATION list only "
            "(no rockyou sample file loaded)"
        )

    def provenance(self) -> Dict[str, object]:
        return {
            "total_entries": len(self),
            "file_loaded": self.file_loaded,
            "source_path": self.source_path,
            "file_lines_read": self.file_lines,
            "demo_entries": self.demo_entries,
            "truncated_at_limit": self.truncated,
            "limit": self.limit,
            "notes": list(self.notes),
        }


def load_wordlist(
    path: Optional[str] = None,
    limit: int = DEFAULT_WORDLIST_LIMIT,
    include_demo: bool = True,
) -> Wordlist:
    """Load the rockyou sample if it is present, always with a working fallback.

    Resolution order: explicit path, PASSWORD_AUDITOR_WORDLIST, then
    DEFAULT_WORDLIST_PATH. A missing file is a note, not an error.
    """
    if limit <= 0:
        raise AuditError("--wordlist-limit must be greater than 0")

    notes: List[str] = []
    entries = set()
    demo_count = 0
    if include_demo:
        entries.update(word.lower() for word in DEMO_WORDLIST)
        demo_count = len(entries)

    resolved = path or os.environ.get(WORDLIST_ENV_VAR) or DEFAULT_WORDLIST_PATH
    candidate = Path(resolved).expanduser()

    if not candidate.exists():
        notes.append(
            f"wordlist file not found at '{candidate}'. Running with the built-in "
            "demonstration list. Supply the assignment's rockyou sample with "
            "--wordlist PATH (see the module docstring)."
        )
        if not include_demo:
            raise AuditError(
                f"no wordlist available: '{candidate}' is missing and the "
                "demonstration list was disabled with --no-demo-wordlist"
            )
        LOGGER.info("wordlist file missing, using demonstration list")
        return Wordlist(frozenset(entries), None, 0, demo_count, False, limit, notes)

    if candidate.is_dir():
        raise AuditError(f"--wordlist expects a file but '{candidate}' is a directory")

    file_added = 0
    truncated = False
    try:
        with candidate.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, raw in enumerate(handle, start=1):
                if line_number > limit:
                    truncated = True
                    break
                word = raw.strip()
                if not word or word.startswith("#"):
                    continue
                lowered = word.lower()
                if lowered not in entries:
                    entries.add(lowered)
                file_added += 1
    except PermissionError as exc:
        raise AuditError(f"cannot read '{candidate}': permission denied") from exc
    except OSError as exc:
        raise AuditError(f"cannot read '{candidate}': {exc}") from exc

    if file_added == 0:
        notes.append(f"'{candidate}' contained no usable entries (blank or comments only)")
    if truncated:
        notes.append(f"only the first {limit:,} lines of '{candidate}' were loaded")
    LOGGER.info("loaded %d wordlist lines from file", file_added)
    return Wordlist(
        frozenset(entries), str(candidate), file_added, demo_count, truncated, limit, notes
    )


# =========================================================================== #
# SECTION 4 -- MUTATION ENGINE (offensive component 2)                        #
# =========================================================================== #

@dataclass(frozen=True)
class MutationMatch:
    """A wordlist hit, optionally reached by reversing attacker rules.

    base_word is the private detail: it is kept out of every report, because
    printing it would disclose most of the audited password.
    """

    base_word: str
    rules: Tuple[str, ...]

    @property
    def is_exact(self) -> bool:
        return not self.rules

    @property
    def base_length(self) -> int:
        return len(self.base_word)

    def rule_chain(self) -> str:
        return " + ".join(self.rules) if self.rules else "exact match, no mutation"

    def public_summary(self) -> str:
        # "an 8-character", "an 11-character", "an 18-character", else "a"
        article = "an" if self.base_length in (8, 11, 18) or 80 <= self.base_length <= 89 else "a"
        if self.is_exact:
            return (
                "appears verbatim in the common-password wordlist "
                f"({article} {self.base_length}-character entry)"
            )
        return (
            f"reduces to {article} {self.base_length}-character common-password entry "
            f"after reversing: {self.rule_chain()}"
        )


class MutationEngine:
    """Generates attacker-style wordlist variations and detects them in reverse.

    Design note (this is the interesting part of the lab): generating every
    mutation of a 200,000-line rockyou sample would produce billions of strings.
    Real cracking tools stream those rules; an auditor does not need to. So
    generate() exists for demonstration and testing on single words, while
    detect() works backwards -- it peels appended digits, years, and symbols,
    normalises capitalization, reverses leet substitutions, and looks the result
    up in the wordlist. That turns an unbounded generation problem into a small
    number of set lookups per password.
    """

    def __init__(
        self,
        limits: Optional[MutationLimits] = None,
        append_digits: Sequence[str] = DEFAULT_APPEND_DIGITS,
        append_symbols: Sequence[str] = DEFAULT_APPEND_SYMBOLS,
        prepend: Sequence[str] = DEFAULT_PREPEND,
        year_range: Tuple[int, int] = DEFAULT_YEAR_RANGE,
        leet_alternates: bool = False,
    ) -> None:
        self.limits = limits or MutationLimits()
        self.leet_alternates = leet_alternates
        self.append_digits = tuple(append_digits)
        self.append_symbols = tuple(append_symbols)
        self.prepend = tuple(prepend)
        first, last = year_range
        if last < first:
            raise AuditError("--years requires START <= END")
        self.years = tuple(str(year) for year in range(first, last + 1)) + EXTRA_YEARS

    # ----------------------- forward generation ---------------------------- #
    def case_variants(self, word: str) -> List[str]:
        lowered = word.lower()
        variants = [lowered, lowered.capitalize(), lowered.upper(), lowered.title()]
        unique: List[str] = []
        for variant in variants:
            if variant not in unique:
                unique.append(variant)
        return unique[: self.limits.max_case_variants]

    def leet_variants(self, word: str) -> List[str]:
        """Apply subsets of leet substitutions, fewest substitutions first.

        Ordering matters: when the configured cap truncates the list, the forms
        an attacker tries earliest are the ones kept.
        """
        positions = [
            index for index, char in enumerate(word) if char.lower() in LEET_FORWARD
        ][: self.limits.max_leet_positions]
        if not positions:
            return [word]
        options = []
        for index in positions:
            plain = word[index].lower()
            if self.leet_alternates:
                options.append((word[index],) + LEET_FORWARD[plain])
            else:
                options.append((word[index], LEET_PRIMARY[plain]))
        scored: List[Tuple[int, int, str]] = []
        for rank, combo in enumerate(itertools.product(*options)):
            chars = list(word)
            substitutions = 0
            for index, replacement in zip(positions, combo):
                if chars[index] != replacement:
                    substitutions += 1
                chars[index] = replacement
            scored.append((substitutions, rank, "".join(chars)))
        scored.sort()
        variants: List[str] = []
        for _, _, candidate in scored:
            if candidate not in variants:
                variants.append(candidate)
            if len(variants) >= self.limits.max_leet_variants:
                break
        return variants

    def suffix_tokens(self) -> List[str]:
        """Appended digit, year, and symbol tokens, in the order rules try them."""
        tokens: List[str] = []
        for token in self.append_digits + self.years:
            if token not in tokens:
                tokens.append(token)
        return tokens

    def rule_space_estimate(self) -> int:
        """How many strings the configured rules can produce per base word.

        Used to cap the attack-model entropy of a mutated wordlist entry: an
        attacker needs at most (wordlist size x rule space) guesses to find it.
        """
        leet_forms = min(
            2 ** self.limits.max_leet_positions, self.limits.max_leet_variants
        )
        space = (
            self.limits.max_case_variants
            * leet_forms
            * max(len(self.prepend), 1)
            * max(len(self.suffix_tokens()), 1)
            * max(len(self.append_symbols), 1)
        )
        return max(space, 1)

    def generate(self, word: str, max_variants: Optional[int] = None) -> List[str]:
        """Return attacker-style mutations of a single base word, deterministically."""
        if not word or not word.strip():
            raise AuditError("mutation generation needs a non-empty base word")
        cap = max_variants or self.limits.max_variants_per_word
        suffixes = self.suffix_tokens()
        cased_forms = self.case_variants(word)
        # Leet substitution is the outermost loop and is ordered by how many
        # letters it changes, so a small cap still yields variants across every
        # case form rather than thousands of variants of just the first one.
        leet_by_case = [self.leet_variants(cased) for cased in cased_forms]
        depth = max(len(forms) for forms in leet_by_case)
        results: List[str] = []
        seen = set()
        for level in range(depth):
            for forms in leet_by_case:
                if level >= len(forms):
                    continue
                leeted = forms[level]
                for head in self.prepend:
                    for digits in suffixes:
                        for symbol in self.append_symbols:
                            candidate = f"{head}{leeted}{digits}{symbol}"
                            if candidate in seen:
                                continue
                            seen.add(candidate)
                            results.append(candidate)
                            if len(results) >= cap:
                                return results
        return results

    # ----------------------- reverse detection ----------------------------- #
    def _peel_options(self, text: str) -> List[Tuple[str, str]]:
        """Every way to strip one trailing or leading affix run off text.

        Each split length is tried, not just the longest run. That matters more
        than it looks: in D@n1312019 the trailing digits are 312019, but the
        affix an attacker appended is only the year 2019 -- the 31 belongs to the
        leet spelling of the base word. Taking the greedy run would leave D@n1
        and the base word would never be recovered.
        """
        options: List[Tuple[str, str]] = []
        digits = re.search(r"\d+$", text)
        if digits:
            run = digits.group(0)
            for size in range(1, min(len(run), self.limits.max_affix_run) + 1):
                piece = run[-size:]
                if size == 4 and 1900 <= int(piece) <= 2100:
                    rule = "appended year"
                else:
                    rule = f"appended digits (x{size})"
                options.append((text[: len(text) - size], rule))
        symbols = re.search(r"[^A-Za-z0-9]+$", text)
        if symbols:
            run = symbols.group(0)
            for size in range(1, min(len(run), self.limits.max_affix_run) + 1):
                options.append(
                    (text[: len(text) - size], f"appended symbols (x{size})")
                )
        leading = re.match(r"^[^A-Za-z]+", text)
        if leading:
            run = leading.group(0)
            for size in range(1, min(len(run), 3) + 1):
                options.append((text[size:], "prefixed characters"))
        return options

    def _candidate_cores(self, password: str) -> List[Tuple[str, Tuple[str, ...]]]:
        """Stems reachable by peeling affixes, breadth first so the shortest
        rule chain to any given stem is the one that is kept."""
        first_seen: Dict[str, Tuple[str, ...]] = {password: ()}
        order: List[Tuple[str, Tuple[str, ...]]] = [(password, ())]
        queue: List[Tuple[str, Tuple[str, ...]]] = [(password, ())]
        depth = {password: 0}
        while queue and len(order) < self.limits.max_cores:
            current, rules = queue.pop(0)
            if depth[current] >= self.limits.max_affix_peels:
                continue
            for core, rule in self._peel_options(current):
                if len(core) < self.limits.min_base_length or core in first_seen:
                    continue
                chain = rules + (rule,)
                first_seen[core] = chain
                depth[core] = depth[current] + 1
                order.append((core, chain))
                queue.append((core, chain))
                if len(order) >= self.limits.max_cores:
                    break
        return order

    def _unleet_variants(self, word: str) -> Iterator[Tuple[str, Tuple[str, ...]]]:
        """Yield plausible de-leeted forms of word, identity first."""
        # Take as many substitution points as the variant budget allows rather
        # than a fixed count: most leet characters map one way (0 -> o), so a
        # long password is affordable, while an ambiguous '1' (i or l) triples
        # the work and is what the budget is really protecting against.
        positions: List[int] = []
        options: List[Tuple[str, ...]] = []
        product = 1
        for index, char in enumerate(word):
            if char not in LEET_REVERSE:
                continue
            if len(positions) >= self.limits.max_leet_positions:
                break
            choices = (char,) + LEET_REVERSE[char]
            if product * len(choices) > self.limits.max_unleet_variants:
                break
            positions.append(index)
            options.append(choices)
            product *= len(choices)
        if not positions:
            yield word, ()
            return
        produced = 0
        for combo in itertools.product(*options):
            if produced >= self.limits.max_unleet_variants:
                return
            chars = list(word)
            changed = False
            for index, replacement in zip(positions, combo):
                if chars[index] != replacement:
                    chars[index] = replacement
                    changed = True
            produced += 1
            yield "".join(chars), (("leet substitution",) if changed else ())

    def detect(self, password: str, wordlist: Wordlist) -> Optional[MutationMatch]:
        """Find the best wordlist hit reachable by reversing attacker rules."""
        if not password:
            return None
        best: Optional[MutationMatch] = None
        for core, affix_rules in self._candidate_cores(password):
            if len(core) < self.limits.min_base_length:
                continue
            lowered = core.lower()
            case_rules: Tuple[str, ...] = () if lowered == core else ("capitalization",)
            for variant, leet_rules in self._unleet_variants(lowered):
                if len(variant) < self.limits.min_base_length:
                    continue
                if not wordlist.contains(variant):
                    continue
                match = MutationMatch(variant, affix_rules + case_rules + leet_rules)
                if best is None or self._better(match, best):
                    best = match
        return best

    @staticmethod
    def _better(candidate: MutationMatch, incumbent: MutationMatch) -> bool:
        """Prefer the longest base word, then the shortest rule chain."""
        if candidate.base_length != incumbent.base_length:
            return candidate.base_length > incumbent.base_length
        return len(candidate.rules) < len(incumbent.rules)


# =========================================================================== #
# SECTION 5 -- STRENGTH SCORER (offensive component 1)                        #
# =========================================================================== #

@dataclass
class Finding:
    """One observation about a password. private_detail never leaves this object."""

    code: str
    severity: str  # critical | high | medium | low | info
    summary: str
    advice: str
    private_detail: str = ""

    def public_dict(self) -> Dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "summary": self.summary,
            "advice": self.advice,
        }


@dataclass
class StrengthResult:
    """Everything the scorer learned about one password."""

    length: int
    char_classes: Dict[str, bool]
    pool_size: int
    pool_bits: float
    attack_bits: float
    guesses_log10: float
    score: int
    engine_score: int
    rating: str
    engine: str
    hard_reject: bool
    hard_reject_reason: str
    findings: List[Finding]
    feedback: List[str]
    patterns: List[Dict[str, object]]
    mutation: Optional[MutationMatch]

    def crack_times(self) -> List[Dict[str, object]]:
        expected_guesses = 2.0 ** max(self.attack_bits - 1.0, 0.0)
        rows = []
        for label, rate in GUESS_RATES:
            rows.append(
                {
                    "scenario": label,
                    "seconds": round(expected_guesses / rate, 3),
                    "display": human_duration(expected_guesses / rate),
                }
            )
        return rows


def classify_characters(password: str) -> Dict[str, bool]:
    return {
        "lowercase": any(char.islower() and char.isascii() for char in password),
        "uppercase": any(char.isupper() and char.isascii() for char in password),
        "digit": any(char.isdigit() and char.isascii() for char in password),
        "symbol": any(
            (char in string.punctuation) or char == " " for char in password
        ),
        "other": any(not char.isascii() for char in password),
    }


def pool_entropy_bits(password: str) -> Tuple[int, float]:
    """Naive uniform-random entropy: length * log2(observed character pool).

    This is the number most password meters show, and it is an upper bound that
    only holds if every character was chosen at random. It is exactly why
    P@ssw0rd2026! looks strong (13 chars, 4 classes, ~85 bits) while an attacker
    needs only a handful of guesses. Reports print it next to the attack-model
    estimate so the gap is visible.
    """
    if not password:
        return 0, 0.0
    classes = classify_characters(password)
    pool = sum(POOL_SIZES[name] for name, present in classes.items() if present)
    if pool <= 1:
        return pool, 0.0
    return pool, len(password) * math.log2(pool)


def score_from_log10_guesses(guesses_log10: float) -> int:
    score = 0
    for bound in SCORE_LOG10_BOUNDS:
        if guesses_log10 >= bound:
            score += 1
    return min(score, 4)


def human_duration(seconds: float) -> str:
    if seconds < 1:
        return "less than a second"
    units = (
        ("century", "centuries", 3153600000.0),
        ("year", "years", 31536000.0),
        ("day", "days", 86400.0),
        ("hour", "hours", 3600.0),
        ("minute", "minutes", 60.0),
        ("second", "seconds", 1.0),
    )
    for singular, plural, size in units:
        if seconds >= size:
            value = seconds / size
            if value >= 1e6:
                return f"more than a million {plural}"
            if value >= 10:
                return f"about {value:,.0f} {plural}"
            if abs(value - 1.0) < 0.05:
                return f"about 1 {singular}"
            return f"about {value:.1f} {plural}"
    return "less than a second"  # pragma: no cover


SEQUENCE_ALPHABETS: Tuple[str, ...] = (
    string.ascii_lowercase,
    string.digits,
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1qaz2wsx",
)


def find_sequence_run(password: str, minimum: int = 4) -> Optional[int]:
    """Return the length of the longest keyboard/alphabet run, if any."""
    lowered = password.lower()
    longest = 0
    for alphabet in SEQUENCE_ALPHABETS:
        for source in (alphabet, alphabet[::-1]):
            for start in range(len(source) - minimum + 1):
                for size in range(len(source) - start, minimum - 1, -1):
                    if source[start : start + size] in lowered:
                        longest = max(longest, size)
                        break
    return longest or None


class StrengthScorer:
    """Scores a password with zxcvbn plus explicit wordlist/mutation checks.

    The hard rule required by the lab: if the password is a known common
    password, or reduces to one after reversing attacker mutations, the score is
    forced to 0 no matter how much character variety it has.
    """

    def __init__(
        self,
        wordlist: Wordlist,
        engine: Optional[MutationEngine] = None,
        use_zxcvbn: bool = True,
    ) -> None:
        self.wordlist = wordlist
        self.mutations = engine or MutationEngine()
        self.use_zxcvbn = bool(use_zxcvbn and ZXCVBN_AVAILABLE)
        self.engine_name = "zxcvbn" if self.use_zxcvbn else "built-in heuristic"

    # ------------------------------------------------------------------ #
    def score(self, password: str) -> StrengthResult:
        if password is None:
            raise AuditError("no password supplied")
        if not password:
            raise AuditError("password is empty")
        register_secret(password)

        classes = classify_characters(password)
        pool, pool_bits = pool_entropy_bits(password)
        findings: List[Finding] = []
        feedback: List[str] = []
        patterns: List[Dict[str, object]] = []

        mutation = self.mutations.detect(password, self.wordlist)
        if mutation is not None:
            register_secret(mutation.base_word)

        if self.use_zxcvbn:
            engine_score, guesses_log10, feedback, patterns = self._zxcvbn(password)
        else:
            engine_score, guesses_log10 = self._heuristic(password, pool_bits, mutation)
            feedback.append(
                "zxcvbn is not installed, so scoring used the built-in heuristic. "
                "Install it with 'pip install zxcvbn' for pattern-aware scoring."
            )

        attack_bits = guesses_log10 * math.log2(10.0)
        score = engine_score
        hard_reject = False
        reason = ""

        # --- explicit wordlist rules (independent of zxcvbn) --------------- #
        if mutation is not None:
            hard_reject = True
            if mutation.is_exact:
                reason = "known common password"
                findings.append(
                    Finding(
                        code="WORDLIST_EXACT",
                        severity="critical",
                        summary=mutation.public_summary(),
                        advice=(
                            "Pick something that is not on any leaked-password list: "
                            "four or more unrelated words, or 16+ random characters "
                            "from a password manager."
                        ),
                        private_detail=mutation.base_word,
                    )
                )
            else:
                reason = "wordlist entry with attacker mutations applied"
                findings.append(
                    Finding(
                        code="WORDLIST_MUTATION",
                        severity="critical",
                        summary=mutation.public_summary(),
                        advice=(
                            "Mutation rules like these are built into every cracking "
                            "tool, so they add almost no work for an attacker. Change "
                            "the base word itself rather than decorating it."
                        ),
                        private_detail=mutation.base_word,
                    )
                )
            # Cap the attack estimate at the cost of running the rule set:
            # roughly (wordlist size) x (rules tried). Documented, deliberately
            # generous to the defender.
            rule_space = self.mutations.rule_space_estimate()
            capped = math.log2(max(len(self.wordlist), 1) * rule_space)
            attack_bits = min(attack_bits, capped)
            guesses_log10 = min(guesses_log10, capped / math.log2(10.0))
            score = 0

        # --- pattern findings that stand on their own ---------------------- #
        repeat = re.search(r"(.)\1{2,}", password)
        if repeat:
            findings.append(
                Finding(
                    code="REPEATED_CHARACTERS",
                    severity="medium",
                    summary=f"contains a run of {len(repeat.group(0))} identical characters",
                    advice="Remove the repeated run; repeats are cheap for attackers to try.",
                    private_detail=repeat.group(0),
                )
            )
        run_length = find_sequence_run(password)
        if run_length:
            findings.append(
                Finding(
                    code="KEYBOARD_SEQUENCE",
                    severity="high",
                    summary=f"contains a {run_length}-character keyboard or alphabet run",
                    advice="Avoid straight runs such as keyboard rows or counting sequences.",
                )
            )
        if len(password) < 12:
            findings.append(
                Finding(
                    code="SHORT_LENGTH",
                    severity="high" if len(password) < 8 else "medium",
                    summary=f"only {len(password)} characters long",
                    advice="Length beats complexity. Aim for 16 or more characters.",
                )
            )
        if password != password.strip():
            findings.append(
                Finding(
                    code="EDGE_WHITESPACE",
                    severity="low",
                    summary="starts or ends with whitespace, which is easy to mistype",
                    advice="Remove leading and trailing spaces.",
                )
            )
        if not findings:
            findings.append(
                Finding(
                    code="NO_WEAKNESS_FOUND",
                    severity="info",
                    summary="no wordlist hit, mutation, repeat, or run was detected",
                    advice="Store it in a password manager and do not reuse it anywhere.",
                )
            )

        return StrengthResult(
            length=len(password),
            char_classes=classes,
            pool_size=pool,
            pool_bits=pool_bits,
            attack_bits=attack_bits,
            guesses_log10=guesses_log10,
            score=score,
            engine_score=engine_score,
            rating=SCORE_LABELS[score],
            engine=self.engine_name,
            hard_reject=hard_reject,
            hard_reject_reason=reason,
            findings=findings,
            feedback=feedback,
            patterns=patterns,
            mutation=mutation,
        )

    # ------------------------------------------------------------------ #
    def _zxcvbn(self, password: str) -> Tuple[int, float, List[str], List[Dict[str, object]]]:
        """Run zxcvbn, keeping only non-revealing parts of its output.

        zxcvbn's match sequence includes the matched token and dictionary word.
        Those are fragments of the password, so only the pattern name and the
        token length are retained.
        """
        try:
            result = _zxcvbn_score(password)  # type: ignore[misc]
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.warning("zxcvbn failed (%s), falling back to the heuristic", exc)
            pool, pool_bits = pool_entropy_bits(password)
            engine_score, guesses_log10 = self._heuristic(password, pool_bits, None)
            return engine_score, guesses_log10, ["zxcvbn raised an error; heuristic used"], []
        feedback: List[str] = []
        raw_feedback = result.get("feedback") or {}
        warning = (raw_feedback.get("warning") or "").strip()
        if warning:
            feedback.append(warning)
        for suggestion in raw_feedback.get("suggestions") or []:
            text = str(suggestion).strip()
            if text:
                feedback.append(text)
        patterns: List[Dict[str, object]] = []
        for item in result.get("sequence") or []:
            patterns.append(
                {
                    "pattern": str(item.get("pattern", "unknown")),
                    "characters_covered": len(str(item.get("token", ""))),
                }
            )
        guesses_log10 = float(result.get("guesses_log10") or 0.0)
        return int(result.get("score", 0)), guesses_log10, feedback, patterns

    def _heuristic(
        self, password: str, pool_bits: float, mutation: Optional[MutationMatch]
    ) -> Tuple[int, float]:
        """Fallback scorer used when zxcvbn is unavailable.

        Start from naive pool entropy, then subtract for the structures zxcvbn
        would have found: wordlist relationships, repeats, runs, and all-digit or
        single-class passwords. Documented so the report can explain itself.
        """
        bits = pool_bits
        if mutation is not None:
            bits = min(bits, math.log2(max(len(self.wordlist), 1)) + 12.0)
        if re.search(r"(.)\1{2,}", password):
            bits -= 6.0
        run = find_sequence_run(password)
        if run:
            bits -= 4.0 + 2.0 * run
        classes = sum(1 for present in classify_characters(password).values() if present)
        if classes == 1:
            bits -= 8.0
        if len(password) < 8:
            bits -= 8.0
        bits = max(bits, 1.0)
        guesses_log10 = bits / math.log2(10.0)
        return score_from_log10_guesses(guesses_log10), guesses_log10


# =========================================================================== #
# SECTION 6 -- POLICY ENFORCER (defensive component 3)                        #
# =========================================================================== #

@dataclass
class PasswordPolicy:
    """Configurable password requirements. Drop this into a real registration flow.

    Defaults follow NIST SP 800-63B where practical: length is the primary
    control, known-breached passwords are blocked outright, and a long passphrase
    is exempt from character-class rules (set passphrase_exemption_length to 0 to
    disable that behaviour).
    """

    name: str = "CSIT 2033 baseline"
    min_length: int = 12
    max_length: int = 128  # bounded so a huge input cannot stall PBKDF2
    # Composition rules default to OFF, on the evidence. Measured over ~400
    # candidates, the character-class rules were the deciding rule four times,
    # and all four were 16-character random strings that zxcvbn rated 4/4 at
    # ~53 bits -- centuries of work against this tool's PBKDF2 settings. They
    # rejected four strong passwords and not one weak one, which is the concrete
    # version of why NIST SP 800-63B dropped composition requirements: they push
    # people toward Summer2026! and turn away password-manager output. Length,
    # guess resistance, and the breached-password check do the real work. Turn
    # them back on with --require-digit etc., or --policy-profile composition.
    require_lowercase: bool = False
    require_uppercase: bool = False
    require_digit: bool = False
    require_symbol: bool = False
    min_strength_score: int = 3
    min_attack_bits: float = 40.0
    forbid_wordlist_exact: bool = True
    forbid_wordlist_mutations: bool = True
    forbid_repeated_runs: bool = True
    forbid_sequences: bool = True
    forbid_edge_whitespace: bool = True
    passphrase_exemption_length: int = 20
    banned_terms: Tuple[str, ...] = (
        "trine", "csit", "veridos", "vericloud", "admin", "administrator",
        "username", "changeme", "welcome", "company", "letmein",
    )

    def settings_dict(self) -> Dict[str, object]:
        """Policy settings as reported (banned terms are listed; they are not secret)."""
        return {
            "name": self.name,
            "min_length": self.min_length,
            "max_length": self.max_length,
            "require_lowercase": self.require_lowercase,
            "require_uppercase": self.require_uppercase,
            "require_digit": self.require_digit,
            "require_symbol": self.require_symbol,
            "min_strength_score": self.min_strength_score,
            "min_attack_bits": self.min_attack_bits,
            "forbid_wordlist_exact": self.forbid_wordlist_exact,
            "forbid_wordlist_mutations": self.forbid_wordlist_mutations,
            "forbid_repeated_runs": self.forbid_repeated_runs,
            "forbid_sequences": self.forbid_sequences,
            "forbid_edge_whitespace": self.forbid_edge_whitespace,
            "passphrase_exemption_length": self.passphrase_exemption_length,
            "banned_terms_count": len(self.banned_terms),
            "statement": self.statement_lines(),
        }

    def statement(self) -> List[Tuple[str, str]]:
        """The policy written out rule by rule as (label, requirement) pairs.

        Single source of truth for the policy text: the terminal header, the
        registration prompt, the HTML report, and the JSON results all render
        this, so the stated policy can never drift from the enforced one.
        """
        rules: List[Tuple[str, str]] = [
            (
                "Length",
                f"at least {self.min_length} characters, and no more than "
                f"{self.max_length}.",
            )
        ]
        classes = [
            description
            for description, required in (
                ("a lowercase letter", self.require_lowercase),
                ("an uppercase letter", self.require_uppercase),
                ("a digit", self.require_digit),
                ("a symbol", self.require_symbol),
            )
            if required
        ]
        if classes:
            if len(classes) > 1:
                joined = ", ".join(classes[:-1]) + ", and " + classes[-1]
            else:
                joined = classes[0]
            rules.append(("Character types", f"must contain {joined}."))
        else:
            rules.append(
                (
                    "Character types",
                    "no composition requirements. Length, guess resistance, and the "
                    "breached-password check are the controls, following NIST SP "
                    "800-63B; mixing in a digit does not make a common password safe, "
                    "and requiring one turns away strong generated passwords.",
                )
            )
        if classes and self.passphrase_exemption_length > 0:
            rules.append(
                (
                    "Passphrase exemption",
                    f"a password of {self.passphrase_exemption_length} characters or "
                    "more that already meets the strength rules is exempt from the "
                    "character-type requirements, following NIST SP 800-63B, which "
                    "treats length as the stronger control.",
                )
            )
        rules.append(
            (
                "Strength score",
                f"at least {self.min_strength_score} out of 4 from the scoring engine.",
            )
        )
        rules.append(
            (
                "Attack-model entropy",
                f"at least {self.min_attack_bits:.0f} bits, measured as the guesses an "
                "attacker needs rather than the naive character-pool estimate.",
            )
        )
        if self.forbid_wordlist_exact:
            rules.append(
                (
                    "Known passwords",
                    "rejected outright if the password appears in the common-password "
                    "wordlist, however much character variety it has.",
                )
            )
        if self.forbid_wordlist_mutations:
            rules.append(
                (
                    "Mutations",
                    "rejected if the password reduces to a wordlist entry once "
                    "capitalization, leet substitutions, and appended digits, years, or "
                    "symbols are reversed.",
                )
            )
        if self.forbid_repeated_runs:
            rules.append(("Repeats", "no run of three or more identical characters."))
        if self.forbid_sequences:
            rules.append(
                (
                    "Sequences",
                    "no keyboard or alphabet run of four or more characters, such as a "
                    "keyboard row or a counting sequence.",
                )
            )
        if self.forbid_edge_whitespace:
            rules.append(("Whitespace", "no leading or trailing spaces."))
        if self.banned_terms:
            rules.append(
                (
                    "Banned terms",
                    f"must not contain any of the {len(self.banned_terms)} organisation, "
                    "product, service, or role terms on the banned list.",
                )
            )
        rules.append(
            (
                "Storage",
                f"accepted passwords are hashed with PBKDF2-HMAC-{PBKDF2_HASH_NAME.upper()} "
                f"at {PBKDF2_ITERATIONS:,} iterations with a unique "
                f"{PBKDF2_SALT_BYTES}-byte random salt; the password itself is never "
                "stored, logged, or reported.",
            )
        )
        return rules

    def statement_lines(self) -> List[str]:
        """The policy as plain 'Label: requirement' lines for terminal output."""
        return [f"{label}: {requirement}" for label, requirement in self.statement()]

    def summary_line(self) -> str:
        classes = [
            label
            for label, required in (
                ("lower", self.require_lowercase),
                ("upper", self.require_uppercase),
                ("digit", self.require_digit),
                ("symbol", self.require_symbol),
            )
            if required
        ]
        return (
            f"{self.name}: length {self.min_length}-{self.max_length}, "
            f"classes {'+'.join(classes) if classes else 'none required'}, "
            f"min score {self.min_strength_score}/4, "
            f"min attack-model {self.min_attack_bits:.0f} bits"
        )


def nist_aligned_policy() -> PasswordPolicy:
    """A policy closer to NIST SP 800-63B than the classic corporate baseline.

    Same shape as the default policy, which already drops composition rules, but
    with NIST's recommended 15-character floor for user-chosen passwords rather
    than 12.
    """
    return PasswordPolicy(
        name="NIST SP 800-63B aligned",
        min_length=15,
        require_lowercase=False,
        require_uppercase=False,
        require_digit=False,
        require_symbol=False,
        min_strength_score=3,
        min_attack_bits=40.0,
        passphrase_exemption_length=0,  # no class rules to exempt anything from
    )


def composition_policy() -> PasswordPolicy:
    """The classic corporate policy: 12 characters and all four character types.

    Kept as a profile so the lab can audit one candidate set both ways and show
    what the composition rules actually buy -- which, measured on a mixed batch,
    is nothing weak caught and four strong passwords turned away.
    """
    return PasswordPolicy(
        name="classic composition rules",
        require_lowercase=True,
        require_uppercase=True,
        require_digit=True,
        require_symbol=True,
        passphrase_exemption_length=20,
    )


POLICY_PROFILES: Dict[str, object] = {
    "baseline": PasswordPolicy,
    "composition": composition_policy,
    "nist": nist_aligned_policy,
}


@dataclass
class PolicyDecision:
    """The verdict: accepted or rejected, with the reasons and the advice."""

    allowed: bool
    policy_name: str
    violations: List[Finding]
    advice: List[str]
    exemptions: List[str]

    def public_dict(self) -> Dict[str, object]:
        return {
            "allowed": self.allowed,
            "policy_name": self.policy_name,
            "outcome": "accepted" if self.allowed else "rejected",
            "violations": [violation.public_dict() for violation in self.violations],
            "advice": list(self.advice),
            "exemptions_applied": list(self.exemptions),
        }


class PolicyEnforcer:
    """Reusable accept/reject module for a registration or admin workflow.

    Usage in an application:
        enforcer = PolicyEnforcer(PasswordPolicy(), StrengthScorer(load_wordlist()))
        strength, decision = enforcer.evaluate(candidate_password)
        if not decision.allowed:
            show(decision.advice)
    """

    def __init__(self, policy: PasswordPolicy, scorer: StrengthScorer) -> None:
        self.policy = policy
        self.scorer = scorer

    def evaluate(self, password: str) -> Tuple[StrengthResult, PolicyDecision]:
        strength = self.scorer.score(password)
        return strength, self.check(password, strength)

    def check(self, password: str, strength: StrengthResult) -> PolicyDecision:
        policy = self.policy
        violations: List[Finding] = []
        exemptions: List[str] = []

        if len(password) < policy.min_length:
            violations.append(
                Finding(
                    "POLICY_MIN_LENGTH",
                    "high",
                    f"shorter than the {policy.min_length}-character minimum "
                    f"(it is {len(password)})",
                    f"Add at least {policy.min_length - len(password)} more characters. "
                    "An extra word is easier to remember than an extra symbol.",
                )
            )
        if len(password) > policy.max_length:
            violations.append(
                Finding(
                    "POLICY_MAX_LENGTH",
                    "medium",
                    f"longer than the {policy.max_length}-character maximum",
                    f"Shorten it to {policy.max_length} characters or fewer.",
                )
            )

        class_rules_active = any(
            (policy.require_lowercase, policy.require_uppercase,
             policy.require_digit, policy.require_symbol)
        )
        passphrase_exempt = (
            class_rules_active
            and policy.passphrase_exemption_length > 0
            and len(password) >= policy.passphrase_exemption_length
            and not strength.hard_reject
            and strength.score >= policy.min_strength_score
        )
        if passphrase_exempt:
            exemptions.append(
                f"character-class rules waived: {len(password)} characters meets the "
                f"{policy.passphrase_exemption_length}-character passphrase exemption"
            )
        else:
            class_rules = (
                ("lowercase", policy.require_lowercase, "a lowercase letter"),
                ("uppercase", policy.require_uppercase, "an uppercase letter"),
                ("digit", policy.require_digit, "a digit"),
                ("symbol", policy.require_symbol, "a symbol such as ! ? # or -"),
            )
            for key, required, description in class_rules:
                if required and not strength.char_classes.get(key, False):
                    violations.append(
                        Finding(
                            f"POLICY_REQUIRE_{key.upper()}",
                            "medium",
                            f"missing {description}",
                            f"Add {description}, or use a passphrase of at least "
                            f"{policy.passphrase_exemption_length} characters, which is "
                            "exempt from character-class rules.",
                        )
                    )

        if strength.hard_reject:
            if strength.mutation is not None and strength.mutation.is_exact:
                if policy.forbid_wordlist_exact:
                    violations.append(
                        Finding(
                            "POLICY_WORDLIST_EXACT",
                            "critical",
                            "matches a known common password, so character variety "
                            "cannot rescue it",
                            "Choose a passphrase of four or more unrelated words, or "
                            "generate 16+ random characters.",
                            private_detail=strength.mutation.base_word,
                        )
                    )
            elif policy.forbid_wordlist_mutations and strength.mutation is not None:
                violations.append(
                    Finding(
                        "POLICY_WORDLIST_MUTATION",
                        "critical",
                        "is a common password with predictable mutations applied "
                        f"({strength.mutation.rule_chain()})",
                        "Start from words an attacker's wordlist does not contain. "
                        "Swapping letters for symbols does not help.",
                        private_detail=strength.mutation.base_word,
                    )
                )

        if strength.score < policy.min_strength_score:
            violations.append(
                Finding(
                    "POLICY_MIN_SCORE",
                    "high",
                    f"strength score {strength.score}/4 is below the required "
                    f"{policy.min_strength_score}/4",
                    "Add length and unpredictability rather than more symbols.",
                )
            )
        if strength.attack_bits < policy.min_attack_bits:
            violations.append(
                Finding(
                    "POLICY_MIN_BITS",
                    "high",
                    f"attack-model entropy {strength.attack_bits:.1f} bits is below the "
                    f"required {policy.min_attack_bits:.0f} bits",
                    "Each extra unrelated word adds roughly 12 to 20 bits.",
                )
            )

        if policy.forbid_repeated_runs:
            for finding in strength.findings:
                if finding.code == "REPEATED_CHARACTERS":
                    violations.append(
                        Finding(
                            "POLICY_REPEATED_RUN",
                            "medium",
                            finding.summary,
                            finding.advice,
                            finding.private_detail,
                        )
                    )
        if policy.forbid_sequences:
            for finding in strength.findings:
                if finding.code == "KEYBOARD_SEQUENCE":
                    violations.append(
                        Finding(
                            "POLICY_SEQUENCE",
                            "medium",
                            finding.summary,
                            finding.advice,
                        )
                    )
        if policy.forbid_edge_whitespace and password != password.strip():
            violations.append(
                Finding(
                    "POLICY_EDGE_WHITESPACE",
                    "low",
                    "starts or ends with whitespace",
                    "Trim the leading and trailing spaces.",
                )
            )

        lowered = password.lower()
        for term in policy.banned_terms:
            if term in lowered:
                violations.append(
                    Finding(
                        "POLICY_BANNED_TERM",
                        "high",
                        "contains a banned organisation, product, or role term "
                        "(the term itself is withheld from this report)",
                        "Remove words connected to the organisation, the service, or "
                        "your role; attackers add those to their wordlists first.",
                        private_detail=term,
                    )
                )
                break

        advice = self._build_advice(violations, strength)
        return PolicyDecision(
            allowed=not violations,
            policy_name=policy.name,
            violations=violations,
            advice=advice,
            exemptions=exemptions,
        )

    def _build_advice(
        self, violations: Sequence[Finding], strength: StrengthResult
    ) -> List[str]:
        if not violations:
            advice = [
                "Accepted. Store it only in a password manager and never reuse it.",
                "Turn on multi-factor authentication; a strong password is one layer.",
            ]
            if strength.attack_bits < 60:
                advice.append(
                    "It clears the policy but is not future-proof. One more unrelated "
                    "word would raise it above 60 bits."
                )
            return advice
        advice: List[str] = []
        seen = set()
        for violation in violations:
            if violation.advice not in seen:
                advice.append(violation.advice)
                seen.add(violation.advice)
        advice.append(
            "A worked example of the shape to aim for: four unrelated words joined by "
            "punctuation, such as 'thicket-Kestrel-42-clove' (invent your own, never "
            "reuse an example from a document)."
        )
        for note in strength.feedback:
            if note not in seen:
                advice.append(f"Scorer note: {note}")
                seen.add(note)
        return advice


# =========================================================================== #
# SECTION 7 -- PASSWORD STORAGE (hashlib.pbkdf2_hmac)                         #
# =========================================================================== #

@dataclass
class HashRecord:
    """A stored credential. The salt and hash never appear in reports or logs."""

    algorithm: str
    iterations: int
    salt_bytes: int
    key_bytes: int
    salt_hex: str
    hash_hex: str
    elapsed_ms: float

    def public_dict(self) -> Dict[str, object]:
        """Report-safe view: parameters only, no salt and no hash."""
        return {
            "algorithm": self.algorithm,
            "iterations": self.iterations,
            "salt_bytes": self.salt_bytes,
            "key_bytes": self.key_bytes,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "salt_stored": "yes, unique per password (value withheld)",
            "hash_stored": "yes (value withheld)",
        }

    def encoded(self) -> str:
        """Storage format for a real database column. Never printed by this tool."""
        return f"pbkdf2_{PBKDF2_HASH_NAME}${self.iterations}${self.salt_hex}${self.hash_hex}"


def hash_password(
    password: str,
    iterations: int = PBKDF2_ITERATIONS,
    salt: Optional[bytes] = None,
) -> HashRecord:
    """Derive a PBKDF2-HMAC-SHA256 hash with a fresh random salt.

    Settings are documented at the top of this file. A unique salt per password
    means two users with the same password get different hashes, which defeats
    precomputed rainbow tables and stops an attacker from spotting shared
    passwords in a stolen table.
    """
    if not password:
        raise AuditError("cannot hash an empty password")
    if iterations < 1:
        raise AuditError("PBKDF2 iterations must be at least 1")
    register_secret(password)
    salt = salt if salt is not None else os.urandom(PBKDF2_SALT_BYTES)
    started = datetime.now(timezone.utc)
    derived = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_NAME,
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=PBKDF2_KEY_BYTES,
    )
    elapsed_ms = (datetime.now(timezone.utc) - started).total_seconds() * 1000.0
    record = HashRecord(
        algorithm=f"pbkdf2_hmac-{PBKDF2_HASH_NAME}",
        iterations=iterations,
        salt_bytes=len(salt),
        key_bytes=len(derived),
        salt_hex=salt.hex(),
        hash_hex=derived.hex(),
        elapsed_ms=elapsed_ms,
    )
    register_secret(record.hash_hex)
    register_secret(record.salt_hex)
    return record


def verify_password(password: str, record: HashRecord) -> bool:
    """Constant-time verification against a stored record."""
    if not password:
        return False
    candidate = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_NAME,
        password.encode("utf-8"),
        bytes.fromhex(record.salt_hex),
        record.iterations,
        dklen=record.key_bytes,
    )
    return hmac.compare_digest(candidate, bytes.fromhex(record.hash_hex))


# =========================================================================== #
# SECTION 8 -- PUBLIC RECORDS AND REPORTS                                     #
# =========================================================================== #

def build_public_record(
    label: str,
    strength: StrengthResult,
    decision: PolicyDecision,
    stored: Optional[HashRecord] = None,
) -> Dict[str, object]:
    """Build the only structure reports are allowed to see.

    The password, the matched wordlist word, the salt, and the hash are not
    copied in. Every value here is either a number, a policy setting, or text
    this tool authored.
    """
    record: Dict[str, object] = {
        "label": label,
        "length": strength.length,
        "character_classes_present": {
            name: bool(present) for name, present in strength.char_classes.items()
        },
        "scoring": {
            "engine": strength.engine,
            "score": strength.score,
            "rating": strength.rating,
            "engine_raw_score": strength.engine_score,
            "score_overridden": strength.hard_reject,
            "override_reason": strength.hard_reject_reason,
        },
        "entropy_estimates_bits": {
            "naive_character_pool": round(strength.pool_bits, 1),
            "attack_model": round(strength.attack_bits, 1),
            "character_pool_size": strength.pool_size,
            "guesses_log10": round(strength.guesses_log10, 2),
            "explanation": (
                "naive_character_pool = length x log2(pool of character types used). "
                "It assumes every character was chosen at random, so it is an upper "
                "bound. attack_model = log2(guesses an attacker needs), which accounts "
                "for wordlists, mutation rules, and keyboard patterns. Judge a password "
                "by attack_model; the gap between the two numbers is the illusion of "
                "complexity."
            ),
        },
        "guess_time_estimates": strength.crack_times(),
        "patterns_detected": strength.patterns,
        "findings": [finding.public_dict() for finding in strength.findings],
        "scorer_feedback": list(strength.feedback),
        "policy_decision": decision.public_dict(),
        "advice": list(decision.advice),
    }
    if stored is not None:
        record["storage"] = stored.public_dict()
    return record


def build_aggregate(records: Sequence[Dict[str, object]]) -> Dict[str, object]:
    """Roll a batch of results up into the numbers a list-wide audit is for.

    Auditing 250 entries one block at a time says little; the distribution says
    a lot. Every value here is derived from the public records, so no secret
    reaches the aggregate either.
    """
    total = len(records)
    if not total:
        return {"candidates": 0}
    score_distribution = {str(score): 0 for score in range(5)}
    failures: Dict[str, int] = {}
    bits: List[float] = []
    lengths: List[int] = []
    exact_hits = 0
    mutation_hits = 0
    accepted = 0
    for record in records:
        scoring = record.get("scoring", {}) or {}
        entropy = record.get("entropy_estimates_bits", {}) or {}
        decision = record.get("policy_decision", {}) or {}
        score = int(scoring.get("score", 0))  # type: ignore[arg-type]
        score_distribution[str(max(0, min(4, score)))] += 1
        bits.append(float(entropy.get("attack_model", 0.0)))  # type: ignore[arg-type]
        lengths.append(int(record.get("length", 0)))  # type: ignore[arg-type]
        if decision.get("allowed"):
            accepted += 1
        for violation in decision.get("violations", []) or []:
            code = str(violation.get("code", "UNKNOWN"))
            failures[code] = failures.get(code, 0) + 1
        codes = {str(finding.get("code")) for finding in record.get("findings", []) or []}
        if "WORDLIST_EXACT" in codes:
            exact_hits += 1
        if "WORDLIST_MUTATION" in codes:
            mutation_hits += 1
    ordered_bits = sorted(bits)
    middle = len(ordered_bits) // 2
    median_bits = (
        ordered_bits[middle]
        if len(ordered_bits) % 2
        else (ordered_bits[middle - 1] + ordered_bits[middle]) / 2.0
    )
    return {
        "candidates": total,
        "accepted": accepted,
        "rejected": total - accepted,
        "acceptance_rate_percent": round(100.0 * accepted / total, 1),
        "score_distribution": score_distribution,
        "score_labels": list(SCORE_LABELS),
        "length": {
            "min": min(lengths),
            "median": sorted(lengths)[len(lengths) // 2],
            "max": max(lengths),
        },
        "attack_model_bits": {
            "min": round(min(bits), 1),
            "median": round(median_bits, 1),
            "mean": round(sum(bits) / total, 1),
            "max": round(max(bits), 1),
        },
        "wordlist_exact_hits": exact_hits,
        "wordlist_mutation_hits": mutation_hits,
        "policy_failures_by_rule": [
            {
                "code": code,
                "count": count,
                "share_percent": round(100.0 * count / total, 1),
            }
            for code, count in sorted(failures.items(), key=lambda item: (-item[1], item[0]))
        ],
    }


def build_report_payload(
    records: Sequence[Dict[str, object]],
    policy: PasswordPolicy,
    wordlist: Wordlist,
    engine: MutationEngine,
    mode: str,
) -> Dict[str, object]:
    accepted = sum(
        1
        for record in records
        if isinstance(record.get("policy_decision"), dict)
        and record["policy_decision"].get("allowed")  # type: ignore[index]
    )
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "mode": mode,
        "privacy_note": (
            "This report deliberately contains no passwords, no hashes, no salts, and "
            "no matched wordlist fragments."
        ),
        "environment": {
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "zxcvbn_available": ZXCVBN_AVAILABLE,
        },
        "policy": policy.settings_dict(),
        "wordlist": wordlist.provenance(),
        "mutation_limits": {
            "max_case_variants": engine.limits.max_case_variants,
            "max_leet_positions": engine.limits.max_leet_positions,
            "max_leet_variants": engine.limits.max_leet_variants,
            "max_variants_per_word": engine.limits.max_variants_per_word,
            "max_unleet_variants": engine.limits.max_unleet_variants,
            "max_affix_peels": engine.limits.max_affix_peels,
            "max_affix_run": engine.limits.max_affix_run,
            "min_base_length": engine.limits.min_base_length,
        },
        "hashing": {
            "algorithm": f"pbkdf2_hmac-{PBKDF2_HASH_NAME}",
            "iterations": PBKDF2_ITERATIONS,
            "salt_bytes": PBKDF2_SALT_BYTES,
            "key_bytes": PBKDF2_KEY_BYTES,
            "note": "one fresh os.urandom salt per password; values never reported",
        },
        "summary": {
            "candidates_audited": len(records),
            "accepted": accepted,
            "rejected": len(records) - accepted,
        },
        "aggregate": build_aggregate(records),
        "results": list(records),
    }


def write_json_report(payload: Dict[str, object], path: Path) -> Path:
    text = json.dumps(payload, indent=2, sort_keys=False)
    assert_no_leak(text, f"JSON report {path}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise AuditError(f"cannot write JSON report to '{path}': {exc}") from exc
    return path


# ---------------------------- HTML report ---------------------------------- #
_HTML_STYLE = """
:root {
  --paper: #ffffff;
  --ink: #171c22;
  --muted: #5c6874;
  --rule: #d5dbe1;
  --wash: #f2f5f8;
  --steel: #2f5d8c;
  --ghost: #b3bec9;
  --reject: #9e1c2f;
  --allow: #17603f;
}
* { box-sizing: border-box; }
body {
  margin: 0 auto; padding: 2.5rem 1.5rem 4rem; max-width: 46rem;
  background: var(--paper); color: var(--ink);
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
  font-size: 17px; line-height: 1.55; text-align: left;
}
h1 { font-size: 1.9rem; line-height: 1.15; margin: 0 0 .35rem; font-weight: 600; }
h2 { font-size: 1.15rem; margin: 2.6rem 0 .6rem; font-weight: 600; }
h3 { font-size: 1.05rem; margin: 0 0 .15rem; font-weight: 600; }
p { margin: .5rem 0; }
.lede { color: var(--muted); margin: 0 0 1.6rem; }
.meta { display: grid; grid-template-columns: 11rem 1fr; gap: .2rem .9rem;
  border-top: 1px solid var(--rule); border-bottom: 1px solid var(--rule);
  padding: .9rem 0; margin: 0 0 1.2rem; font-size: .93rem; }
.meta dt { color: var(--muted); }
.meta dd { margin: 0; font-variant-numeric: tabular-nums; }
.dist { display: grid; grid-template-columns: 7.5rem 1fr 4.5rem; gap: .3rem .7rem;
  align-items: center; font-size: .9rem; margin: .6rem 0 1.2rem;
  font-variant-numeric: tabular-nums; page-break-inside: avoid; }
.dist .label { color: var(--muted); }
.dist .meter { background: var(--wash); height: 1rem; }
.dist .meter > div { background: var(--steel); height: 100%; }
.dist .meter > div.pass { background: var(--allow); }
.policy { display: grid; grid-template-columns: 11rem 1fr; gap: .45rem .9rem;
  margin: .8rem 0 1.4rem; font-size: .95rem; page-break-inside: avoid;
  break-inside: avoid; }
.policy dt { color: var(--muted); }
.policy dd { margin: 0; }
.note { background: var(--wash); border-left: 3px solid var(--steel);
  padding: .7rem .9rem; font-size: .92rem; margin: 1.2rem 0; }
.candidate { border-top: 1px solid var(--rule); padding: 1.4rem 0 .4rem;
  page-break-inside: avoid; break-inside: avoid; }
.verdict { font-size: 1.05rem; margin: .1rem 0 .9rem; font-weight: 600; }
.verdict.rejected { color: var(--reject); }
.verdict.accepted { color: var(--allow); }
.subtle { color: var(--muted); font-weight: 400; font-size: .92rem; }
.scale { margin: 1.1rem 0 1.3rem; }
.scale-track { position: relative; height: 2.6rem;
  border-bottom: 1px solid var(--rule); }
.tickmark { position: absolute; top: 0; bottom: 0; width: 1px;
  background: var(--rule); }
.tickmark.floor { background: var(--steel); opacity: .5; }
.bar { position: absolute; left: 0; height: .95rem; }
.bar.attack { top: .2rem; background: var(--steel); }
.bar.naive { top: 1.4rem; background: transparent;
  border: 1px solid var(--ghost); border-left: none; }
.bar-label { position: absolute; top: 0; font-size: .72rem; line-height: .95rem;
  white-space: nowrap; font-variant-numeric: tabular-nums; }
.bar-label.inside { right: .4rem; }
.bar.attack .bar-label.inside { color: var(--paper); }
.bar.naive .bar-label.inside { color: var(--muted); }
.bar-label.outside { left: calc(100% + .4rem); color: var(--muted); }
.axis { position: relative; height: 1.15rem; margin-top: .15rem; font-size: .72rem;
  color: var(--muted); font-variant-numeric: tabular-nums; }
.axis span { position: absolute; transform: translateX(-50%); white-space: nowrap; }
.axis span.start { transform: none; }
.axis span.end { transform: translateX(-100%); }
.readings { display: grid; grid-template-columns: 1fr 1fr; gap: .1rem 1.2rem;
  font-size: .93rem; margin: .6rem 0 1rem; font-variant-numeric: tabular-nums; }
.readings span { color: var(--muted); }
table { width: 100%; border-collapse: collapse; font-size: .92rem; margin: .5rem 0 1rem; }
th, td { text-align: left; vertical-align: top; padding: .38rem .5rem .38rem 0;
  border-bottom: 1px solid var(--rule); }
th { color: var(--muted); font-weight: 600; }
code { font-family: ui-monospace, "SFMono-Regular", Consolas, monospace;
  font-size: .82em; }
.sev-critical { color: var(--reject); font-weight: 600; }
.sev-high { color: #8a5b12; }
ul { margin: .4rem 0 1rem; padding-left: 1.2rem; }
li { margin: .25rem 0; }
footer { margin-top: 3rem; border-top: 1px solid var(--rule); padding-top: .8rem;
  font-size: .86rem; color: var(--muted); }
@media print {
  body { padding: 0; font-size: 11.5pt; max-width: none; }
  .no-print { display: none !important; }
  .candidate, table, .scale { page-break-inside: avoid; break-inside: avoid; }
  h2 { page-break-after: avoid; }
  a { text-decoration: none; color: inherit; }
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
@page { margin: 0.75in; }
"""


def _bar_width(bits: float) -> float:
    """Bar width as a percentage of the 0-to-AXIS_MAX_BITS axis.

    A floor of 0.6% keeps a near-zero bar visible instead of invisible.
    """
    return max(0.6, min(100.0, (bits / AXIS_MAX_BITS) * 100.0))


def _axis_left(bits: float) -> float:
    """Position on the axis, unclamped at the low end so 0 sits at 0%."""
    return max(0.0, min(100.0, (bits / AXIS_MAX_BITS) * 100.0))


# Landmarks drawn on the bit axis, in bits. The policy floor is added at render
# time because it is configurable.
AXIS_TICKS: Tuple[float, ...] = (0.0, 28.0, 64.0, 96.0, AXIS_MAX_BITS)
LABEL_INSIDE_THRESHOLD = 34.0  # percent; narrower bars get an outside label


def _render_scale(attack_bits: float, naive_bits: float, floor_bits: float) -> str:
    """Draw the two entropy estimates on one shared bit axis.

    The gap between the solid bar (what an attacker actually needs) and the
    hollow bar (what the character mix suggests) is the whole point of the
    report, so it gets the widest element on the page.
    """
    esc = html.escape
    parts: List[str] = ['<div class="scale"><div class="scale-track">']
    for tick in AXIS_TICKS:
        if 0.0 < tick < AXIS_MAX_BITS:
            parts.append(f'<div class="tickmark" style="left:{_axis_left(tick):.2f}%"></div>')
    if 0.0 < floor_bits < AXIS_MAX_BITS:
        parts.append(
            f'<div class="tickmark floor" style="left:{_axis_left(floor_bits):.2f}%"></div>'
        )
    for kind, bits in (("attack", attack_bits), ("naive", naive_bits)):
        width = _bar_width(bits)
        name = "attack model" if kind == "attack" else "naive pool"
        off_scale = " (off scale)" if bits > AXIS_MAX_BITS else ""
        placement = "inside" if width >= LABEL_INSIDE_THRESHOLD else "outside"
        parts.append(
            f'<div class="bar {kind}" style="width:{width:.1f}%">'
            f'<span class="bar-label {placement}">{esc(name)} {bits:.1f} bits'
            f"{off_scale}</span></div>"
        )
    parts.append("</div>")
    parts.append('<div class="axis">')
    for index, tick in enumerate(AXIS_TICKS):
        css = "start" if index == 0 else ("end" if tick == AXIS_MAX_BITS else "")
        text = f"{tick:.0f} bits" if tick == AXIS_MAX_BITS else f"{tick:.0f}"
        parts.append(
            f'<span class="{css}" style="left:{_axis_left(tick):.2f}%">{esc(text)}</span>'
        )
    if 0.0 < floor_bits < AXIS_MAX_BITS:
        parts.append(
            f'<span style="left:{_axis_left(floor_bits):.2f}%">'
            f"{floor_bits:.0f} floor</span>"
        )
    parts.append("</div></div>")
    return "\n".join(parts)


def _render_candidate_html(record: Dict[str, object], floor_bits: float = 40.0) -> str:
    esc = html.escape
    decision = record.get("policy_decision", {}) or {}
    scoring = record.get("scoring", {}) or {}
    entropy = record.get("entropy_estimates_bits", {}) or {}
    allowed = bool(decision.get("allowed"))
    attack = float(entropy.get("attack_model", 0.0))
    naive = float(entropy.get("naive_character_pool", 0.0))
    classes = record.get("character_classes_present", {}) or {}
    present = ", ".join(name for name, flag in classes.items() if flag) or "none"

    parts: List[str] = ['<section class="candidate">']
    parts.append(f"<h3>{esc(str(record.get('label', 'candidate')))}</h3>")
    verdict_class = "accepted" if allowed else "rejected"
    verdict_word = "Accepted by policy" if allowed else "Rejected by policy"
    reasons = len(decision.get("violations", []) or [])
    detail = "" if allowed else f' <span class="subtle">{reasons} rule(s) not met</span>'
    parts.append(f'<p class="verdict {verdict_class}">{verdict_word}{detail}</p>')

    parts.append(_render_scale(attack, naive, floor_bits))

    override = ""
    if scoring.get("score_overridden"):
        override = (
            f" <span class=\"subtle\">(engine said "
            f"{esc(str(scoring.get('engine_raw_score')))}/4, overridden: "
            f"{esc(str(scoring.get('override_reason')))})</span>"
        )
    parts.append('<div class="readings">')
    parts.append(
        f"<div><span>Score:</span> {esc(str(scoring.get('score')))}/4 "
        f"{esc(str(scoring.get('rating')))}{override}</div>"
    )
    parts.append(f"<div><span>Length:</span> {esc(str(record.get('length')))} characters</div>")
    parts.append(f"<div><span>Character types:</span> {esc(present)}</div>")
    parts.append(f"<div><span>Scoring engine:</span> {esc(str(scoring.get('engine')))}</div>")
    parts.append("</div>")

    guess_rows = record.get("guess_time_estimates", []) or []
    if guess_rows:
        parts.append("<table><thead><tr><th>Guessing scenario</th><th>Expected time</th>"
                     "</tr></thead><tbody>")
        for row in guess_rows:
            parts.append(
                f"<tr><td>{esc(str(row.get('scenario')))}</td>"
                f"<td>{esc(str(row.get('display')))}</td></tr>"
            )
        parts.append("</tbody></table>")

    findings = record.get("findings", []) or []
    if findings:
        parts.append("<table><thead><tr><th>Finding</th><th>What was observed</th>"
                     "</tr></thead><tbody>")
        for finding in findings:
            severity = str(finding.get("severity", "info"))
            parts.append(
                f'<tr><td><code>{esc(str(finding.get("code")))}</code><br>'
                f'<span class="sev-{esc(severity)}">{esc(severity)}</span></td>'
                f'<td>{esc(str(finding.get("summary")))}</td></tr>'
            )
        parts.append("</tbody></table>")

    violations = decision.get("violations", []) or []
    if violations:
        parts.append("<table><thead><tr><th>Policy rule</th><th>Why it failed</th>"
                     "</tr></thead><tbody>")
        for violation in violations:
            parts.append(
                f'<tr><td><code>{esc(str(violation.get("code")))}</code></td>'
                f'<td>{esc(str(violation.get("summary")))}</td></tr>'
            )
        parts.append("</tbody></table>")

    for exemption in decision.get("exemptions_applied", []) or []:
        parts.append(f'<p class="subtle">Exemption applied: {esc(str(exemption))}</p>')

    advice = record.get("advice", []) or []
    if advice:
        parts.append("<p><strong>Advice</strong></p><ul>")
        for item in advice:
            parts.append(f"<li>{esc(str(item))}</li>")
        parts.append("</ul>")

    storage = record.get("storage")
    if isinstance(storage, dict):
        parts.append(
            '<p class="subtle">Stored with {} at {} iterations, {}-byte unique salt, '
            "{}-byte key, {} ms to derive. Salt and hash values are withheld.</p>".format(
                esc(str(storage.get("algorithm"))),
                esc(f"{int(storage.get('iterations', 0)):,}"),
                esc(str(storage.get("salt_bytes"))),
                esc(str(storage.get("key_bytes"))),
                esc(str(storage.get("elapsed_ms"))),
            )
        )
    parts.append("</section>")
    return "\n".join(parts)


def _render_batch_summary(aggregate: Dict[str, object], floor_bits: float) -> str:
    """The list-wide view: how a whole password list fares against the policy."""
    esc = html.escape
    total = int(aggregate.get("candidates", 0))  # type: ignore[arg-type]
    if total < 2:
        return ""
    distribution = aggregate.get("score_distribution", {}) or {}
    labels = aggregate.get("score_labels", list(SCORE_LABELS)) or list(SCORE_LABELS)
    bits = aggregate.get("attack_model_bits", {}) or {}
    failures = aggregate.get("policy_failures_by_rule", []) or []
    accepted = int(aggregate.get("accepted", 0))  # type: ignore[arg-type]
    rate = aggregate.get("acceptance_rate_percent", 0)
    biggest = max(
        (int(count) for count in distribution.values()), default=1  # type: ignore[arg-type]
    ) or 1

    parts = ["<h2>Batch summary</h2>"]
    parts.append(
        f"<p>{total:,} candidates were audited. {accepted:,} met the policy "
        f"({esc(str(rate))}%), {total - accepted:,} did not. Attack-model entropy across "
        f"the batch ran from {esc(str(bits.get('min')))} to {esc(str(bits.get('max')))} "
        f"bits, median {esc(str(bits.get('median')))}, against a policy floor of "
        f"{floor_bits:.0f} bits.</p>"
    )
    parts.append('<div class="dist">')
    for score in range(5):
        count = int(distribution.get(str(score), 0))  # type: ignore[arg-type]
        width = (count / biggest) * 100.0
        css = " pass" if score >= 3 else ""
        name = labels[score] if score < len(labels) else str(score)
        parts.append(f'<div class="label">{score}/4 {esc(str(name))}</div>')
        parts.append(
            f'<div class="meter"><div class="{css.strip()}" '
            f'style="width:{width:.1f}%"></div></div>'
        )
        parts.append(f"<div>{count:,} ({100.0 * count / total:.0f}%)</div>")
    parts.append("</div>")
    exact = int(aggregate.get("wordlist_exact_hits", 0))  # type: ignore[arg-type]
    mutated = int(aggregate.get("wordlist_mutation_hits", 0))  # type: ignore[arg-type]
    parts.append(
        f"<p>Wordlist checks accounted for {exact:,} verbatim matches and "
        f"{mutated:,} mutated matches.</p>"
    )
    if accepted == 0 and exact + mutated == total:
        parts.append(
            "<p>Every candidate matched the wordlist, so none could pass whatever its "
            "composition. A 0% acceptance rate is the expected result for candidates "
            "drawn from a leaked list, and it is not evidence that the policy is set "
            "too high: these passwords are rejected for being already known, not for "
            "being short or simple.</p>"
        )
    if failures:
        parts.append(
            "<table><thead><tr><th>Policy rule</th><th>Candidates failing it</th>"
            "</tr></thead><tbody>"
        )
        for row in failures:
            parts.append(
                f'<tr><td><code>{esc(str(row.get("code")))}</code></td>'
                f'<td>{int(row.get("count", 0)):,} of {total:,} '  # type: ignore[arg-type]
                f'({esc(str(row.get("share_percent")))}%)</td></tr>'
            )
        parts.append("</tbody></table>")
    return "\n".join(parts)


def render_html_report(payload: Dict[str, object], max_detail: int = DEFAULT_MAX_DETAIL) -> str:
    esc = html.escape
    tool = payload.get("tool", {}) or {}
    wordlist = payload.get("wordlist", {}) or {}
    policy = payload.get("policy", {}) or {}
    summary = payload.get("summary", {}) or {}
    hashing = payload.get("hashing", {}) or {}
    environment = payload.get("environment", {}) or {}

    source = (
        esc(str(wordlist.get("source_path")))
        if wordlist.get("file_loaded")
        else "built-in demonstration list (no rockyou sample supplied)"
    )
    entry_count = esc(f"{int(wordlist.get('total_entries', 0)):,}")

    head = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>Password audit report - {esc(str(tool.get('name')))}</title>",
        f"<style>{_HTML_STYLE}</style>",
        "</head><body>",
        "<h1>Password audit and policy decisions</h1>",
        '<p class="lede">Which candidate passwords survive a wordlist-and-mutation '
        "attack, and what the enforcement policy did about each one.</p>",
        '<p class="no-print note">Print to PDF: Ctrl+P (Cmd+P on macOS), then choose '
        '"Save as PDF". Page breaks are set so no candidate is split across pages.</p>',
        "<dl class=\"meta\">",
        f"<dt>Report generated</dt><dd>{esc(str(payload.get('generated_utc')))}</dd>",
        f"<dt>Tool</dt><dd>{esc(str(tool.get('name')))} {esc(str(tool.get('version')))}"
        f" (schema {esc(str(payload.get('report_schema_version')))})</dd>",
        f"<dt>Run mode</dt><dd>{esc(str(payload.get('mode')))}</dd>",
        f"<dt>Wordlist</dt><dd>{source}, {entry_count} entries</dd>",
        f"<dt>Policy</dt><dd>{esc(str(policy.get('name')))}, written out in full "
        "below</dd>",
        f"<dt>Candidates</dt><dd>{esc(str(summary.get('candidates_audited')))} audited, "
        f"{esc(str(summary.get('accepted')))} accepted, "
        f"{esc(str(summary.get('rejected')))} rejected</dd>",
        f"<dt>Environment</dt><dd>Python {esc(str(environment.get('python')))} on "
        f"{esc(str(environment.get('platform')))}, zxcvbn "
        f"{'available' if environment.get('zxcvbn_available') else 'not installed'}</dd>",
        "</dl>",
        f'<p class="note">{esc(str(payload.get("privacy_note")))} Findings describe '
        "structure only, so this file is safe to attach to a lab submission.</p>",
    ]

    try:
        floor_bits = float(policy.get("min_attack_bits", 40.0))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        floor_bits = 40.0
    body = ["<h2>Password policy in force</h2>",
            "<p>Every candidate below was accepted or rejected against these rules. "
            "They come straight from the policy object the tool enforced on this run, "
            "so the policy stated here is the policy applied.</p>",
            '<dl class="policy">']
    for line in policy.get("statement", []) or []:
        text = str(line)
        label, _, requirement = text.partition(": ")
        body.append(
            f"<dt>{esc(label)}</dt><dd>{esc(requirement or text)}</dd>"
        )
    body.append("</dl>")

    results = list(payload.get("results", []) or [])
    aggregate = payload.get("aggregate", {}) or {}
    if isinstance(aggregate, dict):
        body.append(_render_batch_summary(aggregate, floor_bits))

    body.append("<h2>Candidates</h2>")
    shown = results if max_detail <= 0 else results[:max_detail]
    if len(shown) < len(results):
        body.append(
            f"<p>Showing the first {len(shown):,} of {len(results):,} candidates in "
            "full. The JSON results file contains every one, and the batch summary "
            "above covers the whole set.</p>"
        )
    for record in shown:
        body.append(_render_candidate_html(record, floor_bits))

    explain = [
        "<h2>How to read the two entropy numbers</h2>",
        "<p>The <strong>naive pool</strong> estimate is length multiplied by the log base "
        "2 of the character pool the password draws on. It is the number most strength "
        "meters show, and it is only true if every character was picked at random. A "
        "13-character password using all four character types scores about 85 bits by "
        "that measure even when it is a dictionary word wearing a disguise.</p>",
        "<p>The <strong>attack model</strong> estimate is the log base 2 of how many "
        "guesses an attacker actually needs, given that they run wordlists, leet "
        "substitution rules, appended years, and keyboard patterns first. When the two "
        "bars in a candidate block differ wildly, the password is complex-looking rather "
        "than hard to guess. Judge by the shorter bar.</p>",
        "<p>Rough landmarks: below 28 bits falls to an online attack, {:.0f} bits is this "
        "policy's floor, 64 bits resists a serious offline attack against a slow hash, "
        "and 96 bits or more is what a password manager generates by default. The axis "
        "above each candidate is marked at those points.</p>".format(floor_bits),
        "<h2>How accepted passwords are stored</h2>",
        "<p>{} with {} iterations, a fresh {}-byte random salt per password from "
        "os.urandom, and a {}-byte derived key. The unique salt is what stops one "
        "precomputed table from cracking every account at once, and the iteration count "
        "is what makes each guess expensive. Verification is constant-time.</p>".format(
            esc(str(hashing.get("algorithm"))),
            esc(f"{int(hashing.get('iterations', 0)):,}"),
            esc(str(hashing.get("salt_bytes"))),
            esc(str(hashing.get("key_bytes"))),
        ),
        "<footer>Generated offline by {} {}. No network calls, no passwords, no hashes, "
        "no salts, and no matched wordlist fragments are contained in this file.</footer>".format(
            esc(str(tool.get("name"))), esc(str(tool.get("version")))
        ),
        "</body></html>",
    ]
    return "\n".join(head + body + explain)


def write_html_report(
    payload: Dict[str, object], path: Path, max_detail: int = DEFAULT_MAX_DETAIL
) -> Path:
    text = render_html_report(payload, max_detail)
    assert_no_leak(text, f"HTML report {path}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise AuditError(f"cannot write HTML report to '{path}': {exc}") from exc
    return path


# =========================================================================== #
# SECTION 9 -- TERMINAL PRESENTATION                                          #
# =========================================================================== #

def score_bar(score: int, width: int = 20) -> str:
    filled = int(round((score / 4.0) * width))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def print_policy(palette: _Palette, policy: PasswordPolicy, indent: str = "   ") -> None:
    """Write the policy out rule by rule, so the terminal states what it enforces."""
    out(palette.bold(" Policy in force -- every rule applied to every candidate:"))
    for line in policy.statement_lines():
        for wrapped in textwrap.wrap(
            line,
            width=70,
            initial_indent=f"{indent}- ",
            subsequent_indent=f"{indent}  ",
            break_on_hyphens=False,  # keeps "character-type" on one line
        ):
            out(wrapped)
    out("")


def print_header(
    palette: _Palette,
    wordlist: Wordlist,
    scorer: StrengthScorer,
    policy: PasswordPolicy,
    show_policy: bool = True,
) -> None:
    line = "=" * 72
    out(palette.bold(line))
    out(palette.bold(f" {TOOL_NAME} {__version__} -- password audit and policy enforcer"))
    out(palette.bold(line))
    out(f" Wordlist : {wordlist.describe()}")
    out(f" Scoring  : {scorer.engine_name}")
    out(f" Policy   : {policy.summary_line()}")
    for note in wordlist.notes:
        out(palette.yellow(f" Note     : {note}"))
    out("")
    if show_policy:
        print_policy(palette, policy)


def print_result(
    palette: _Palette,
    label: str,
    strength: StrengthResult,
    decision: PolicyDecision,
    show_matches: bool = False,
) -> None:
    classes = ", ".join(name for name, flag in strength.char_classes.items() if flag) or "none"
    colour = palette.green if strength.score >= 3 else (
        palette.yellow if strength.score == 2 else palette.red
    )
    out(palette.bold(f"[{label}]"))
    out(f"  Length       : {strength.length} characters; types: {classes}")
    out(
        "  Score        : "
        + colour(f"{strength.score}/4 {strength.rating} {score_bar(strength.score)}")
    )
    if strength.hard_reject:
        out(
            palette.red(
                f"  Override     : engine scored {strength.engine_score}/4, forced to 0 "
                f"({strength.hard_reject_reason})"
            )
        )
    out(
        f"  Naive pool   : {strength.pool_bits:6.1f} bits  "
        f"(length x log2({strength.pool_size}); assumes random characters)"
    )
    out(
        f"  Attack model : {strength.attack_bits:6.1f} bits  "
        f"({strength.engine}: wordlists, mutation rules, keyboard patterns)"
    )
    for row in strength.crack_times():
        out(f"  Guess time   : {row['display']} -- {row['scenario']}")
    out("  Findings     :")
    for finding in strength.findings:
        out(f"    - [{finding.severity.upper():8}] {finding.code}: {finding.summary}")
        if show_matches and finding.private_detail:
            out(palette.dim(f"        terminal-only detail: {finding.private_detail}"))
    verdict = (
        palette.green("ACCEPTED")
        if decision.allowed
        else palette.red(f"REJECTED ({len(decision.violations)} rule(s) not met)")
    )
    out(f"  Decision     : {verdict}")
    for violation in decision.violations:
        out(f"    - {violation.code}: {violation.summary}")
    for exemption in decision.exemptions:
        out(palette.dim(f"    - exemption: {exemption}"))
    out("  Advice       :")
    for item in decision.advice:
        out(f"    * {item}")
    out("")


# =========================================================================== #
# SECTION 10 -- INPUT HELPERS                                                 #
# =========================================================================== #

def print_aggregate(palette: _Palette, aggregate: Dict[str, object], floor_bits: float) -> None:
    """Print the list-wide view after a batch run."""
    total = int(aggregate.get("candidates", 0))  # type: ignore[arg-type]
    if total < 2:
        return
    bits = aggregate.get("attack_model_bits", {}) or {}
    distribution = aggregate.get("score_distribution", {}) or {}
    failures = aggregate.get("policy_failures_by_rule", []) or []
    accepted = int(aggregate.get("accepted", 0))  # type: ignore[arg-type]
    out(palette.bold("-" * 72))
    out(palette.bold(" Batch summary"))
    out(palette.bold("-" * 72))
    out(
        f"  Candidates   : {total:,} audited, {accepted:,} accepted "
        f"({aggregate.get('acceptance_rate_percent')}%), {total - accepted:,} rejected"
    )
    out(
        f"  Attack model : min {bits.get('min')} / median {bits.get('median')} / "
        f"max {bits.get('max')} bits (policy floor {floor_bits:.0f})"
    )
    exact = int(aggregate.get("wordlist_exact_hits", 0))  # type: ignore[arg-type]
    mutated = int(aggregate.get("wordlist_mutation_hits", 0))  # type: ignore[arg-type]
    out(f"  Wordlist     : {exact} verbatim, {mutated} mutated matches")
    if accepted == 0 and exact + mutated == total:
        out(palette.dim(
            "                 every candidate matched the wordlist, so none could pass "
            "whatever\n                 its composition -- expected for a leaked list, "
            "not a sign the policy\n                 is set too high"
        ))
    out("  Score spread :")
    biggest = max((int(v) for v in distribution.values()), default=1) or 1  # type: ignore[arg-type]
    for score in range(5):
        count = int(distribution.get(str(score), 0))  # type: ignore[arg-type]
        filled = int(round((count / biggest) * 28))
        bar = "#" * filled + "-" * (28 - filled)
        out(f"    {score}/4 {SCORE_LABELS[score]:<12} [{bar}] {count:,} "
            f"({100.0 * count / total:.0f}%)")
    if failures:
        out("  Top failures :")
        for row in failures[:6]:
            out(f"    - {row.get('code')}: {row.get('count')} of {total:,} "
                f"({row.get('share_percent')}%)")
    out("")


def read_hidden_password(prompt: str = "Password (input hidden): ") -> str:
    """Read a password without echoing it. No --password flag exists on purpose:

    a password on the command line lands in shell history and in the process
    list, where any other local user can read it.
    """
    import getpass

    try:
        value = getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        raise
    except Exception as exc:  # pragma: no cover - terminal dependent
        raise AuditError(
            f"hidden input is unavailable here ({exc}). Pipe the password in with "
            "--stdin instead, or run --demo."
        ) from exc
    if not value:
        raise AuditError("no password entered")
    register_secret(value)
    return value


def read_password_file(
    path: str,
    limit: int = DEFAULT_AUDIT_LIMIT,
    sample: str = "first",
    seed: Optional[int] = None,
) -> List[str]:
    """Read candidate passwords from a list file such as a rockyou sample.

    Decoding is lenient: real leaked lists contain bytes that are not valid
    UTF-8, and a password auditor that crashes on its own input is useless. This
    is also why the tool reads the file directly instead of taking a shell pipe,
    which would fail on those same bytes.

    sample="random" uses reservoir sampling, so a 14-million-line file is read
    once, in a single pass, without ever being held in memory. It also leaves the
    sample in an arbitrary order, which keeps report labels from mapping back to
    line numbers in the source list.
    """
    if limit < 1:
        raise AuditError("--audit-limit must be at least 1")
    if sample not in ("first", "random"):
        raise AuditError("--audit-sample must be 'first' or 'random'")
    candidate = Path(path).expanduser()
    if not candidate.exists():
        raise AuditError(f"password list not found: '{candidate}'")
    if candidate.is_dir():
        raise AuditError(f"--audit-file expects a file but '{candidate}' is a directory")

    rng = random.Random(seed)
    reservoir: List[str] = []
    considered = 0
    try:
        with candidate.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                line = raw.rstrip("\r\n")
                if not line.strip() or line.startswith("#"):
                    continue
                if sample == "first":
                    reservoir.append(line)
                    if len(reservoir) >= limit:
                        break
                    continue
                if len(reservoir) < limit:
                    reservoir.append(line)
                else:
                    position = rng.randrange(considered + 1)
                    if position < limit:
                        reservoir[position] = line
                considered += 1
    except PermissionError as exc:
        raise AuditError(f"cannot read '{candidate}': permission denied") from exc
    except OSError as exc:
        raise AuditError(f"cannot read '{candidate}': {exc}") from exc

    if not reservoir:
        raise AuditError(
            f"'{candidate}' contained no usable passwords (blank lines and lines "
            "starting with '#' are skipped)"
        )
    for value in reservoir:
        register_secret(value)
    return reservoir


def read_stdin_passwords() -> List[str]:
    if sys.stdin is None or sys.stdin.isatty():
        raise AuditError("--stdin expects piped input, for example: echo pw | ... --stdin")
    values = [line.rstrip("\n\r") for line in sys.stdin if line.strip()]
    if not values:
        raise AuditError("--stdin received no usable lines")
    for value in values:
        register_secret(value)
    return values


# =========================================================================== #
# SECTION 11 -- WORKFLOWS                                                     #
# =========================================================================== #

def audit_passwords(
    enforcer: PolicyEnforcer,
    palette: _Palette,
    items: Sequence[Tuple[str, str]],
    show_matches: bool,
    quiet: bool,
) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    total = len(items)
    for index, (label, password) in enumerate(items, start=1):
        strength, decision = enforcer.evaluate(password)
        if not quiet:
            print_result(palette, label, strength, decision, show_matches)
        elif total >= 50 and (index % 50 == 0 or index == total):
            out(palette.dim(f"  audited {index}/{total}"))
        records.append(build_public_record(label, strength, decision))
    return records


def registration_demo(
    enforcer: PolicyEnforcer,
    palette: _Palette,
    attempts: Sequence[str],
    iterations: int,
    show_matches: bool,
) -> List[Dict[str, object]]:
    """Scripted registration flow: reject, allow a retry, then accept and hash."""
    out(palette.bold("-" * 72))
    out(palette.bold(" Registration demonstration (scripted, fictional passwords)"))
    out(palette.bold("-" * 72))
    records: List[Dict[str, object]] = []
    for attempt, password in enumerate(attempts, start=1):
        label = f"registration attempt {attempt}"
        strength, decision = enforcer.evaluate(password)
        print_result(palette, label, strength, decision, show_matches)
        if not decision.allowed:
            out(palette.yellow("  -> rejected, the user is asked to try again\n"))
            records.append(build_public_record(label, strength, decision))
            continue
        out(palette.green("  -> accepted, hashing for storage"))
        stored = hash_password(password, iterations=iterations)
        out(
            f"     {stored.algorithm}, {stored.iterations:,} iterations, "
            f"{stored.salt_bytes}-byte unique salt, {stored.key_bytes}-byte key, "
            f"{stored.elapsed_ms:.0f} ms"
        )
        out("     salt and hash are held in memory only and never printed or reported")
        ok = verify_password(password, stored)
        bad = verify_password(password + "-wrong", stored)
        out(f"     verification with the correct password: {ok}")
        out(f"     verification with a wrong password    : {bad}")
        out("")
        records.append(build_public_record(label, strength, decision, stored))
        break
    return records


def interactive_registration(
    enforcer: PolicyEnforcer,
    palette: _Palette,
    iterations: int,
    max_attempts: int,
    show_matches: bool,
) -> List[Dict[str, object]]:
    """Interactive registration with hidden entry, confirmation, and retries."""
    out(palette.bold("Registration: choose a password that satisfies the policy."))
    print_policy(palette, enforcer.policy)
    records: List[Dict[str, object]] = []
    for attempt in range(1, max_attempts + 1):
        label = f"registration attempt {attempt}"
        password = read_hidden_password(f"Attempt {attempt}/{max_attempts} password: ")
        confirmation = read_hidden_password("Confirm password: ")
        if password != confirmation:
            out(palette.red("  The two entries did not match. Try again.\n"))
            continue
        strength, decision = enforcer.evaluate(password)
        print_result(palette, label, strength, decision, show_matches)
        if not decision.allowed:
            remaining = max_attempts - attempt
            if remaining:
                out(palette.yellow(f"  Rejected. {remaining} attempt(s) left.\n"))
            records.append(build_public_record(label, strength, decision))
            continue
        stored = hash_password(password, iterations=iterations)
        out(palette.green("  Accepted and stored."))
        out(
            f"  {stored.algorithm}, {stored.iterations:,} iterations, "
            f"{stored.salt_bytes}-byte unique salt, {stored.key_bytes}-byte key, "
            f"{stored.elapsed_ms:.0f} ms to derive"
        )
        out("  The salt and hash stay in memory; neither is printed or reported.")
        out(f"  Self-check, correct password verifies: {verify_password(password, stored)}")
        out("")
        records.append(build_public_record(label, strength, decision, stored))
        return records
    out(palette.red("Registration abandoned: no acceptable password was supplied."))
    return records


def show_mutations(engine: MutationEngine, word: str, max_show: int, palette: _Palette) -> None:
    variants = engine.generate(word)
    out(palette.bold(f"Mutation engine output for base word '{word}'"))
    out(
        f"  generated {len(variants):,} variants "
        f"(cap {engine.limits.max_variants_per_word:,}); showing the first {max_show}"
    )
    out(
        f"  rules: {engine.limits.max_case_variants} case forms x leet substitutions "
        f"(max {engine.limits.max_leet_positions} positions, "
        f"{engine.limits.max_leet_variants} forms) x prefixes {list(engine.prepend)} "
        f"x digit/year suffixes x symbol suffixes"
    )
    out("")
    for index, variant in enumerate(variants[:max_show], start=1):
        out(f"  {index:4}. {variant}")
    if len(variants) > max_show:
        out(f"  ... {len(variants) - max_show:,} more")
    out("")
    out(palette.dim(
        "  Detection works in reverse: peel appended digits/years/symbols, normalise "
        "capitalization, undo leet substitutions, then look the result up in the "
        "wordlist. That is a few set lookups per password instead of billions of "
        "generated strings."
    ))
    out("")


# =========================================================================== #
# SECTION 12 -- TESTS (run with --self-test or: python -m unittest ...)        #
# =========================================================================== #

def _test_wordlist() -> Wordlist:
    return Wordlist(
        entries=frozenset(word.lower() for word in DEMO_WORDLIST),
        source_path=None,
        file_lines=0,
        demo_entries=len(DEMO_WORDLIST),
        truncated=False,
        limit=DEFAULT_WORDLIST_LIMIT,
        notes=[],
    )


def _test_enforcer(policy: Optional[PasswordPolicy] = None) -> PolicyEnforcer:
    wordlist = _test_wordlist()
    scorer = StrengthScorer(wordlist, MutationEngine())
    return PolicyEnforcer(policy or PasswordPolicy(), scorer)


class TestMutationEngine(unittest.TestCase):
    """Component 2: generation and detection of wordlist variations."""

    def setUp(self) -> None:
        self.engine = MutationEngine()
        self.wordlist = _test_wordlist()

    def test_generation_includes_leet_and_appended_forms(self) -> None:
        variants = set(self.engine.generate("password"))
        self.assertIn("password", variants)
        self.assertIn("Password1", variants)
        self.assertIn("P@ssw0rd2026!", variants)  # combined rules required by the lab

    def test_generation_respects_limits(self) -> None:
        engine = MutationEngine(MutationLimits(max_variants_per_word=50))
        variants = engine.generate("password")
        self.assertEqual(len(variants), 50)
        self.assertEqual(len(variants), len(set(variants)), "variants must be unique")

    def test_generation_rejects_empty_word(self) -> None:
        with self.assertRaises(AuditError):
            self.engine.generate("   ")

    def test_detects_exact_wordlist_entry(self) -> None:
        match = self.engine.detect("password", self.wordlist)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertTrue(match.is_exact)
        self.assertEqual(match.base_word, "password")

    def test_detects_combined_mutation_chain(self) -> None:
        match = self.engine.detect("P@ssw0rd2026!", self.wordlist)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.base_word, "password")
        chain = match.rule_chain()
        self.assertIn("appended year", chain)
        self.assertIn("appended symbols", chain)
        self.assertIn("capitalization", chain)
        self.assertIn("leet substitution", chain)

    def test_detects_ambiguous_leet_one_as_letter(self) -> None:
        # '1' may stand for i or l, so both branches must be explored.
        match = self.engine.detect("L3tm31n!", self.wordlist)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.base_word, "letmein")

    def test_detects_season_and_year(self) -> None:
        match = self.engine.detect("Summer2026!", self.wordlist)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.base_word, "summer")

    def test_detects_year_behind_leet_digits(self) -> None:
        # The trailing digit run is 312019, but only 2019 is the appended affix:
        # 31 is part of the leet spelling of the base word. Regression test for
        # a greedy peel that used to lose the whole run.
        wordlist = Wordlist(frozenset({"daniel", "babygirl", "chocolate"}), None, 0, 3,
                            False, 100, [])
        for probe, expected in (("D@n1312019#", "daniel"),
                                ("8@8y91r12027!!", "babygirl"),
                                ("Ch0c01@732027!!", "chocolate")):
            match = self.engine.detect(probe, wordlist)
            self.assertIsNotNone(match, probe)
            assert match is not None
            self.assertEqual(match.base_word, expected)
            self.assertIn("leet substitution", match.rule_chain())

    def test_core_search_is_bounded(self) -> None:
        engine = MutationEngine(MutationLimits(max_cores=6))
        cores = engine._candidate_cores("Ch0c01@732027!!")
        self.assertLessEqual(len(cores), 6)
        self.assertEqual(cores[0][0], "Ch0c01@732027!!", "the password itself comes first")

    def test_no_false_positive_on_unrelated_passphrase(self) -> None:
        self.assertIsNone(
            self.engine.detect("brisk-lantern-quarry-clove", self.wordlist)
        )

    def test_short_fragments_are_ignored(self) -> None:
        engine = MutationEngine(MutationLimits(min_base_length=6))
        wordlist = Wordlist(frozenset({"cat"}), None, 0, 1, False, 10, [])
        self.assertIsNone(engine.detect("cat12345", wordlist))


class TestStrengthScorer(unittest.TestCase):
    """Component 1: scoring, entropy estimation, and the hard-reject rule."""

    def setUp(self) -> None:
        self.scorer = StrengthScorer(_test_wordlist(), MutationEngine())

    def test_known_common_password_scores_zero(self) -> None:
        result = self.scorer.score("password")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.rating, "Very weak")
        self.assertTrue(result.hard_reject)
        self.assertTrue(any(f.code == "WORDLIST_EXACT" for f in result.findings))

    def test_mutation_rejected_despite_character_variety(self) -> None:
        result = self.scorer.score("P@ssw0rd2026!")
        self.assertTrue(all(result.char_classes[k] for k in ("lowercase", "uppercase", "digit", "symbol")))
        self.assertGreater(result.pool_bits, 70.0, "naive entropy should look strong")
        self.assertEqual(result.score, 0, "wordlist mutations must score 0 anyway")
        self.assertTrue(result.hard_reject)
        self.assertTrue(any(f.code == "WORDLIST_MUTATION" for f in result.findings))
        self.assertLess(result.attack_bits, result.pool_bits)

    def test_strong_passphrase_scores_well(self) -> None:
        result = self.scorer.score("Vp9!tundra-Kestrel-thicket")
        self.assertFalse(result.hard_reject)
        self.assertGreaterEqual(result.score, 3)
        self.assertGreater(result.attack_bits, 40.0)

    def test_pool_entropy_matches_formula(self) -> None:
        pool, bits = pool_entropy_bits("abcdefgh")
        self.assertEqual(pool, 26)
        self.assertAlmostEqual(bits, 8 * math.log2(26), places=6)
        pool, bits = pool_entropy_bits("Abcdefg1!")
        self.assertEqual(pool, 26 + 26 + 10 + 33)
        self.assertAlmostEqual(bits, 9 * math.log2(95), places=6)

    def test_keyboard_run_and_repeat_findings(self) -> None:
        codes = {f.code for f in self.scorer.score("aaabbb1234!Zq").findings}
        self.assertIn("REPEATED_CHARACTERS", codes)
        self.assertIn("KEYBOARD_SEQUENCE", codes)

    def test_empty_password_raises(self) -> None:
        with self.assertRaises(AuditError):
            self.scorer.score("")

    def test_fallback_heuristic_still_rejects_wordlist_entries(self) -> None:
        scorer = StrengthScorer(_test_wordlist(), MutationEngine(), use_zxcvbn=False)
        result = scorer.score("P@ssw0rd2026!")
        self.assertEqual(result.engine, "built-in heuristic")
        self.assertEqual(result.score, 0)
        self.assertTrue(result.hard_reject)

    def test_crack_time_rows_present(self) -> None:
        rows = self.scorer.score("brisk-lantern-quarry-clove").crack_times()
        self.assertEqual(len(rows), len(GUESS_RATES))
        self.assertTrue(all(row["display"] for row in rows))


class TestPolicyEnforcer(unittest.TestCase):
    """Component 3: accept/reject decisions and improvement advice."""

    def setUp(self) -> None:
        self.enforcer = _test_enforcer()

    def test_rejects_known_common_password(self) -> None:
        _, decision = self.enforcer.evaluate("password")
        self.assertFalse(decision.allowed)
        codes = {v.code for v in decision.violations}
        self.assertIn("POLICY_WORDLIST_EXACT", codes)
        self.assertTrue(decision.advice)

    def test_rejects_mutation_with_full_character_variety(self) -> None:
        _, decision = self.enforcer.evaluate("P@ssw0rd2026!")
        self.assertFalse(decision.allowed)
        self.assertIn("POLICY_WORDLIST_MUTATION", {v.code for v in decision.violations})

    def test_rejects_short_password_with_length_advice(self) -> None:
        _, decision = self.enforcer.evaluate("Xk7$q!")
        self.assertFalse(decision.allowed)
        self.assertIn("POLICY_MIN_LENGTH", {v.code for v in decision.violations})
        self.assertTrue(any("more characters" in item for item in decision.advice))

    def test_composition_profile_rejects_missing_character_class(self) -> None:
        policy = composition_policy()
        policy.passphrase_exemption_length = 0
        _, decision = _test_enforcer(policy).evaluate("thicketkestrelclove")
        self.assertFalse(decision.allowed)
        codes = {v.code for v in decision.violations}
        self.assertIn("POLICY_REQUIRE_UPPERCASE", codes)
        self.assertIn("POLICY_REQUIRE_DIGIT", codes)
        self.assertIn("POLICY_REQUIRE_SYMBOL", codes)

    def test_accepts_strong_password(self) -> None:
        _, decision = self.enforcer.evaluate("Vp9!tundra-Kestrel-thicket")
        self.assertTrue(decision.allowed, [v.code for v in decision.violations])
        self.assertTrue(decision.advice)

    def test_passphrase_exemption_waives_class_rules(self) -> None:
        enforcer = _test_enforcer(composition_policy())
        _, decision = enforcer.evaluate("orchid-canyon-verdict-thicket")
        self.assertTrue(decision.allowed, [v.code for v in decision.violations])
        self.assertTrue(decision.exemptions)

    def test_no_exemption_is_claimed_when_no_class_rules_exist(self) -> None:
        # The default policy has no composition rules, so a long passphrase has
        # nothing to be exempt from and the report must not claim otherwise.
        _, decision = self.enforcer.evaluate("orchid-canyon-verdict-thicket")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.exemptions, [])

    def test_statement_covers_the_rules_that_are_enforced(self) -> None:
        text = " ".join(self.enforcer.policy.statement_lines())
        for expected in ("at least 12 characters", "no composition requirements",
                         "3 out of 4", "40 bits", "common-password wordlist",
                         "leet substitutions", "PBKDF2-HMAC-SHA256", "600,000 iterations"):
            self.assertIn(expected, text)
        composition = " ".join(composition_policy().statement_lines())
        self.assertIn("a lowercase letter", composition)
        self.assertIn("Passphrase exemption", composition)

    def test_statement_follows_the_configuration(self) -> None:
        policy = PasswordPolicy(
            min_length=16,
            require_symbol=False,
            min_strength_score=4,
            passphrase_exemption_length=0,
            forbid_sequences=False,
        )
        text = " ".join(policy.statement_lines())
        self.assertIn("at least 16 characters", text)
        self.assertNotIn("a symbol", text)
        self.assertIn("4 out of 4", text)
        self.assertNotIn("Passphrase exemption", text)
        self.assertNotIn("Sequences", text)

    def test_policy_settings_are_configurable(self) -> None:
        relaxed = PasswordPolicy(
            name="relaxed",
            min_length=6,
            require_uppercase=False,
            require_symbol=False,
            min_strength_score=0,
            min_attack_bits=0.0,
            forbid_sequences=False,
            passphrase_exemption_length=0,
        )
        _, decision = _test_enforcer(relaxed).evaluate("mq7vue")
        self.assertTrue(decision.allowed, [v.code for v in decision.violations])

    def test_nist_profile_raises_the_length_floor(self) -> None:
        policy = nist_aligned_policy()
        self.assertEqual(policy.min_length, 15)
        for flag in (policy.require_lowercase, policy.require_uppercase,
                     policy.require_digit, policy.require_symbol):
            self.assertFalse(flag)
        self.assertTrue(policy.forbid_wordlist_exact, "breached passwords still blocked")
        text = " ".join(policy.statement_lines())
        self.assertNotIn("must contain", text)

    def test_default_policy_has_no_composition_rules(self) -> None:
        policy = PasswordPolicy()
        for flag in (policy.require_lowercase, policy.require_uppercase,
                     policy.require_digit, policy.require_symbol):
            self.assertFalse(flag)
        self.assertTrue(policy.forbid_wordlist_exact)
        self.assertTrue(policy.forbid_wordlist_mutations)
        self.assertEqual(policy.min_attack_bits, 40.0)

    def test_strong_generated_password_is_no_longer_rejected_for_a_missing_class(self) -> None:
        # The measured false rejection: 16 random characters, no digit. Strong by
        # every other measure, refused by the old composition rules.
        candidate = "Krtvbmqxslnwjhfd"
        _, default_decision = self.enforcer.evaluate(candidate)
        self.assertTrue(default_decision.allowed,
                        [v.code for v in default_decision.violations])
        _, strict_decision = _test_enforcer(composition_policy()).evaluate(candidate)
        self.assertFalse(strict_decision.allowed)
        self.assertIn("POLICY_REQUIRE_DIGIT", {v.code for v in strict_decision.violations})

    def test_profile_is_applied_and_explicit_flags_win(self) -> None:
        parser = build_parser()
        nist = policy_from_args(parser.parse_args(["--policy-profile", "nist"]), parser)
        self.assertEqual(nist.min_length, 15)
        self.assertFalse(nist.require_symbol)
        strict = policy_from_args(
            parser.parse_args(["--policy-profile", "composition"]), parser
        )
        self.assertTrue(strict.require_symbol)
        raised = policy_from_args(
            parser.parse_args(["--policy-profile", "nist", "--min-length", "20"]), parser
        )
        self.assertEqual(raised.min_length, 20)
        self.assertFalse(raised.require_symbol, "the rest of the profile is kept")
        baseline = policy_from_args(parser.parse_args([]), parser)
        self.assertEqual(baseline.min_length, PasswordPolicy.min_length)
        self.assertFalse(baseline.require_symbol)

    def test_a_leaked_list_entry_cannot_pass_even_without_wordlist_rules(self) -> None:
        # The point of the 0% result: length and composition alone stop these,
        # so the zero is a property of the input, not a policy set too high.
        relaxed = PasswordPolicy(
            forbid_wordlist_exact=False, forbid_wordlist_mutations=False
        )
        enforcer = _test_enforcer(relaxed)
        for entry in ("password", "iloveyou", "princess", "qwerty"):
            strength = enforcer.scorer.score(entry)
            strength.hard_reject = False          # ignore the score override too
            strength.score = strength.engine_score
            self.assertFalse(enforcer.check(entry, strength).allowed, entry)

    def test_banned_term_is_flagged_without_revealing_it(self) -> None:
        _, decision = self.enforcer.evaluate("Trine-quarry-thicket-42!")
        codes = {v.code for v in decision.violations}
        self.assertIn("POLICY_BANNED_TERM", codes)
        summary = next(v.summary for v in decision.violations if v.code == "POLICY_BANNED_TERM")
        self.assertNotIn("trine", summary.lower())


class TestPasswordStorage(unittest.TestCase):
    """PBKDF2 hashing of accepted passwords."""

    def test_verify_accepts_correct_and_rejects_wrong(self) -> None:
        record = hash_password("orchid-canyon-verdict-7731", iterations=PBKDF2_TEST_ITERATIONS)
        self.assertTrue(verify_password("orchid-canyon-verdict-7731", record))
        self.assertFalse(verify_password("orchid-canyon-verdict-7732", record))
        self.assertFalse(verify_password("", record))

    def test_salts_are_unique_per_password(self) -> None:
        first = hash_password("orchid-canyon-verdict-7731", iterations=PBKDF2_TEST_ITERATIONS)
        second = hash_password("orchid-canyon-verdict-7731", iterations=PBKDF2_TEST_ITERATIONS)
        self.assertNotEqual(first.salt_hex, second.salt_hex)
        self.assertNotEqual(first.hash_hex, second.hash_hex)

    def test_documented_parameters_are_recorded(self) -> None:
        record = hash_password("orchid-canyon-verdict-7731", iterations=PBKDF2_TEST_ITERATIONS)
        self.assertEqual(record.algorithm, "pbkdf2_hmac-sha256")
        self.assertEqual(record.salt_bytes, PBKDF2_SALT_BYTES)
        self.assertEqual(record.key_bytes, PBKDF2_KEY_BYTES)
        public = record.public_dict()
        self.assertNotIn("salt_hex", public)
        self.assertNotIn("hash_hex", public)

    def test_empty_password_and_bad_iterations_raise(self) -> None:
        with self.assertRaises(AuditError):
            hash_password("")
        with self.assertRaises(AuditError):
            hash_password("abcdefgh", iterations=0)


class TestWordlistLoading(unittest.TestCase):
    """Loading the rockyou sample from a configurable path."""

    def test_loads_file_and_skips_comments(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.txt"
            path.write_text("# comment\nhunter2\n\nCorrectHorse\n", encoding="utf-8")
            wordlist = load_wordlist(str(path))
            self.assertTrue(wordlist.file_loaded)
            self.assertEqual(wordlist.file_lines, 2)
            self.assertTrue(wordlist.contains("hunter2"))
            self.assertTrue(wordlist.contains("correcthorse"), "lookups are case-insensitive")

    def test_limit_truncates(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.txt"
            path.write_text("\n".join(f"word{n}" for n in range(50)), encoding="utf-8")
            wordlist = load_wordlist(str(path), limit=10)
            self.assertTrue(wordlist.truncated)
            self.assertEqual(wordlist.file_lines, 10)

    def test_missing_file_falls_back_to_demo_list(self) -> None:
        wordlist = load_wordlist("no/such/file-does-not-exist.txt")
        self.assertFalse(wordlist.file_loaded)
        self.assertTrue(wordlist.contains("password"))
        self.assertTrue(wordlist.notes)

    def test_missing_file_without_demo_list_raises(self) -> None:
        with self.assertRaises(AuditError):
            load_wordlist("no/such/file-does-not-exist.txt", include_demo=False)


class TestBatchAudit(unittest.TestCase):
    """Reading a password list and rolling the results up."""

    def setUp(self) -> None:
        self.enforcer = _test_enforcer()
        self.engine = MutationEngine()

    def _list_file(self, folder: str, name: str = "list.txt") -> Path:
        path = Path(folder) / name
        # Latin-1 bytes are deliberate: real leaked lists are not valid UTF-8.
        body = "# header comment\npassword\n\nqwerty123\nSummer2026!\n"
        with path.open("wb") as handle:
            handle.write(body.encode("utf-8"))
            handle.write("caf\xe9brasil\n".encode("latin-1"))
        return path

    def test_reads_list_skipping_blanks_and_comments(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            path = self._list_file(folder)
            values = read_password_file(str(path), limit=10)
            self.assertEqual(len(values), 4)
            self.assertNotIn("", values)
            self.assertTrue(all(not v.startswith("#") for v in values))

    def test_limit_and_random_sample(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "many.txt"
            path.write_text("\n".join(f"candidate{n}" for n in range(500)), encoding="utf-8")
            first = read_password_file(str(path), limit=5, sample="first")
            self.assertEqual(first, [f"candidate{n}" for n in range(5)])
            sampled = read_password_file(str(path), limit=5, sample="random", seed=42)
            self.assertEqual(len(sampled), 5)
            self.assertEqual(
                sampled, read_password_file(str(path), limit=5, sample="random", seed=42),
                "the same seed must reproduce the same sample",
            )

    def test_bad_input_raises_clear_errors(self) -> None:
        import tempfile

        with self.assertRaises(AuditError):
            read_password_file("no/such/list.txt")
        with tempfile.TemporaryDirectory() as folder:
            empty = Path(folder) / "empty.txt"
            empty.write_text("# only a comment\n\n", encoding="utf-8")
            with self.assertRaises(AuditError):
                read_password_file(str(empty))
            with self.assertRaises(AuditError):
                read_password_file(str(folder))
            with self.assertRaises(AuditError):
                read_password_file(str(empty), limit=0)

    def test_aggregate_describes_the_batch(self) -> None:
        records = []
        for label, password in (("a", "password"), ("b", "P@ssw0rd2026!"),
                                ("c", "quartz-ledger-wander-sift")):
            strength, decision = self.enforcer.evaluate(password)
            records.append(build_public_record(label, strength, decision))
        aggregate = build_aggregate(records)
        self.assertEqual(aggregate["candidates"], 3)
        self.assertEqual(aggregate["accepted"], 1)
        self.assertEqual(aggregate["score_distribution"]["0"], 2)
        self.assertEqual(aggregate["wordlist_exact_hits"], 1)
        self.assertEqual(aggregate["wordlist_mutation_hits"], 1)
        codes = {row["code"] for row in aggregate["policy_failures_by_rule"]}
        self.assertIn("POLICY_MIN_SCORE", codes)
        self.assertEqual(aggregate["attack_model_bits"]["max"],
                         max(r["entropy_estimates_bits"]["attack_model"] for r in records))

    def test_aggregate_of_empty_batch(self) -> None:
        self.assertEqual(build_aggregate([])["candidates"], 0)

    def test_all_wordlist_hits_are_explained_not_left_looking_like_a_bug(self) -> None:
        records = []
        for index, password in enumerate(("password", "qwerty", "iloveyou", "monkey")):
            strength, decision = self.enforcer.evaluate(password)
            records.append(build_public_record(f"candidate-{index}", strength, decision))
        payload = build_report_payload(
            records, self.enforcer.policy, self.enforcer.scorer.wordlist, self.engine,
            "audit-file",
        )
        as_html = render_html_report(payload)
        self.assertIn("Every candidate matched the wordlist", as_html)
        self.assertIn("not evidence that the policy is set", as_html)

    def test_mixed_batch_has_no_such_note(self) -> None:
        records = []
        for label, password in (("a", "password"), ("b", "Vp9!tundra-Kestrel-thicket")):
            strength, decision = self.enforcer.evaluate(password)
            records.append(build_public_record(label, strength, decision))
        payload = build_report_payload(
            records, self.enforcer.policy, self.enforcer.scorer.wordlist, self.engine,
            "audit-file",
        )
        self.assertNotIn("Every candidate matched the wordlist", render_html_report(payload))

    def test_html_summarises_batch_and_caps_detail(self) -> None:
        records = []
        for index in range(6):
            strength, decision = self.enforcer.evaluate(f"Summer202{index}!")
            records.append(build_public_record(f"candidate-{index}", strength, decision))
        payload = build_report_payload(
            records, self.enforcer.policy, self.enforcer.scorer.wordlist, self.engine,
            "audit-file",
        )
        as_html = render_html_report(payload, max_detail=2)
        self.assertIn("<h2>Batch summary</h2>", as_html)
        self.assertIn("Showing the first 2 of 6 candidates", as_html)
        self.assertEqual(as_html.count('<section class="candidate">'), 2)
        self.assertEqual(len(payload["results"]), 6, "the JSON keeps every candidate")
        self.assertEqual(
            render_html_report(payload, max_detail=0).count('<section class="candidate">'), 6
        )


class TestReportSafety(unittest.TestCase):
    """Reports must carry results without carrying secrets."""

    def setUp(self) -> None:
        forget_secrets()
        self.enforcer = _test_enforcer()
        self.engine = MutationEngine()

    def tearDown(self) -> None:
        forget_secrets()

    def _payload(self, label: str, password: str) -> Tuple[Dict[str, object], Dict[str, object]]:
        strength, decision = self.enforcer.evaluate(password)
        stored = (
            hash_password(password, iterations=PBKDF2_TEST_ITERATIONS)
            if decision.allowed
            else None
        )
        record = build_public_record(label, strength, decision, stored)
        payload = build_report_payload(
            [record], self.enforcer.policy, self.enforcer.scorer.wordlist, self.engine, "test"
        )
        return record, payload

    def test_password_absent_from_json_and_html(self) -> None:
        password = "Zq7!tundra-Kestrel-thicket"
        _, payload = self._payload("candidate", password)
        as_json = json.dumps(payload)
        as_html = render_html_report(payload)
        for blob in (as_json, as_html):
            self.assertNotIn(password, blob)
            self.assertNotIn("tundra", blob)
            self.assertNotIn("Kestrel", blob)

    def test_matched_wordlist_word_absent_from_reports(self) -> None:
        _, payload = self._payload("candidate", "Summer2026!")
        as_json = json.dumps(payload)
        as_html = render_html_report(payload)
        self.assertNotIn("Summer2026", as_json)
        self.assertNotIn("Summer2026", as_html)
        self.assertNotIn("summer", as_json.lower().replace("summary", ""))
        self.assertIn("WORDLIST_MUTATION", as_json)  # the finding itself is reported

    def test_hash_and_salt_absent_from_reports(self) -> None:
        record, payload = self._payload("candidate", "orchid-quarry-verdict-thicket")
        self.assertTrue(record["policy_decision"]["allowed"])  # type: ignore[index]
        as_json = json.dumps(payload)
        storage = record["storage"]
        assert isinstance(storage, dict)
        self.assertEqual(storage["iterations"], PBKDF2_TEST_ITERATIONS)
        for secret in _ACTIVE_SECRETS:
            if len(secret) >= 32:  # hash and salt hex strings
                self.assertNotIn(secret, as_json)

    def test_report_contains_scores_estimates_findings_decisions_advice(self) -> None:
        record, payload = self._payload("candidate", "P@ssw0rd2026!")
        self.assertEqual(record["scoring"]["score"], 0)  # type: ignore[index]
        self.assertIn("attack_model", record["entropy_estimates_bits"])  # type: ignore[operator]
        self.assertTrue(record["findings"])
        self.assertFalse(record["policy_decision"]["allowed"])  # type: ignore[index]
        self.assertTrue(record["advice"])
        self.assertEqual(payload["summary"]["rejected"], 1)  # type: ignore[index]

    def test_html_states_the_policy_and_labels_its_readings(self) -> None:
        _, payload = self._payload("candidate", "P@ssw0rd2026!")
        as_html = render_html_report(payload)
        self.assertIn("<h2>Password policy in force</h2>", as_html)
        self.assertLess(
            as_html.index("Password policy in force"),
            as_html.index("<h2>Candidates</h2>"),
            "the policy is stated before the candidates it was applied to",
        )
        self.assertIn("<dt>Length</dt><dd>at least 12 characters", as_html)
        for label in ("Score:", "Length:", "Character types:", "Scoring engine:"):
            self.assertIn(f"<span>{label}</span>", as_html)

    def test_html_is_offline_and_printable(self) -> None:
        _, payload = self._payload("candidate", "P@ssw0rd2026!")
        as_html = render_html_report(payload)
        self.assertNotIn("http://", as_html)
        self.assertNotIn("https://", as_html)
        self.assertNotIn("<script", as_html.lower())
        self.assertIn("@media print", as_html)
        self.assertIn("@page", as_html)

    def test_leak_guard_blocks_a_bad_write(self) -> None:
        register_secret("Zq7!tundra-Kestrel")
        with self.assertRaises(ReportSafetyError):
            assert_no_leak("report body containing Zq7!tundra-Kestrel", "unit test")

    def test_logging_scrubs_secrets(self) -> None:
        register_secret("Zq7!tundra-Kestrel")
        self.assertEqual(scrub("value Zq7!tundra-Kestrel here"), "value [REDACTED] here")


def run_self_test(verbosity: int = 2) -> int:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    return 0 if result.wasSuccessful() else 1


# =========================================================================== #
# SECTION 13 -- COMMAND LINE INTERFACE                                        #
# =========================================================================== #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password_auditor.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Audit passwords against a wordlist and attacker mutation rules, then "
            "enforce a configurable password policy."
        ),
        epilog=(
            "examples:\n"
            "  python password_auditor.py --demo\n"
            "  python password_auditor.py --check --count 2\n"
            "  python password_auditor.py --register\n"
            "  python password_auditor.py --mutations password --max-show 40\n"
            "  python password_auditor.py --check --wordlist wordlists/rockyou-sample.txt\n"
            "  python password_auditor.py --self-test\n\n"
            "there is deliberately no --password flag: a password typed on the command\n"
            "line is stored in shell history and visible in the process list.\n"
        ),
    )
    modes = parser.add_argument_group("modes (choose one, default --demo)")
    modes.add_argument("--demo", action="store_true",
                       help="audit the built-in fictional passwords and run a scripted "
                            "registration flow, no input needed")
    modes.add_argument("--check", action="store_true",
                       help="audit password(s) typed with hidden input")
    modes.add_argument("--register", action="store_true",
                       help="interactive registration demo with hidden input and retries")
    modes.add_argument("--stdin", action="store_true",
                       help="audit passwords piped in, one per line (for automation)")
    modes.add_argument("--audit-file", metavar="PATH",
                       help="audit passwords from a list file, one per line (rockyou "
                            "sample, exported list, or your own candidates)")
    modes.add_argument("--show-policy", action="store_true",
                       help="print the password policy this configuration enforces, "
                            "then exit")
    modes.add_argument("--mutations", metavar="WORD",
                       help="show the mutations the engine generates for WORD")
    modes.add_argument("--self-test", action="store_true",
                       help="run the built-in test suite and exit")
    modes.add_argument("--version", action="version",
                       version=f"{TOOL_NAME} {__version__}")

    wordlist_group = parser.add_argument_group("wordlist")
    wordlist_group.add_argument("--wordlist", metavar="PATH",
                                help=f"rockyou sample path (default: {DEFAULT_WORDLIST_PATH}, "
                                     f"or ${WORDLIST_ENV_VAR})")
    wordlist_group.add_argument("--wordlist-limit", type=int, default=DEFAULT_WORDLIST_LIMIT,
                                metavar="N", help="max lines to read (default: %(default)s)")
    wordlist_group.add_argument("--demo-wordlist", action=argparse.BooleanOptionalAction,
                                default=True,
                                help="include the built-in demonstration list "
                                     "(default: enabled)")

    policy_group = parser.add_argument_group("policy")
    policy_group.add_argument("--policy-profile", choices=sorted(POLICY_PROFILES),
                              default="baseline",
                              help="starting point for the policy: 'baseline' (classic "
                                   "composition rules) or 'nist' (length-led, no "
                                   "composition rules). Any policy flag you pass "
                                   "overrides the profile (default: %(default)s)")
    policy_group.add_argument("--min-length", type=int, default=PasswordPolicy.min_length,
                              metavar="N", help="minimum length (default: %(default)s)")
    policy_group.add_argument("--max-length", type=int, default=PasswordPolicy.max_length,
                              metavar="N", help="maximum length (default: %(default)s)")
    policy_group.add_argument("--min-score", type=int, default=PasswordPolicy.min_strength_score,
                              choices=range(0, 5), metavar="0-4",
                              help="minimum strength score (default: %(default)s)")
    policy_group.add_argument("--min-bits", type=float, default=PasswordPolicy.min_attack_bits,
                              metavar="B",
                              help="minimum attack-model bits (default: %(default)s)")
    policy_group.add_argument("--require-lowercase", action=argparse.BooleanOptionalAction,
                              default=True, help="(default: required)")
    policy_group.add_argument("--require-uppercase", action=argparse.BooleanOptionalAction,
                              default=True, help="(default: required)")
    policy_group.add_argument("--require-digit", action=argparse.BooleanOptionalAction,
                              default=True, help="(default: required)")
    policy_group.add_argument("--require-symbol", action=argparse.BooleanOptionalAction,
                              default=True, help="(default: required)")
    policy_group.add_argument("--passphrase-exemption", type=int,
                              default=PasswordPolicy.passphrase_exemption_length, metavar="N",
                              help="length at which class rules are waived, 0 disables "
                                   "(default: %(default)s)")

    engine_group = parser.add_argument_group("engine and mutation limits")
    engine_group.add_argument("--zxcvbn", action=argparse.BooleanOptionalAction, default=True,
                              help="use zxcvbn when installed (default: enabled)")
    engine_group.add_argument("--max-variants", type=int,
                              default=MutationLimits.max_variants_per_word, metavar="N",
                              help="cap on generated variants per word (default: %(default)s)")
    engine_group.add_argument("--max-leet-positions", type=int,
                              default=MutationLimits.max_leet_positions, metavar="N",
                              help="letters considered for leet substitution "
                                   "(default: %(default)s)")
    engine_group.add_argument("--max-unleet-variants", type=int,
                              default=MutationLimits.max_unleet_variants, metavar="N",
                              help="cap on reverse leet enumeration (default: %(default)s)")
    engine_group.add_argument("--leet-alternates", action="store_true",
                              help="also generate secondary substitutions (a->4, s->5); "
                                   "detection always considers every substitution")
    engine_group.add_argument("--years", nargs=2, type=int, default=list(DEFAULT_YEAR_RANGE),
                              metavar=("START", "END"),
                              help="year range appended by the mutation engine "
                                   "(default: %(default)s)")
    engine_group.add_argument("--pbkdf2-iterations", type=int, default=PBKDF2_ITERATIONS,
                              metavar="N", help="PBKDF2 iterations (default: %(default)s)")

    io_group = parser.add_argument_group("output")
    io_group.add_argument("--audit-limit", type=int, default=DEFAULT_AUDIT_LIMIT,
                          metavar="N",
                          help="how many passwords to read with --audit-file "
                               "(default: %(default)s)")
    io_group.add_argument("--audit-sample", choices=("first", "random"), default="first",
                          help="take the first N lines or a random sample of N "
                               "(default: %(default)s)")
    io_group.add_argument("--audit-seed", type=int, metavar="N",
                          help="seed for --audit-sample random, for a repeatable sample")
    io_group.add_argument("--max-detail", type=int, default=DEFAULT_MAX_DETAIL,
                          metavar="N",
                          help="candidates given a full block in the HTML report, 0 for "
                               "all; the JSON always holds every one (default: %(default)s)")
    io_group.add_argument("--count", type=int, default=1, metavar="N",
                          help="how many passwords to prompt for with --check "
                               "(default: %(default)s)")
    io_group.add_argument("--max-show", type=int, default=30, metavar="N",
                          help="variants to display with --mutations (default: %(default)s)")
    io_group.add_argument("--report-dir", default=DEFAULT_REPORT_DIR, metavar="DIR",
                          help="where reports are written (default: %(default)s)")
    io_group.add_argument("--json-out", metavar="PATH", help="override the JSON report path")
    io_group.add_argument("--html-out", metavar="PATH", help="override the HTML report path")
    io_group.add_argument("--reports", action=argparse.BooleanOptionalAction, default=True,
                          help="write the JSON and HTML reports (default: enabled)")
    io_group.add_argument("--show-matches", action="store_true",
                          help="print matched wordlist words in the terminal only; they "
                               "are never written to reports or logs")
    io_group.add_argument("--log-file", metavar="PATH",
                          help="append redacted diagnostics to a log file")
    io_group.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    io_group.add_argument("--quiet", action="store_true",
                          help="suppress per-candidate terminal output")
    io_group.add_argument("--verbose", action="store_true", help="verbose diagnostics")
    return parser


def policy_from_args(
    args: argparse.Namespace, parser: Optional[argparse.ArgumentParser] = None
) -> PasswordPolicy:
    """Build the policy from the chosen profile, then apply explicit overrides.

    Only flags the user actually typed override the profile. Comparing each value
    against the parser default is what tells the two apart, so
    `--policy-profile nist` keeps its own relaxed class rules while
    `--policy-profile nist --min-length 20` still raises the length.
    """
    factory = POLICY_PROFILES.get(getattr(args, "policy_profile", "baseline"))
    policy = factory() if callable(factory) else PasswordPolicy()

    overrides = (
        ("min_length", "min_length"),
        ("max_length", "max_length"),
        ("require_lowercase", "require_lowercase"),
        ("require_uppercase", "require_uppercase"),
        ("require_digit", "require_digit"),
        ("require_symbol", "require_symbol"),
        ("min_score", "min_strength_score"),
        ("min_bits", "min_attack_bits"),
        ("passphrase_exemption", "passphrase_exemption_length"),
    )
    for flag, field_name in overrides:
        if not hasattr(args, flag):
            continue
        value = getattr(args, flag)
        default = parser.get_default(flag) if parser is not None else None
        if parser is None or value != default:
            setattr(policy, field_name, value)

    if policy.min_length < 1:
        raise AuditError("--min-length must be at least 1")
    if policy.max_length < policy.min_length:
        raise AuditError("--max-length must be greater than or equal to --min-length")
    if policy.passphrase_exemption_length < 0:
        raise AuditError("--passphrase-exemption cannot be negative")
    return policy


def engine_from_args(args: argparse.Namespace) -> MutationEngine:
    if args.max_variants < 1:
        raise AuditError("--max-variants must be at least 1")
    if args.max_leet_positions < 0:
        raise AuditError("--max-leet-positions cannot be negative")
    if args.max_unleet_variants < 1:
        raise AuditError("--max-unleet-variants must be at least 1")
    limits = MutationLimits(
        max_leet_positions=args.max_leet_positions,
        max_variants_per_word=args.max_variants,
        max_unleet_variants=args.max_unleet_variants,
    )
    return MutationEngine(
        limits,
        year_range=(args.years[0], args.years[1]),
        leet_alternates=args.leet_alternates,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    try:
        configure_logging(args.verbose, args.log_file)
        palette = _Palette(_colour_supported(args.no_color))
        engine = engine_from_args(args)

        if args.show_policy:
            policy = policy_from_args(args, parser)
            print_policy(palette, policy, indent="  ")
            return 0

        if args.mutations:
            show_mutations(engine, args.mutations, max(1, args.max_show), palette)
            return 0

        wordlist = load_wordlist(args.wordlist, args.wordlist_limit, args.demo_wordlist)
        policy = policy_from_args(args, parser)
        scorer = StrengthScorer(wordlist, engine, use_zxcvbn=args.zxcvbn)
        enforcer = PolicyEnforcer(policy, scorer)

        if args.pbkdf2_iterations < 1:
            raise AuditError("--pbkdf2-iterations must be at least 1")

        selected = [name for name in ("check", "register", "stdin", "demo")
                    if getattr(args, name)]
        if args.audit_file:
            selected.append("audit-file")
        if len(selected) > 1:
            raise AuditError(f"choose a single mode, not {' and '.join('--' + s for s in selected)}")
        mode = selected[0] if selected else "demo"

        print_header(palette, wordlist, scorer, policy, show_policy=not args.quiet)
        records: List[Dict[str, object]] = []

        if mode == "demo":
            if not ZXCVBN_AVAILABLE:
                out(palette.yellow(
                    " zxcvbn is not installed; the built-in heuristic scorer is in use. "
                    "Install it with: pip install zxcvbn\n"
                ))
            out(palette.dim(
                " Auditing the built-in fictional demonstration passwords. None of these "
                "is a real credential.\n"
            ))
            records.extend(
                audit_passwords(enforcer, palette, DEMO_CANDIDATES, args.show_matches, args.quiet)
            )
            records.extend(
                registration_demo(
                    enforcer, palette, DEMO_REGISTRATION_ATTEMPTS,
                    args.pbkdf2_iterations, args.show_matches,
                )
            )
        elif mode == "check":
            count = max(1, args.count)
            items = []
            for index in range(1, count + 1):
                prompt = (
                    f"Password {index}/{count} (input hidden): " if count > 1
                    else "Password (input hidden): "
                )
                items.append((f"candidate-{index}", read_hidden_password(prompt)))
            out("")
            records.extend(
                audit_passwords(enforcer, palette, items, args.show_matches, args.quiet)
            )
        elif mode == "stdin":
            passwords = read_stdin_passwords()
            items = [(f"candidate-{n}", pw) for n, pw in enumerate(passwords, start=1)]
            records.extend(
                audit_passwords(enforcer, palette, items, args.show_matches, args.quiet)
            )
        elif mode == "audit-file":
            passwords = read_password_file(
                args.audit_file, args.audit_limit, args.audit_sample, args.audit_seed
            )
            out(palette.dim(
                f" Auditing {len(passwords):,} password(s) from '{args.audit_file}' "
                f"({args.audit_sample} {args.audit_limit:,}). Labels are sequential and "
                "carry no line numbers, so the report cannot be mapped back to the "
                "source list.\n"
            ))
            items = [(f"candidate-{n}", pw) for n, pw in enumerate(passwords, start=1)]
            records.extend(
                audit_passwords(enforcer, palette, items, args.show_matches, args.quiet)
            )
        elif mode == "register":
            records.extend(
                interactive_registration(
                    enforcer, palette, args.pbkdf2_iterations, 3, args.show_matches
                )
            )

        accepted = sum(
            1 for record in records
            if isinstance(record.get("policy_decision"), dict)
            and record["policy_decision"].get("allowed")  # type: ignore[index]
        )
        if len(records) > 1:
            print_aggregate(palette, build_aggregate(records), policy.min_attack_bits)
        out(palette.bold(
            f"Summary: {len(records)} candidate(s) audited, {accepted} accepted, "
            f"{len(records) - accepted} rejected."
        ))

        if args.reports and records:
            payload = build_report_payload(records, policy, wordlist, engine, mode)
            report_dir = Path(args.report_dir)
            json_path = Path(args.json_out) if args.json_out else report_dir / DEFAULT_JSON_NAME
            html_path = Path(args.html_out) if args.html_out else report_dir / DEFAULT_HTML_NAME
            write_json_report(payload, json_path)
            write_html_report(payload, html_path, args.max_detail)
            out(f"JSON results : {json_path}")
            out(f"HTML report  : {html_path}  (open it and print to PDF)")
        elif args.reports:
            out(palette.yellow("No candidates were audited, so no reports were written."))
        return 0

    except AuditError as exc:
        out(f"error: {exc}")
        return 1
    except ReportSafetyError as exc:
        out(f"report blocked: {exc}")
        return 1
    except KeyboardInterrupt:
        out("\ninterrupted")
        return 130
    except BrokenPipeError:
        # The reader closed the pipe (for example `| head` or `| more`). Point
        # stdout at the null device so the interpreter's own flush at exit does
        # not raise a second time, then leave quietly.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:  # pragma: no cover
            pass
        return 0
    except Exception as exc:  # pragma: no cover - last-resort handler
        LOGGER.exception("unexpected failure")
        out(f"unexpected error: {type(exc).__name__}: {scrub(str(exc))}")
        return 1
    finally:
        forget_secrets()


if __name__ == "__main__":
    sys.exit(main())
