#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phish_detector.py - Automated Phishing Email Detector
CSIT 2033 - Week 8 Lab  (Cybersecurity strategy: Defensive)

Parses EML / MBOX email files and scores every message for phishing likelihood.

  1. Email parser          headers, plain/HTML bodies, links, attachments, delivery path
                           (EML, MBOX, folders, and messages forwarded "as attachment")
  2. Authentication        SPF / DKIM / DMARC -- the verdicts your mail provider recorded
                           at delivery, plus live re-checks (dnspython + dkimpy):
                           SPF record evaluation, DKIM signature verification, DMARC
                           policy lookup and alignment
  3. Threat intelligence   every link is checked against the OpenPhish public phishing
                           feed, and against VirusTotal when you supply a free API key
  4. NLP-lite features     urgency, threats, credential requests, payment and reward
                           lures, generic greetings, BEC phrasing, writing style
  5. Explainable scoring   a transparent logistic model: phishing probability plus the
                           exact contribution of every feature that fired
  6. Reports               self-contained HTML, PDF (reportlab) and JSON

Safety: the tool never opens, renders, or visits links found in an email. It only
looks them up in threat-intelligence sources. All reports show links defanged
(hxxps://example[.]com) so nobody clicks them by accident.

Usage
  python phish_detector.py message.eml
  python phish_detector.py inbox.mbox suspicious_folder/ -o reports
  python phish_detector.py message.eml --vt-key YOUR_KEY      (or set VT_API_KEY)
  python phish_detector.py message.eml --offline               (no DNS, feeds, VirusTotal)
  python phish_detector.py --lab                                (built-in samples, offline)
  python phish_detector.py --self-test                          (verify the tool works)
  On Windows use:  py phish_detector.py ...

Install
  pip install dnspython dkimpy tldextract reportlab requests
  Every dependency is optional; a missing one disables only the check that needs it.
"""

from __future__ import annotations

import argparse
import base64
import email
import email.policy
import email.utils
import hashlib
import html
import io
import ipaddress
import json
import logging
import mailbox
import math
import os
import re
import sys
import time
import unicodedata
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage, Message
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, quote, unquote, urlsplit

__version__ = "1.0.0"
TOOL_NAME = "phish_detector"
USER_AGENT = f"{TOOL_NAME}/{__version__} (educational phishing-analysis lab tool)"

# ----------------------------------------------------------------------------
# Optional dependencies -- each one only enables a feature
# ----------------------------------------------------------------------------
try:
    import dns.exception
    import dns.resolver
    import dns.reversename
    HAVE_DNS = True
except ImportError:  # pragma: no cover
    HAVE_DNS = False

try:
    import dkim  # package name: dkimpy
    HAVE_DKIM = True
except ImportError:  # pragma: no cover
    HAVE_DKIM = False

try:
    import tldextract
    # suffix_list_urls=() -> use the bundled Public Suffix List snapshot (no network)
    _TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    _TLD_PRIV = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                      include_psl_private_domains=True)
    HAVE_TLDEXTRACT = True
except Exception:  # pragma: no cover
    _TLD = _TLD_PRIV = None
    HAVE_TLDEXTRACT = False

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:  # pragma: no cover
    HAVE_REQUESTS = False


# ============================================================================
# Console output (ANSI colors when supported; never crashes on cp1252 consoles)
# ============================================================================
class Console:
    CODES = {"red": "31", "green": "32", "yellow": "33", "blue": "34",
             "magenta": "35", "cyan": "36", "bold": "1", "dim": "2"}

    def __init__(self, color: str = "auto", quiet: bool = False):
        self.quiet = quiet
        self.color = self._want_color(color)

    @staticmethod
    def _want_color(mode: str) -> bool:
        if mode == "always":
            return True
        if mode == "never" or os.environ.get("NO_COLOR"):
            return False
        if os.environ.get("FORCE_COLOR"):
            return True
        if any(k in os.environ for k in ("COLAB_RELEASE_TAG", "COLAB_GPU")):
            return True  # Colab renders ANSI colors in !python output
        try:
            if not sys.stdout.isatty():
                return False
        except Exception:
            return False
        if os.name == "nt":
            try:
                os.system("")  # turns on ANSI escape processing in Windows 10+ consoles
            except Exception:
                return False
        return True

    def paint(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        return "".join(f"\033[{self.CODES[s]}m" for s in styles) + text + "\033[0m"

    def out(self, msg: str = "") -> None:
        if not self.quiet:
            print(msg, flush=True)

    def info(self, msg: str) -> None:
        self.out(self.paint("[*] ", "cyan") + msg)

    def ok(self, msg: str) -> None:
        self.out(self.paint("[+] ", "green") + msg)

    def warn(self, msg: str) -> None:
        print(self.paint("[!] ", "yellow") + msg, file=sys.stderr, flush=True)

    def err(self, msg: str) -> None:
        print(self.paint("[x] ", "red") + msg, file=sys.stderr, flush=True)


CON = Console("never", quiet=True)  # replaced in main(); silent when imported as a module


def _harden_stdio() -> None:
    """Windows consoles often use cp1252; replace unprintable characters instead of crashing."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass


# ============================================================================
# Reference data
# ============================================================================
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com", "rocketmail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
    "mac.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "gmx.de",
    "mail.com", "yandex.com", "yandex.ru", "zohomail.com", "tutanota.com", "tuta.io",
    "mail.ru", "qq.com", "163.com", "126.com", "inbox.com", "hushmail.com", "comcast.net",
    "sbcglobal.net", "cox.net", "charter.net", "earthlink.net", "bellsouth.net", "web.de",
}

URL_SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "bl.ink",
    "lnkd.in", "qrco.de", "short.io", "v.gd", "x.co", "soo.gd", "clck.ru", "u.to", "shrtco.de",
    "adf.ly", "bit.do", "mcaf.ee", "dlvr.it", "ift.tt", "surl.li", "gg.gg", "tny.im",
    "short.gy", "kutt.it", "did.li", "2no.co", "qr.net", "qrs.ly", "tinu.be", "lc.cx",
    "shorturl.com", "urlz.fr", "n9.cl", "hyperurl.co", "forms.gle",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "club", "online", "site", "live", "click", "link", "work",
    "rest", "country", "gq", "tk", "ml", "cf", "ga", "icu", "buzz", "monster", "cam", "quest",
    "sbs", "cfd", "bond", "cyou", "lat", "win", "loan", "men", "date", "racing", "review",
    "stream", "download", "kim", "party", "science", "trade", "accountant", "cricket",
    "faith", "webcam", "bid", "su", "pw", "ws", "shop", "store", "best", "fun", "today",
    "mom", "beauty", "hair", "skin", "makeup", "autos", "boats", "lol", "ink", "help",
    "support", "digital", "life",
}

# Free web hosting / app platforms / tunnels that are heavily abused for phishing pages
FREE_HOSTING_SUFFIXES = {
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "r2.dev", "netlify.app",
    "vercel.app", "glitch.me", "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "nftstorage.link",
    "w3s.link", "weebly.com", "weeblysite.com", "wixsite.com", "square.site", "godaddysites.com",
    "webflow.io", "blogspot.com", "000webhostapp.com", "framer.website", "framer.app",
    "carrd.co", "mystrikingly.com", "onrender.com", "herokuapp.com", "replit.app", "repl.co",
    "github.io", "gitlab.io", "azurewebsites.net", "blob.core.windows.net",
    "storage.googleapis.com", "s3.amazonaws.com", "amplifyapp.com", "backblazeb2.com",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt", "duckdns.org",
    "ddns.net", "hopto.org", "zapto.org", "sytes.net", "jotform.com", "typeform.com",
    "sites.google.com", "notion.site", "canva.site", "yolasite.com", "wordpress.com",
}

# Big shared platforms: a feed entry on one of these must match the exact URL,
# never just the host (one bad Google Doc does not make docs.google.com malicious).
SHARED_PLATFORM_SITES = {
    "google.com", "googleusercontent.com", "googleapis.com", "microsoft.com", "live.com",
    "office.com", "sharepoint.com", "onedrive.com", "1drv.ms", "dropbox.com", "box.com",
    "github.com", "githubusercontent.com", "amazonaws.com", "cloudfront.net", "azureedge.net",
    "windows.net", "linkedin.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "youtube.com", "apple.com", "icloud.com", "adobe.com", "docusign.net", "wetransfer.com",
    "notion.so", "canva.com", "figma.com", "zoom.us", "mailchimp.com", "salesforce.com",
}

# Email-service-provider click trackers: a link-text mismatch through these is normal
CLICK_TRACKERS = {
    "list-manage.com", "mailchimp.com", "sendgrid.net", "mandrillapp.com", "mailgun.org",
    "hubspotlinks.com", "hubspotemail.net", "hs-sites.com", "sparkpostmail.com",
    "exacttarget.com", "cmail19.com", "cmail20.com", "createsend.com", "rs6.net",
    "klclick.com", "klclick1.com", "klclick2.com", "klaviyomail.com", "awstrack.me",
    "amazonses.com", "sailthru.com", "iterable.com", "customeriomail.com", "mlsend.com",
    "convertkit-mail.com", "ck.page", "sendibt2.com", "sendibt3.com", "pstmrk.it",
    "mktoweb.com", "mkto-ab220141.com", "constantcontact.com", "substack.com", "beehiiv.com",
    "mailerlite.com", "emltrk.com", "mcsv.net", "ctfassets.net",
}

# Mail providers / ESPs whose Message-ID domain legitimately differs from the From domain
MSGID_PROVIDERS = {
    "google.com", "gmail.com", "mail.gmail.com", "outlook.com", "prod.outlook.com",
    "amazonses.com", "sendgrid.net", "mailgun.org", "mandrillapp.com", "sparkpostmail.com",
    "exacttarget.com", "mcsv.net", "yahoo.com", "icloud.com", "apple.com", "hubspot.com",
    "salesforce.com", "smtp-relay.gmail.com", "mail.yahoo.com", "zoho.com", "mx.google.com",
}

REDIRECT_PARAMS = {"url", "u", "q", "redirect", "redirect_uri", "redirect_url", "redir",
                   "target", "dest", "destination", "next", "continue", "link", "goto",
                   "return", "returnurl", "return_url", "r", "to", "out", "rurl"}

# Brand catalogue: key -> (display-name aliases, legitimate registered domains, strict)
#  * aliases are matched as whole words in the From display name
#  * strict=True: the alias is also a common word or surname ("Chase", "Apple"), so it only
#    counts when the display name is essentially just the brand ("Chase", "Chase Bank Alerts")
BRANDS: dict[str, tuple[list[str], list[str], bool]] = {
    "paypal": (["paypal"], ["paypal.com", "paypal.me", "paypalobjects.com",
                            "paypal-communication.com", "paypal-community.com"], False),
    "microsoft": (["microsoft", "office 365", "office365", "microsoft 365", "onedrive",
                   "one drive", "sharepoint", "outlook web", "outlook team", "owa",
                   "microsoft teams", "microsoft account"],
                  ["microsoft.com", "microsoftonline.com", "office.com", "office365.com",
                   "office.net", "live.com", "outlook.com", "hotmail.com", "sharepoint.com",
                   "onedrive.com", "1drv.ms", "msft.net", "azure.com", "windows.net",
                   "microsoft365.com", "msn.com", "skype.com", "xbox.com", "bing.com",
                   "cloud.microsoft", "mail.microsoft", "sway.com"], False),
    "apple": (["apple", "apple id", "icloud", "itunes", "app store", "apple support"],
              ["apple.com", "icloud.com", "me.com", "mac.com", "apple.news"], True),
    "amazon": (["amazon", "amazon prime", "prime video", "aws", "amazon web services"],
               ["amazon.com", "amazonaws.com", "amazonses.com", "media-amazon.com",
                "ssl-images-amazon.com", "aboutamazon.com", "primevideo.com"], False),
    "netflix": (["netflix"], ["netflix.com", "netflix.net"], False),
    "google": (["google", "gmail", "google workspace", "google drive", "google docs"],
               ["google.com", "gmail.com", "googlemail.com", "youtube.com", "gstatic.com",
                "googleusercontent.com", "goo.gl", "g.co", "withgoogle.com"], False),
    "facebook": (["facebook", "meta for business", "instagram", "whatsapp"],
                 ["facebook.com", "facebookmail.com", "fb.com", "meta.com", "instagram.com",
                  "whatsapp.com", "fbcdn.net"], False),
    "linkedin": (["linkedin"], ["linkedin.com", "licdn.com"], False),
    "dropbox": (["dropbox"], ["dropbox.com", "dropboxmail.com"], False),
    "docusign": (["docusign"], ["docusign.com", "docusign.net"], False),
    "adobe": (["adobe", "adobe sign", "adobe acrobat"], ["adobe.com", "adobesign.com",
                                                        "echosign.com", "adobelogin.com"], False),
    "chase": (["chase", "chase bank", "jpmorgan chase"], ["chase.com", "jpmorgan.com",
                                                          "jpmorganchase.com"], True),
    "wellsfargo": (["wells fargo"], ["wellsfargo.com", "wf.com"], False),
    "bankofamerica": (["bank of america"], ["bankofamerica.com", "bofa.com", "mbna.com"], False),
    "citibank": (["citibank", "citi"], ["citi.com", "citibank.com", "citicards.com"], True),
    "americanexpress": (["american express", "amex"], ["americanexpress.com", "aexp.com"], False),
    "capitalone": (["capital one"], ["capitalone.com"], False),
    "usps": (["usps", "us postal service", "united states postal service", "postal service"],
             ["usps.com", "usps.gov"], False),
    "fedex": (["fedex"], ["fedex.com"], False),
    "ups": (["ups", "united parcel service"], ["ups.com"], True),
    "dhl": (["dhl", "dhl express"], ["dhl.com", "dhl.de"], False),
    "irs": (["irs", "internal revenue service"], ["irs.gov", "treasury.gov"], False),
    "coinbase": (["coinbase"], ["coinbase.com"], False),
    "binance": (["binance"], ["binance.com", "binance.us"], False),
    "metamask": (["metamask"], ["metamask.io"], False),
    "steam": (["steam", "steam support", "steam community"],
              ["steampowered.com", "steamcommunity.com"], True),
    "zoom": (["zoom", "zoom video"], ["zoom.us", "zoom.com"], True),
    "walmart": (["walmart"], ["walmart.com"], False),
    "costco": (["costco"], ["costco.com"], False),
    "venmo": (["venmo"], ["venmo.com"], False),
    "zelle": (["zelle"], ["zellepay.com", "zelle.com"], False),
    "cashapp": (["cash app", "cashapp"], ["cash.app", "square.com", "squareup.com"], False),
    "att": (["at&t", "att"], ["att.com", "att.net"], True),
    "verizon": (["verizon"], ["verizon.com", "verizonwireless.com", "verizon.net"], False),
    "tmobile": (["t-mobile", "tmobile"], ["t-mobile.com"], False),
    "yahoo": (["yahoo"], ["yahoo.com", "yahoo.net", "yahoomail.com"], False),
    "github": (["github"], ["github.com", "githubusercontent.com", "github.io"], False),
    "okta": (["okta"], ["okta.com", "oktacdn.com"], False),
    "norton": (["norton", "norton 360", "norton lifelock"], ["norton.com", "nortonlifelock.com",
                                                            "gen.digital"], True),
    "mcafee": (["mcafee"], ["mcafee.com"], True),
    "geeksquad": (["geek squad"], ["geeksquad.com", "bestbuy.com"], False),
}

# Extra registrable labels that should be compared against look-alike domains
EXTRA_LOOKALIKE_LABELS = {
    "office365": "microsoft", "microsoftonline": "microsoft", "outlook": "microsoft",
    "onedrive": "microsoft", "sharepoint": "microsoft", "icloud": "apple", "gmail": "google",
    "instagram": "facebook", "whatsapp": "facebook", "bankofamerica": "bankofamerica",
    "steamcommunity": "steam", "steampowered": "steam", "citibank": "citibank",
}

GENERIC_DISPLAY_WORDS = {"bank", "online", "support", "security", "service", "services",
                         "alert", "alerts", "team", "notification", "notifications",
                         "customer", "account", "accounts", "billing", "card", "id", "store",
                         "pay", "center", "centre", "help", "desk", "the", "inc", "llc",
                         "official", "verification", "update", "updates", "no-reply", "noreply"}

ORG_ROLE_WORDS = re.compile(
    r"\b(support|security|helpdesk|help desk|service desk|it department|it dept|it team|"
    r"administrator|admin|billing|payroll|human resources|hr department|accounts payable|"
    r"accounting|finance department|compliance|webmaster|postmaster|mail ?administrator|"
    r"customer service|account team|verification|office of the|president|ceo|cfo|chancellor|"
    r"provost|dean|director|registrar|financial aid|bursar|bank|notification)\b", re.I)

RISKY_EXT_EXEC = {"exe", "scr", "pif", "com", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
                  "wsh", "hta", "ps1", "psm1", "msi", "msix", "msixbundle", "appx",
                  "appxbundle", "jar", "lnk", "cpl", "reg", "dll", "chm", "url", "scf",
                  "application", "gadget", "msc", "inf", "sct", "xll", "one", "library-ms",
                  "settingcontent-ms", "appref-ms"}
RISKY_EXT_HTML = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml", "xht"}
RISKY_EXT_MACRO = {"docm", "dotm", "xlsm", "xltm", "xlsb", "xlam", "pptm", "potm", "ppam",
                   "ppsm", "sldm"}
RISKY_EXT_DISK = {"iso", "img", "vhd", "vhdx", "udf"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "tar", "cab", "ace", "arj", "lzh", "bz2",
               "xz", "z", "uue"}
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png",
             "gif", "csv", "rtf", "odt", "mp3", "mp4", "wav"}

INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10")]


# ============================================================================
# Small helpers
# ============================================================================
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shorten(text: str, limit: int = 120) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def fmt_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_internal_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(addr.version == net.version and addr in net for net in INTERNAL_NETS)


def _fallback_registered(host: str) -> str:
    labels = [l for l in host.split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in {"co", "com", "net", "org", "gov", "edu", "ac",
                                               "or", "ne", "go", "gob", "nic", "ltd", "plc"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _split_host(host: str, private: bool) -> tuple[str, str, str]:
    """(subdomain, registrable label, public suffix) for a hostname."""
    host = (host or "").strip(".").lower()
    if not host or is_ip_literal(host):
        return "", host, ""
    extractor = _TLD_PRIV if private else _TLD
    if extractor is not None:
        try:
            r = extractor(host)
            if r.suffix and r.domain:
                return r.subdomain, r.domain, r.suffix
        except Exception:
            pass
    reg = _fallback_registered(host)
    sub = host[: -len(reg)].rstrip(".") if host.endswith(reg) else ""
    label, _, suffix = reg.partition(".")
    return sub, label, suffix


def org_domain(host: str) -> str:
    """Organizational domain as DMARC defines it (public suffix + one label)."""
    host = (host or "").strip(".").lower()
    if not host or is_ip_literal(host):
        return host
    _, label, suffix = _split_host(host, private=False)
    return f"{label}.{suffix}" if suffix else label


def site_domain(host: str) -> str:
    """Registrable 'site' including private suffixes, so x.web.app and y.web.app differ."""
    host = (host or "").strip(".").lower()
    if not host or is_ip_literal(host):
        return host
    _, label, suffix = _split_host(host, private=True)
    return f"{label}.{suffix}" if suffix else label


def host_suffix(host: str) -> str:
    return _split_host(host, private=False)[2]


def has_valid_suffix(host: str) -> bool:
    """True if host ends in a real public suffix (used to tell 'paypal.com' from 'invoice.pdf')."""
    host = host.strip(".").lower()
    if "." not in host or is_ip_literal(host):
        return False
    if _TLD is not None:
        try:
            return bool(_TLD(host).suffix)
        except Exception:
            pass
    last = host.rsplit(".", 1)[-1]
    return last.isalpha() and 2 <= len(last) <= 12 and last not in DECOY_EXT | RISKY_EXT_HTML


def host_to_unicode(host: str) -> str:
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                out.append(label.encode("ascii").decode("idna"))
                continue
            except Exception:
                pass
        out.append(label)
    return ".".join(out)


def host_to_ascii(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except Exception:
        return host


def defang(url: str) -> str:
    """hxxps://evil[.]com/path -- safe to paste into reports and tickets."""
    if not url:
        return url
    m = re.match(r"(?i)^([a-z][a-z0-9+.-]*)(://)([^/?#]*)(.*)$", url)
    if not m:
        return url.replace(".", "[.]")
    scheme, sep, netloc, rest = m.groups()
    scheme = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}.get(scheme.lower(), scheme)
    netloc = netloc.replace(".", "[.]").replace("@", "[@]")
    return f"{scheme}{sep}{netloc}{rest}"


def defang_host(host: str) -> str:
    return host.replace(".", "[.]") if host else host


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# Characters that look like Latin letters (homoglyphs) and digit substitutions
_CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y",
    "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u0501": "d", "\u0261": "g",
    "\u04cf": "l", "\u03bf": "o", "\u03b1": "a", "\u03bd": "v", "\u03c1": "p", "\u03b5": "e",
    "\u03b9": "i", "\u03ba": "k", "\u03c4": "t", "\u03c5": "u", "\u0131": "i", "\u0142": "l",
    "\u0251": "a", "\u0269": "i", "\u01c0": "l",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "$": "s",
    "@": "a", "!": "i", "|": "l",
}


def skeleton(text: str) -> str:
    """Fold homoglyphs/digit swaps so 'pаypa1' (Cyrillic а, digit 1) becomes 'paypal'."""
    text = unicodedata.normalize("NFKD", text.lower())
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = "".join(_CONFUSABLES.get(c, c) for c in text)
    for seq, rep in (("rn", "m"), ("vv", "w"), ("cl", "d"), ("ii", "u")):
        text = text.replace(seq, rep)
    return text


def _all_brand_domains() -> set[str]:
    out = set()
    for _, (_, domains, _) in BRANDS.items():
        out.update(domains)
    return out


BRAND_DOMAINS = _all_brand_domains()


def brand_for_domain(domain: str) -> Optional[str]:
    """Brand key that legitimately owns this domain (or its organizational domain)."""
    d = (domain or "").lower().strip(".")
    org = org_domain(d)
    for key, (_, domains, _) in BRANDS.items():
        if d in domains or org in domains or any(d.endswith("." + x) for x in domains):
            return key
    return None


def _lookalike_targets() -> dict[str, str]:
    targets = {key: key for key in BRANDS}
    targets.update(EXTRA_LOOKALIKE_LABELS)
    return targets


def add_custom_brand(spec: str) -> Optional[str]:
    """--brand "trine=trine.edu,my.trine.edu" adds a protected brand at runtime."""
    name, _, domains = spec.partition("=")
    name = name.strip()
    dom_list = [d.strip().lower() for d in domains.split(",") if d.strip()]
    if not name or not dom_list:
        return None
    key = re.sub(r"[^a-z0-9]", "", name.lower())
    label = _split_host(dom_list[0], private=False)[1]
    aliases = [name.lower()] + ([label] if len(label) >= 5 and label != name.lower() else [])
    BRANDS[key] = (aliases, dom_list, False)
    BRAND_DOMAINS.update(dom_list)
    if label and label != key:
        EXTRA_LOOKALIKE_LABELS[label] = key
    return key


def brand_lookalike(host: str) -> Optional[tuple[str, str, str]]:
    """
    Detect domains imitating a protected brand.
    Returns (brand, technique, explanation) or None.
      homoglyph   - characters swapped for look-alikes: paypa1.com, micr0soft, xn--pypal-4ve
      typosquat   - one or two characters off: paypall.com, microsfot.com
      combosquat  - brand plus extra words: paypal-resolution-center.com
    """
    host = (host or "").lower().strip(".")
    if not host or is_ip_literal(host):
        return None
    if brand_for_domain(host):
        return None
    _, label, _ = _split_host(host, private=False)
    label_u = host_to_unicode(label) if label.startswith("xn--") else label
    if not label_u:
        return None
    tokens = [t for t in re.split(r"[-_.]", label_u) if t]
    flat = label_u.replace("-", "").replace("_", "")
    sk = skeleton(flat)
    for target, brand in _lookalike_targets().items():
        if label_u == target:
            return None  # brand's own label on another TLD, e.g. amazon.de
        if sk == target and flat != target:
            return brand, "homoglyph", f"'{label_u}' imitates '{target}' with look-alike characters"
        if len(target) >= 6 and len(flat) >= 5 and flat[0] == target[0]:
            dist = levenshtein(flat, target)
            if dist == 1 or (dist == 2 and len(target) >= 9):
                return brand, "typosquat", f"'{label_u}' is {dist} character(s) away from '{target}'"
        if len(tokens) > 1 and target in tokens:
            return brand, "combosquat", f"'{label_u}' combines the brand '{target}' with extra words"
        if len(tokens) > 1 and any(skeleton(t) == target for t in tokens):
            fake = next(t for t in tokens if skeleton(t) == target)
            return brand, "homoglyph + combosquat", (f"'{label_u}' spells '{target}' as '{fake}' "
                                                     f"(look-alike characters) and adds extra words")
        if len(target) >= 7 and target in flat and flat != target:
            return brand, "combosquat", f"'{label_u}' embeds the brand '{target}'"
    return None


def display_name_brand(display: str) -> Optional[str]:
    """Brand key claimed by a From display name, or None."""
    if not display:
        return None
    dn = " ".join(display.lower().replace('"', " ").split())
    for key, (aliases, _, strict) in BRANDS.items():
        for alias in aliases:
            if not re.search(r"(?<![a-z0-9])" + re.escape(alias) + r"(?![a-z0-9])", dn):
                continue
            if not strict:
                return key
            rest = re.sub(r"(?<![a-z0-9])" + re.escape(alias) + r"(?![a-z0-9])", " ", dn)
            words = [w for w in re.split(r"[^a-z0-9&-]+", rest) if w]
            if all(w in GENERIC_DISPLAY_WORDS for w in words):
                return key
    return None


# ============================================================================
# Data model
# ============================================================================
@dataclass
class RawMessage:
    source: str        # file the message came from
    label: str         # human label, e.g. "inbox.mbox #3"
    raw: bytes
    depth: int = 0     # >0 for messages that were attached to another message


@dataclass
class Link:
    url: str                   # effective destination (after unwrapping Safe Links etc.)
    original: str              # exactly as found in the message
    scheme: str
    host: str
    site: str                  # registrable site (x.web.app and y.web.app differ)
    path: str = ""
    query: str = ""
    userinfo: str = ""
    port: Optional[int] = None
    text: str = ""             # visible anchor text, if any
    source: str = "text"       # html-a, html-form, html-area, html-iframe, text, attachment:<name>...
    wrapper: str = ""          # e.g. "Microsoft Defender Safe Links"
    flags: list = field(default_factory=list)   # [code, detail]
    risk: float = 0.0
    feed: Optional[dict] = None
    vt: Optional[dict] = None


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    disposition: str
    extension: str
    magic: str = ""
    flags: list = field(default_factory=list)   # [code, detail]
    inner_files: list = field(default_factory=list)
    vt: Optional[dict] = None


@dataclass
class Hop:
    number: int                # 1 = first server that handled the message
    from_host: str
    from_ip: str
    by_host: str
    protocol: str
    timestamp: str
    delay_s: Optional[float]
    raw: str


@dataclass
class ParsedEmail:
    label: str
    source: str
    raw_size: int
    raw_sha256: str
    headers: list = field(default_factory=list)
    subject: str = ""
    date_raw: str = ""
    date_iso: str = ""
    message_id: str = ""
    in_reply_to: str = ""
    references: str = ""
    from_display: str = ""
    from_addr: str = ""
    from_domain: str = ""
    from_count: int = 0
    sender_addr: str = ""
    reply_to: list = field(default_factory=list)
    return_path: str = ""
    to: list = field(default_factory=list)
    cc: list = field(default_factory=list)
    x_mailer: str = ""
    list_unsubscribe: bool = False
    hops: list = field(default_factory=list)
    auth_results: list = field(default_factory=list)
    arc_auth_results: list = field(default_factory=list)
    received_spf: list = field(default_factory=list)
    dkim_signatures: list = field(default_factory=list)
    text_plain: str = ""
    text_html: str = ""
    visible_text: str = ""
    html_stats: dict = field(default_factory=dict)
    links: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    embedded: list = field(default_factory=list)     # raw bytes of attached .eml messages
    defects: list = field(default_factory=list)
    date_dt: Optional[datetime] = None


def _clean(value: Any) -> str:
    """str() that never leaves lone surrogates behind (8-bit headers decode to surrogates)."""
    s = value if isinstance(value, str) else str(value)
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        s = s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return s


def _oneline(value: Any) -> str:
    return " ".join(_clean(value).split())


# ============================================================================
# HTML analysis (stdlib HTMLParser -- the HTML is parsed, never rendered)
# ============================================================================
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|mso-hide\s*:\s*all|"
    r"font-size\s*:\s*0(?:\.0*)?(?:px|pt|em|rem|%)?\s*(?:;|$|!)|"
    r"opacity\s*:\s*0(?:\.0*)?\s*(?:;|$|!)|max-height\s*:\s*0(?:px)?\s*(?:;|$|!)", re.I)


class HTMLAnalyzer(HTMLParser):
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
            "param", "source", "track", "wbr"}
    SKIP = {"script", "style", "head", "title", "template"}
    BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table",
             "section", "article", "header", "footer", "blockquote", "td", "th", "hr"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self.other_links: list[tuple[str, str]] = []
        self.forms: list[dict] = []
        self.orphan_password_inputs = 0
        self.scripts = 0
        self.iframes = 0
        self.meta_refresh = 0
        self.images = 0
        self.remote_images = 0
        self.tracking_pixels = 0
        self.event_handlers = 0
        self.base_href = ""
        self.hidden_chars = 0
        self._visible: list[str] = []
        self._skip_depth = 0
        self._a_stack: list[list] = []
        self._hidden_stack: list[tuple[str, bool]] = []
        self._form: Optional[dict] = None

    # -- tags ---------------------------------------------------------------
    def handle_starttag(self, tag: str, attrs: list) -> None:
        tag = tag.lower()
        a = {(k or "").lower(): (v or "") for k, v in attrs}
        if any(k.startswith("on") for k in a):
            self.event_handlers += 1
        if tag in self.SKIP:
            if tag == "script":
                self.scripts += 1
                if a.get("src"):
                    self.other_links.append((a["src"], "html-script"))
            self._skip_depth += 1
            return
        hidden = bool(_HIDDEN_STYLE.search(a.get("style", ""))) or "hidden" in a
        if tag not in self.VOID:
            self._hidden_stack.append((tag, hidden))
        if tag in self.BLOCK:
            self._visible.append("\n")
        if tag == "a":
            self._a_stack.append([a.get("href", "").strip() or None, []])
        elif tag == "area" and a.get("href"):
            self.other_links.append((a["href"].strip(), "html-area"))
        elif tag == "form":
            self._form = {"action": a.get("action", "").strip(), "method": (a.get("method") or "get").lower(),
                          "inputs": [], "password": False}
            self.forms.append(self._form)
            if self._form["action"]:
                self.other_links.append((self._form["action"], "html-form"))
        elif tag in ("input", "button"):
            itype = (a.get("type") or "text").lower()
            if self._form is not None:
                self._form["inputs"].append(itype)
                if itype == "password":
                    self._form["password"] = True
            elif itype == "password":
                self.orphan_password_inputs += 1
            if a.get("formaction"):
                self.other_links.append((a["formaction"].strip(), "html-form"))
        elif tag == "img":
            self.images += 1
            src = a.get("src", "")
            if src.lower().startswith(("http://", "https://")):
                self.remote_images += 1
            if a.get("width", "").strip() in ("0", "1") or a.get("height", "").strip() in ("0", "1"):
                self.tracking_pixels += 1
        elif tag in ("iframe", "frame", "embed", "object"):
            self.iframes += 1
            src = a.get("src") or a.get("data") or ""
            if src:
                self.other_links.append((src.strip(), "html-iframe"))
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh += 1
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
            if m:
                self.other_links.append((m.group(1).strip(), "html-meta-refresh"))
        elif tag == "base":
            self.base_href = a.get("href", "")

    def handle_startendtag(self, tag: str, attrs: list) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() not in self.VOID and tag.lower() not in self.SKIP:
            self.handle_endtag(tag)
        elif tag.lower() in self.SKIP:
            self._skip_depth = max(0, self._skip_depth - 1)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self.SKIP:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if tag == "a" and self._a_stack:
            href, parts = self._a_stack.pop()
            if href:
                self.anchors.append((href, " ".join("".join(parts).split())))
        elif tag == "form":
            self._form = None
        for i in range(len(self._hidden_stack) - 1, -1, -1):
            if self._hidden_stack[i][0] == tag:
                del self._hidden_stack[i:]
                break
        if tag in self.BLOCK:
            self._visible.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if any(h for _, h in self._hidden_stack):
            self.hidden_chars += len(data.strip())
            return
        self._visible.append(data)
        for entry in self._a_stack:
            entry[1].append(data)

    # -- results ------------------------------------------------------------
    def visible_text(self) -> str:
        text = "".join(self._visible).replace("\xa0", " ")
        lines = [" ".join(line.split()) for line in text.splitlines()]
        out, blank = [], False
        for line in lines:
            if line:
                out.append(line)
                blank = False
            elif not blank and out:
                out.append("")
                blank = True
        return "\n".join(out).strip()

    def stats(self) -> dict:
        return {"forms": len(self.forms),
                "password_forms": sum(1 for f in self.forms if f["password"]) + self.orphan_password_inputs,
                "form_actions": [f["action"] for f in self.forms if f["action"]][:5],
                "scripts": self.scripts, "iframes": self.iframes, "meta_refresh": self.meta_refresh,
                "images": self.images, "remote_images": self.remote_images,
                "tracking_pixels": self.tracking_pixels, "event_handlers": self.event_handlers,
                "hidden_chars": self.hidden_chars, "base_href": self.base_href}


def analyze_html(markup: str) -> HTMLAnalyzer:
    parser = HTMLAnalyzer()
    try:
        parser.feed(markup)
        parser.close()
    except Exception:  # malformed markup -- keep whatever was collected
        pass
    return parser


# ============================================================================
# URL handling
# ============================================================================
_URL_IN_TEXT = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`{}|\\^\[\]]{3,}")
_DISPLAY_URL = re.compile(
    r"^(?:[a-z][a-z0-9+.-]*://)?(?:www\.)?(?P<host>[a-z0-9\u00a1-\uffff-]+(?:\.[a-z0-9\u00a1-\uffff-]+)+)"
    r"(?::\d+)?(?:[/?#]\S*)?$", re.I)
_LOGIN_RX = re.compile(
    r"(?<![a-z])(log-?in|sign-?in|log-?on|verify|verification|accounts?|secure|webscr|passwords?|"
    r"passwd|credentials?|auth|oauth|unlock|wallet|billing|confirm(?:ation)?|validat(?:e|ion)|"
    r"recover(?:y)?|suspend(?:ed)?|restore|sso|mfa|2fa|authenticat(?:e|ion)|reactivat(?:e|ion))(?![a-z])")
FLAG_RISK = {"ip-host": 1.5, "punycode": 1.2, "lookalike": 2.2, "brand-elsewhere": 1.3,
             "shortener": 0.7, "suspicious-tld": 0.5, "userinfo": 1.2, "many-subdomains": 0.5,
             "obfuscated": 0.4, "free-hosting": 0.6, "redirect": 0.6, "script-scheme": 1.2,
             "login-keywords": 0.4, "nonstandard-port": 0.4, "text-mismatch": 1.6,
             "text-mismatch-tracked": 0.3, "backslash": 1.0}


def _strip_url_token(u: str) -> str:
    u = u.strip().strip("<>\"'")
    while u and u[-1] in ".,;:!?'\"]}>":
        u = u[:-1]
    if u.endswith(")") and u.count("(") < u.count(")"):
        u = u[:-1]
    return u


def unwrap_url(url: str) -> tuple[str, str]:
    """Recover the real destination from security-gateway link wrappers."""
    wrapper = ""
    for _ in range(3):
        try:
            p = urlsplit(url)
            host = (p.hostname or "").lower()
        except ValueError:
            break
        q = parse_qs(p.query)
        if host.endswith("safelinks.protection.outlook.com") and "url" in q:
            url, wrapper = q["url"][0], "Microsoft Defender Safe Links"
        elif host == "urldefense.proofpoint.com" and "u" in q:
            inner = q["u"][0].replace("_", "/")
            inner = re.sub(r"-([0-9A-Fa-f]{2})", lambda m: "%" + m.group(1), inner)
            url, wrapper = unquote(inner), "Proofpoint URL Defense"
        elif host == "urldefense.com" and p.path.startswith("/v3/__"):
            inner = url.split("/v3/__", 1)[1].split("__;", 1)[0]
            url, wrapper = inner, "Proofpoint URL Defense"
        elif host in ("www.google.com", "google.com") and p.path == "/url" and ("q" in q or "url" in q):
            url, wrapper = (q.get("q") or q.get("url"))[0], "Google redirect"
        elif host.endswith("linkprotect.cudasvc.com") and "a" in q:
            url, wrapper = q["a"][0], "Barracuda Link Protection"
        else:
            if "mimecast" in host and not wrapper:
                wrapper = "Mimecast (destination hidden by gateway)"
            break
    return url, wrapper


def _split_url(url: str) -> Optional[tuple]:
    try:
        p = urlsplit(url)
    except ValueError:
        return None
    try:
        host = (p.hostname or "").strip(".").lower()
    except ValueError:
        host = ""
    try:
        port = p.port
    except ValueError:
        port = None
    userinfo = p.netloc.rpartition("@")[0] if "@" in p.netloc else ""
    return p.scheme.lower(), host, port, p.path or "", p.query or "", userinfo


def url_key(host: str, path: str, query: str) -> str:
    """Canonical key for feed matching: host + path (no trailing slash) + query."""
    key = host_to_ascii(host.lower()) + (path.rstrip("/") if path else "")
    return key + ("?" + query if query else "")


def _flag(link: Link, code: str, detail: str) -> None:
    if not any(f[0] == code for f in link.flags):
        link.flags.append([code, detail])


def _score_url_flags(link: Link) -> None:
    host, site = link.host, link.site
    if is_ip_literal(host):
        _flag(link, "ip-host", f"Uses a raw IP address ({host}) instead of a domain name")
    if "xn--" in host or any(ord(c) > 127 for c in host):
        _flag(link, "punycode", f"Internationalized domain '{host_to_unicode(host)}' "
                                f"({host_to_ascii(host)}) can hide look-alike characters")
    login_found: list[str] = []
    if host and not brand_for_domain(host):
        path_q = unquote(link.path + " " + link.query).lower()
        login_found = sorted({m.group(1) for m in _LOGIN_RX.finditer(path_q)})
    lookalike = brand_lookalike(host)
    if lookalike:
        _flag(link, "lookalike", f"{lookalike[2]} - imitates {lookalike[0]} ({lookalike[1]})")
    elif host and not is_ip_literal(host) and not brand_for_domain(host):
        sub = _split_host(host, private=False)[0]
        sub_tokens = set(re.split(r"[^a-z0-9]+", sub))
        path_tokens = set(re.split(r"[^a-z0-9]+", unquote(link.path + " " + link.query).lower()))
        for target, brand in _lookalike_targets().items():
            if len(target) < 4:
                continue
            # brand in a subdomain is always suspicious; in a path only next to login wording
            where = "subdomain" if target in sub_tokens else \
                "path" if (target in path_tokens and login_found) else ""
            if where:
                _flag(link, "brand-elsewhere", f"Brand name '{target}' appears in the {where} of "
                                               f"an unrelated site ({site})")
                break
    if site in URL_SHORTENERS or host in URL_SHORTENERS:
        _flag(link, "shortener", f"URL shortener ({host}) hides the real destination")
    suffix = host_suffix(host)
    tld = suffix.rsplit(".", 1)[-1] if suffix else ""
    if tld in SUSPICIOUS_TLDS:
        _flag(link, "suspicious-tld", f".{tld} is one of the top-level domains most abused for phishing")
    if link.userinfo:
        _flag(link, "userinfo", f"Text before '@' ('{shorten(link.userinfo, 40)}') is ignored by "
                                f"browsers - the real host is {host}")
    sub = _split_host(host, private=False)[0] if host and not is_ip_literal(host) else ""
    if sub and len(sub.split(".")) >= 4:
        _flag(link, "many-subdomains", f"{len(sub.split('.'))} stacked subdomains ({shorten(sub, 50)})")
    if len(link.url) > 200 or link.url.count("%") >= 15:
        _flag(link, "obfuscated", f"Very long or heavily encoded URL ({len(link.url)} characters)")
    lowered = host.lower()
    if any(lowered == s or lowered.endswith("." + s) for s in FREE_HOSTING_SUFFIXES) or \
            (lowered == "docs.google.com" and link.path.startswith("/forms")):
        _flag(link, "free-hosting", f"Hosted on a free site/app/form platform ({host}) that "
                                    f"attackers use for throwaway phishing pages")
    if login_found:
        _flag(link, "login-keywords", "Path mentions " + ", ".join(login_found[:4]))
    if link.port and link.port not in (80, 443):
        _flag(link, "nonstandard-port", f"Non-standard port {link.port}")
    link.risk = round(sum(FLAG_RISK.get(code, 0.2) for code, _ in link.flags), 2)


def _check_text_mismatch(link: Link) -> None:
    text = (link.text or "").strip()
    if not text or len(text) > 300:
        return
    m = _DISPLAY_URL.match(text.replace(" ", ""))
    if not m:
        return
    shown = m.group("host").lower().strip(".")
    if not has_valid_suffix(host_to_ascii(shown)):
        return
    if site_domain(shown) == link.site or org_domain(shown) == org_domain(link.host):
        return
    tracked = link.site in CLICK_TRACKERS or org_domain(link.host) in CLICK_TRACKERS
    if tracked:
        _flag(link, "text-mismatch-tracked", f"Link text shows '{shorten(text, 60)}' but goes through "
                                             f"the mail-marketing tracker {link.host}")
    else:
        _flag(link, "text-mismatch", f"Link text shows '{shorten(text, 60)}' but actually opens "
                                     f"{defang_host(link.host)}")


def build_links(entries: list[tuple[str, str, str]]) -> list[Link]:
    """entries = (url, anchor_text, source). Unwraps, de-duplicates and flags every link."""
    links: list[Link] = []
    seen: dict[str, Link] = {}
    queue = list(entries)
    guard = 0
    while queue and guard < 500:
        guard += 1
        raw_url, text, source = queue.pop(0)
        if not raw_url:
            continue
        url = _strip_url_token(_clean(raw_url))
        url = re.sub(r"\s+", "", url)
        if not url or url.startswith("#"):
            continue
        if url.lower().startswith("www."):
            url = "http://" + url
        scheme = url.split(":", 1)[0].lower() if ":" in url else ""
        if scheme in ("javascript", "data", "vbscript"):
            key = scheme + ":" + url[:80]
            if key not in seen:
                lk = Link(url=shorten(url, 160), original=shorten(url, 160), scheme=scheme, host="",
                          site="", text=text, source=source)
                _flag(lk, "script-scheme", f"'{scheme}:' link runs code or embeds content instead of "
                                           f"opening a web page")
                lk.risk = FLAG_RISK["script-scheme"]
                seen[key] = lk
                links.append(lk)
            continue
        if scheme not in ("http", "https", "ftp"):
            continue
        backslash = "\\" in url
        if backslash:
            url = url.replace("\\", "/")
        dest, wrapper = unwrap_url(url)
        parts = _split_url(dest)
        if not parts or not parts[1]:
            continue
        sch, host, port, path, query, userinfo = parts
        key = url_key(host, path, query)
        if key in seen:
            existing = seen[key]
            if text and not existing.text:
                existing.text = text
                _check_text_mismatch(existing)
            continue
        lk = Link(url=dest, original=url, scheme=sch, host=host, site=site_domain(host), path=path,
                  query=query, userinfo=userinfo, port=port, text=text, source=source, wrapper=wrapper)
        if backslash:
            _flag(lk, "backslash", "Backslashes in the URL can make browsers and filters disagree "
                                   "about the real host")
        for name, values in parse_qs(query).items():
            if name.lower() in REDIRECT_PARAMS:
                for v in values:
                    if re.match(r"(?i)^https?://", v):
                        target = _split_url(v)
                        if target and target[1] and site_domain(target[1]) != lk.site:
                            _flag(lk, "redirect", f"Redirects to another site: {defang(shorten(v, 80))}")
                            queue.append((v, "", "redirect-target"))
        _score_url_flags(lk)
        _check_text_mismatch(lk)
        seen[key] = lk
        links.append(lk)
    for lk in links:
        lk.risk = round(sum(FLAG_RISK.get(code, 0.2) for code, _ in lk.flags), 2)
    return links


def urls_in_text(text: str) -> list[str]:
    return [_strip_url_token(m.group(0)) for m in _URL_IN_TEXT.finditer(text or "")]


# ============================================================================
# Attachments
# ============================================================================
def sniff_magic(data: bytes) -> str:
    head = data[:16]
    if head.startswith(b"MZ"):
        return "exe"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"Rar!"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if head.startswith(b"\x89PNG"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if head.startswith(b"GIF8"):
        return "gif"
    if head.startswith(b"L\x00\x00\x00"):
        return "lnk"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    sample = data[:2048].lstrip().lower()
    if sample.startswith(b"<svg") or (sample.startswith(b"<?xml") and b"<svg" in sample):
        return "svg"
    if sample.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<form",
                          b"<meta", b"<div", b"<iframe")):
        return "html"
    return ""


_PDF_URI = re.compile(rb"/URI\s*\(([^)]{4,2048})\)")
_SMUGGLING = re.compile(r"atob\s*\(|new\s+Blob\s*\(|msSaveOrOpenBlob|createObjectURL|"
                        r"unescape\s*\(|String\.fromCharCode|eval\s*\(|document\.write\s*\(|"
                        r"window\.location(?:\.href)?\s*=|location\.replace\s*\(", re.I)


def analyze_attachment(filename: str, ctype: str, disp: str, data: bytes,
                       charset: str = "utf-8") -> tuple[Attachment, list[tuple[str, str, str]], dict]:
    """Static checks only -- nothing is opened or executed. Returns (attachment, links, html_stats)."""
    name = filename or "(unnamed)"
    lowered = name.lower().strip()
    ext = lowered.rsplit(".", 1)[-1].strip() if "." in lowered else ""
    magic = sniff_magic(data)
    att = Attachment(filename=name, content_type=ctype, size=len(data), sha256=sha256_hex(data),
                     md5=hashlib.md5(data).hexdigest(), disposition=disp or "", extension=ext, magic=magic)
    links: list[tuple[str, str, str]] = []
    html_stats: dict = {}

    def flag(code: str, detail: str) -> None:
        if not any(f[0] == code for f in att.flags):
            att.flags.append([code, detail])

    if "\u202e" in name or "\u202d" in name:
        flag("rtlo", "Filename hides its real extension with a right-to-left override character")
    if ext in RISKY_EXT_EXEC or magic in ("exe", "lnk"):
        flag("executable", f"Executable or script file type (.{ext or magic}) - can run code when opened")
    if ext in RISKY_EXT_HTML or (magic in ("html", "svg") and ext not in ("txt", "eml")):
        flag("html", "HTML/SVG attachment - opens a local web page that can host a fake login form")
    if ext in RISKY_EXT_MACRO:
        flag("macro", f"Macro-enabled Office document (.{ext})")
    if ext in RISKY_EXT_DISK or magic == "iso":
        flag("disk-image", "Disk image (ISO/IMG/VHD) - used to smuggle files past Mark-of-the-Web protection")
    parts = [p.strip() for p in lowered.split(".")]
    risky_final = RISKY_EXT_EXEC | RISKY_EXT_HTML | RISKY_EXT_MACRO | RISKY_EXT_DISK | ARCHIVE_EXT
    if len(parts) >= 3 and parts[-2] in DECOY_EXT and ext in risky_final:
        flag("double-ext", f"Double extension '.{parts[-2]}.{ext}' disguises the real file type")
    if re.search(r"\s{5,}\.\w+$", name):
        flag("double-ext", "Padding spaces push the real extension out of view")
    mismatch = ""
    if magic == "exe" and ext not in ("exe", "dll", "scr", "com", "sys", "cpl", "msi"):
        mismatch = f"content is a Windows executable but the name ends in .{ext or '(none)'}"
    elif magic in ("html", "svg") and ext in DECOY_EXT:
        mismatch = f"content is {magic.upper()} but the name ends in .{ext}"
    elif ext == "pdf" and data and magic not in ("pdf", ""):
        mismatch = f"named .pdf but content looks like {magic or 'something else'}"
    elif ext in ("docx", "xlsx", "pptx") and data and magic != "zip":
        mismatch = f"named .{ext} but content is not an Office Open XML package"
    if mismatch:
        flag("mismatch", "File type mismatch: " + mismatch)

    if magic == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infos = zf.infolist()[:500]
                att.inner_files = [zi.filename for zi in infos[:25]]
                if any(zi.flag_bits & 0x1 for zi in infos):
                    flag("encrypted-archive", "Password-protected archive - its contents cannot be scanned")
                names = [zi.filename.lower() for zi in infos]
                if any(n.endswith("vbaproject.bin") for n in names):
                    flag("macro", "Office document contains a VBA macro project (vbaProject.bin)")
                inner_risky = [n for n in names if n.rsplit(".", 1)[-1] in
                               RISKY_EXT_EXEC | RISKY_EXT_HTML | RISKY_EXT_DISK | RISKY_EXT_MACRO]
                if inner_risky and ext not in ("docx", "xlsx", "pptx", "docm", "xlsm", "pptm"):
                    flag("archive-risky", "Archive contains risky files: " + ", ".join(inner_risky[:4]))
        except Exception:
            if ext in ARCHIVE_EXT:
                flag("encrypted-archive", "Archive could not be opened (corrupt or unusual encryption)")
    if ext in ARCHIVE_EXT or magic in ("rar", "7z", "gzip"):
        flag("archive", f"Compressed archive (.{ext or magic}) - can hide malicious files from scanners")
    if magic == "ole" and (b"_VBA_PROJECT" in data or b"V\x00B\x00A\x00" in data or b"Macros" in data):
        flag("macro", "Legacy Office document appears to contain VBA macros")
    if magic == "pdf":
        active = [k for k in (b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction", b"/EmbeddedFile",
                              b"/SubmitForm") if k in data]
        if active:
            flag("pdf-active", "PDF contains active content: " + ", ".join(k.decode()[1:] for k in active))
        for m in _PDF_URI.finditer(data[:5_000_000]):
            uri = m.group(1).decode("latin-1", "replace").replace("\\", "")
            links.append((uri, "", f"attachment:{name}"))
    if magic in ("html", "svg") or ext in RISKY_EXT_HTML:
        try:
            text = data.decode(charset or "utf-8", errors="replace")
        except LookupError:
            text = data.decode("utf-8", errors="replace")
        parser = analyze_html(text)
        html_stats = parser.stats()
        for href, anchor_text in parser.anchors:
            links.append((href, anchor_text, f"attachment:{name}"))
        for href, src in parser.other_links:
            links.append((href, "", f"attachment:{name}"))
        for u in urls_in_text(text):
            links.append((u, "", f"attachment:{name}"))
        if html_stats.get("password_forms"):
            flag("credential-form", "Attachment contains a password form (credential-harvesting page)")
        if _SMUGGLING.search(text):
            flag("smuggling", "Obfuscated script (atob/Blob/eval/redirect) typical of HTML smuggling "
                              "and redirect loaders")
    return att, links, html_stats


# ============================================================================
# Email parsing
# ============================================================================
_RCV_FROM = re.compile(r"^\s*from\s+(\S+)(.*?)(?=\bby\b|;|$)", re.I | re.S)
_RCV_BY = re.compile(r"\bby\s+([^\s;()]+)", re.I)
_RCV_WITH = re.compile(r"\bwith\s+([^\s;()]+)", re.I)
_IP_BRACKET = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]{3,45})\]")
_IPV4_ANY = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def _valid_ip(candidate: str) -> str:
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def parse_received(values: list[str]) -> list[Hop]:
    """Received headers are prepended by each server, so the bottom one is hop #1."""
    hops: list[Hop] = []
    total = len(values)
    for idx, value in enumerate(values):
        v = _oneline(value)
        from_host = from_ip = by_host = proto = ""
        m = _RCV_FROM.search(v)
        if m:
            from_host = m.group(1).strip("()[];")
            clause = m.group(1) + " " + m.group(2)
            ip_m = _IP_BRACKET.search(clause)
            if ip_m:
                from_ip = _valid_ip(ip_m.group(1))
            if not from_ip:
                ip4 = _IPV4_ANY.search(clause)
                if ip4:
                    from_ip = _valid_ip(ip4.group(1))
        b = _RCV_BY.search(v)
        if b:
            by_host = b.group(1).strip("()[];")
        w = _RCV_WITH.search(v)
        if w:
            proto = w.group(1)
        ts = ""
        if ";" in v:
            try:
                dt = email.utils.parsedate_to_datetime(v.rsplit(";", 1)[1].strip())
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                ts = dt.isoformat()
            except Exception:
                ts = ""
        hops.append(Hop(number=total - idx, from_host=from_host, from_ip=from_ip, by_host=by_host,
                        protocol=proto, timestamp=ts, delay_s=None, raw=v))
    ordered = sorted(hops, key=lambda h: h.number)
    for prev, cur in zip(ordered, ordered[1:]):
        if prev.timestamp and cur.timestamp:
            try:
                cur.delay_s = (datetime.fromisoformat(cur.timestamp) -
                               datetime.fromisoformat(prev.timestamp)).total_seconds()
            except Exception:
                cur.delay_s = None
    return ordered


def parse_tag_list(value: str) -> dict:
    """Parse 'k=v; k=v' lists (DKIM-Signature, DMARC records)."""
    out: dict[str, str] = {}
    for part in _clean(value).split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().lower()
            out[k] = re.sub(r"\s+", "", v) if k in ("b", "bh", "p") else " ".join(v.split())
    return out


def _addresses(msg: Message, name: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for value in msg.get_all(name) or []:
        try:
            for a in value.addresses:
                if a.addr_spec and "@" in a.addr_spec:
                    out.append((_oneline(a.display_name or ""), _oneline(a.addr_spec).lower()))
        except Exception:
            for dn, addr in email.utils.getaddresses([_clean(value)]):
                if "@" in addr:
                    out.append((_oneline(dn), addr.strip().lower()))
    return out


def _header(msg: Message, name: str) -> str:
    try:
        value = msg.get(name)
    except Exception:
        return ""
    return _oneline(value) if value is not None else ""


def _header_all(msg: Message, name: str) -> list[str]:
    try:
        return [_oneline(v) for v in (msg.get_all(name) or [])]
    except Exception:
        return []


def _domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[1].strip(" >.").lower() if "@" in addr else ""


def _leaf_parts(part: Message, depth: int = 0):
    """Walk MIME leaves, but do NOT descend into attached messages (message/rfc822)."""
    if depth > 25:
        return
    if depth > 0 and part.get_content_type() == "message/rfc822":
        yield part
        return
    if part.is_multipart():
        payload = part.get_payload()
        if isinstance(payload, list):
            for sub in payload:
                if isinstance(sub, Message):
                    yield from _leaf_parts(sub, depth + 1)
        return
    yield part


def _part_text(part: Message) -> str:
    try:
        content = part.get_content()
        if isinstance(content, bytes):
            raise TypeError
        return _clean(content)
    except Exception:
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")


def parse_email(rm: RawMessage) -> ParsedEmail:
    raw = rm.raw.lstrip()
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    pe = ParsedEmail(label=rm.label, source=rm.source, raw_size=len(raw), raw_sha256=sha256_hex(raw))
    try:
        pe.headers = [(_clean(k), _oneline(v)) for k, v in msg.raw_items()]
    except Exception:
        pe.headers = []
    pe.subject = _header(msg, "Subject")
    pe.date_raw = _header(msg, "Date")
    if pe.date_raw:
        try:
            dt = email.utils.parsedate_to_datetime(pe.date_raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            pe.date_dt, pe.date_iso = dt, dt.isoformat()
        except Exception:
            pe.defects.append("Date header could not be parsed")
    pe.message_id = _header(msg, "Message-ID")
    pe.in_reply_to = _header(msg, "In-Reply-To")
    pe.references = _header(msg, "References")
    froms = _addresses(msg, "From")
    pe.from_count = len(froms)
    if froms:
        pe.from_display, pe.from_addr = froms[0]
    else:
        raw_from = _header(msg, "From")
        m = re.search(r"[\w.+'-]+@[\w.-]+", raw_from)
        pe.from_addr = m.group(0).lower() if m else ""
        pe.from_display = raw_from
    pe.from_domain = _domain_of(pe.from_addr)
    sender = _addresses(msg, "Sender")
    pe.sender_addr = sender[0][1] if sender else ""
    pe.reply_to = [a for _, a in _addresses(msg, "Reply-To")]
    rp = _header(msg, "Return-Path")
    m = re.search(r"<([^>]*)>", rp)
    pe.return_path = (m.group(1) if m else rp).strip().lower()
    pe.to = [a for _, a in _addresses(msg, "To")]
    pe.cc = [a for _, a in _addresses(msg, "Cc")]
    pe.x_mailer = _header(msg, "X-Mailer") or _header(msg, "User-Agent")
    pe.list_unsubscribe = bool(_header(msg, "List-Unsubscribe"))
    pe.hops = parse_received(_header_all(msg, "Received"))
    pe.auth_results = _header_all(msg, "Authentication-Results")
    pe.arc_auth_results = _header_all(msg, "ARC-Authentication-Results")
    pe.received_spf = _header_all(msg, "Received-SPF")
    pe.dkim_signatures = [parse_tag_list(v) for v in _header_all(msg, "DKIM-Signature")]
    for defect in getattr(msg, "defects", [])[:10]:
        pe.defects.append(type(defect).__name__)

    text_parts: list[str] = []
    html_parts: list[str] = []
    link_entries: list[tuple[str, str, str]] = []
    html_stats_total: dict = {}
    for part in _leaf_parts(msg):
        try:
            ctype = part.get_content_type()
            disp = part.get_content_disposition() or ""
            try:
                fname = _clean(part.get_filename() or "")
            except Exception:
                fname = ""
            if ctype == "message/rfc822" or (fname.lower().endswith(".eml") and ctype != "text/plain"):
                inner = part.get_payload()
                inner_msg = inner[0] if isinstance(inner, list) and inner else inner
                try:
                    inner_bytes = inner_msg.as_bytes() if isinstance(inner_msg, Message) \
                        else (part.get_payload(decode=True) or b"")
                except Exception:
                    inner_bytes = b""
                if inner_bytes:
                    pe.embedded.append(inner_bytes)
                    att = Attachment(filename=fname or "attached-message.eml", content_type=ctype,
                                     size=len(inner_bytes), sha256=sha256_hex(inner_bytes),
                                     md5=hashlib.md5(inner_bytes).hexdigest(), disposition=disp,
                                     extension="eml", magic="email")
                    att.flags.append(["attached-message", "Contains a complete email message "
                                                          "(analyzed separately in this report)"])
                    pe.attachments.append(att)
                continue
            is_body = ctype in ("text/plain", "text/html") and disp != "attachment" and not fname
            if is_body:
                (text_parts if ctype == "text/plain" else html_parts).append(_part_text(part))
                continue
            data = part.get_payload(decode=True) or b""
            if disp == "inline" and ctype.startswith("image/") and not fname:
                html_stats_total["inline_images"] = html_stats_total.get("inline_images", 0) + 1
                continue
            att, att_links, att_html = analyze_attachment(fname, ctype, disp, data,
                                                          part.get_content_charset() or "utf-8")
            pe.attachments.append(att)
            link_entries.extend(att_links)
            if att_html:
                html_stats_total.setdefault("attachment_html", []).append({"file": att.filename, **att_html})
        except Exception as exc:  # one broken MIME part must not stop the analysis
            pe.defects.append(f"MIME part skipped ({type(exc).__name__}: {shorten(str(exc), 80)})")

    pe.text_plain = "\n\n".join(t for t in text_parts if t.strip())
    pe.text_html = "\n".join(h for h in html_parts if h.strip())
    html_visible = ""
    if pe.text_html:
        parser = analyze_html(pe.text_html)
        html_visible = parser.visible_text()
        html_stats_total.update(parser.stats())
        for href, text in parser.anchors:
            link_entries.append((href, text, "html-a"))
        for href, src in parser.other_links:
            link_entries.append((href, "", src))
        for u in urls_in_text(html_visible):
            link_entries.append((u, "", "html-text"))
        html_stats_total["visible_words"] = len(html_visible.split())
    for u in urls_in_text(pe.text_plain):
        link_entries.append((u, "", "text"))
    pe.visible_text = html_visible if len(html_visible.strip()) >= 20 else (pe.text_plain or html_visible)
    pe.html_stats = html_stats_total
    pe.links = build_links(link_entries)
    return pe


# ============================================================================
# Input loading (EML, MBOX, folders)
# ============================================================================
MBOX_SUFFIXES = {".mbox", ".mbx", ".mbs"}
EMAIL_SUFFIXES = {".eml", ".mbox", ".mbx", ".mbs", ".txt", ".email", ".msg", ""}


def _looks_like_mbox(path: Path, data: bytes) -> bool:
    return path.suffix.lower() in MBOX_SUFFIXES or data[:5] == b"From "


def load_inputs(paths: list[str], max_messages: int = 200) -> tuple[list[RawMessage], list[str]]:
    messages: list[RawMessage] = []
    warnings: list[str] = []
    files: list[Path] = []
    for p in paths:
        path = Path(p).expanduser()
        if path.is_dir():
            found = sorted(f for f in path.rglob("*") if f.is_file() and not f.name.startswith(".")
                           and f.suffix.lower() in EMAIL_SUFFIXES - {""})
            if not found:
                warnings.append(f"No .eml/.mbox files found in folder {path}")
            files.extend(found)
        elif path.is_file():
            files.append(path)
        else:
            warnings.append(f"Input not found: {p}")
    for f in files:
        if len(messages) >= max_messages:
            warnings.append(f"Stopped at --max-messages={max_messages}; remaining input skipped")
            break
        if f.suffix.lower() == ".msg":
            warnings.append(f"{f.name}: Outlook .msg files are not supported - in Outlook on the web use "
                            f"Download (or View > View message source) to get the .eml/raw source")
            continue
        try:
            data = f.read_bytes()
        except OSError as exc:
            warnings.append(f"Cannot read {f}: {exc}")
            continue
        if not data.strip():
            warnings.append(f"{f.name} is empty")
            continue
        if _looks_like_mbox(f, data):
            try:
                box = mailbox.mbox(str(f), create=False)
                try:
                    for i, key in enumerate(box.iterkeys(), 1):
                        if len(messages) >= max_messages:
                            warnings.append(f"Stopped at --max-messages={max_messages}")
                            break
                        messages.append(RawMessage(str(f), f"{f.name} #{i}", box.get_bytes(key)))
                finally:
                    box.close()
            except Exception as exc:
                warnings.append(f"Could not read {f.name} as MBOX ({exc})")
        else:
            if not re.match(rb"\s*[A-Za-z][A-Za-z0-9-]*:", data[:500]):
                warnings.append(f"{f.name} does not start with email headers - skipped")
                continue
            messages.append(RawMessage(str(f), f.name, data))
    return messages, warnings


# ============================================================================
# DNS client: caching, timeouts, resolver fallback, health canary
# ============================================================================
OK, NXDOMAIN, NODATA, TIMEOUT, ERROR, DISABLED = "ok", "nxdomain", "nodata", "timeout", "error", "disabled"


@dataclass
class DNSAnswer:
    status: str
    records: list = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == OK


class DNSClient:
    """Thin dnspython wrapper.

    A timeout is reported as TIMEOUT, never as "no record" -- confusing the two makes a
    slow DNS server look like a domain with no SPF/DMARC (a classic false positive).
    """
    CANARIES = ("google.com", "cloudflare.com")
    PUBLIC = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    def __init__(self, enabled: bool = True, timeout: float = 4.0, nameservers: Optional[list] = None):
        self.enabled = bool(enabled and HAVE_DNS)
        self.timeout = timeout
        self.cache: dict[tuple[str, str], DNSAnswer] = {}
        self.queries = 0
        self.timeouts_in_row = 0
        self.note = ""
        if enabled and not HAVE_DNS:
            self.note = "dnspython is not installed - live DNS checks disabled (pip install dnspython)"
        self._custom_ns = list(nameservers or [])
        self._resolver = self._make_resolver() if self.enabled else None

    def _make_resolver(self, public: bool = False):
        resolver = None
        if not public:
            try:
                resolver = dns.resolver.Resolver()
            except Exception:  # no /etc/resolv.conf, odd Windows registry, sandboxes...
                resolver = None
        if resolver is None:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = list(self.PUBLIC)
        if self._custom_ns:
            resolver.nameservers = list(self._custom_ns)
        resolver.lifetime = self.timeout
        resolver.timeout = min(2.0, self.timeout)
        return resolver

    def _raw(self, name: str, rtype: str) -> DNSAnswer:
        self.queries += 1
        try:
            answer = self._resolver.resolve(name, rtype, lifetime=self.timeout)
        except dns.resolver.NXDOMAIN:
            return DNSAnswer(NXDOMAIN, [], "domain does not exist")
        except dns.resolver.NoAnswer:
            return DNSAnswer(NODATA, [], f"no {rtype} records")
        except dns.exception.Timeout:
            return DNSAnswer(TIMEOUT, [], "DNS query timed out")
        except dns.resolver.NoNameservers:
            return DNSAnswer(ERROR, [], "all DNS servers failed (SERVFAIL)")
        except Exception as exc:  # invalid names, network errors...
            return DNSAnswer(ERROR, [], f"{type(exc).__name__}: {shorten(str(exc), 80)}")
        records: list = []
        for rr in answer:
            try:
                if rtype == "TXT":
                    records.append(b"".join(rr.strings).decode("utf-8", "replace"))
                elif rtype == "MX":
                    records.append((int(rr.preference), rr.exchange.to_text().rstrip(".").lower()))
                elif rtype in ("A", "AAAA"):
                    records.append(rr.address)
                elif rtype == "PTR":
                    records.append(rr.target.to_text().rstrip(".").lower())
                else:
                    records.append(rr.to_text())
            except Exception:
                continue
        return DNSAnswer(OK, records)

    def health_check(self) -> bool:
        """Some networks (captive portals, filtered sandboxes) answer NXDOMAIN for everything.
        Probe well-known names first so that cannot masquerade as 'sender domain does not exist'."""
        if not self.enabled:
            return False
        results = [self._raw(n, "A") for n in self.CANARIES]
        if any(r.ok for r in results):
            return True
        if not self._custom_ns and HAVE_DNS:
            self._resolver = self._make_resolver(public=True)
            results = [self._raw(n, "A") for n in self.CANARIES]
            if any(r.ok for r in results):
                self.note = "System DNS failed the health check; switched to public resolvers (1.1.1.1 / 8.8.8.8)"
                return True
        if all(r.status == NXDOMAIN for r in results):
            why = "the resolver claims well-known domains do not exist (DNS is intercepted or filtered here)"
        else:
            why = "DNS servers are unreachable from this network"
        self.note = (f"Live DNS checks disabled: {why}. Authentication relies on the verdicts recorded "
                     f"in the message headers.")
        self.enabled = False
        return False

    def query(self, name: str, rtype: str) -> DNSAnswer:
        name = (name or "").strip().rstrip(".").lower()
        if not name:
            return DNSAnswer(ERROR, [], "empty name")
        key = (name, rtype)
        if key in self.cache:
            return self.cache[key]
        if not self.enabled:
            return DNSAnswer(DISABLED, [], self.note or "live DNS disabled")
        if self.timeouts_in_row >= 4:
            return DNSAnswer(TIMEOUT, [], "skipped - DNS stopped responding")
        result = self._raw(host_to_ascii(name), rtype)
        if result.status == TIMEOUT:
            self.timeouts_in_row += 1
            if self.timeouts_in_row == 4:
                self.note = "DNS stopped responding during the run; later live lookups were skipped"
        else:
            self.timeouts_in_row = 0
        self.cache[key] = result
        return result


# ============================================================================
# SPF (RFC 7208) evaluator
# ============================================================================
SPF_QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
_SPF_MECH = re.compile(r"^(all|include|a|mx|ptr|exists)(?::([^/]+))?(/\d{1,2})?(//\d{1,3})?$", re.I)
_SPF_MOD = re.compile(r"^([a-z][a-z0-9_.-]*)=(.*)$", re.I)
_SPF_MACRO = re.compile(r"%\{([slodiphcrtvSLODIPHCRTV])(\d*)(r?)([.\-+,/_=]*)\}|%%|%_|%-")


class _SPFStop(Exception):
    def __init__(self, result: str, why: str):
        super().__init__(why)
        self.result, self.why = result, why


class SPFEvaluator:
    """Implements check_host(): ip4/ip6/a/mx/include/exists/ptr/all, redirect=, macros,
    the 10-DNS-lookup limit and the 2-void-lookup limit. Every step is written to a trace
    so the report can show exactly why SPF passed or failed."""
    MAX_LOOKUPS = 10
    MAX_VOID = 2

    def __init__(self, dnsc: DNSClient):
        self.dns = dnsc
        self._lookups = self._void = 0
        self._ctx: dict = {}
        self._top_record = ""

    def check(self, ip: str, mail_from: str, helo: str = "") -> dict:
        out = {"result": "none", "domain": "", "record": "", "trace": [], "lookups": 0,
               "ip": ip, "sender": mail_from, "error": ""}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            out["error"] = f"invalid sending IP '{ip}'"
            return out
        sender = mail_from if "@" in mail_from else f"postmaster@{mail_from}"
        domain = sender.rsplit("@", 1)[1].strip(".").lower()
        out["domain"] = domain
        self._lookups = self._void = 0
        self._top_record = ""
        self._ctx = {"ip": addr, "sender": sender, "helo": helo or domain}
        trace: list[str] = out["trace"]
        trace.append(f"check_host(ip={addr}, sender={sender})")
        try:
            result, _ = self._check_host(domain, trace, 0)
        except _SPFStop as stop:
            result = stop.result
            out["error"] = stop.why
            trace.append(f"-> {stop.result}: {stop.why}")
        out.update(result=result, record=self._top_record, lookups=self._lookups)
        return out

    # -- internals -------------------------------------------------------
    def _check_host(self, domain: str, trace: list, depth: int) -> tuple[str, str]:
        pad = "  " * depth
        if depth > 10:
            raise _SPFStop("permerror", "include/redirect nesting is too deep")
        ans = self.dns.query(domain, "TXT")
        if ans.status in (TIMEOUT, ERROR):
            raise _SPFStop("temperror", f"TXT lookup for {domain} failed ({ans.error})")
        if ans.status == DISABLED:
            raise _SPFStop("none", "live DNS disabled")
        records = [t.strip() for t in ans.records
                   if t.strip().lower() == "v=spf1" or t.strip().lower().startswith("v=spf1 ")]
        if not records:
            trace.append(f"{pad}{domain}: no SPF record")
            return "none", ""
        if len(records) > 1:
            raise _SPFStop("permerror", f"{domain} publishes {len(records)} SPF records (only one allowed)")
        record = " ".join(records[0].split())
        if depth == 0:
            self._top_record = record
        trace.append(f'{pad}{domain}: "{shorten(record, 260)}"')
        redirect = None
        for term in record.split()[1:]:
            mod = _SPF_MOD.match(term)
            if mod:
                if mod.group(1).lower() == "redirect":
                    redirect = mod.group(2)
                continue
            qual, body = "+", term
            if body[:1] in SPF_QUALIFIERS:
                qual, body = body[0], body[1:]
            if self._match(body, domain, trace, depth, pad):
                result = SPF_QUALIFIERS[qual]
                trace.append(f"{pad}  matched '{term}' -> {result}")
                return result, record
        if redirect:
            self._count()
            target = self._expand(redirect, domain)
            trace.append(f"{pad}  redirect={target}")
            result, _ = self._check_host(target, trace, depth + 1)
            if result == "none":
                raise _SPFStop("permerror", f"redirect target {target} has no SPF record")
            return result, record
        trace.append(f"{pad}  no mechanism matched -> neutral")
        return "neutral", record

    def _count(self) -> None:
        self._lookups += 1
        if self._lookups > self.MAX_LOOKUPS:
            raise _SPFStop("permerror", "more than 10 DNS-querying mechanisms (RFC 7208 limit)")

    def _q(self, name: str, rtype: str, count_void: bool = True) -> DNSAnswer:
        ans = self.dns.query(name, rtype)
        if ans.status in (TIMEOUT, ERROR):
            raise _SPFStop("temperror", f"{rtype} lookup for {name} failed ({ans.error})")
        if ans.status in (NXDOMAIN, NODATA) and count_void:
            self._void += 1
            if self._void > self.MAX_VOID:
                raise _SPFStop("permerror", "more than 2 void DNS lookups (RFC 7208 limit)")
        return ans

    def _addr_match(self, name: str, c4: int, c6: int, count_void: bool = True) -> bool:
        ip = self._ctx["ip"]
        ans = self._q(name, "A" if ip.version == 4 else "AAAA", count_void)
        cidr = c4 if ip.version == 4 else c6
        for rec in ans.records:
            try:
                if ip in ipaddress.ip_network(f"{rec}/{cidr}", strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _match(self, body: str, domain: str, trace: list, depth: int, pad: str) -> bool:
        ip = self._ctx["ip"]
        low = body.lower()
        if low.startswith(("ip4:", "ip6:")):
            want = 4 if low.startswith("ip4") else 6
            try:
                net = ipaddress.ip_network(body[4:], strict=False)
            except ValueError:
                raise _SPFStop("permerror", f"invalid network in '{body}'")
            return ip.version == want == net.version and ip in net
        m = _SPF_MECH.match(body)
        if not m:
            raise _SPFStop("permerror", f"unknown SPF mechanism '{body}'")
        mech, arg = m.group(1).lower(), m.group(2)
        c4 = int(m.group(3)[1:]) if m.group(3) else 32
        c6 = int(m.group(4)[2:]) if m.group(4) else 128
        if mech == "all":
            return True
        self._count()
        target = self._expand(arg, domain) if arg else domain
        if mech == "include":
            trace.append(f"{pad}  include:{target}")
            result, _ = self._check_host(target, trace, depth + 1)
            if result == "none":
                raise _SPFStop("permerror", f"included domain {target} has no SPF record")
            return result == "pass"
        if mech == "a":
            return self._addr_match(target, c4, c6)
        if mech == "mx":
            ans = self._q(target, "MX")
            hosts = [h for _, h in sorted(ans.records)][:10]
            return any(self._addr_match(h, c4, c6, count_void=False) for h in hosts if h)
        if mech == "exists":
            return bool(self._q(target, "A").records)
        if mech == "ptr":  # deprecated; DNS errors here mean "no match", not temperror
            try:
                rev = dns.reversename.from_address(str(ip)).to_text().rstrip(".")
            except Exception:
                return False
            for name in self.dns.query(rev, "PTR").records[:10]:
                fwd = self.dns.query(name, "A" if ip.version == 4 else "AAAA")
                if str(ip) in fwd.records and (name == target or name.endswith("." + target)):
                    return True
            return False
        return False

    def _expand(self, spec: str, domain: str) -> str:
        ctx = self._ctx
        ip = ctx["ip"]
        local, _, sender_domain = ctx["sender"].rpartition("@")

        def value(letter: str) -> str:
            letter = letter.lower()
            return {"s": ctx["sender"], "l": local or "postmaster", "o": sender_domain, "d": domain,
                    "i": str(ip) if ip.version == 4 else ".".join(ip.exploded.replace(":", "")),
                    "v": "in-addr" if ip.version == 4 else "ip6", "h": ctx["helo"], "p": "unknown",
                    "c": str(ip), "r": "unknown", "t": str(int(time.time()))}.get(letter, "")

        def repl(m: re.Match) -> str:
            token = m.group(0)
            if token == "%%":
                return "%"
            if token == "%_":
                return " "
            if token == "%-":
                return "%20"
            letter, digits, reverse, delims = m.groups()
            parts = re.split("[" + re.escape(delims or ".") + "]", value(letter))
            if reverse:
                parts.reverse()
            if digits and int(digits) > 0:
                parts = parts[-int(digits):]
            result = ".".join(parts)
            return quote(result, safe="") if letter.isupper() else result

        return _SPF_MACRO.sub(repl, spec).strip(".")


# ============================================================================
# DKIM verification (dkimpy) and DMARC
# ============================================================================
class _DKIMDNSTempError(Exception):
    pass


class _ListLogHandler(logging.Handler):
    """Collects dkimpy's warnings/errors so the report can say WHY a signature failed."""
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.messages.append(record.getMessage())
        except Exception:
            pass


def verify_dkim(raw: bytes, signatures: list[dict], dnsc: DNSClient) -> list[dict]:
    """Cryptographically verify every DKIM-Signature header against the public key in DNS."""
    checks = []
    for tags in signatures:
        checks.append({"domain": tags.get("d", "").lower(), "selector": tags.get("s", ""),
                       "algorithm": tags.get("a", ""), "signed_headers": tags.get("h", ""),
                       "body_length_limit": "l" in tags, "result": "not checked", "reason": ""})
    if not checks:
        return checks
    if not dnsc.enabled:
        for c in checks:
            c["reason"] = "live checks off"
        return checks
    if not HAVE_DKIM:
        for c in checks:
            c["reason"] = "dkimpy not installed (pip install dkimpy)"
        return checks

    handler = _ListLogHandler()
    logger = logging.getLogger(f"{TOOL_NAME}.dkim")
    logger.handlers = [handler]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    def dnsfunc(name, timeout=5):
        qname = name.decode("ascii", "replace") if isinstance(name, bytes) else str(name)
        ans = dnsc.query(qname, "TXT")
        if ans.status in (TIMEOUT, ERROR):
            raise _DKIMDNSTempError(f"key lookup {qname.rstrip('.')} failed ({ans.error})")
        if not ans.ok or not ans.records:
            return None
        keys = [r for r in ans.records if "p=" in r] or ans.records
        return keys[0].encode("utf-8")

    try:
        verifier = dkim.DKIM(raw, logger=logger, timeout=int(max(1, dnsc.timeout)))
    except Exception as exc:
        for c in checks:
            c.update(result="permerror", reason=f"message could not be prepared ({exc})")
        return checks
    for idx, c in enumerate(checks):
        handler.messages.clear()
        try:
            ok = verifier.verify(idx=idx, dnsfunc=dnsfunc)
            c["result"] = "pass" if ok else "fail"
            if not ok:
                errs = handler.messages
                reason = errs[-1] if errs else "signature does not match the signed headers"
                if "missing public key" in reason.lower() or "no key" in reason.lower():
                    c["result"] = "permerror"
                    reason = f"public key not found at {c['selector']}._domainkey.{c['domain']}"
                c["reason"] = shorten(reason, 160)
        except _DKIMDNSTempError as exc:
            c.update(result="temperror", reason=str(exc))
        except Exception as exc:
            msg = str(exc)
            if "body hash mismatch" in msg:
                c.update(result="fail", reason="body hash mismatch - the body changed after signing")
            else:
                c.update(result="permerror" if "format" in type(exc).__name__.lower() else "fail",
                         reason=shorten(f"{type(exc).__name__}: {msg}", 160))
    return checks


def lookup_dmarc(dnsc: DNSClient, from_domain: str) -> dict:
    out = {"status": "not checked", "queried": "", "record": "", "policy": "", "sp": "", "pct": 100,
           "adkim": "r", "aspf": "r", "inherited": False, "error": ""}
    if not from_domain:
        out["status"] = "no From domain"
        return out
    if not dnsc.enabled:
        return out
    for i, dom in enumerate(dict.fromkeys([from_domain, org_domain(from_domain)])):
        name = f"_dmarc.{dom}"
        out["queried"] = name
        ans = dnsc.query(name, "TXT")
        if ans.status in (TIMEOUT, ERROR):
            out.update(status="temperror", error=ans.error)
            return out
        records = [t for t in ans.records if t.strip().lower().startswith("v=dmarc1")]
        if len(records) > 1:
            out.update(status="permerror", error="more than one DMARC record")
            return out
        if records:
            tags = parse_tag_list(records[0])
            out.update(status="found", record=" ".join(records[0].split()),
                       policy=tags.get("p", "").lower(), sp=tags.get("sp", "").lower(),
                       adkim=(tags.get("adkim", "r").lower() or "r")[:1],
                       aspf=(tags.get("aspf", "r").lower() or "r")[:1], inherited=i == 1)
            try:
                out["pct"] = int(tags.get("pct", "100"))
            except ValueError:
                pass
            return out
    out["status"] = "none"
    return out


def aligned(domain_a: str, domain_b: str, mode: str = "r") -> bool:
    a, b = (domain_a or "").lower().strip("."), (domain_b or "").lower().strip(".")
    if not a or not b:
        return False
    return a == b if mode == "s" else org_domain(a) == org_domain(b)


def check_domain_exists(dnsc: DNSClient, domain: str) -> Optional[dict]:
    if not domain or not dnsc.enabled:
        return None
    mx = dnsc.query(domain, "MX")
    if mx.status == NXDOMAIN:
        return {"status": "nxdomain", "detail": f"{domain} does not exist in DNS"}
    if mx.status in (TIMEOUT, ERROR):
        return {"status": "temperror", "detail": mx.error}
    if mx.ok:
        hosts = [h for _, h in sorted(mx.records)]
        if hosts and all(not h for h in hosts):
            return {"status": "null-mx", "detail": f"{domain} publishes a null MX - it accepts no mail"}
        return {"status": "ok", "detail": "MX: " + ", ".join(h for h in hosts[:3] if h)}
    a = dnsc.query(domain, "A")
    if a.ok:
        return {"status": "ok", "detail": "no MX record; mail falls back to the A record"}
    if a.status in (TIMEOUT, ERROR):
        return {"status": "temperror", "detail": a.error}
    return {"status": "no-mail", "detail": f"{domain} has neither MX nor A records - replies cannot be delivered"}


# ============================================================================
# Receipt-time authentication headers (what your mail provider recorded)
# ============================================================================
_AR_METHOD = re.compile(r"(?:^|[;\s])(spf|dkim|dmarc|arc|compauth|iprev|auth|bimi|dkim-atps|smime)"
                        r"\s*=\s*([A-Za-z]+)", re.I)


def parse_auth_results(value: str) -> dict:
    v = _oneline(value)
    out = {"authserv_id": "", "spf": None, "dkim": [], "dmarc": None, "compauth": None, "raw": v}
    first, _, rest = v.partition(";")
    head = re.sub(r"\([^)]*\)", "", first).strip()
    if head and "=" not in head:
        out["authserv_id"] = head.split()[0]
        body = rest
    else:
        body = v
    matches = list(_AR_METHOD.finditer(body))
    for i, m in enumerate(matches):
        end = matches[i + 1].start(1) if i + 1 < len(matches) else len(body)
        seg = body[m.start(1):end]
        method, result = m.group(1).lower(), m.group(2).lower()
        comments = " ".join(re.findall(r"\(([^)]*)\)", seg))
        plain = re.sub(r"\([^)]*\)", " ", seg)
        props = {k.lower(): val.strip('"').rstrip(";") for k, val in
                 re.findall(r"\b([a-z]+\.[a-z0-9_-]+|action|reason)\s*=\s*(\"[^\"]*\"|[^\s;]+)", plain, re.I)}
        if method == "spf":
            ip_m = re.search(r"(?:designates|sender IP is|client-ip[=:]?)\s*\[?([0-9a-fA-F:.]{7,45})",
                             comments + " " + plain, re.I)
            out["spf"] = {"result": result, "mailfrom": props.get("smtp.mailfrom", "").lower(),
                          "ip": _valid_ip(ip_m.group(1).strip(".")) if ip_m else "", "comment": comments}
        elif method == "dkim":
            d = props.get("header.d", "") or props.get("header.i", "").lstrip("@").split("@")[-1]
            out["dkim"].append({"result": result, "domain": d.lower(), "selector": props.get("header.s", ""),
                                "comment": comments})
        elif method == "dmarc":
            pm = re.search(r"\bp=([a-z]+)", comments, re.I)
            policy = pm.group(1).lower() if pm else props.get("action", "").lower()
            out["dmarc"] = {"result": result, "header_from": props.get("header.from", "").lower(),
                            "policy": policy, "comment": comments}
        elif method == "compauth":
            out["compauth"] = {"result": result, "reason": props.get("reason", "")}
    return out


def parse_received_spf(value: str) -> Optional[dict]:
    v = _oneline(value)
    m = re.match(r"(pass|fail|softfail|neutral|none|temperror|permerror)\b", v, re.I)
    if not m:
        return None
    ip = re.search(r"client-ip=([0-9a-fA-F:.]+)", v)
    env = re.search(r"envelope-from=\"?<?([^\s;>\"]+)", v)
    return {"result": m.group(1).lower(), "mailfrom": env.group(1).lower() if env else "",
            "ip": _valid_ip(ip.group(1)) if ip else "", "comment": shorten(v, 200)}


def parse_recorded_auth(pe: ParsedEmail) -> dict:
    """Use the TOPMOST Authentication-Results header: it was added by your own mail system.
    Lower ones were added before delivery and could have been forged by the sender."""
    out = {"present": False, "authserv_id": "", "spf": None, "dkim": [], "dmarc": None,
           "compauth": None, "source": "", "ignored": 0, "raw": []}
    if pe.auth_results:
        first = parse_auth_results(pe.auth_results[0])
        group = [first]
        for v in pe.auth_results[1:]:
            parsed = parse_auth_results(v)
            if parsed["authserv_id"] == first["authserv_id"]:
                group.append(parsed)
            else:
                out["ignored"] += 1
        out["authserv_id"] = first["authserv_id"]
        for parsed in group:
            out["spf"] = out["spf"] or parsed["spf"]
            out["dkim"].extend(parsed["dkim"])
            out["dmarc"] = out["dmarc"] or parsed["dmarc"]
            out["compauth"] = out["compauth"] or parsed["compauth"]
            out["raw"].append(parsed["raw"])
        out["source"] = "Authentication-Results"
    if not out["spf"] and pe.received_spf:
        rs = parse_received_spf(pe.received_spf[0])
        if rs:
            out["spf"] = rs
            out["source"] = out["source"] or "Received-SPF"
    out["present"] = bool(out["spf"] or out["dkim"] or out["dmarc"])
    return out


@dataclass
class AuthSummary:
    recorded: dict
    origin_ip: str = ""
    origin_ip_source: str = ""
    helo: str = ""
    mail_from: str = ""
    mail_from_source: str = ""
    live_enabled: bool = False
    live_note: str = ""
    spf_live: Optional[dict] = None
    dkim_live: list = field(default_factory=list)
    dmarc_record: Optional[dict] = None
    dmarc_live: str = ""
    domain_check: Optional[dict] = None
    alignment: dict = field(default_factory=dict)
    effective: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)


def _origin(pe: ParsedEmail, recorded: dict) -> tuple[str, str, str]:
    """(sending IP, where it came from, HELO name). Prefers what the receiver recorded."""
    helo = chain_ip = chain_src = ""
    for hop in sorted(pe.hops, key=lambda h: -h.number):          # walk from the top (receiver) down
        if hop.from_ip and not is_internal_ip(hop.from_ip):
            if org_domain(hop.from_host) == org_domain(hop.by_host) and \
                    org_domain(hop.by_host) in ("outlook.com", "office365.com"):
                continue                                             # Microsoft 365 internal relay
            helo, chain_ip, chain_src = hop.from_host, hop.from_ip, f"Received header (hop {hop.number})"
            break
    for v in pe.received_spf:
        m = re.search(r"client-ip=([0-9a-fA-F:.]+)", v)
        if m and _valid_ip(m.group(1)):
            hm = re.search(r"helo=\"?([^\s;\"]+)", v)
            return _valid_ip(m.group(1)), "Received-SPF header", (hm.group(1) if hm else helo)
    spf = recorded.get("spf") or {}
    if spf.get("ip"):
        return spf["ip"], "Authentication-Results header", helo
    return chain_ip, chain_src, helo


def _mail_from(pe: ParsedEmail, recorded: dict, helo: str) -> tuple[str, str]:
    if pe.return_path and "@" in pe.return_path:
        return pe.return_path, "Return-Path header"
    spf = recorded.get("spf") or {}
    if spf.get("mailfrom"):
        mf = spf["mailfrom"]
        return mf, "Authentication-Results (smtp.mailfrom)"
    if pe.return_path in ("", "<>") and helo and "." in helo and pe.hops:
        return f"postmaster@{helo}", "HELO name (null envelope sender)"
    if pe.from_addr:
        return pe.from_addr, "From header (no envelope information available)"
    return "", ""


def evaluate_auth(pe: ParsedEmail, raw: bytes, dnsc: DNSClient, spf_eval: SPFEvaluator) -> AuthSummary:
    recorded = parse_recorded_auth(pe)
    auth = AuthSummary(recorded=recorded)
    auth.origin_ip, auth.origin_ip_source, auth.helo = _origin(pe, recorded)
    auth.mail_from, auth.mail_from_source = _mail_from(pe, recorded, auth.helo)
    auth.live_enabled = dnsc.enabled
    if recorded["present"]:
        who = recorded["authserv_id"] or "the receiving mail system"
        auth.notes.append(f"Delivery-time verdicts come from {who} ({recorded['source']}, topmost header).")
        if recorded["ignored"]:
            auth.notes.append(f"{recorded['ignored']} lower Authentication-Results header(s) from other "
                              f"systems were ignored - senders can forge those.")
    else:
        auth.notes.append("No Authentication-Results header: the message was exported without delivery "
                          "metadata, so authentication relies on live checks only.")
    if pe.arc_auth_results:
        auth.notes.append("ARC headers present - the message passed through a forwarder or mailing list.")

    if dnsc.enabled:
        if auth.origin_ip and auth.mail_from:
            auth.spf_live = spf_eval.check(auth.origin_ip, auth.mail_from, auth.helo)
        else:
            auth.notes.append("SPF not re-checked live: the sending IP or envelope sender is unknown.")
        auth.dmarc_record = lookup_dmarc(dnsc, pe.from_domain)
        auth.domain_check = check_domain_exists(dnsc, pe.from_domain)
    else:
        auth.live_note = dnsc.note or "Live DNS checks are off (offline mode)."
    auth.dkim_live = verify_dkim(raw, pe.dkim_signatures, dnsc)

    # ---- effective verdicts: delivery-time results first, live checks as fallback ----
    from_dom = pe.from_domain
    dm = auth.dmarc_record or {}
    adkim, aspf = dm.get("adkim", "r"), dm.get("aspf", "r")
    rec_spf = recorded.get("spf")
    if rec_spf:
        spf_r, spf_src = rec_spf["result"], "recorded"
        spf_domain = _domain_of(rec_spf["mailfrom"]) or rec_spf["mailfrom"] or _domain_of(auth.mail_from)
    elif auth.spf_live:
        spf_r, spf_src, spf_domain = auth.spf_live["result"], "live", auth.spf_live["domain"]
    else:
        spf_r, spf_src, spf_domain = "unknown", "", _domain_of(auth.mail_from)

    if recorded.get("dkim"):
        results = [d["result"] for d in recorded["dkim"]]
        passing = [d["domain"] for d in recorded["dkim"] if d["result"] == "pass"]
        dkim_r = "pass" if passing else "fail" if any(r in ("fail", "permerror", "policy") for r in results) \
            else results[0]
        dkim_src = "recorded"
    elif any(c["result"] != "not checked" for c in auth.dkim_live):
        passing = [c["domain"] for c in auth.dkim_live if c["result"] == "pass"]
        results = [c["result"] for c in auth.dkim_live]
        dkim_r = "pass" if passing else "temperror" if all(r == "temperror" for r in results) else "fail"
        dkim_src = "live"
    elif pe.dkim_signatures:
        passing, dkim_r, dkim_src = [], "unverified", ""
    else:
        passing, dkim_r, dkim_src = [], "none", "headers"

    spf_aligned = None if spf_r == "unknown" else (spf_r == "pass" and aligned(spf_domain, from_dom, aspf))
    dkim_aligned = None if dkim_r == "unverified" else any(aligned(d, from_dom, adkim) for d in passing)
    auth.alignment = {"spf": spf_aligned, "dkim": dkim_aligned, "spf_domain": spf_domain,
                      "dkim_domains": passing, "adkim": adkim, "aspf": aspf}

    rec_dmarc = recorded.get("dmarc")
    policy = ""
    if rec_dmarc:
        dmarc_r, dmarc_src, policy = rec_dmarc["result"], "recorded", rec_dmarc.get("policy", "")
    elif dm.get("status") == "found":
        dmarc_r = "pass" if (spf_aligned or dkim_aligned) else "fail"
        dmarc_src = "computed (live policy + " + ("recorded" if recorded["present"] else "live") + " SPF/DKIM)"
    elif dm.get("status") == "none":
        dmarc_r, dmarc_src = "none", "live"
    else:
        dmarc_r, dmarc_src = "unknown", ""
    if dm.get("status") == "found":
        policy = policy or (dm["sp"] if dm["inherited"] and dm["sp"] else dm["policy"])
        live_spf_ok = bool(auth.spf_live and auth.spf_live["result"] == "pass" and
                           aligned(auth.spf_live["domain"], from_dom, aspf))
        live_dkim_ok = any(c["result"] == "pass" and aligned(c["domain"], from_dom, adkim) for c in auth.dkim_live)
        auth.dmarc_live = "pass" if (live_spf_ok or live_dkim_ok) else "fail"
    elif dm.get("status") == "none":
        auth.dmarc_live = "none"
    auth.effective = {"spf": spf_r, "spf_source": spf_src, "dkim": dkim_r, "dkim_source": dkim_src,
                      "dmarc": dmarc_r, "dmarc_source": dmarc_src, "policy": policy}

    # ---- explain disagreements between delivery-time and live results ----
    if recorded.get("dkim") and any(d["result"] == "pass" for d in recorded["dkim"]):
        live_fail = [c for c in auth.dkim_live if c["result"] in ("fail", "permerror")]
        if live_fail:
            auth.notes.append("Live DKIM re-check failed (" + live_fail[0]["reason"] + ") although it passed "
                              "at delivery. That is normal for copied/forwarded messages or rotated keys, so "
                              "the delivery-time result is used.")
    if rec_spf and auth.spf_live and auth.spf_live["result"] != rec_spf["result"] and \
            auth.spf_live["result"] not in ("temperror",):
        auth.notes.append(f"SPF today evaluates to '{auth.spf_live['result']}' (delivery-time: "
                          f"'{rec_spf['result']}'); DNS records may have changed since delivery.")
    return auth


# ============================================================================
# Threat intelligence: public phishing feed + local blocklists + VirusTotal
# ============================================================================
PUBLIC_FEEDS = {
    "openphish": {
        "name": "OpenPhish Community Feed",
        "urls": ["https://openphish.com/feed.txt",
                 "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt"],
        "terms": "free for non-commercial use, refreshed about every 12 hours",
    },
}


def default_cache_dir() -> Path:
    env = os.environ.get("PHISH_DETECTOR_CACHE")
    return Path(env) if env else Path.home() / ".cache" / TOOL_NAME


def http_get(url: str, timeout: float = 20, headers: Optional[dict] = None) -> tuple[int, bytes, str]:
    hdrs = {"User-Agent": USER_AGENT}
    hdrs.update(headers or {})
    if HAVE_REQUESTS:
        try:
            resp = requests.get(url, headers=hdrs, timeout=timeout)
            return resp.status_code, resp.content, ""
        except Exception as exc:
            return 0, b"", f"{type(exc).__name__}: {shorten(str(exc), 100)}"
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=hdrs), timeout=timeout) as resp:
            return resp.status, resp.read(), ""
    except urllib.error.HTTPError as exc:
        return exc.code, b"", f"HTTP {exc.code}"
    except Exception as exc:
        return 0, b"", f"{type(exc).__name__}: {shorten(str(exc), 100)}"


def _age(path: Path) -> str:
    try:
        hours = (time.time() - path.stat().st_mtime) / 3600
    except OSError:
        return "unknown age"
    return f"{hours * 60:.0f} min old" if hours < 1 else f"{hours:.1f} h old"


class ThreatFeeds:
    """Downloads/caches public feeds and indexes them for exact, path, host and domain matches."""
    RANK = {"exact": 4, "path": 3, "host": 2, "domain": 1}

    def __init__(self, use_public: bool = True, feed_files: tuple = (), cache_dir: Optional[str] = None,
                 ttl_hours: float = 6.0, timeout: float = 20):
        self.use_public = use_public
        self.feed_files = [Path(f) for f in feed_files]
        self.cache_dir = Path(cache_dir) if cache_dir else default_cache_dir()
        self.ttl = ttl_hours * 3600
        self.timeout = timeout
        self.feeds: list[dict] = []

    def load(self) -> list[dict]:
        if self.use_public:
            for key, meta in PUBLIC_FEEDS.items():
                self._load_public(key, meta)
        for path in self.feed_files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                self._index(f"Local blocklist ({path.name})", text, str(path), "user supplied")
            except OSError as exc:
                self.feeds.append({"name": f"Local blocklist ({path.name})", "status": "unavailable",
                                   "count": 0, "source": str(path), "terms": "", "note": str(exc)})
        return self.status()

    def _load_public(self, key: str, meta: dict) -> None:
        cache = self.cache_dir / f"{key}_feed.txt"
        text, source, note = None, "", ""
        if cache.exists() and time.time() - cache.stat().st_mtime < self.ttl:
            text, source = cache.read_text(encoding="utf-8", errors="replace"), f"local cache ({_age(cache)})"
        else:
            for url in meta["urls"]:
                code, body, err = http_get(url, self.timeout)
                if code == 200 and b"http" in body[:4096]:
                    text, source = body.decode("utf-8", "replace"), url
                    try:
                        self.cache_dir.mkdir(parents=True, exist_ok=True)
                        cache.write_text(text, encoding="utf-8")
                    except OSError:
                        pass
                    break
                note = (note + "; " if note else "") + f"{urlsplit(url).hostname}: {err or f'HTTP {code}'}"
            if text is None and cache.exists():
                text = cache.read_text(encoding="utf-8", errors="replace")
                source = f"stale local cache ({_age(cache)}) - download failed"
        if text is None:
            self.feeds.append({"name": meta["name"], "status": "unavailable", "count": 0, "source": "",
                               "terms": meta["terms"], "note": note or "download failed"})
            return
        self._index(meta["name"], text, source, meta["terms"])

    def _index(self, name: str, text: str, source: str, terms: str) -> None:
        feed = {"name": name, "status": "loaded", "count": 0, "source": source, "terms": terms, "note": "",
                "exact": set(), "by_host": {}, "hosts": set(), "sites": {}}
        for line in text.splitlines():
            entry = line.strip()
            if not entry or entry.startswith(("#", ";", "//", "!")):
                continue
            entry = entry.split()[0]
            if "://" in entry or "/" in entry:
                if "://" not in entry:
                    entry = "http://" + entry
                parts = _split_url(entry)
                if not parts or not parts[1]:
                    continue
                _, host, _, path, query, _ = parts
                host = host_to_ascii(host)
                key = url_key(host, path, query)
                feed["exact"].add(key)
                feed["by_host"].setdefault(host, []).append(key)
            else:
                host = host_to_ascii(entry.lower().strip(".").removeprefix("*."))
                if not host:
                    continue
                feed["hosts"].add(host)
            feed["sites"].setdefault(site_domain(host), host)
            feed["count"] += 1
        self.feeds.append(feed)

    @staticmethod
    def _shared(site: str, host: str) -> bool:
        if site in SHARED_PLATFORM_SITES or org_domain(host) in SHARED_PLATFORM_SITES:
            return True
        return any(site == s or site.endswith("." + s) for s in FREE_HOSTING_SUFFIXES)

    def check(self, link: Link) -> Optional[dict]:
        if not link.host or not self.feeds:
            return None
        host = host_to_ascii(link.host)
        key = url_key(host, link.path, link.query)
        site = link.site
        big_platform = site in SHARED_PLATFORM_SITES or org_domain(host) in SHARED_PLATFORM_SITES
        best = None
        for feed in self.feeds:
            if feed.get("status") != "loaded":
                continue
            hit = None
            if key in feed["exact"]:
                hit = ("exact", key)
            else:
                for k in feed["by_host"].get(host, []):
                    if key.startswith(k + "/") or key.startswith(k + "?"):
                        hit = ("path", k)
                        break
                if not hit and not big_platform and (host in feed["by_host"] or host in feed["hosts"]):
                    hit = ("host", feed["by_host"].get(host, [host])[0])
                if not hit and not self._shared(site, host):
                    if site in feed["sites"] or site in feed["hosts"]:
                        hit = ("domain", feed["sites"].get(site, site))
            if hit and (best is None or self.RANK[hit[0]] > self.RANK[best["match"]]):
                best = {"feed": feed["name"], "match": hit[0], "entry": hit[1]}
        return best

    def status(self) -> list[dict]:
        return [{k: v for k, v in f.items() if k in ("name", "status", "count", "source", "terms", "note")}
                for f in self.feeds]


class VirusTotalClient:
    """VirusTotal API v3 lookups (reports only -- nothing is uploaded or submitted).
    Free tier: 4 requests/minute and 500/day, so calls are paced and cached for 24 h."""
    API = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, max_urls: int = 4, max_files: int = 2, max_total: int = 40,
                 interval: float = 15.5, cache_dir: Optional[str] = None, timeout: float = 25):
        self.key = (api_key or "").strip()
        self.enabled = bool(self.key)
        self.max_urls, self.max_files, self.max_total = max_urls, max_files, max_total
        self.interval, self.timeout = interval, timeout
        self.calls = 0
        self.cache_hits = 0
        self.stopped = ""
        self._last = 0.0
        self._mem: dict[str, dict] = {}
        self.cache_path = (Path(cache_dir) if cache_dir else default_cache_dir()) / "virustotal_cache.json"
        try:
            self._cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            self._cache = {}

    def save_cache(self) -> None:
        try:
            cutoff = time.time() - 7 * 86400
            data = {k: v for k, v in self._cache.items() if v.get("ts", 0) > cutoff}
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(data), encoding="utf-8")
        except Exception:
            pass

    def _request(self, path: str) -> tuple[Optional[dict], str]:
        if self.stopped:
            return None, self.stopped
        if self.calls >= self.max_total:
            self.stopped = f"per-run limit of {self.max_total} lookups reached"
            return None, self.stopped
        wait = self.interval - (time.time() - self._last)
        if self._last and wait > 0:
            CON.info(f"VirusTotal free tier = 4 lookups/minute; waiting {wait:.0f}s ...")
            time.sleep(wait)
        code, body, err = http_get(self.API + path, self.timeout, {"x-apikey": self.key,
                                                                  "accept": "application/json"})
        self._last = time.time()
        self.calls += 1
        if code == 200:
            try:
                return json.loads(body.decode("utf-8")), ""
            except ValueError:
                return None, "unreadable response"
        if code == 404:
            return {"__not_found__": True}, ""
        if code in (401, 403):
            self.stopped = "API key rejected - check VT_API_KEY"
        elif code == 429:
            self.stopped = "quota exceeded (free tier: 4/minute, 500/day)"
        elif code == 0:
            self.stopped = f"network error ({err})"
        else:
            return None, f"HTTP {code}"
        return None, self.stopped

    @staticmethod
    def _summarize(data: dict, gui: str) -> dict:
        if data.get("__not_found__"):
            return {"status": "not found", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
                    "engines": [], "last_analysis": "", "gui": gui}
        obj = data.get("data", {})
        attrs = obj.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        results = attrs.get("last_analysis_results", {}) or {}
        flagged = sorted(f"{eng}: {res.get('result') or res.get('category')}" for eng, res in results.items()
                         if isinstance(res, dict) and res.get("category") in ("malicious", "suspicious"))
        ts = attrs.get("last_analysis_date")
        return {"status": "found", "malicious": int(stats.get("malicious", 0) or 0),
                "suspicious": int(stats.get("suspicious", 0) or 0),
                "harmless": int(stats.get("harmless", 0) or 0),
                "undetected": int(stats.get("undetected", 0) or 0), "engines": flagged[:8],
                "last_analysis": datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d") if ts else "",
                "reputation": attrs.get("reputation"), "gui": gui}

    def _lookup(self, cache_key: str, path: str, gui: str, gui_from_id: str) -> dict:
        if cache_key in self._mem:
            return self._mem[cache_key]
        cached = self._cache.get(cache_key)
        if cached and time.time() - cached.get("ts", 0) < 86400:
            self.cache_hits += 1
            res = dict(cached["result"], cached=True)
        else:
            data, err = self._request(path)
            if data is None:
                res = {"status": "error", "error": err, "gui": gui}
            else:
                if not data.get("__not_found__") and data.get("data", {}).get("id") and gui_from_id:
                    gui = gui_from_id + data["data"]["id"]
                res = self._summarize(data, gui)
                self._cache[cache_key] = {"ts": time.time(), "result": res}
        self._mem[cache_key] = res
        return res

    def url_report(self, url: str) -> dict:
        vid = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        return self._lookup("url:" + url, f"/urls/{vid}",
                            "https://www.virustotal.com/gui/search/" + quote(url, safe=""),
                            "https://www.virustotal.com/gui/url/")

    def file_report(self, sha256: str) -> dict:
        return self._lookup("file:" + sha256, f"/files/{sha256}",
                            "https://www.virustotal.com/gui/file/" + sha256, "")

    def status(self) -> dict:
        return {"enabled": self.enabled, "calls": self.calls, "cache_hits": self.cache_hits,
                "stopped": self.stopped}


# ============================================================================
# NLP-lite: phrase lexicons + simple text statistics
# ============================================================================
LEXICON: dict[str, list[str]] = {
    "urgency": [
        r"\burgent(?:ly)?\b", r"\bimmediate(?:ly)?\b", r"as soon as possible", r"\basap\b",
        r"within (?:the next )?(?:\d+|one|two|three|twenty[- ]four|forty[- ]eight) (?:hours?|hrs?|days?)",
        r"\b(?:expires?|expiring|expiration) (?:today|tonight|soon|in \d+)", r"final (?:notice|warning|reminder)",
        r"last (?:chance|warning|notice|reminder)", r"action (?:is )?required", r"immediate action",
        r"time[- ]sensitive", r"respond (?:now|immediately|today)", r"right away", r"don'?t delay",
        r"limited time", r"\bact now\b", r"\bdeadline\b", r"today only", r"before it'?s too late",
    ],
    "threat": [
        r"\bsuspend(?:ed|sion)?\b",
        r"(?:account|access|mailbox|card)\s+(?:has been |have been |is |was |will be )?(?:temporarily )?"
        r"(?:locked|disabled|deactivated|restricted|limited|blocked|on hold)",
        r"\bterminat(?:ed|ion)\b", r"unauthori[sz]ed (?:access|activity|login|transaction|sign-?in|charge)",
        r"unusual (?:activity|sign-?in|login|transaction)", r"suspicious (?:activity|sign-?in|login|transaction)",
        r"security (?:alert|breach|warning|issue)", r"(?:has been|was|were) compromised", r"legal action",
        r"\bpenalt(?:y|ies)\b", r"\barrest(?:ed)?\b", r"\blawsuit\b",
        r"permanently (?:deleted|closed|removed|disabled|suspended)", r"lose (?:access|all)",
        r"will be (?:closed|deleted|deactivated|suspended|blocked|disabled|returned)",
        r"failure to (?:comply|respond|verify|update|confirm|act)",
    ],
    "credential": [
        r"verify (?:your )?(?:account|identity|information|details|email|login|mailbox)",
        r"confirm (?:your )?(?:account|identity|password|information|details|email|credentials|login)",
        r"update (?:your )?(?:payment|billing|account|banking|card|delivery) (?:information|details|method|info)",
        r"(?:re-?)?enter (?:your )?(?:password|credentials|login|details)",
        r"(?:log|sign) ?(?:in|on) to (?:your )?(?:account|portal|mailbox)", r"reset your password",
        r"password (?:expir\w*|reset|will expire)", r"(?:keep|retain) (?:your )?(?:current |same )?password",
        r"validate (?:your )?(?:account|mailbox|email|credentials)", r"social security|\bssn\b",
        r"(?:one[- ]time|verification|security|authentication) (?:code|passcode|pin)",
        r"\bmfa\b|two[- ]factor|\b2fa\b", r"mailbox (?:is )?(?:full|quota|storage)", r"\bcredentials?\b",
    ],
    "financial": [
        r"\binvoice\b", r"payment (?:due|failed|declined|pending|required|overdue|information)",
        r"\bwire transfer\b", r"bank (?:transfer|account|details)", r"\brefund\b", r"\boverdue\b",
        r"outstanding (?:balance|invoice|payment)", r"\bbitcoin\b|\bcrypto(?:currency)?\b|\bbtc\b|\busdt\b",
        r"\btax (?:refund|return)\b", r"\bpayroll\b", r"direct deposit", r"\bw-?2\b", r"\bremittance\b",
        r"purchase order", r"(?:redelivery|processing|customs|shipping) fee",
    ],
    "reward": [
        r"\bcongratulations\b", r"you(?:'ve| have)? won\b(?!')", r"\bwinner\b", r"\bprize\b", r"\blottery\b",
        r"claim (?:your|the|now)", r"\breward\b", r"\binheritance\b", r"\bmillion (?:dollars|usd)\b",
        r"you(?:'ve| have) been selected", r"exclusive (?:offer|deal)", r"cash prize", r"free (?:gift|iphone|money)",
    ],
    "greeting": [
        r"^\s*(?:dear|hello|hi|greetings),? (?:valued |dear )?(?:customer|user|client|member|account ?holder|"
        r"sir(?:/madam)?|madam|beneficiary|friend|email user|webmail user|subscriber|employee|staff|"
        r"colleague|recipient|applicant|student)\b",
        r"^\s*dear [\w.+-]+@[\w.-]+",
    ],
    "cta": [
        r"click (?:here|below|the (?:link|button)|on the link)", r"follow the (?:link|instructions below)",
        r"open the attach(?:ed|ment)", r"download (?:the )?(?:attachment|document|file|invoice)",
        r"(?:view|review|access|open) (?:the |your )?(?:document|file|invoice|message|voicemail|statement)",
        r"scan (?:the )?qr code", r"tap (?:here|below)", r"(?:verify|confirm|update|log ?in|sign ?in) now",
    ],
    "bec": [
        r"are you (?:available|at your desk|in the office|around)", r"(?:quick|small) (?:favou?r|task|request)",
        r"\bi need you to\b", r"keep (?:this|it) (?:confidential|between us|private)", r"\bdiscreet(?:ly)?\b",
        r"(?:i'?m|i am) (?:in a meeting|tied up|unavailable|traveling)", r"can'?t (?:talk|take calls)",
        r"reply (?:with|to me) (?:your )?(?:cell|phone|number)", r"\btext me\b", r"\bkindly\b",
        r"(?:send|share) (?:me )?(?:the )?(?:codes?|pictures? of)",
    ],
    "gift_card": [
        r"gift ?cards?", r"(?:itunes|apple|google play|amazon|steam|ebay|walmart|target|visa) (?:gift )?cards?",
        r"scratch (?:off )?the (?:back|card)", r"(?:card|redemption) codes?",
    ],
}
_LEX_RX = {cat: [re.compile(p, re.I | re.M) for p in pats] for cat, pats in LEXICON.items()}
STOPWORDS = set("""a about above after again against all also am an and any are as at be because been before
being below between both but by can could did do does doing down during each few for from further had has have
having he her here hers him his how i if in into is it its itself just me more most my no nor not now of off on
once only or other our ours out over own same she should so some such than that the their theirs them then there
these they this those through to too under until up very was we were what when where which while who whom why
will with would you your yours yourself please thank thanks dear hello regards team email message""".split())


def nlp_analyze(pe: ParsedEmail) -> dict:
    body = (pe.visible_text or "")[:60000]
    text = (pe.subject or "") + "\n" + body
    hits: dict[str, list[str]] = {}
    for cat, patterns in _LEX_RX.items():
        found: list[str] = []
        source = body if cat == "greeting" else text
        for rx in patterns:
            m = rx.search(source)
            if m:
                phrase = " ".join(m.group(0).split()).strip(" ,.:;")
                if phrase and phrase.lower() not in (f.lower() for f in found):
                    found.append(phrase)
        hits[cat] = found
    words = re.findall(r"[A-Za-z][A-Za-z'-]*", body)
    wc = len(words)
    caps = [w for w in words if len(w) >= 3 and w.isupper()]
    content_words = [w.lower() for w in words if len(w) > 3 and w.lower() not in STOPWORDS]
    stats = {
        "words": wc, "unique_words": len({w.lower() for w in words}),
        "sentences": max(1, len(re.findall(r"[.!?]+(?:\s|$)", body))) if wc else 0,
        "avg_word_length": round(sum(map(len, words)) / wc, 1) if wc else 0,
        "caps_ratio": round(len(caps) / wc, 3) if wc else 0.0, "caps_words": caps[:8],
        "exclamations": text.count("!"), "links": len(pe.links),
        "link_density": round(len(pe.links) / max(1, wc) * 100, 1),
        "top_terms": Counter(content_words).most_common(10),
    }
    return {"hits": hits, "stats": stats}


# ============================================================================
# Feature catalogue: (category, title, why it matters)
# Weights are log-odds contributions; the report shows them x10 as "points".
# ============================================================================
FEATURE_INFO: dict[str, tuple[str, str, str]] = {
    "auth.dmarc_fail": ("Authentication", "DMARC failed for the From domain",
                        "The From domain publishes a DMARC policy, but neither SPF nor DKIM produced a pass aligned "
                        "with it. That is what a spoofed sender looks like."),
    "auth.spf_fail": ("Authentication", "SPF failed",
                      "The server that delivered the message is explicitly not allowed to send for the envelope domain."),
    "auth.spf_softfail": ("Authentication", "SPF soft-failed",
                          "The envelope domain marks this sending server as probably not authorized (~all)."),
    "auth.dkim_fail": ("Authentication", "DKIM signature did not verify",
                       "A DKIM signature is present but invalid: the message was altered after signing, the signature "
                       "is forged, or the signing key is missing."),
    "auth.unauthenticated": ("Authentication", "No successful SPF or DKIM authentication",
                             "Nothing ties this message to the domain it claims to come from."),
    "auth.no_dmarc": ("Authentication", "From domain publishes no DMARC policy",
                      "Without DMARC, receivers have no rule for rejecting forged mail from this domain. Throwaway "
                      "phishing domains rarely publish one."),
    "auth.compauth_fail": ("Authentication", "Microsoft 365 composite authentication failed",
                           "Microsoft's combined verdict (SPF, DKIM, DMARC and sender reputation) for this message was "
                           "'fail'."),
    "auth.domain_missing": ("Sender", "Sender domain cannot receive mail",
                            "The From domain does not exist or has no mail servers, so replies go nowhere - typical of "
                            "spoofed or disposable domains."),
    "auth.dmarc_pass": ("Authentication", "DMARC passed (aligned SPF or DKIM)",
                        "The From domain is authenticated. This lowers risk but is not proof of safety: attackers "
                        "authenticate their own look-alike domains and hijacked accounts."),
    "hdr.sender_lookalike": ("Sender", "Sender domain imitates a brand",
                             "The From address uses a domain built to resemble a well-known brand."),
    "hdr.brand_display": ("Sender", "Display name impersonates a brand",
                          "The name you see claims to be a known company, but the address behind it belongs to an "
                          "unrelated domain."),
    "hdr.display_email_mismatch": ("Sender", "Display name shows a different email address",
                                   "An address inside the display name makes mail apps show a trusted address while the "
                                   "real sender is someone else."),
    "hdr.replyto_mismatch": ("Sender", "Replies go to a different domain",
                             "Your reply would go to a different organization than the visible sender - a common way "
                             "to take over the conversation."),
    "hdr.freemail_org": ("Sender", "Free webmail account posing as an organization",
                         "Companies, schools and banks do not send official requests from free webmail accounts."),
    "hdr.returnpath_mismatch": ("Sender", "Envelope sender differs from the From domain",
                                "The bounce address belongs to another domain. Normal for marketing platforms, "
                                "suspicious when authentication also fails."),
    "hdr.fake_reply": ("Headers", "Fake reply",
                       "The subject starts with RE: but the message is not part of any real thread - it is meant to "
                       "make a first contact feel familiar."),
    "hdr.missing": ("Headers", "Missing or duplicated standard headers",
                    "Real mail systems always add these headers; their absence or duplication points to hand-built "
                    "or spoofed messages."),
    "hdr.date_anomaly": ("Headers", "Date header does not fit the delivery timeline",
                         "The claimed send date disagrees with when the servers actually handled the message."),
    "hdr.phish_kit": ("Headers", "Phishing toolkit or simulation header",
                      "Headers left by phishing frameworks or bulk-mail scripts. Gophish is also used for authorized "
                      "awareness tests, so this may be your organization's training email."),
    "hdr.msgid_mismatch": ("Headers", "Message-ID from an unrelated domain",
                           "The Message-ID was generated by a domain unrelated to the sender (weak signal)."),
    "url.text_mismatch": ("Links", "Link text hides the real destination",
                          "The text shows one web address but the link opens another - the core phishing trick."),
    "url.text_mismatch_tracked": ("Links", "Link routed through a marketing tracker",
                                  "The visible address differs because a mail-marketing service tracks clicks. Usually "
                                  "benign, but the final destination cannot be verified."),
    "url.ip_host": ("Links", "Link uses a raw IP address",
                    "Legitimate organizations link to named domains, not bare IP addresses."),
    "url.punycode": ("Links", "Internationalized (punycode) domain",
                     "Non-ASCII domains can contain characters that look identical to Latin letters."),
    "url.lookalike": ("Links", "Link to a look-alike brand domain",
                      "The domain is crafted to resemble a well-known brand (typosquatting, homoglyphs or "
                      "brand-plus-words)."),
    "url.brand_elsewhere": ("Links", "Brand name used inside an unrelated URL",
                            "Putting a brand in the subdomain or path makes an unrelated site look official."),
    "url.shortener": ("Links", "URL shortener", "Shorteners hide the final destination from readers and filters."),
    "url.suspicious_tld": ("Links", "Frequently abused top-level domain",
                           "Some cheap top-level domains host a disproportionate share of phishing sites."),
    "url.userinfo": ("Links", "'@' trick in a URL",
                     "Everything before '@' in a URL is ignored, so https://bank.com@evil.site opens evil.site."),
    "url.many_subdomains": ("Links", "Deeply nested subdomains",
                            "Long chains of subdomains push the real domain out of view."),
    "url.obfuscated": ("Links", "Long or heavily encoded URL", "Length and encoding hide what a link really does."),
    "url.free_hosting": ("Links", "Free hosting or form-builder platform",
                         "Free web hosts, app platforms and form builders let attackers publish phishing pages in "
                         "minutes."),
    "url.redirect": ("Links", "Redirect to another site", "A link that forwards to a different site via a URL parameter."),
    "url.script_scheme": ("Links", "Script or data link",
                          "javascript: and data: links run code or embed pages instead of opening a website."),
    "url.login_keywords": ("Links", "Login/verify wording in the link path",
                           "Paths like /login, /verify or /webscr on an unrelated domain usually lead to fake sign-in "
                           "pages."),
    "url.nonstd_port": ("Links", "Unusual network port", "Web links on non-standard ports are rare in legitimate email."),
    "url.backslash": ("Links", "Backslash host trick", "Backslashes can make a browser and a filter see different hosts."),
    "html.form": ("Message body", "Form embedded in the email",
                  "Legitimate senders never ask you to type passwords into an email; embedded forms send your data "
                  "straight to the attacker."),
    "html.hidden_text": ("Message body", "Large amount of hidden text",
                         "Invisible text is padded in to mislead spam filters' language analysis."),
    "html.script": ("Message body", "Scripts or event handlers in the HTML",
                    "Email clients block scripts; their presence indicates a phishing kit or an evasion attempt."),
    "html.refresh_iframe": ("Message body", "Auto-redirect or embedded frame",
                            "Meta-refresh tags and frames load remote content automatically."),
    "html.image_only": ("Message body", "Image-based message with little text",
                        "Messages that are mostly images (often a QR code) evade text-based filters."),
    "ti.feed": ("Threat intelligence", "Link listed in a phishing threat feed",
                "The URL, host or domain appears on a curated list of confirmed phishing sites."),
    "ti.vt_url": ("Threat intelligence", "VirusTotal engines flag a link",
                  "Security vendors aggregated by VirusTotal classify this URL as malicious or suspicious."),
    "ti.vt_file": ("Threat intelligence", "VirusTotal engines flag an attachment",
                   "Antivirus engines know this attachment's SHA-256 hash as malicious."),
    "nlp.urgency": ("Language", "Urgency pressure", "Deadlines and 'act now' wording rush readers past careful judgment."),
    "nlp.threat": ("Language", "Threats or account-problem warnings",
                   "Warnings about suspension, locked accounts or legal action create fear."),
    "nlp.credential": ("Language", "Asks you to verify, log in or reset credentials",
                       "Phishing exists to harvest credentials; legitimate services rarely ask you to confirm them by "
                       "email."),
    "nlp.financial": ("Language", "Payment or invoice language", "Invoices, payments and fees are the usual pretext for fraud."),
    "nlp.reward": ("Language", "Prize or reward lure", "Unexpected winnings and rewards are bait."),
    "nlp.greeting": ("Language", "Generic greeting", "'Dear Customer' means the sender does not know who you are."),
    "nlp.cta": ("Language", "Pushy call to action", "Insistent instructions to click, open or download."),
    "nlp.bec": ("Language", "Business email compromise (BEC) phrasing",
                "'Are you available?', 'quick favor' and 'keep this confidential' are typical of executive-impersonation "
                "and gift-card fraud."),
    "nlp.gift_card": ("Language", "Gift card request", "Requests to buy gift cards and send the codes are almost always fraud."),
    "nlp.cred_plus_link": ("Language", "Credential request plus a place to enter it",
                           "Asking for credentials and supplying the link or form to type them into is the core "
                           "phishing pattern."),
    "nlp.style": ("Language", "Shouting style", "Excessive capitals and exclamation marks are common in scam mail."),
    "nlp.short_with_link": ("Language", "Very short message built around a link",
                            "Little context and one link: the reader is meant to click without thinking."),
    "att.executable": ("Attachments", "Executable or script attachment", "Opening it runs code on your computer."),
    "att.double_ext": ("Attachments", "Disguised file extension",
                       "Double extensions and right-to-left tricks make a dangerous file look like a document."),
    "att.html": ("Attachments", "HTML or SVG attachment",
                 "HTML/SVG attachments open a local web page - a favorite way to deliver fake login pages past link "
                 "scanners."),
    "att.credential_form": ("Attachments", "Attachment contains a password form", "The attachment is a credential-harvesting page."),
    "att.smuggling": ("Attachments", "Obfuscated script in an attachment",
                      "atob/Blob/eval patterns are used for HTML smuggling and hidden redirects."),
    "att.macro": ("Attachments", "Macro-enabled Office document", "Macros can download and run malware."),
    "att.disk_image": ("Attachments", "Disk-image attachment",
                       "ISO/IMG/VHD files are used to bypass Windows Mark-of-the-Web protections."),
    "att.archive": ("Attachments", "Archive attachment", "Archives hide their contents from quick inspection and some scanners."),
    "att.encrypted_archive": ("Attachments", "Password-protected archive",
                              "Encryption stops security scanners from inspecting the contents; the password is usually "
                              "in the email."),
    "att.archive_risky": ("Attachments", "Archive contains risky files", "Executables, scripts or HTML files inside an archive."),
    "att.mismatch": ("Attachments", "File content does not match its name", "The file's real format differs from its extension."),
    "att.pdf_active": ("Attachments", "PDF with active content", "JavaScript, launch actions or embedded files inside a PDF."),
    "trust.no_links": ("Structure", "Nothing to click or open",
                       "No links, forms or attachments: the usual phishing payloads are absent."),
}

BIAS = -2.6   # log-odds of an email with no indicators (about 7%)
LINK_FEATURES = {"text-mismatch": ("url.text_mismatch", 1.6), "text-mismatch-tracked": ("url.text_mismatch_tracked", 0.3),
                 "ip-host": ("url.ip_host", 1.5), "punycode": ("url.punycode", 1.2), "lookalike": ("url.lookalike", 2.2),
                 "brand-elsewhere": ("url.brand_elsewhere", 1.3), "shortener": ("url.shortener", 0.7),
                 "suspicious-tld": ("url.suspicious_tld", 0.5), "userinfo": ("url.userinfo", 1.2),
                 "many-subdomains": ("url.many_subdomains", 0.5), "obfuscated": ("url.obfuscated", 0.4),
                 "free-hosting": ("url.free_hosting", 0.6), "redirect": ("url.redirect", 0.6),
                 "script-scheme": ("url.script_scheme", 1.2), "login-keywords": ("url.login_keywords", 0.4),
                 "nonstandard-port": ("url.nonstd_port", 0.4), "backslash": ("url.backslash", 1.0)}
ATT_FEATURES = {"executable": ("att.executable", 3.0), "rtlo": ("att.double_ext", 2.0),
                "double-ext": ("att.double_ext", 2.0), "html": ("att.html", 1.6),
                "credential-form": ("att.credential_form", 1.2), "smuggling": ("att.smuggling", 1.5),
                "macro": ("att.macro", 2.0), "disk-image": ("att.disk_image", 2.0), "archive": ("att.archive", 0.6),
                "encrypted-archive": ("att.encrypted_archive", 1.5), "archive-risky": ("att.archive_risky", 2.5),
                "mismatch": ("att.mismatch", 1.2), "pdf-active": ("att.pdf_active", 1.0)}
NLP_FEATURES = {"urgency": ("nlp.urgency", 0.35, 3), "threat": ("nlp.threat", 0.4, 3),
                "credential": ("nlp.credential", 0.5, 3), "financial": ("nlp.financial", 0.25, 3),
                "reward": ("nlp.reward", 0.35, 3), "cta": ("nlp.cta", 0.3, 2), "bec": ("nlp.bec", 0.45, 3)}


@dataclass
class Feature:
    fid: str
    category: str
    title: str
    weight: float
    evidence: list
    why: str
    impact_pp: float = 0.0


def _add(features: list, fid: str, weight: float, evidence: list) -> None:
    category, title, why = FEATURE_INFO[fid]
    features.append(Feature(fid, category, title, round(weight, 2),
                            [shorten(str(e), 240) for e in evidence if e][:6], why))


def _domain_owned_by(brand: str, domain: str) -> bool:
    _, domains, _ = BRANDS.get(brand, ([], [], False))
    d = (domain or "").lower()
    return d in domains or org_domain(d) in domains or any(d.endswith("." + x) for x in domains)


def extract_features(pe: ParsedEmail, auth: AuthSummary, nlp: dict) -> list:
    f: list[Feature] = []
    eff = auth.effective
    spf, dkim_r, dmarc = eff.get("spf", "unknown"), eff.get("dkim", "none"), eff.get("dmarc", "unknown")
    org_from = org_domain(pe.from_domain)

    # ---- authentication ----------------------------------------------------
    if dmarc == "fail":
        pol = eff.get("policy") or ""
        _add(f, "auth.dmarc_fail", 2.0, [f"DMARC=fail for {pe.from_domain}" + (f" (policy {pol})" if pol else "")
                                         + f" [{eff.get('dmarc_source')}]"])
    elif dmarc == "pass":
        _add(f, "auth.dmarc_pass", -1.2, [f"DMARC=pass for {pe.from_domain} [{eff.get('dmarc_source')}]"])
    elif dmarc == "none":
        _add(f, "auth.no_dmarc", 0.5, [f"No DMARC record for {pe.from_domain or '(no From domain)'}"])
    if spf == "fail":
        _add(f, "auth.spf_fail", 1.2, [f"SPF=fail for {auth.alignment.get('spf_domain')} from {auth.origin_ip or 'unknown IP'}"])
    elif spf == "softfail":
        _add(f, "auth.spf_softfail", 0.6, [f"SPF=softfail for {auth.alignment.get('spf_domain')} from {auth.origin_ip or 'unknown IP'}"])
    if dkim_r in ("fail", "permerror"):
        reasons = [f"d={c['domain']}: {c['reason']}" for c in auth.dkim_live if c["result"] in ("fail", "permerror")]
        _add(f, "auth.dkim_fail", 0.9 if eff.get("dkim_source") == "recorded" else 0.5,
             reasons or [f"DKIM={dkim_r} [{eff.get('dkim_source')}]"])
    if spf in ("fail", "softfail", "neutral", "none", "permerror") and dkim_r in ("none", "fail", "permerror", "neutral"):
        _add(f, "auth.unauthenticated", 0.8, [f"SPF={spf}, DKIM={dkim_r}"])
    comp = (auth.recorded or {}).get("compauth")
    if comp and comp.get("result") == "fail":
        _add(f, "auth.compauth_fail", 0.5 if dmarc == "fail" else 1.0,
             [f"compauth=fail" + (f" reason={comp.get('reason')}" if comp.get("reason") else "")])
    dc = auth.domain_check or {}
    if dc.get("status") == "nxdomain":
        _add(f, "auth.domain_missing", 1.5, [dc.get("detail")])
    elif dc.get("status") in ("no-mail", "null-mx"):
        _add(f, "auth.domain_missing", 0.8, [dc.get("detail")])

    # ---- sender & headers ----------------------------------------------------
    sender_look = brand_lookalike(pe.from_domain) if pe.from_domain else None
    if sender_look:
        _add(f, "hdr.sender_lookalike", 2.0, [f"{pe.from_addr}: {sender_look[2]}"])
    claimed = display_name_brand(pe.from_display)
    if claimed and not _domain_owned_by(claimed, pe.from_domain):
        _add(f, "hdr.brand_display", 1.8, [f"Display name '{pe.from_display}' suggests {claimed}, but the address is "
                                           f"{pe.from_addr or '(none)'}"])
    m = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", pe.from_display or "")
    if m and org_domain(m.group(1)) != org_from:
        _add(f, "hdr.display_email_mismatch", 1.4, [f"Display name contains {m.group(0)}; real sender is {pe.from_addr}"])
    for rt in pe.reply_to:
        rt_dom = _domain_of(rt)
        if rt_dom and org_domain(rt_dom) != org_from:
            heavy = rt_dom in FREEMAIL_DOMAINS
            _add(f, "hdr.replyto_mismatch", 1.2 if heavy else 0.9,
                 [f"Reply-To {rt} ({'free webmail' if heavy else 'different domain'}) vs From {pe.from_addr}"])
            break
    if pe.from_domain in FREEMAIL_DOMAINS and (claimed or ORG_ROLE_WORDS.search(pe.from_display or "")):
        _add(f, "hdr.freemail_org", 1.0, [f"'{pe.from_display}' <{pe.from_addr}> uses a free webmail account"])
    mf_dom = _domain_of(auth.mail_from) if "@" in auth.mail_from else ""
    if mf_dom and pe.from_domain and org_domain(mf_dom) != org_from and dmarc != "pass":
        _add(f, "hdr.returnpath_mismatch", 0.3, [f"Envelope sender {auth.mail_from} vs From {pe.from_addr}"])
    if re.match(r"^\s*(?:re|aw|sv|antw)\s*:", pe.subject or "", re.I) and not pe.in_reply_to and not pe.references:
        _add(f, "hdr.fake_reply", 0.6, [f"Subject '{shorten(pe.subject, 80)}' but no In-Reply-To/References headers"])
    missing = [h for h, v in (("Message-ID", pe.message_id), ("Date", pe.date_raw)) if not v]
    problems = [f"missing {h}" for h in missing]
    if pe.from_count != 1:
        problems.append(f"{pe.from_count} From addresses" if pe.from_count else "no parsable From address")
    if problems:
        _add(f, "hdr.missing", 1.0 if pe.from_count > 1 else 0.4, ["; ".join(problems)])
    if pe.date_dt:
        first_hop = next((h for h in pe.hops if h.timestamp), None)
        ref = datetime.fromisoformat(first_hop.timestamp) if first_hop else utc_now()
        delta = (pe.date_dt - ref).total_seconds()
        if delta > 86400:
            _add(f, "hdr.date_anomaly", 0.3, [f"Date header is {delta / 3600:.0f} h after the first server saw the message"])
        elif first_hop and delta < -3 * 86400:
            _add(f, "hdr.date_anomaly", 0.3, [f"Date header is {-delta / 86400:.0f} days before the message was sent"])
    header_names = {k.lower() for k, _ in pe.headers}
    mailer = (pe.x_mailer or "").lower()
    if {"x-gophish-contact", "x-gophish-signature"} & header_names or "gophish" in mailer or "king phisher" in mailer:
        _add(f, "hdr.phish_kit", 2.0, [f"X-Mailer/Gophish header present ({pe.x_mailer or 'X-Gophish-*'})"])
    elif "phpmailer" in mailer:
        _add(f, "hdr.phish_kit", 0.3, [f"X-Mailer: {pe.x_mailer} (bulk-mail script also common in phishing kits)"])
    mid_dom = pe.message_id.rsplit("@", 1)[-1].strip("<> ").lower() if "@" in pe.message_id else ""
    if mid_dom and pe.from_domain and org_domain(mid_dom) != org_from and not any(
            mid_dom == p or mid_dom.endswith("." + p) for p in MSGID_PROVIDERS):
        _add(f, "hdr.msgid_mismatch", 0.2, [f"Message-ID domain {mid_dom} vs From domain {pe.from_domain}"])

    # ---- links -----------------------------------------------------------------
    for code, (fid, weight) in LINK_FEATURES.items():
        hits = [lk for lk in pe.links if any(fl[0] == code for fl in lk.flags)]
        if hits:
            ev = []
            for lk in hits[:4]:
                detail = next(fl[1] for fl in lk.flags if fl[0] == code)
                ev.append(f"{defang(shorten(lk.url, 90)) or lk.scheme + ':'} - {detail}")
            _add(f, fid, weight, ev)

    # ---- HTML body ---------------------------------------------------------------
    hs = pe.html_stats or {}
    if hs.get("password_forms"):
        _add(f, "html.form", 1.8, ["Message body contains a password form" +
                                   (f" posting to {defang(hs['form_actions'][0])}" if hs.get("form_actions") else "")])
    elif hs.get("forms"):
        _add(f, "html.form", 0.8, [f"{hs['forms']} HTML form(s) in the message body"])
    hidden = hs.get("hidden_chars", 0)
    if hidden >= 300 and hidden > 0.25 * max(1, len(pe.visible_text)):
        _add(f, "html.hidden_text", 0.7, [f"{hidden} characters of invisible text vs {len(pe.visible_text)} visible"])
    if hs.get("scripts") or hs.get("event_handlers"):
        _add(f, "html.script", 0.8, [f"{hs.get('scripts', 0)} <script> tag(s), {hs.get('event_handlers', 0)} event handler(s)"])
    if hs.get("meta_refresh") or hs.get("iframes"):
        _add(f, "html.refresh_iframe", 0.8, [f"{hs.get('meta_refresh', 0)} meta refresh, {hs.get('iframes', 0)} frame(s)"])
    words = nlp["stats"]["words"]
    images = hs.get("images", 0) + hs.get("inline_images", 0)
    if images and words < 25 and (pe.links or pe.attachments):
        _add(f, "html.image_only", 0.5, [f"{images} image(s) but only {words} words of text"])

    # ---- threat intelligence ---------------------------------------------------
    feed_hits = [lk for lk in pe.links if lk.feed]
    if feed_hits:
        best = max(feed_hits, key=lambda lk: ThreatFeeds.RANK[lk.feed["match"]])
        weight = {"exact": 4.0, "path": 4.0, "host": 3.0, "domain": 2.0}[best.feed["match"]]
        _add(f, "ti.feed", weight, [f"{defang(shorten(lk.url, 90))} - {lk.feed['match']} match in {lk.feed['feed']}"
                                    for lk in feed_hits])
    vt_hits = [lk for lk in pe.links if lk.vt and lk.vt.get("status") == "found"
               and (lk.vt.get("malicious") or lk.vt.get("suspicious"))]
    if vt_hits:
        top = max(vt_hits, key=lambda lk: (lk.vt["malicious"], lk.vt["suspicious"]))
        mal, sus = top.vt["malicious"], top.vt["suspicious"]
        weight = 3.5 if mal >= 5 else 2.5 if mal >= 2 else 1.0 if mal == 1 else 0.6 if sus >= 2 else 0.3
        _add(f, "ti.vt_url", weight, [f"{defang(shorten(lk.url, 90))} - {lk.vt['malicious']} malicious, "
                                      f"{lk.vt['suspicious']} suspicious verdicts" for lk in vt_hits])
    vt_files = [a for a in pe.attachments if a.vt and a.vt.get("status") == "found" and a.vt.get("malicious")]
    if vt_files:
        mal = max(a.vt["malicious"] for a in vt_files)
        _add(f, "ti.vt_file", 4.0 if mal >= 3 else 1.5,
             [f"{a.filename} ({a.sha256[:16]}...) - {a.vt['malicious']} malicious verdicts" for a in vt_files])

    # ---- language (NLP-lite) -------------------------------------------------------
    hits = nlp["hits"]
    for cat, (fid, per_hit, cap) in NLP_FEATURES.items():
        if hits.get(cat):
            _add(f, fid, per_hit * min(len(hits[cat]), cap), [", ".join(f"'{h}'" for h in hits[cat][:6])])
    if hits.get("greeting"):
        _add(f, "nlp.greeting", 0.5, [f"'{hits['greeting'][0]}'"])
    if hits.get("gift_card"):
        _add(f, "nlp.gift_card", 1.6, [", ".join(f"'{h}'" for h in hits["gift_card"][:4])])
    payload = pe.links or hs.get("forms") or any(a.flags for a in pe.attachments)
    if hits.get("credential") and payload:
        _add(f, "nlp.cred_plus_link", 0.8, [f"Asks for credentials ('{hits['credential'][0]}') and provides "
                                            f"{len(pe.links)} link(s)/form(s) to enter them"])
    st = nlp["stats"]
    if (st["words"] >= 20 and st["caps_ratio"] > 0.12) or st["exclamations"] >= 4:
        _add(f, "nlp.style", 0.3, [f"{st['caps_ratio']:.0%} of words in capitals, {st['exclamations']} exclamation marks"])
    if 0 < st["words"] < 40 and pe.links and not hits.get("bec"):
        _add(f, "nlp.short_with_link", 0.3, [f"{st['words']} words of text, {len(pe.links)} link(s)"])

    # ---- attachments ------------------------------------------------------------
    for code, (fid, weight) in ATT_FEATURES.items():
        flagged = [a for a in pe.attachments if any(fl[0] == code for fl in a.flags)]
        if flagged and not any(x.fid == fid for x in f):
            _add(f, fid, weight, [f"{a.filename}: " + next(fl[1] for fl in a.flags if fl[0] == code) for a in flagged])

    # ---- trust signal ------------------------------------------------------------
    if not pe.links and not pe.attachments and not hs.get("forms") and \
            not (hits.get("bec") or hits.get("gift_card") or hits.get("financial")):
        _add(f, "trust.no_links", -0.5, ["No links, forms or attachments in the message"])
    return f


def score_features(features: list) -> tuple[float, float]:
    """Logistic model: p = 1 / (1 + e^-(bias + sum of weights))."""
    z = BIAS + sum(ft.weight for ft in features)
    p = 1.0 / (1.0 + math.exp(-z))
    for ft in features:
        p_without = 1.0 / (1.0 + math.exp(-(z - ft.weight)))
        ft.impact_pp = round((p - p_without) * 100, 1)
    features.sort(key=lambda ft: (-abs(ft.weight), ft.fid))
    return z, p


def verdict_for(p: float) -> tuple[str, str]:
    if p >= 0.80:
        return "Phishing", "critical"
    if p >= 0.50:
        return "Likely phishing", "high"
    if p >= 0.20:
        return "Suspicious", "medium"
    return "Likely legitimate", "low"


def fmt_prob(p: float) -> str:
    if p >= 0.9995:
        return ">99.9%"
    if p < 0.0005:
        return "<0.1%"
    return f"{p * 100:.1f}%"


@dataclass
class AnalysisResult:
    email: ParsedEmail
    auth: AuthSummary
    features: list
    nlp: dict
    logit: float
    probability: float
    verdict: str
    level: str
    summary: str = ""
    recommendations: list = field(default_factory=list)
    notes: list = field(default_factory=list)


def _lc(s: str) -> str:
    """Lower-case a title for use mid-sentence, but keep acronyms such as DMARC intact."""
    return s if len(s) > 1 and s[1].isupper() else s[:1].lower() + s[1:]


def _join(items: list) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def narrative(r: AnalysisResult) -> str:
    risk = [ft for ft in r.features if ft.weight > 0]
    trust = [ft for ft in r.features if ft.weight < 0]
    lead = f"Rated {r.verdict.lower()} ({fmt_prob(r.probability)} phishing probability)."
    if not risk:
        text = lead + " No phishing indicators fired."
    elif r.level == "low":
        text = lead + " Only weak indicators fired: " + _join([_lc(ft.title) for ft in risk[:3]]) + "."
    else:
        text = lead + " Main drivers: " + _join([_lc(ft.title) for ft in risk[:3]]) + "."
        if len(risk) > 3:
            text += f" {len(risk) - 3} weaker indicator(s) also fired."
    if trust:
        text += " Lowering the score: " + _join([_lc(ft.title) for ft in trust]) + "."
    if any(ft.fid == "auth.dmarc_pass" for ft in trust) and r.probability >= 0.5:
        text += (" Passing authentication only proves which domain sent the message; attackers authenticate "
                 "their own look-alike domains and hijacked accounts.")
    return text


def recommendations(pe: ParsedEmail, features: list, level: str) -> list:
    fids = {ft.fid for ft in features}
    recs: list[str] = []
    if level in ("critical", "high"):
        recs += ["Do not click links, open attachments, scan QR codes or reply.",
                 "Report it with your mail app's Report phishing button (or forward it as an attachment to your "
                 "security/IT team), then delete it.",
                 "If you already clicked or typed a password: change that password from a page you open yourself "
                 "and turn on multi-factor authentication."]
    elif level == "medium":
        recs += ["Verify through a channel you already trust before acting: call a known number or type the "
                 "website address yourself.",
                 "Do not enter credentials or payment details through links in this message."]
    else:
        recs.append("No significant indicators. Normal caution still applies to unexpected requests.")
    if {"nlp.gift_card", "nlp.bec"} & fids and level != "low":
        recs.append("Confirm any payment or gift-card request in person or by phone with the supposed requester - "
                    "never by replying to the email.")
    if level in ("critical", "high"):
        iocs = sorted({defang_host(lk.host) for lk in pe.links if lk.host and
                       (lk.feed or (lk.vt and lk.vt.get("malicious")) or lk.risk >= 1.5)})
        if iocs:
            recs.append("SOC: block these hosts at the mail gateway and web proxy: " + ", ".join(iocs[:6]) + ".")
        if pe.from_domain and pe.from_domain not in FREEMAIL_DOMAINS and not brand_for_domain(pe.from_domain) and \
                ("hdr.sender_lookalike" in fids or "auth.dmarc_pass" not in fids):
            recs.append(f"SOC: block or quarantine mail from {defang_host(pe.from_domain)} unless it is a known "
                        f"business contact.")
    bad = [a for a in pe.attachments if any(fl[0] not in ("archive", "attached-message") for fl in a.flags)]
    if bad and level != "low":
        recs.append(f"SOC: hunt for other copies of '{bad[0].filename}' by SHA-256 {bad[0].sha256} and quarantine them.")
    return recs


# ============================================================================
# Analysis engine
# ============================================================================
class PhishAnalyzer:
    def __init__(self, live: bool = True, use_feeds: bool = True, feed_files: tuple = (), vt_key: str = "",
                 vt_max_urls: int = 4, vt_max_files: int = 2, vt_max_total: int = 40, vt_interval: float = 15.5,
                 dns_timeout: float = 4.0, nameservers: Optional[list] = None, cache_dir: Optional[str] = None):
        self.live = live
        self.dns = DNSClient(enabled=live, timeout=dns_timeout, nameservers=nameservers)
        if live and self.dns.enabled:
            self.dns.health_check()
        self.spf = SPFEvaluator(self.dns)
        self.feeds = ThreatFeeds(use_public=use_feeds and live, feed_files=tuple(feed_files), cache_dir=cache_dir)
        self.feed_status = self.feeds.load()
        self.vt = None
        if vt_key and live:
            self.vt = VirusTotalClient(vt_key, vt_max_urls, vt_max_files, vt_max_total, vt_interval, cache_dir)
            self.vt_note = "enabled"
        else:
            self.vt_note = "offline mode" if not live else "no API key supplied (set VT_API_KEY or --vt-key)"

    def analyze(self, rm: RawMessage) -> AnalysisResult:
        pe = parse_email(rm)
        auth = evaluate_auth(pe, rm.raw.lstrip(), self.dns, self.spf)
        for lk in pe.links:
            lk.feed = self.feeds.check(lk)
        notes = self._virustotal(pe) if self.vt else []
        nlp = nlp_analyze(pe)
        features = extract_features(pe, auth, nlp)
        logit, prob = score_features(features)
        verdict, level = verdict_for(prob)
        res = AnalysisResult(pe, auth, features, nlp, logit, prob, verdict, level, notes=notes)
        res.summary = narrative(res)
        res.recommendations = recommendations(pe, features, level)
        return res

    def _virustotal(self, pe: ParsedEmail) -> list:
        notes = []
        cands = [lk for lk in pe.links if lk.host and lk.scheme in ("http", "https")]
        cands.sort(key=lambda lk: (-(lk.risk + (3 if lk.feed else 0)), lk.url))
        chosen = [lk for lk in cands if not (brand_for_domain(lk.host) and lk.risk == 0)][: self.vt.max_urls]
        for lk in chosen:
            lk.vt = self.vt.url_report(lk.url)
        files = sorted([a for a in pe.attachments if a.magic != "email" and a.size > 0], key=lambda a: -len(a.flags))
        for a in files[: self.vt.max_files]:
            a.vt = self.vt.file_report(a.sha256)
        skipped = len(cands) - len(chosen)
        if skipped > 0:
            notes.append(f"VirusTotal: looked up the {len(chosen)} highest-risk link(s); {skipped} other link(s) "
                         f"skipped to stay inside the free-tier quota.")
        if self.vt.stopped:
            notes.append(f"VirusTotal stopped early: {self.vt.stopped}.")
        return notes


def analyze_inputs(paths: list, analyzer: PhishAnalyzer, max_messages: int = 200) -> tuple[list, list]:
    raws, warnings = load_inputs(paths, max_messages)
    results: list[AnalysisResult] = []
    queue = list(raws)
    count = 0
    while queue:
        rm = queue.pop(0)
        count += 1
        try:
            res = analyzer.analyze(rm)
        except Exception as exc:  # keep going; report what failed
            warnings.append(f"{rm.label}: analysis failed ({type(exc).__name__}: {shorten(str(exc), 120)})")
            continue
        results.append(res)
        _print_result(count, res)
        if rm.depth < 2:
            for j, inner in enumerate(res.email.embedded, 1):
                queue.insert(j - 1, RawMessage(rm.source, f"{rm.label} > attached message {j}", inner, rm.depth + 1))
    return results, warnings


LEVEL_COLORS = {"critical": ("red", "bold"), "high": ("red",), "medium": ("yellow",), "low": ("green",)}


def _print_result(n: int, r: AnalysisResult) -> None:
    tag = CON.paint(f"{r.verdict.upper():<17}", *LEVEL_COLORS[r.level])
    CON.out(f"  [{n:>2}] {tag} {fmt_prob(r.probability):>6}  {shorten(r.email.subject or '(no subject)', 54)}")
    CON.out(CON.paint(f"        from {r.email.from_addr or '?'}  |  {r.email.label}", "dim"))
    for ft in [x for x in r.features if x.weight > 0][:3]:
        CON.out(CON.paint(f"        +{ft.weight * 10:>3.0f} pts  {ft.title}", "dim"))


# ============================================================================
# Reports: JSON
# ============================================================================
def _link_dict(lk: Link) -> dict:
    return {"url": lk.url, "url_defanged": defang(lk.url), "original": lk.original if lk.original != lk.url else "",
            "host": lk.host, "site": lk.site, "text": lk.text, "source": lk.source, "wrapper": lk.wrapper,
            "flags": [{"code": c, "detail": d} for c, d in lk.flags], "risk": lk.risk, "feed": lk.feed,
            "virustotal": lk.vt}


def result_to_dict(r: AnalysisResult) -> dict:
    pe, a = r.email, r.auth
    return {
        "label": pe.label, "source": pe.source, "sha256": pe.raw_sha256, "size_bytes": pe.raw_size,
        "verdict": r.verdict, "level": r.level, "probability": round(r.probability, 5),
        "logit": round(r.logit, 3), "summary": r.summary, "recommendations": r.recommendations, "notes": r.notes,
        "message": {"subject": pe.subject, "from_display": pe.from_display, "from": pe.from_addr,
                    "reply_to": pe.reply_to, "return_path": pe.return_path, "to": pe.to, "cc": pe.cc,
                    "date": pe.date_raw, "message_id": pe.message_id, "x_mailer": pe.x_mailer},
        "features": [{"id": ft.fid, "category": ft.category, "title": ft.title, "weight": ft.weight,
                      "points": round(ft.weight * 10), "impact_pp": ft.impact_pp, "evidence": ft.evidence,
                      "why": ft.why} for ft in r.features],
        "authentication": {"recorded": a.recorded, "origin_ip": a.origin_ip, "origin_ip_source": a.origin_ip_source,
                           "helo": a.helo, "mail_from": a.mail_from, "mail_from_source": a.mail_from_source,
                           "live_checks": a.live_enabled, "live_note": a.live_note, "spf_live": a.spf_live,
                           "dkim": a.dkim_live, "dmarc_record": a.dmarc_record, "dmarc_live": a.dmarc_live,
                           "domain_check": a.domain_check, "alignment": a.alignment, "effective": a.effective,
                           "notes": a.notes},
        "links": [_link_dict(lk) for lk in pe.links],
        "attachments": [{"filename": at.filename, "content_type": at.content_type, "size": at.size,
                         "sha256": at.sha256, "md5": at.md5, "magic": at.magic,
                         "flags": [{"code": c, "detail": d} for c, d in at.flags], "inner_files": at.inner_files,
                         "virustotal": at.vt} for at in pe.attachments],
        "nlp": r.nlp, "html": pe.html_stats,
        "delivery_path": [{"hop": h.number, "from_host": h.from_host, "from_ip": h.from_ip, "by_host": h.by_host,
                           "protocol": h.protocol, "timestamp": h.timestamp, "delay_seconds": h.delay_s}
                          for h in pe.hops],
        "defects": pe.defects,
    }


def write_json(results: list, meta: dict, path: Path) -> None:
    doc = {"report": meta, "messages": [result_to_dict(r) for r in results]}
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


# ============================================================================
# Reports: HTML (self-contained; scripts and remote content blocked by CSP)
# ============================================================================
REPORT_CSS = """
*{box-sizing:border-box}
:root{--paper:#F4F6F9;--card:#FFFFFF;--ink:#16202C;--slate:#566273;--rule:#DCE2EA;--rule2:#C4CDD8;
--air:#1C4F8C;--air-soft:#EAF0F7;--low:#2B7A4B;--medium:#9C5B00;--high:#C0391F;--critical:#8B1A1A;
--ok:#2B7A4B;--bad:#B3261E;--neutral:#6B7686;
--serif:Charter,"Bitstream Charter","Sitka Text",Cambria,Georgia,serif;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,"SFMono-Regular","Cascadia Mono",Consolas,"Liberation Mono",monospace;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--paper:#0E131A;--card:#151C26;--ink:#E4E9F0;--slate:#A3AEBD;
--rule:#273140;--rule2:#3A4656;--air:#8DB3EA;--air-soft:#1A2636;--low:#5DBB85;--medium:#E3A142;--high:#F2785D;
--critical:#FF9090;--ok:#5DBB85;--bad:#FF8A80;--neutral:#9AA5B4;color-scheme:dark}}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 var(--sans)}
.wrap{max-width:1060px;margin:0 auto;padding:30px 22px 56px}
h1,h2,h3{font-family:var(--serif);font-weight:600;line-height:1.2;margin:0}
h1{font-size:31px;letter-spacing:-.01em}
.lede{color:var(--slate);margin:6px 0 0;max-width:60ch}
.masthead{display:grid;grid-template-columns:1fr minmax(280px,420px);gap:28px;align-items:start;
border-bottom:2px solid var(--ink);padding-bottom:20px}
.runinfo{margin:0;display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;font-size:13px}
.runinfo dt{color:var(--slate)}.runinfo dd{margin:0;overflow-wrap:anywhere}
.warnings{margin:14px 0 0;padding-left:18px;color:var(--medium);font-size:13.5px}
.overview{margin:26px 0 6px}.overview h2{font-size:20px;margin-bottom:8px}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th{text-align:left;font-weight:600;color:var(--slate);border-bottom:1px solid var(--rule2);padding:6px 8px;font-size:12.5px}
td{border-bottom:1px solid var(--rule);padding:7px 8px;vertical-align:top}
.scroll{overflow-x:auto}
.num{text-align:right;font-family:var(--mono);white-space:nowrap}
.pill{display:inline-block;padding:0 9px;border-radius:999px;font-size:12px;font-weight:600;border:1.5px solid currentColor;white-space:nowrap}
.lvl-low{color:var(--low)}.lvl-medium{color:var(--medium)}.lvl-high{color:var(--high)}.lvl-critical{color:var(--critical)}
.v-low{--v:var(--low)}.v-medium{--v:var(--medium)}.v-high{--v:var(--high)}.v-critical{--v:var(--critical)}
.case{background:var(--card);border:1px solid var(--rule);border-top:5px solid var(--v);border-radius:3px;margin:34px 0;padding:22px 26px 12px}
.case-head{display:flex;gap:18px;align-items:flex-start}
.postmark{width:238px;flex:none;color:var(--v);margin:-8px -6px 0 -16px}
.pm-arc{font:600 10.5px var(--sans);letter-spacing:2.4px}
.pm-pct{font:700 31px var(--serif)}
.pm-sub{font:700 8.4px var(--sans);letter-spacing:.7px}
.envelope{flex:1;min-width:0}
.case-no{color:var(--slate);font-size:13px;margin:0 0 4px}
.subject{font-size:23px;margin:0 0 10px;overflow-wrap:anywhere}
.addr{display:grid;grid-template-columns:max-content 1fr;gap:3px 12px;margin:0;font-size:14px}
.addr dt{color:var(--slate)}.addr dd{margin:0;overflow-wrap:anywhere}
.summary{font-size:15.5px;max-width:80ch;margin:18px 0 6px;padding-left:14px;border-left:3px solid var(--v)}
.case h3{font-size:19px;margin:24px 0 8px}
.math{font-size:13.5px;color:var(--slate);margin:0 0 6px}
.drivers{list-style:none;margin:0;padding:0}
.drv{display:grid;grid-template-columns:48px 132px 1fr;gap:14px;align-items:start;padding:10px 0;border-top:1px solid var(--rule)}
.pts{font:600 15px/1.3 var(--mono);text-align:right}
.risk .pts{color:var(--bad)}.trust .pts{color:var(--ok)}
.bar{height:9px;margin-top:6px;background:var(--rule);border-radius:2px;position:relative;overflow:hidden}
.bar i{position:absolute;top:0;bottom:0;left:0;background:var(--bad)}
.trust .bar i{background:var(--ok);left:auto;right:0}
.drv-title{font-weight:600}.cat{color:var(--slate);font-size:12.5px;margin-left:8px}
.ev{margin:3px 0 0;font:12.5px/1.5 var(--mono);overflow-wrap:anywhere}
.why{margin:4px 0 0;color:var(--slate);font-size:13.5px;max-width:82ch}
.todo{margin:0;padding-left:20px}.todo li{margin:5px 0;max-width:88ch;overflow-wrap:anywhere}
details{border-top:1px solid var(--rule);padding:2px 0 6px}
details>summary{cursor:pointer;font:600 17px/1.3 var(--serif);padding:10px 0}
summary:focus-visible{outline:2px solid var(--air);outline-offset:3px}
.count{color:var(--slate);font:400 14px var(--sans);margin-left:6px}
code,.mono{font-family:var(--mono);font-size:12.5px;overflow-wrap:anywhere}
.res{display:inline-block;font:600 12px/1.6 var(--mono);padding:0 6px;border-radius:3px;border:1px solid currentColor}
.res.ok{color:var(--ok)}.res.bad{color:var(--bad)}.res.neutral{color:var(--neutral)}
.meta{color:var(--slate);font-size:12.5px;margin-top:3px;overflow-wrap:anywhere}
.flags{margin:0;padding:0;list-style:none}.flags li{margin:0 0 5px}
.flags b{font:600 12px var(--mono);color:var(--bad);margin-right:4px}
.hit{color:var(--bad);font-weight:600}.quiet{color:var(--slate)}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:12px 0;font-size:13.5px}
.kv dt{color:var(--slate)}.kv dd{margin:0;overflow-wrap:anywhere}
pre{background:var(--air-soft);padding:10px 12px;border-radius:3px;overflow-x:auto;font:12px/1.5 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere;margin:6px 0}
.chips{display:flex;flex-wrap:wrap;gap:5px;margin:2px 0 0}
.chip{border:1px solid var(--rule2);border-radius:3px;padding:0 6px;font-size:12.5px}
.notes{margin:8px 0;padding-left:18px;color:var(--slate);font-size:13.5px}
.notes li{margin:3px 0;max-width:90ch}
footer{margin-top:40px;border-top:2px solid var(--ink);padding-top:14px;color:var(--slate);font-size:13.5px}
footer p{max-width:92ch;margin:6px 0}
a{color:var(--air)}
@media (max-width:760px){.masthead{grid-template-columns:1fr}.case-head{flex-direction:column}
.postmark{width:200px;margin:0}.drv{grid-template-columns:44px 1fr}.drv .bar{display:none}.case{padding:16px}}
@media (prefers-reduced-motion:no-preference){.case{scroll-margin-top:12px}}
@media print{body{background:#fff}.case{break-inside:auto}}
"""

_RES_CLASS = {"pass": "ok", "fail": "bad", "softfail": "bad", "permerror": "bad", "policy": "bad"}


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _res(value: str) -> str:
    v = value or "unknown"
    return f'<span class="res {_RES_CLASS.get(v.lower(), "neutral")}">{_e(v)}</span>'


def _stamp_pct(p: float) -> str:
    return ">99%" if p >= 0.995 else "<1%" if p < 0.005 else f"{round(p * 100)}%"


def _postmark_svg(r: AnalysisResult, uid: int, stamp_date: str) -> str:
    bars = "".join(f'<path d="M168 {y} q 7 -6 14 0 ' + "t 14 0 " * 8 + '"/>' for y in (52, 72, 92, 112))
    label = f"{r.verdict}: {fmt_prob(r.probability)} phishing probability"
    return f"""<svg class="postmark" viewBox="0 0 300 170" role="img" aria-label="{_e(label)}">
<defs><path id="pt{uid}" d="M24 85 A61 61 0 0 1 146 85"/><path id="pb{uid}" d="M15 85 A70 70 0 0 0 155 85"/></defs>
<g transform="rotate(-7 150 85)">
<g fill="none" stroke="currentColor" stroke-linecap="round"><circle cx="85" cy="85" r="76" stroke-width="2.4"/>
<circle cx="85" cy="85" r="56" stroke-width="1.4"/><g stroke-width="3">{bars}</g></g>
<g fill="currentColor"><text class="pm-arc"><textPath href="#pt{uid}" startOffset="50%" text-anchor="middle">PHISH DETECTOR</textPath></text>
<text class="pm-arc"><textPath href="#pb{uid}" startOffset="50%" text-anchor="middle">{_e(stamp_date)}</textPath></text>
<circle cx="13" cy="85" r="2.6"/><circle cx="157" cy="85" r="2.6"/>
<text x="85" y="92" class="pm-pct" text-anchor="middle">{_e(_stamp_pct(r.probability))}</text>
<text x="85" y="110" class="pm-sub" text-anchor="middle">{_e(r.verdict.upper())}</text></g></g></svg>"""


def _html_drivers(r: AnalysisResult) -> str:
    total = sum(ft.weight for ft in r.features)
    exp = -r.logit
    math_line = (f"Base {BIAS * 10:+.0f} points, indicators {total * 10:+.0f} points, total {r.logit * 10:+.0f} "
                 f"points. Probability = 1 / (1 + e<sup>{exp:+.2f}</sup>) = <b>{_e(fmt_prob(r.probability))}</b>. "
                 f"Points are log-odds &times; 10.")
    if not r.features:
        return f'<p class="math">{math_line}</p><p class="quiet">No indicators fired.</p>'
    biggest = max(abs(ft.weight) for ft in r.features) or 1
    rows = []
    for ft in r.features:
        kind = "risk" if ft.weight > 0 else "trust"
        width = max(4, round(abs(ft.weight) / biggest * 100))
        without = min(1.0, max(0.0, r.probability - ft.impact_pp / 100))
        counterfactual = (f" Without this indicator: {fmt_prob(without)}."
                          if abs(ft.impact_pp) >= 0.5 and fmt_prob(without) != fmt_prob(r.probability) else "")
        ev = "<br>".join(_e(x) for x in ft.evidence)
        rows.append(
            f'<li class="drv {kind}"><span class="pts">{ft.weight * 10:+.0f}</span>'
            f'<span class="bar" aria-hidden="true"><i style="width:{width}%"></i></span>'
            f'<div><span class="drv-title">{_e(ft.title)}</span><span class="cat">{_e(ft.category)}</span>'
            f'<p class="ev">{ev}</p><p class="why">{_e(ft.why + counterfactual)}</p></div></li>')
    return f'<p class="math">{math_line}</p><ul class="drivers">{"".join(rows)}</ul>'


def _html_auth(r: AnalysisResult) -> str:
    a, rec, eff = r.auth, r.auth.recorded, r.auth.effective

    def rec_cell(kind: str) -> str:
        if kind == "spf" and rec.get("spf"):
            x = rec["spf"]
            return _res(x["result"]) + (f'<div class="meta">mailfrom {_e(x["mailfrom"])}</div>' if x.get("mailfrom") else "")
        if kind == "dkim" and rec.get("dkim"):
            return "<br>".join(_res(d["result"]) + (f' <span class="meta">d={_e(d["domain"])}</span>'
                                                    if d["domain"] not in ("", "none") else "") for d in rec["dkim"])
        if kind == "dmarc" and rec.get("dmarc"):
            x = rec["dmarc"]
            return _res(x["result"]) + (f'<div class="meta">policy {_e(x["policy"])}</div>' if x.get("policy") else "")
        return '<span class="quiet">not recorded</span>'

    def live_cell(kind: str) -> str:
        if kind == "dkim":
            if not a.dkim_live:
                return '<span class="quiet">no DKIM signature</span>'
            return "<br>".join(_res(c["result"]) + f' <span class="meta">d={_e(c["domain"])} s={_e(c["selector"])}'
                               + (f" - {_e(c['reason'])}" if c.get("reason") else "") + "</span>" for c in a.dkim_live)
        if not a.live_enabled:
            return '<span class="quiet">not checked</span>'
        if kind == "spf":
            if not a.spf_live:
                return '<span class="quiet">not possible (sender IP unknown)</span>'
            s = a.spf_live
            return _res(s["result"]) + f'<div class="meta">{_e(s["domain"])}, {s["lookups"]} DNS lookup(s)' + \
                (f" - {_e(s['error'])}" if s.get("error") else "") + "</div>"
        dm = a.dmarc_record or {}
        if dm.get("status") == "found":
            pol = dm["sp"] if dm["inherited"] and dm["sp"] else dm["policy"]
            return _res(a.dmarc_live or "unknown") + f'<div class="meta">record p={_e(pol)}' + \
                (" (inherited from organizational domain)" if dm["inherited"] else "") + "</div>"
        if dm.get("status") == "none":
            return _res("none") + '<div class="meta">no DMARC record published</div>'
        return _res(dm.get("status", "unknown"))

    rows = "".join(f"<tr><td><b>{k.upper()}</b></td><td>{rec_cell(k)}</td><td>{live_cell(k)}</td>"
                   f"<td>{_res(eff.get(k, 'unknown'))}<div class='meta'>{_e(eff.get(k + '_source', ''))}</div></td></tr>"
                   for k in ("spf", "dkim", "dmarc"))
    al = a.alignment or {}

    def yn(v: Optional[bool]) -> str:
        return "unknown" if v is None else "yes" if v else "no"

    kv = [("Sending server IP", f"{a.origin_ip or 'unknown'}" + (f" (from {a.origin_ip_source})" if a.origin_ip_source else "")),
          ("Envelope sender", f"{a.mail_from or 'unknown'}" + (f" (from {a.mail_from_source})" if a.mail_from_source else "")),
          ("DMARC alignment", f"SPF aligned: {yn(al.get('spf'))}, DKIM aligned: {yn(al.get('dkim'))}"),
          ("Effective policy", eff.get("policy") or "unknown")]
    if a.dmarc_record and a.dmarc_record.get("record"):
        kv.append(("DMARC record", a.dmarc_record["record"]))
    if a.domain_check:
        kv.append(("Sender domain mail check", f"{a.domain_check['status']}: {a.domain_check.get('detail', '')}"))
    if not a.live_enabled and a.live_note:
        kv.append(("Live checks", a.live_note))
    out = [f'<div class="scroll"><table><thead><tr><th>Check</th><th>At delivery (recorded)</th>'
           f'<th>Live re-check</th><th>Used for score</th></tr></thead><tbody>{rows}</tbody></table></div>',
           '<dl class="kv">' + "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in kv) + "</dl>"]
    if a.notes:
        out.append('<ul class="notes">' + "".join(f"<li>{_e(n)}</li>" for n in a.notes) + "</ul>")
    if a.spf_live and a.spf_live.get("trace"):
        out.append("<details><summary>SPF evaluation trace</summary><pre>" + _e("\n".join(a.spf_live["trace"])) + "</pre></details>")
    if rec.get("raw"):
        out.append("<details><summary>Recorded Authentication-Results</summary><pre>" + _e("\n\n".join(rec["raw"])) + "</pre></details>")
    return "".join(out)


def _intel_cell(lk: Link, feeds_loaded: bool) -> str:
    parts = []
    if lk.feed:
        parts.append(f'<span class="hit">Listed in {_e(lk.feed["feed"])}</span><div class="meta">{_e(lk.feed["match"])} '
                     f'match: {_e(defang(lk.feed["entry"]))}</div>')
    elif lk.host:
        parts.append('<span class="quiet">Not in threat feed</span>' if feeds_loaded else '<span class="quiet">No feed loaded</span>')
    vt = lk.vt
    if vt:
        if vt.get("status") == "found":
            cls = "hit" if vt["malicious"] or vt["suspicious"] else "quiet"
            parts.append(f'<div class="{cls}">VirusTotal: {vt["malicious"]} malicious, {vt["suspicious"]} suspicious, '
                         f'{vt["harmless"]} harmless</div>')
            if vt.get("engines"):
                parts.append(f'<div class="meta">{_e(", ".join(vt["engines"][:4]))}</div>')
        elif vt.get("status") == "not found":
            parts.append('<div class="quiet">VirusTotal: no report yet</div>')
        else:
            parts.append(f'<div class="quiet">VirusTotal: {_e(vt.get("error", "error"))}</div>')
        if vt.get("gui"):
            parts.append(f'<div class="meta"><a href="{_e(vt["gui"])}" rel="noreferrer noopener" target="_blank">'
                         f'Open VirusTotal report</a></div>')
    return "".join(parts)


def _html_links(r: AnalysisResult, feeds_loaded: bool) -> str:
    links = sorted(r.email.links, key=lambda lk: (-(lk.risk + (4 if lk.feed else 0)), lk.url))
    if not links:
        return '<p class="quiet">No links found.</p>'
    rows = []
    for lk in links[:60]:
        meta = []
        if lk.text:
            meta.append(f"Shown as: \u201c{_e(shorten(lk.text, 90))}\u201d")
        meta.append(f"Found in: {_e(lk.source)}")
        if lk.wrapper:
            meta.append(f"Unwrapped from {_e(lk.wrapper)}")
        flags = ("<ul class='flags'>" + "".join(f"<li><b>{_e(c)}</b>{_e(d)}</li>" for c, d in lk.flags) + "</ul>"
                 if lk.flags else '<span class="quiet">No issues found</span>')
        rows.append(f"<tr><td><code>{_e(defang(lk.url))}</code><div class='meta'>{'<br>'.join(meta)}</div></td>"
                    f"<td>{flags}</td><td>{_intel_cell(lk, feeds_loaded)}</td></tr>")
    more = f'<p class="meta">{len(links) - 60} more link(s) are listed in the JSON report.</p>' if len(links) > 60 else ""
    return ('<div class="scroll"><table><thead><tr><th style="width:42%">Destination (defanged)</th><th>Findings</th>'
            f'<th style="width:24%">Threat intelligence</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>{more}')


def _html_attachments(r: AnalysisResult) -> str:
    if not r.email.attachments:
        return '<p class="quiet">No attachments.</p>'
    rows = []
    for at in r.email.attachments:
        flags = ("<ul class='flags'>" + "".join(f"<li><b>{_e(c)}</b>{_e(d)}</li>" for c, d in at.flags) + "</ul>"
                 if at.flags else '<span class="quiet">No issues found</span>')
        inner = f'<div class="meta">Contains: {_e(", ".join(at.inner_files[:8]))}</div>' if at.inner_files else ""
        vt = ""
        if at.vt:
            if at.vt.get("status") == "found":
                vt = f'<div class="{"hit" if at.vt["malicious"] else "quiet"}">VirusTotal: {at.vt["malicious"]} malicious</div>'
            elif at.vt.get("status") == "not found":
                vt = '<div class="quiet">VirusTotal: hash not known</div>'
        rows.append(f"<tr><td><code>{_e(at.filename)}</code><div class='meta'>{_e(at.content_type)}, "
                    f"{_e(fmt_bytes(at.size))}{', content: ' + _e(at.magic) if at.magic else ''}</div>{inner}</td>"
                    f"<td>{flags}</td><td><code>{_e(at.sha256)}</code>{vt}</td></tr>")
    return ('<div class="scroll"><table><thead><tr><th>File</th><th>Findings</th><th style="width:30%">SHA-256</th>'
            f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div>')


_CATEGORY_NAMES = {"urgency": "Urgency", "threat": "Threats", "credential": "Credential requests",
                   "financial": "Money and invoices", "reward": "Rewards", "greeting": "Generic greeting",
                   "cta": "Calls to action", "bec": "BEC phrasing", "gift_card": "Gift cards"}


def _html_language(r: AnalysisResult) -> str:
    hits, st = r.nlp["hits"], r.nlp["stats"]
    rows = "".join(f"<tr><td>{_e(_CATEGORY_NAMES.get(cat, cat))}</td><td><div class='chips'>"
                   + "".join(f"<span class='chip'>{_e(h)}</span>" for h in found) + "</div></td></tr>"
                   for cat, found in hits.items() if found)
    table = (f'<table><thead><tr><th style="width:24%">Lexicon</th><th>Matched phrases</th></tr></thead>'
             f'<tbody>{rows}</tbody></table>' if rows else '<p class="quiet">No phishing phrases matched.</p>')
    kv = [("Words", st["words"]), ("Sentences", st["sentences"]), ("Average word length", st["avg_word_length"]),
          ("Words in capitals", f"{st['caps_ratio']:.0%}"), ("Exclamation marks", st["exclamations"]),
          ("Links per 100 words", st["link_density"]),
          ("Most frequent terms", ", ".join(f"{w} ({n})" for w, n in st["top_terms"][:8]) or "none")]
    excerpt = _URL_IN_TEXT.sub(lambda m: defang(m.group(0)), r.email.visible_text[:1500])
    return (table + '<dl class="kv">' + "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in kv) + "</dl>"
            + "<details><summary>Visible text excerpt (links defanged)</summary><pre>" + _e(excerpt or "(empty)")
            + "</pre></details>")


def _html_path(r: AnalysisResult) -> str:
    hops = r.email.hops
    if not hops:
        return '<p class="quiet">No Received headers.</p>'
    rows = "".join(
        f"<tr><td class='num'>{h.number}</td><td><code>{_e(h.from_host or '-')}</code>"
        f"<div class='meta'>{_e(h.from_ip)}</div></td><td><code>{_e(h.by_host or '-')}</code></td>"
        f"<td>{_e(h.protocol)}</td><td class='mono'>{_e(h.timestamp[:19].replace('T', ' ') if h.timestamp else '')}</td>"
        f"<td class='num'>{'' if h.delay_s is None else _e(f'{h.delay_s:.0f}s')}</td></tr>" for h in hops)
    return ('<div class="scroll"><table><thead><tr><th>Hop</th><th>From</th><th>By</th><th>Protocol</th>'
            f'<th>Time</th><th>Delay</th></tr></thead><tbody>{rows}</tbody></table></div>'
            '<p class="meta">Hop 1 is the first server that handled the message; only the top hops, added by your '
            'own provider, can be fully trusted.</p>')


def _html_case(r: AnalysisResult, idx: int, total: int, stamp_date: str, feeds_loaded: bool) -> str:
    pe = r.email
    addr = [("From", f"{pe.from_display} <{pe.from_addr}>" if pe.from_display else pe.from_addr or "(none)")]
    if pe.reply_to:
        addr.append(("Reply-To", ", ".join(pe.reply_to)))
    addr += [("To", ", ".join(pe.to[:4]) + (" ..." if len(pe.to) > 4 else "") or "(none)"),
             ("Date", pe.date_raw or "(none)"), ("Source", pe.label)]
    recs = "".join(f"<li>{_e(x)}</li>" for x in r.recommendations)
    notes = "".join(f"<li>{_e(n)}</li>" for n in r.notes)
    headers = "\n".join(f"{k}: {shorten(v, 600)}" for k, v in pe.headers[:150])
    return f"""<article class="case v-{r.level}" id="m{idx}">
<div class="case-head">{_postmark_svg(r, idx, stamp_date)}
<div class="envelope"><p class="case-no">Message {idx} of {total}</p><h2 class="subject">{_e(pe.subject or '(no subject)')}</h2>
<dl class="addr">{''.join(f'<dt>{_e(k)}</dt><dd>{_e(v)}</dd>' for k, v in addr)}</dl></div></div>
<p class="summary">{_e(r.summary)}</p>
<h3>Why this score</h3>{_html_drivers(r)}
<h3>What to do</h3><ul class="todo">{recs}</ul>{f'<ul class="notes">{notes}</ul>' if notes else ''}
<details open><summary>Sender authentication</summary>{_html_auth(r)}</details>
<details open><summary>Links<span class="count">{len(pe.links)}</span></summary>{_html_links(r, feeds_loaded)}</details>
<details{' open' if pe.attachments else ''}><summary>Attachments<span class="count">{len(pe.attachments)}</span></summary>{_html_attachments(r)}</details>
<details><summary>Language analysis</summary>{_html_language(r)}</details>
<details><summary>Delivery path<span class="count">{len(pe.hops)} hops</span></summary>{_html_path(r)}</details>
<details><summary>Raw headers</summary><pre>{_e(headers)}</pre></details>
</article>"""


def render_html(results: list, meta: dict) -> str:
    stamp_date = datetime.fromisoformat(meta["generated"]).strftime("%b %d %Y").upper()
    feeds_loaded = any(f.get("status") == "loaded" for f in meta.get("feeds", []))
    counts = Counter(r.level for r in results)
    tally = ", ".join(f"{counts[l]} {name.lower()}" for l, name in
                      (("critical", "Phishing"), ("high", "Likely phishing"), ("medium", "Suspicious"),
                       ("low", "Likely legitimate")) if counts[l])
    feeds = "; ".join(f"{f['name']}: " + (f"{f['count']} entries ({f['source']})" if f["status"] == "loaded"
                                          else f"unavailable ({f.get('note', '')})") for f in meta["feeds"]) or "none"
    run = [("Mode", meta["mode_label"]), ("DNS", meta["dns"]), ("Threat feeds", feeds),
           ("VirusTotal", meta["virustotal"]), ("Generated", meta["generated_label"]),
           ("Tool", f"{TOOL_NAME} {__version__}, Python {meta['python']}")]
    warn = ('<ul class="warnings">' + "".join(f"<li>{_e(w)}</li>" for w in meta["warnings"]) + "</ul>"
            if meta.get("warnings") else "")
    overview = ""
    if len(results) > 1:
        rows = "".join(
            f'<tr><td class="num"><a href="#m{i}">{i}</a></td><td><span class="pill lvl-{r.level}">{_e(r.verdict)}</span></td>'
            f'<td class="num">{_e(fmt_prob(r.probability))}</td><td>{_e(shorten(r.email.subject or "(no subject)", 70))}</td>'
            f'<td><code>{_e(r.email.from_addr)}</code></td><td class="meta">{_e(r.email.label)}</td></tr>'
            for i, r in enumerate(results, 1))
        overview = ('<section class="overview"><h2>Messages</h2><div class="scroll"><table><thead><tr><th>#</th>'
                    '<th>Verdict</th><th>Probability</th><th>Subject</th><th>From</th><th>Source</th></tr></thead>'
                    f'<tbody>{rows}</tbody></table></div></section>')
    cases = "".join(_html_case(r, i, len(results), stamp_date, feeds_loaded) for i, r in enumerate(results, 1))
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>Phishing analysis report ({len(results)} message{'s' if len(results) != 1 else ''})</title>
<style>{REPORT_CSS}</style></head>
<body><div class="wrap">
<header class="masthead"><div><h1>Phishing analysis report</h1>
<p class="lede">{len(results)} message{'s' if len(results) != 1 else ''} analyzed: {_e(tally)}. Links in this report are defanged and were never visited.</p>{warn}</div>
<dl class="runinfo">{''.join(f'<dt>{_e(k)}</dt><dd>{_e(v)}</dd>' for k, v in run)}</dl></header>
{overview}{cases}
<footer><p><b>How the score works.</b> Each indicator adds or subtracts log-odds points; the total z goes through the
logistic function p = 1 / (1 + e<sup>-z</sup>). The weights were set by hand from published phishing research rather than
trained on your mail, so read the probability as an informed estimate, not a certainty.</p>
<p><b>Authentication.</b> The verdicts your mail provider recorded at delivery (topmost Authentication-Results header) are
trusted first; live DNS checks re-evaluate SPF, verify DKIM signatures and look up DMARC policy to corroborate them.</p>
<p><b>Sources.</b> OpenPhish Community Feed (free for non-commercial use). VirusTotal public API (reports only;
nothing is submitted). This report is self-contained: scripts and remote content are blocked.</p></footer>
</div></body></html>"""


# ============================================================================
# Reports: PDF (reportlab)
# ============================================================================
LEVEL_HEX = {"low": "#2B7A4B", "medium": "#9C5B00", "high": "#C0391F", "critical": "#8B1A1A"}


def _find_ttf_fonts() -> Optional[tuple[Path, Path, Path]]:
    """A Unicode TTF family so look-alike characters (Cyrillic, Greek) render instead of black boxes."""
    candidates = []
    try:
        import importlib.util
        spec = importlib.util.find_spec("matplotlib")  # Colab always has matplotlib, which bundles DejaVu
        if spec and spec.origin:
            base = Path(spec.origin).parent / "mpl-data" / "fonts" / "ttf"
            candidates.append((base / "DejaVuSans.ttf", base / "DejaVuSans-Bold.ttf", base / "DejaVuSansMono.ttf"))
    except Exception:
        pass
    dv = Path("/usr/share/fonts/truetype/dejavu")
    win = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
    mac = Path("/System/Library/Fonts/Supplemental")
    candidates += [(dv / "DejaVuSans.ttf", dv / "DejaVuSans-Bold.ttf", dv / "DejaVuSansMono.ttf"),
                   (win / "arial.ttf", win / "arialbd.ttf", win / "consola.ttf"),
                   (mac / "Arial.ttf", mac / "Arial Bold.ttf", mac / "Courier New.ttf")]
    for regular, bold, mono in candidates:
        try:
            if regular.exists() and bold.exists() and mono.exists():
                return regular, bold, mono
        except OSError:
            continue
    return None


def write_pdf(results: list, meta: dict, path: Path) -> Optional[str]:
    """Returns None on success, otherwise the reason the PDF was skipped."""
    try:
        from reportlab.graphics.shapes import Circle, Drawing, Group, PolyLine, String
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_RIGHT
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import (KeepTogether, ListFlowable, ListItem, PageBreak, Paragraph,
                                        SimpleDocTemplate, Spacer, Table, TableStyle)
    except ImportError:
        return "reportlab is not installed (pip install reportlab)"

    fonts = _find_ttf_fonts()
    unicode_ok = False
    F, FB, FM = "Helvetica", "Helvetica-Bold", "Courier"
    if fonts:
        try:
            pdfmetrics.registerFont(TTFont("PD-Sans", str(fonts[0])))
            pdfmetrics.registerFont(TTFont("PD-Sans-Bold", str(fonts[1])))
            pdfmetrics.registerFont(TTFont("PD-Mono", str(fonts[2])))
            from reportlab.pdfbase.pdfmetrics import registerFontFamily
            registerFontFamily("PD-Sans", normal="PD-Sans", bold="PD-Sans-Bold", italic="PD-Sans",
                               boldItalic="PD-Sans-Bold")
            F, FB, FM, unicode_ok = "PD-Sans", "PD-Sans-Bold", "PD-Mono", True
        except Exception:
            pass

    INK, SLATE = colors.HexColor("#16202C"), colors.HexColor("#566273")
    RULE, HEADBG = colors.HexColor("#DCE2EA"), colors.HexColor("#EAF0F7")
    BAD, OK = colors.HexColor("#B3261E"), colors.HexColor("#2B7A4B")

    def t(value: Any) -> str:
        s = "" if value is None else str(value)
        s = "".join(ch for ch in s if ch in "\n\t" or ord(ch) >= 32)
        s = "".join(ch if ord(ch) <= 0xFFFF else "?" for ch in s)
        if not unicode_ok:
            s = s.encode("latin-1", "replace").decode("latin-1")
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    base = ParagraphStyle("base", fontName=F, fontSize=8.6, leading=11.4, textColor=INK)
    small = ParagraphStyle("small", parent=base, fontSize=7.5, leading=9.8, textColor=SLATE)
    mono = ParagraphStyle("mono", parent=base, fontName=FM, fontSize=7.1, leading=9.2, wordWrap="CJK")
    bold = ParagraphStyle("bold", parent=base, fontName=FB)
    h1 = ParagraphStyle("h1", parent=base, fontName=FB, fontSize=19, leading=23, spaceAfter=3)
    h2 = ParagraphStyle("h2", parent=base, fontName=FB, fontSize=13, leading=16, spaceAfter=5)
    h3 = ParagraphStyle("h3", parent=base, fontName=FB, fontSize=10.5, leading=13, spaceBefore=10, spaceAfter=4,
                        textColor=colors.HexColor("#1C4F8C"))
    pts_style = ParagraphStyle("pts", parent=base, fontName=FM, fontSize=9, alignment=TA_RIGHT)

    def P(text: Any, style=base) -> Paragraph:
        return Paragraph(t(text), style)

    def table(rows: list, widths: list, header: bool = True) -> Table:
        tb = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
        cmds = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
        if header:
            cmds += [("BACKGROUND", (0, 0), (-1, 0), HEADBG), ("LINEBELOW", (0, 0), (-1, 0), 0.8, SLATE)]
        tb.setStyle(TableStyle(cmds))
        return tb

    def postmark(r: AnalysisResult) -> Drawing:
        col = colors.HexColor(LEVEL_HEX[r.level])
        d = Drawing(150, 100)
        g = Group()
        cx, cy = 48, 50
        g.add(Circle(cx, cy, 45, strokeColor=col, fillColor=None, strokeWidth=1.8))
        g.add(Circle(cx, cy, 33, strokeColor=col, fillColor=None, strokeWidth=0.9))
        for y in (32, 44, 56, 68):
            pts = []
            for k in range(0, 49):
                pts += [97 + k, y + 2.4 * math.sin(k / 48 * 4 * math.pi)]
            g.add(PolyLine(pts, strokeColor=col, strokeWidth=1.7))
        g.add(String(cx, cy + 16, "PHISH DETECTOR", fontName=FB, fontSize=5, fillColor=col, textAnchor="middle"))
        g.add(String(cx, cy - 4, _stamp_pct(r.probability), fontName=FB, fontSize=17, fillColor=col, textAnchor="middle"))
        g.add(String(cx, cy - 15, r.verdict.upper(), fontName=FB, fontSize=5, fillColor=col, textAnchor="middle"))
        g.translate(2, 6)
        g.rotate(-5)
        d.add(g)
        return d

    W = letter[0] - 1.2 * inch
    story: list = [P("Phishing analysis report", h1)]
    counts = Counter(r.level for r in results)
    tally = ", ".join(f"{counts[l]} {n}" for l, n in (("critical", "phishing"), ("high", "likely phishing"),
                                                      ("medium", "suspicious"), ("low", "likely legitimate"))
                      if counts[l])
    story.append(P(f"{len(results)} message(s) analyzed: {tally}. Links are defanged and were never visited.", small))
    story.append(Spacer(1, 8))
    feeds = "; ".join(f"{f['name']}: " + (f"{f['count']} entries" if f["status"] == "loaded" else "unavailable")
                      for f in meta["feeds"]) or "none"
    run_rows = [[P("Mode", small), P(meta["mode_label"])], [P("DNS", small), P(meta["dns"])],
                [P("Threat feeds", small), P(feeds)], [P("VirusTotal", small), P(meta["virustotal"])],
                [P("Generated", small), P(meta["generated_label"])],
                [P("Tool", small), P(f"{TOOL_NAME} {__version__}, Python {meta['python']}")]]
    for w_ in meta.get("warnings", [])[:6]:
        run_rows.append([P("Warning", small), P(w_)])
    story.append(table(run_rows, [0.95 * inch, W - 0.95 * inch], header=False))
    if len(results) > 1:
        story += [Spacer(1, 10), P("Messages", h3)]
        rows = [[P("#", bold), P("Verdict", bold), P("Prob.", bold), P("Subject", bold), P("From", bold)]]
        for i, r in enumerate(results, 1):
            col = colors.HexColor(LEVEL_HEX[r.level])
            rows.append([P(i), Paragraph(f'<font color="{col.hexval()}"><b>{t(r.verdict)}</b></font>', base),
                         P(fmt_prob(r.probability)), P(shorten(r.email.subject or "(no subject)", 70)),
                         P(r.email.from_addr, mono)])
        story.append(table(rows, [0.3 * inch, 1.1 * inch, 0.6 * inch, W - 3.75 * inch, 1.75 * inch]))

    for i, r in enumerate(results, 1):
        pe, a = r.email, r.auth
        story.append(PageBreak())
        addr = [[P("From", small), P(f"{pe.from_display} <{pe.from_addr}>" if pe.from_display else pe.from_addr)]]
        if pe.reply_to:
            addr.append([P("Reply-To", small), P(", ".join(pe.reply_to))])
        addr += [[P("To", small), P(", ".join(pe.to[:3]) or "(none)")], [P("Date", small), P(pe.date_raw or "(none)")],
                 [P("Source", small), P(pe.label)]]
        addr_tb = Table(addr, colWidths=[0.65 * inch, W - 2.25 * inch - 0.65 * inch])
        addr_tb.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                     ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
        head = Table([[postmark(r), [P(f"Message {i} of {len(results)}", small), P(pe.subject or "(no subject)", h2), addr_tb]]],
                     colWidths=[2.25 * inch, W - 2.25 * inch])
        head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        story.append(head)
        summ = Table([[P(r.summary)]], colWidths=[W])
        summ.setStyle(TableStyle([("LINEBEFORE", (0, 0), (0, 0), 2.5, colors.HexColor(LEVEL_HEX[r.level])),
                                  ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
        story += [Spacer(1, 4), summ, P("Why this score", h3)]
        total = sum(ft.weight for ft in r.features)
        story.append(P(f"Base {BIAS * 10:+.0f} points, indicators {total * 10:+.0f} points, total {r.logit * 10:+.0f} "
                       f"points; probability = 1 / (1 + e^({-r.logit:+.2f})) = {fmt_prob(r.probability)}. "
                       f"Points are log-odds x 10.", small))
        story.append(Spacer(1, 3))
        rows = [[P("Points", bold), P("Indicator", bold), P("Evidence and reasoning", bold)]]
        for ft in r.features:
            col = BAD if ft.weight > 0 else OK
            rows.append([Paragraph(f'<font color="{col.hexval()}">{ft.weight * 10:+.0f}</font>', pts_style),
                         [P(ft.title, bold), P(ft.category, small)],
                         [P("\n".join(ft.evidence), mono), P(ft.why, small)]])
        if len(rows) == 1:
            rows.append([P(""), P("No indicators fired"), P("")])
        story.append(table(rows, [0.55 * inch, 1.85 * inch, W - 2.4 * inch]))
        story.append(P("What to do", h3))
        story.append(ListFlowable([ListItem(P(x), leftIndent=10) for x in r.recommendations], bulletType="bullet",
                                  start="\u2022", leftIndent=10, bulletFontName=F))
        for note in r.notes:
            story.append(P(note, small))

        story.append(P("Sender authentication", h3))
        rec, eff = a.recorded, a.effective

        def rec_txt(k: str) -> str:
            if k == "dkim":
                return ", ".join(d["result"] + (f" (d={d['domain']})" if d["domain"] not in ("", "none") else "")
                                 for d in rec.get("dkim", [])) or "not recorded"
            x = rec.get(k)
            return f"{x['result']}" + (f", policy {x['policy']}" if k == "dmarc" and x.get("policy") else "") if x else "not recorded"

        def live_txt(k: str) -> str:
            if k == "dkim":
                return "; ".join(f"{c['result']} d={c['domain']}" + (f" ({c['reason']})" if c.get("reason") else "")
                                 for c in a.dkim_live) or "no signature"
            if not a.live_enabled:
                return "not checked"
            if k == "spf":
                return f"{a.spf_live['result']} ({a.spf_live['domain']})" if a.spf_live else "sender IP unknown"
            dm = a.dmarc_record or {}
            return f"{a.dmarc_live or dm.get('status', 'unknown')}" + (f" (p={dm.get('policy')})" if dm.get("policy") else "")

        rows = [[P("Check", bold), P("At delivery", bold), P("Live re-check", bold), P("Used for score", bold)]]
        for k in ("spf", "dkim", "dmarc"):
            rows.append([P(k.upper(), bold), P(rec_txt(k)), P(live_txt(k)),
                         P(f"{eff.get(k, 'unknown')} ({eff.get(k + '_source') or 'n/a'})")])
        story.append(table(rows, [0.6 * inch, 1.9 * inch, 2.6 * inch, W - 5.1 * inch]))
        al = a.alignment or {}
        kv = [["Sending IP", f"{a.origin_ip or 'unknown'} ({a.origin_ip_source or 'n/a'})"],
              ["Envelope sender", f"{a.mail_from or 'unknown'} ({a.mail_from_source or 'n/a'})"],
              ["Alignment", f"SPF aligned: {al.get('spf')}, DKIM aligned: {al.get('dkim')}"]]
        if not a.live_enabled and a.live_note:
            kv.append(["Live checks", a.live_note])
        kv += [["Note", n] for n in a.notes]
        story.append(Spacer(1, 3))
        story.append(table([[P(k_, small), P(v_)] for k_, v_ in kv], [1.1 * inch, W - 1.1 * inch], header=False))

        story.append(P(f"Links ({len(pe.links)})", h3))
        if pe.links:
            rows = [[P("Destination (defanged)", bold), P("Findings", bold), P("Threat intelligence", bold)]]
            for lk in sorted(pe.links, key=lambda x: (-(x.risk + (4 if x.feed else 0)), x.url))[:30]:
                dest = [P(defang(lk.url), mono)]
                if lk.text:
                    dest.append(P(f"Shown as: {shorten(lk.text, 80)}", small))
                if lk.wrapper:
                    dest.append(P(f"Unwrapped from {lk.wrapper}", small))
                findings = [Paragraph(f"<b>{t(c)}</b> {t(d)}", base) for c, d in lk.flags] or [P("No issues found", small)]
                intel = []
                if lk.feed:
                    intel.append(Paragraph(f'<font color="{BAD.hexval()}"><b>Listed: {t(lk.feed["feed"])}</b></font>'
                                           f' ({t(lk.feed["match"])} match)', base))
                if lk.vt and lk.vt.get("status") == "found":
                    intel.append(P(f"VirusTotal: {lk.vt['malicious']} malicious, {lk.vt['suspicious']} suspicious"))
                elif lk.vt:
                    intel.append(P(f"VirusTotal: {lk.vt.get('status')}", small))
                rows.append([dest, findings, intel or [P("-", small)]])
            story.append(table(rows, [2.6 * inch, W - 4.2 * inch, 1.6 * inch]))
        else:
            story.append(P("No links found.", small))

        if pe.attachments:
            story.append(P(f"Attachments ({len(pe.attachments)})", h3))
            rows = [[P("File", bold), P("Findings", bold), P("SHA-256", bold)]]
            for at in pe.attachments:
                findings = [Paragraph(f"<b>{t(c)}</b> {t(d)}", base) for c, d in at.flags] or [P("No issues found", small)]
                rows.append([[P(at.filename, mono), P(f"{at.content_type}, {fmt_bytes(at.size)}", small)],
                             findings, P(at.sha256, mono)])
            story.append(table(rows, [1.9 * inch, W - 3.6 * inch, 1.7 * inch]))

        hits = [(cat, found) for cat, found in r.nlp["hits"].items() if found]
        st = r.nlp["stats"]
        lang = [P("Language analysis (NLP-lite)", h3)]
        if hits:
            rows = [[P("Lexicon", bold), P("Matched phrases", bold)]]
            rows += [[P(_CATEGORY_NAMES.get(c, c)), P(", ".join(f)) ] for c, f in hits]
            lang.append(table(rows, [1.5 * inch, W - 1.5 * inch]))
        else:
            lang.append(P("No phishing phrases matched.", small))
        lang.append(Spacer(1, 3))
        lang.append(P(f"{st['words']} words, {st['sentences']} sentences, {st['caps_ratio']:.0%} in capitals, "
                      f"{st['exclamations']} exclamation marks, {st['link_density']} links per 100 words. "
                      f"Top terms: " + (", ".join(w for w, _ in st["top_terms"][:8]) or "none") + ".", small))
        story.append(KeepTogether(lang))

        if pe.hops:
            story.append(P(f"Delivery path ({len(pe.hops)} hops)", h3))
            rows = [[P("Hop", bold), P("From", bold), P("By", bold), P("Time (UTC offset kept)", bold)]]
            for h in pe.hops:
                rows.append([P(h.number), [P(h.from_host or "-", mono), P(h.from_ip, small)], P(h.by_host or "-", mono),
                             P((h.timestamp or "")[:19].replace("T", " "), small)])
            story.append(table(rows, [0.4 * inch, 2.6 * inch, 2.5 * inch, W - 5.5 * inch]))

    def furniture(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont(F, 7)
        canvas.setFillColor(SLATE)
        canvas.drawString(0.6 * inch, letter[1] - 0.42 * inch, "Phishing analysis report")
        canvas.drawRightString(letter[0] - 0.6 * inch, letter[1] - 0.42 * inch, meta["generated_label"])
        canvas.drawString(0.6 * inch, 0.4 * inch, f"{TOOL_NAME} {__version__} - links defanged, nothing was visited")
        canvas.drawRightString(letter[0] - 0.6 * inch, 0.4 * inch, f"Page {doc.page}")
        canvas.setStrokeColor(RULE)
        canvas.line(0.6 * inch, letter[1] - 0.48 * inch, letter[0] - 0.6 * inch, letter[1] - 0.48 * inch)
        canvas.restoreState()

    doc = SimpleDocTemplate(str(path), pagesize=letter, leftMargin=0.6 * inch, rightMargin=0.6 * inch,
                            topMargin=0.7 * inch, bottomMargin=0.65 * inch, title="Phishing analysis report",
                            author=TOOL_NAME, subject="Automated phishing email analysis")
    try:
        doc.build(story, onFirstPage=furniture, onLaterPages=furniture)
    except Exception as exc:
        return f"PDF generation failed ({type(exc).__name__}: {shorten(str(exc), 150)})"
    return None


# ============================================================================
# Lab samples: fictional emails for safe offline practice (--lab / --make-samples)
# Domains use reserved names (.example, example.edu) or obviously fake look-alikes;
# IP addresses come from the documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x).
# ============================================================================
LAB_FEED_NAME = "lab_blocklist.feed"
LAB_FEED = ("# Lab blocklist used by the built-in samples (fictional indicators, not real threat data)\n"
            "http://paypa1-resolution-center.com/webscr\nlogin-m365-verify.web.app\n")


def _sample_bytes(trace: list, msg: EmailMessage) -> bytes:
    return ("\r\n".join(trace) + "\r\n").encode("utf-8") + msg.as_bytes(policy=email.policy.SMTP)


def _gmail_trace(sender: str, ip: str, host: str, when: str, dkim_d: str = "", dmarc: str = "pass (p=NONE sp=NONE dis=NONE)",
                 spf: str = "pass") -> list:
    verb = "designates" if spf == "pass" else "does not designate"
    lines = ["Delivered-To: jordan.lee@example.edu",
             f"Received: from {host} ({host}. [{ip}]) by mx.google.com with ESMTPS id 6a1803df08f44-7c9e; {when}",
             f"Received-SPF: {spf} (google.com: domain of {sender} {verb} {ip} as permitted sender) client-ip={ip};"]
    ar = "Authentication-Results: mx.google.com;"
    if dkim_d:
        ar += f" dkim=pass header.i=@{dkim_d} header.s=s2026 header.b=Lab0;"
    ar += (f" spf={spf} (google.com: domain of {sender} {verb} {ip} as permitted sender) smtp.mailfrom={sender};"
           f" dmarc={dmarc} header.from={sender.rsplit('@', 1)[1]}")
    return lines + [ar, f"Return-Path: <{sender}>"]


def build_samples() -> dict:
    samples: dict[str, bytes] = {}
    # 1 -- PayPal credential phish received by Microsoft 365 (Safe Links, look-alike domain, hidden text)
    m = EmailMessage()
    m["From"] = '"PayPal Service" <service@paypa1-resolution-center.com>'
    m["Reply-To"] = '"PayPal Resolution" <paypal.resolution.desk@gmail.com>'
    m["To"] = "jordan.lee@example.edu"
    m["Subject"] = "Your account access has been limited - action required [Case PP-0247-881]"
    m["Date"] = "Tue, 06 Oct 2026 08:14:52 -0700"
    m["Message-ID"] = "<20261006151452.4f2a91@mailer.paypa1-resolution-center.com>"
    m["X-Mailer"] = "PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)"
    safelink = ("https://nam12.safelinks.protection.outlook.com/?url=http%3A%2F%2Fpaypa1-resolution-center.com%2F"
                "webscr%3Fcmd%3D_login-submit%26case%3DPP-0247-881&data=05%7C02%7C&sdata=Xk2&reserved=0")
    salad = " ".join(["Thank you for your order. Your receipt and shipping details are listed below."] * 8)
    m.set_content("Dear Customer,\n\nWe noticed unusual activity on your PayPal account. As a security precaution, "
                  "your account access has been temporarily limited.\n\nTo restore full access, verify your identity "
                  "within 24 hours. Failure to verify will result in permanent suspension of your account.\n\n"
                  "https://www.paypal.com/signin\n\nPayPal Security Team\n")
    m.add_alternative(f"""<html><body style="font-family:Arial,sans-serif;color:#222">
<div style="display:none;font-size:0;max-height:0;overflow:hidden">{salad}</div>
<p><img src="https://www.paypalobjects.com/webstatic/icon/pp258.png" width="120" alt="PayPal"></p>
<p>Dear Customer,</p>
<p>We noticed <b>unusual activity</b> on your PayPal account. As a security precaution, your account access has been
temporarily limited.</p>
<p>To restore full access, verify your identity within 24 hours. Failure to verify will result in permanent
suspension of your account.</p>
<p><a href="{safelink}">https://www.paypal.com/signin</a></p>
<p><a href="{safelink}" style="background:#0070ba;color:#fff;padding:10px 18px">Verify Now</a></p>
<p>Thank you for being a valued customer.<br>PayPal Security Team</p>
<img src="http://paypa1-resolution-center.com/t.gif?id=88213" width="1" height="1" alt="">
</body></html>""", subtype="html")
    samples["01_paypal_credential_phish.eml"] = _sample_bytes([
        "Received: from BN8PR12MB3301.namprd12.prod.outlook.com (2603:10b6:408:6e::20) by "
        "SA1PR12MB6680.namprd12.prod.outlook.com with HTTPS; Tue, 6 Oct 2026 15:14:58 +0000",
        "Authentication-Results: spf=pass (sender IP is 203.0.113.45) smtp.mailfrom=mailer.paypa1-resolution-center.com;"
        " dkim=none (message not signed) header.d=none;dmarc=none action=none "
        "header.from=paypa1-resolution-center.com;compauth=fail reason=601",
        "Received-SPF: Pass (protection.outlook.com: domain of mailer.paypa1-resolution-center.com designates "
        "203.0.113.45 as permitted sender) receiver=protection.outlook.com; client-ip=203.0.113.45; "
        "helo=mailer.paypa1-resolution-center.com;",
        "Received: from mailer.paypa1-resolution-center.com (203.0.113.45) by MW2NAM10FT004.mail.protection.outlook.com "
        "(10.13.155.21) with Microsoft SMTP Server id 15.20.8000.1 via Frontend Transport; Tue, 6 Oct 2026 15:14:55 +0000",
        "Received: from [10.8.0.12] (unknown [198.51.100.77]) by mailer.paypa1-resolution-center.com (Postfix) "
        "with ESMTPSA id 4F2A91; Tue, 6 Oct 2026 08:14:52 -0700",
        "Return-Path: <bounce-77213@mailer.paypa1-resolution-center.com>"], m)

    # 2 -- "Microsoft 365" password expiry from a compromised (fully authenticated) domain, HTML attachment
    m = EmailMessage()
    m["From"] = '"Microsoft 365 Admin" <it-desk@harborview-dental.example>'
    m["To"] = "jordan.lee@example.edu"
    m["Subject"] = "RE: Password Expiration Notice"
    m["Date"] = "Wed, 07 Oct 2026 06:02:07 -0700"
    m["Message-ID"] = "<CAH7x9Lk.20261007.6602@mail.harborview-dental.example>"
    m.set_content("Hello,\n\nYour Microsoft 365 password expires today. To keep your current password, open the "
                  "attached Password Retention Form and sign in to confirm your account.\n\nFailure to confirm "
                  "within 12 hours will result in your mailbox being disabled.\n\nIT Help Desk\n"
                  "Microsoft 365 Administration\n")
    target = base64.b64encode(b"https://login-m365-verify.web.app/submit.php").decode()
    page = (f'<!DOCTYPE html><html><head><title>Microsoft 365</title><script>var u = atob("{target}");'
            'function go(){ window.location.href = u; }</script></head><body style="font-family:Segoe UI,sans-serif">'
            '<h2>Sign in to keep your password</h2><form action="https://login-m365-verify.web.app/submit.php" '
            'method="post"><input type="email" name="login" placeholder="Email address"><br><input type="password" '
            'name="passwd" placeholder="Password"><br><button type="submit">Confirm</button></form></body></html>')
    m.add_attachment(page.encode("utf-8"), maintype="text", subtype="html", filename="Password_Retention_Form.pdf.html")
    samples["02_m365_password_html_attachment.eml"] = _sample_bytes(
        ["Delivered-To: jordan.lee@example.edu",
         "Received: by 2002:a05:7300:5e0c:b0:12a:8c3e:4f21 with SMTP id k12csp2214dyb; Wed, 7 Oct 2026 06:02:11 -0700 (PDT)"]
        + _gmail_trace("it-desk@harborview-dental.example", "192.0.2.61", "mail.harborview-dental.example",
                       "Wed, 07 Oct 2026 06:02:10 -0700 (PDT)", dkim_d="harborview-dental.example",
                       dmarc="pass (p=QUARANTINE sp=QUARANTINE dis=NONE)")[1:], m)

    # 3 -- Business email compromise: gift cards from a free webmail "president"
    m = EmailMessage()
    m["From"] = '"Dr. Elaine Porter, Office of the President" <elaine.porter.office@gmail.com>'
    m["Reply-To"] = "president.eporter@outlook.com"
    m["To"] = "jordan.lee@example.edu"
    m["Subject"] = "Quick favor"
    m["Date"] = "Thu, 08 Oct 2026 07:41:00 -0700"
    m["Message-ID"] = "<CAJ2kq9Mf7Rp0bXz@mail.gmail.com>"
    m.set_content("Hi Jordan,\n\nAre you available? I need you to handle a quick task for me discreetly. I'm in a "
                  "meeting and can't talk right now.\n\nI want to surprise a few staff members. Please purchase 5 "
                  "Apple gift cards at $100 each, scratch the back of each card, and send me pictures of the codes. "
                  "I will reimburse you this afternoon.\n\nKeep this confidential until I announce it.\n\n"
                  "Dr. Elaine Porter\nSent from my iPhone\n")
    samples["03_gift_card_bec.eml"] = _sample_bytes(
        _gmail_trace("elaine.porter.office@gmail.com", "209.85.220.41", "mail-sor-f41.google.com",
                     "Thu, 08 Oct 2026 07:41:03 -0700 (PDT)", dkim_d="gmail.com",
                     dmarc="pass (p=NONE sp=QUARANTINE dis=NONE)"), m)

    # 4 -- Legitimate shipping notification (fully authenticated, links stay on the sender's site)
    m = EmailMessage()
    m["From"] = '"Northwind Outfitters" <orders@northwind-outfitters.example>'
    m["To"] = "jordan.lee@example.edu"
    m["Subject"] = "Your order NW-58210 has shipped"
    m["Date"] = "Fri, 09 Oct 2026 12:20:38 -0700"
    m["Message-ID"] = "<order-58210.shipped.20261009@northwind-outfitters.example>"
    m["List-Unsubscribe"] = "<https://www.northwind-outfitters.example/unsubscribe?u=58210>"
    m.set_content("Hi Jordan,\n\nGood news - your order NW-58210 is on its way. Estimated delivery: Tuesday, "
                  "October 13.\n\nTrack your package: https://www.northwind-outfitters.example/orders/NW-58210/track\n\n"
                  "Thanks for shopping with us,\nNorthwind Outfitters\n")
    m.add_alternative("""<html><body style="font-family:Georgia,serif">
<p>Hi Jordan,</p><p>Good news - your order <b>NW-58210</b> is on its way. Estimated delivery: Tuesday, October 13.</p>
<p><a href="https://www.northwind-outfitters.example/orders/NW-58210/track">Track your package</a></p>
<table><tr><td>Trail Runner 2 jacket</td><td>1</td><td>$89.00</td></tr></table>
<p>Questions? Visit <a href="https://www.northwind-outfitters.example/help">www.northwind-outfitters.example/help</a>.</p>
<p>Thanks for shopping with us,<br>Northwind Outfitters</p></body></html>""", subtype="html")
    trace = _gmail_trace("bounces+8812@mail.northwind-outfitters.example", "198.51.100.24",
                         "o1.mail.northwind-outfitters.example", "Fri, 09 Oct 2026 12:20:41 -0700 (PDT)",
                         dkim_d="northwind-outfitters.example", dmarc="pass (p=REJECT sp=REJECT dis=NONE)")
    trace[-2] = trace[-2].replace("header.from=mail.northwind-outfitters.example",
                                  "header.from=northwind-outfitters.example")
    trace.append("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=northwind-outfitters.example; s=s2026; "
                 "h=from:to:subject:date:message-id; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; "
                 "b=dGhpcyBpcyBhIGxhYiBzYW1wbGUgc2lnbmF0dXJl")
    samples["04_legit_shipping_notice.eml"] = _sample_bytes(trace, m)

    # 5 -- MBOX export with two messages: USPS fee scam (IP link + shortener) and a normal note from a classmate
    m = EmailMessage()
    m["From"] = '"USPS Delivery" <noreply@usps-redelivery-notice.top>'
    m["To"] = "jordan.lee@example.edu"
    m["Subject"] = "USPS: Delivery attempt failed - action required"
    m["Date"] = "Sat, 10 Oct 2026 03:12:05 -0700"
    m["Message-ID"] = "<a81c2f0e9b@usps-redelivery-notice.top>"
    m.set_content("USPS NOTICE\n\nDear Customer,\n\nYour package could not be delivered due to an incomplete address. "
                  "A redelivery fee of $1.99 is required.\n\nUpdate your delivery details within 12 hours or the "
                  "package will be returned to the sender:\nhttp://203.0.113.200/usps/redelivery?id=US9514901185421\n\n"
                  "Alternative link: https://bit.ly/3usps-redeliver\n\nUSPS Customer Service\n")
    usps = _sample_bytes(["Delivered-To: jordan.lee@example.edu",
                          "Received: from usps-redelivery-notice.top (unknown [203.0.113.88]) by mx.google.com with "
                          "ESMTP id 98e67ed59e1d1-2f5a; Sat, 10 Oct 2026 03:12:09 -0700 (PDT)",
                          "Received-SPF: neutral (google.com: 203.0.113.88 is neither permitted nor denied by best "
                          "guess record for domain of noreply@usps-redelivery-notice.top) client-ip=203.0.113.88;",
                          "Authentication-Results: mx.google.com; spf=neutral (google.com: 203.0.113.88 is neither "
                          "permitted nor denied by best guess record for domain of noreply@usps-redelivery-notice.top) "
                          "smtp.mailfrom=noreply@usps-redelivery-notice.top; dmarc=none "
                          "header.from=usps-redelivery-notice.top",
                          "Return-Path: <noreply@usps-redelivery-notice.top>"], m)
    m = EmailMessage()
    m["From"] = '"Sam Rivera" <sam.rivera@example.edu>'
    m["To"] = "jordan.lee@example.edu"
    m["Subject"] = "Lunch Thursday?"
    m["Date"] = "Sat, 10 Oct 2026 18:30:12 -0700"
    m["Message-ID"] = "<CAP5rt8Q2s9@mail.gmail.com>"
    m.set_content("Hey Jordan,\n\nAre we still on for lunch Thursday after the 11:00 lab? I can meet at the student "
                  "center around 12:15.\n\nAlso, can you bring the notes from Tuesday's lecture?\n\nThanks,\nSam\n")
    friend = _sample_bytes(_gmail_trace("sam.rivera@example.edu", "209.85.220.69", "mail-sor-f69.google.com",
                                        "Sat, 10 Oct 2026 18:30:14 -0700 (PDT)", dkim_d="example.edu"), m)

    def mbox_entry(raw: bytes, sender: str, when: str) -> bytes:
        body = raw.replace(b"\r\n", b"\n")
        body = re.sub(rb"(?m)^(>*From )", rb">\1", body)
        return f"From {sender} {when}\n".encode("ascii") + body.rstrip(b"\n") + b"\n\n"

    samples["05_quarantine_export.mbox"] = (mbox_entry(usps, "noreply@usps-redelivery-notice.top", "Sat Oct 10 10:12:09 2026")
                                            + mbox_entry(friend, "sam.rivera@example.edu", "Sun Oct 11 01:30:14 2026"))

    # 6 -- A user reports a DocuSign lure by forwarding it as an attachment (message/rfc822)
    inner = EmailMessage()
    inner["From"] = '"DocuSign via Signature Service" <docs@docusign-envelope-review.com>'
    inner["To"] = "jordan.lee@example.edu"
    inner["Subject"] = "Please review and sign: Updated Payroll Agreement (2 pages)"
    inner["Date"] = "Mon, 12 Oct 2026 09:05:31 -0400"
    inner["Message-ID"] = "<env-7731-2026@docusign-envelope-review.com>"
    inner.set_content("Payroll Department sent you a document to review and sign.\n\nREVIEW DOCUMENT: "
                      "https://tinyurl.com/payroll-docs-2026\n\nThis message will expire in 48 hours. "
                      "Do not share this email.\n")
    inner.add_alternative("""<html><body style="font-family:Helvetica,Arial,sans-serif">
<div style="background:#1e4ca1;color:#fff;padding:18px"><b>DocuSign</b></div>
<p>Payroll Department sent you a document to review and sign.</p>
<p><a href="https://tinyurl.com/payroll-docs-2026" style="background:#ffc423;padding:10px 16px;color:#000">REVIEW DOCUMENT</a></p>
<p>This message will expire in 48 hours. Do not share this email.</p></body></html>""", subtype="html")
    inner_raw = _sample_bytes(_gmail_trace("docs@docusign-envelope-review.com", "198.51.100.140",
                                           "smtp.docusign-envelope-review.com", "Mon, 12 Oct 2026 06:05:36 -0700 (PDT)",
                                           spf="softfail", dmarc="none")[1:], inner)
    outer = EmailMessage()
    outer["From"] = '"Jordan Lee" <jordan.lee@example.edu>'
    outer["To"] = '"Security Team" <phishing-report@example.edu>'
    outer["Subject"] = "FW: Please review and sign: Updated Payroll Agreement (2 pages)"
    outer["Date"] = "Mon, 12 Oct 2026 09:20:44 -0400"
    outer["Message-ID"] = "<CAK8fwd0912@mail.gmail.com>"
    outer.set_content("Reporting this suspicious message. I did not click anything.\n\nJordan\n")
    outer.add_attachment(email.message_from_bytes(inner_raw, policy=email.policy.default),
                         filename="Please review and sign.eml")
    samples["06_reported_phish_forward.eml"] = _sample_bytes(
        _gmail_trace("jordan.lee@example.edu", "209.85.220.41", "mail-sor-f41.google.com",
                     "Mon, 12 Oct 2026 06:20:46 -0700 (PDT)", dkim_d="example.edu")[1:], outer)
    return samples


def write_samples(folder: Path) -> list:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, data in build_samples().items():
        (folder / name).write_bytes(data)
        paths.append(folder / name)
    (folder / LAB_FEED_NAME).write_text(LAB_FEED, encoding="utf-8")
    return paths


# ============================================================================
# Self-test (offline): verifies parsing, SPF/DKIM/DMARC logic, URL tricks, feeds and reports
# ============================================================================
class _FakeDNS(DNSClient):
    def __init__(self, zone: dict):
        super().__init__(enabled=False)
        self.enabled, self.zone, self._custom_ns = True, zone, ["in-memory"]

    def _raw(self, name: str, rtype: str) -> DNSAnswer:
        value = self.zone.get((name.lower().rstrip("."), rtype))
        if value == "timeout":
            return DNSAnswer(TIMEOUT, [], "timed out")
        if value is None:
            known = any(k[0] == name.lower().rstrip(".") for k in self.zone)
            return DNSAnswer(NODATA if known else NXDOMAIN, [], "no records")
        return DNSAnswer(OK, list(value))


def run_self_test() -> int:
    global CON
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="phish_selftest_"))
    outcomes: list[bool] = []
    CON.out(CON.paint(f"{TOOL_NAME} {__version__} self-test (offline)", "bold"))

    def check(name: str, fn) -> None:
        try:
            ok, detail = fn()
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        outcomes.append(ok)
        mark = CON.paint("PASS", "green") if ok else CON.paint("FAIL", "red")
        CON.out(f"  {mark}  {name}" + (f"  ({detail})" if detail else ""))

    def t_samples():
        global CON
        folder = tmp / "lab"
        write_samples(folder)
        saved, CON = CON, Console("never", quiet=True)
        try:
            an = PhishAnalyzer(live=False, use_feeds=False, feed_files=(str(folder / LAB_FEED_NAME),))
            res, _ = analyze_inputs([str(folder)], an)
        finally:
            CON = saved
        got = {r.email.label: r.level for r in res}
        want = {"01_paypal_credential_phish.eml": {"critical"},
                "02_m365_password_html_attachment.eml": {"critical"},
                "03_gift_card_bec.eml": {"high", "critical"}, "04_legit_shipping_notice.eml": {"low"},
                "05_quarantine_export.mbox #1": {"high", "critical"}, "05_quarantine_export.mbox #2": {"low"},
                "06_reported_phish_forward.eml": {"low"},
                "06_reported_phish_forward.eml > attached message 1": {"high", "critical"}}
        bad = [f"{k}: got {got.get(k)}" for k, v in want.items() if got.get(k) not in v]
        return not bad, "; ".join(bad) or f"{len(res)} messages scored as expected"

    zone = {("example.org", "TXT"): ["v=spf1 ip4:192.0.2.0/24 include:_spf.esp.test -all"],
            ("_spf.esp.test", "TXT"): ["v=spf1 ip4:198.51.100.10 exists:%{i}._ip.esp.test ~all"],
            ("203.0.113.9._ip.esp.test", "A"): ["127.0.0.2"], ("redir.org", "TXT"): ["v=spf1 redirect=example.org"],
            ("soft.org", "TXT"): ["v=spf1 mx ~all"], ("soft.org", "MX"): [(10, "mx.soft.org")],
            ("mx.soft.org", "A"): ["192.0.2.200"], ("slow.org", "TXT"): "timeout",
            ("loop.org", "TXT"): ["v=spf1 include:loop.org -all"],
            ("_dmarc.example.org", "TXT"): ["v=DMARC1; p=reject; adkim=s"]}

    def t_spf():
        spf = SPFEvaluator(_FakeDNS(zone))
        cases = [("192.0.2.5", "a@example.org", "pass"), ("198.51.100.10", "a@example.org", "pass"),
                 ("203.0.113.9", "a@example.org", "pass"), ("8.8.8.8", "a@example.org", "fail"),
                 ("8.8.8.8", "a@redir.org", "fail"), ("192.0.2.200", "a@soft.org", "pass"),
                 ("8.8.8.8", "a@soft.org", "softfail"), ("8.8.8.8", "a@slow.org", "temperror"),
                 ("8.8.8.8", "a@nosuch.org", "none"), ("8.8.8.8", "a@loop.org", "permerror")]
        bad = [f"{ip}/{mf}: {spf.check(ip, mf)['result']} != {exp}" for ip, mf, exp in cases
               if spf.check(ip, mf)["result"] != exp]
        return not bad, "; ".join(bad) or f"{len(cases)} cases incl. include, exists macro, redirect, timeout, loop"

    def t_dmarc():
        d = _FakeDNS(zone)
        rec = lookup_dmarc(d, "mail.example.org")
        ok = (rec["status"] == "found" and rec["inherited"] and rec["policy"] == "reject"
              and aligned("mail.example.org", "example.org", "r") and not aligned("mail.example.org", "example.org", "s"))
        return ok, "org-domain fallback and relaxed/strict alignment"

    def t_ar():
        g = parse_auth_results("mx.google.com; dkim=pass header.i=@github.com header.s=pf2023; spf=pass (google.com: "
                               "domain of n@github.com designates 192.30.252.201 as permitted sender) "
                               "smtp.mailfrom=n@github.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com")
        ms = parse_auth_results("spf=fail (sender IP is 203.0.113.7) smtp.mailfrom=evil.example; dkim=none (message "
                                "not signed) header.d=none;dmarc=fail action=quarantine header.from=paypal.com;"
                                "compauth=fail reason=000")
        ok = (g["authserv_id"] == "mx.google.com" and g["spf"]["ip"] == "192.30.252.201"
              and g["dmarc"]["policy"] == "reject" and g["dkim"][0]["domain"] == "github.com"
              and ms["spf"]["result"] == "fail" and ms["dmarc"]["policy"] == "quarantine"
              and ms["compauth"]["result"] == "fail")
        return ok, "Gmail and Microsoft 365 formats"

    def t_urls():
        links = build_links([
            ("https://nam12.safelinks.protection.outlook.com/?url=http%3A%2F%2Fpaypa1-login.com%2Fx", "www.paypal.com", "html-a"),
            ("http://www.paypal.com@evil.example/x", "", "text"), ("https://xn--pypal-4ve.com/", "", "text"),
            ("http://203.0.113.5/login", "", "text"), ("https://bit.ly/abc", "", "text")])
        codes = {lk.host: {c for c, _ in lk.flags} for lk in links}
        ok = ({"lookalike", "text-mismatch"} <= codes.get("paypa1-login.com", set())
              and "userinfo" in codes.get("evil.example", set())
              and {"punycode", "lookalike"} <= codes.get("xn--pypal-4ve.com", set())
              and "ip-host" in codes.get("203.0.113.5", set()) and "shortener" in codes.get("bit.ly", set())
              and links[0].wrapper == "Microsoft Defender Safe Links")
        return ok, "Safe Links unwrap, '@' trick, homoglyph, IP host, shortener, deceptive text"

    def t_feeds():
        feed = tmp / "feed.txt"
        feed.write_text("http://bad.example/phish/\nevil-host.example\nhttps://docs.google.com/forms/d/abc\n", encoding="utf-8")
        tf = ThreatFeeds(use_public=False, feed_files=(str(feed),))
        tf.load()

        def match(u: str):
            hit = tf.check(build_links([(u, "", "text")])[0])
            return hit["match"] if hit else None
        ok = (match("http://bad.example/phish/login.php") == "path" and match("http://evil-host.example/x") == "host"
              and match("https://docs.google.com/forms/d/other") is None
              and match("https://docs.google.com/forms/d/abc") == "exact")
        return ok, "exact, path and host matches; shared platforms need an exact URL"

    def t_dkim():
        if not HAVE_DKIM:
            return True, "skipped: dkimpy not installed"
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError:
            return True, "skipped: cryptography not installed"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                 serialization.NoEncryption())
        pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        msg = (b"From: Alice <alice@example.org>\r\nTo: bob@example.net\r\nSubject: hi\r\n"
               b"Date: Tue, 06 Oct 2026 10:00:00 +0000\r\nMessage-ID: <1@example.org>\r\n\r\nHello Bob\r\n")
        sig = dkim.sign(msg, b"sel1", b"example.org", priv, include_headers=[b"from", b"to", b"subject", b"date"])
        signed, tags = sig + msg, [parse_tag_list(sig.decode().split(":", 1)[1])]
        z = dict(zone)
        z[("sel1._domainkey.example.org", "TXT")] = ["v=DKIM1; k=rsa; p=" + base64.b64encode(pub).decode()]
        good = verify_dkim(signed, tags, _FakeDNS(z))[0]["result"]
        tampered = verify_dkim(signed.replace(b"Hello Bob", b"Hello Eve"), tags, _FakeDNS(z))[0]["result"]
        z[("sel1._domainkey.example.org", "TXT")] = "timeout"
        slow = verify_dkim(signed, tags, _FakeDNS(z))[0]["result"]
        return (good, tampered, slow) == ("pass", "fail", "temperror"), f"valid={good}, tampered={tampered}, timeout={slow}"

    def t_canary():
        liar = _FakeDNS({})
        return (not liar.health_check()) and not liar.enabled, "a resolver that says everything is NXDOMAIN is distrusted"

    def t_escape():
        m = EmailMessage()
        m["From"] = '"<img src=x onerror=alert(1)>" <a@b.example>'
        m["Subject"] = "<script>alert('xss')</script> \u0420\u0430\u0443Pal \U0001F512"
        m["To"] = "c@d.example"
        m.set_content('<a href="http://evil.example/">"><script>alert(2)</script></a>', subtype="html")
        an = PhishAnalyzer(live=False, use_feeds=False)
        r = an.analyze(RawMessage("selftest", "xss.eml", m.as_bytes()))
        meta = build_meta(an, ["selftest"], [], True)
        page = render_html([r], meta)
        write_json([r], meta, tmp / "x.json")
        back = json.loads((tmp / "x.json").read_text(encoding="utf-8"))["messages"][0]["message"]["subject"]
        ok = ("<script>alert" not in page and "<img src=x" not in page and "&lt;script&gt;" in page
              and 'href="http://evil' not in page and "\U0001F512" in back)
        return ok, "hostile subject, display name and link text are escaped; Unicode survives JSON"

    def t_pdf():
        an = PhishAnalyzer(live=False, use_feeds=False)
        r = an.analyze(RawMessage("selftest", "a.eml", build_samples()["01_paypal_credential_phish.eml"]))
        err = write_pdf([r], build_meta(an, ["selftest"], [], True), tmp / "x.pdf")
        if err and "not installed" in err:
            return True, "skipped: " + err
        return (err is None and (tmp / "x.pdf").read_bytes()[:4] == b"%PDF"), err or "PDF written"

    check("Built-in samples get the expected verdicts", t_samples)
    check("SPF evaluator (RFC 7208)", t_spf)
    check("DMARC lookup and alignment", t_dmarc)
    check("Authentication-Results parsing", t_ar)
    check("URL tricks and link unwrapping", t_urls)
    check("Threat-feed matching", t_feeds)
    check("DKIM signature verification", t_dkim)
    check("DNS health canary", t_canary)
    check("HTML report escaping (XSS) and Unicode", t_escape)
    check("PDF report", t_pdf)
    passed = sum(outcomes)
    summary = f"{passed}/{len(outcomes)} checks passed"
    CON.out(CON.paint(summary, "green" if passed == len(outcomes) else "red"))
    return 0 if passed == len(outcomes) else 1


# ============================================================================
# Run metadata, report writing, CLI
# ============================================================================
def build_meta(an: PhishAnalyzer, inputs: list, warnings: list, offline: bool) -> dict:
    now = datetime.now(timezone.utc).astimezone()
    if an.dns.enabled:
        dns_txt = f"live checks on ({an.dns.queries} queries)" + (f"; {an.dns.note}" if an.dns.note else "")
    else:
        dns_txt = an.dns.note or ("off (offline mode)" if offline else "off")
    if an.vt:
        st = an.vt.status()
        vt_txt = f"{st['calls']} lookup(s), {st['cache_hits']} from cache" + (f"; stopped: {st['stopped']}" if st["stopped"] else "")
    else:
        vt_txt = f"off ({an.vt_note})"
    mode = ("Offline: headers and content only, local blocklists (no DNS, internet feeds or VirusTotal)" if offline
            else "Live: DNS authentication checks, public threat feed" + (", VirusTotal" if an.vt else ""))
    return {"tool": TOOL_NAME, "version": __version__, "generated": now.isoformat(timespec="seconds"),
            "generated_label": now.strftime("%Y-%m-%d %H:%M ") + (now.tzname() or ""), "mode": "offline" if offline else "live",
            "mode_label": mode, "dns": dns_txt, "feeds": an.feed_status, "virustotal": vt_txt,
            "inputs": [str(p) for p in inputs], "warnings": list(warnings), "python": sys.version.split()[0],
            "platform": sys.platform, "dependencies": {"dnspython": HAVE_DNS, "dkimpy": HAVE_DKIM,
                                                       "tldextract": HAVE_TLDEXTRACT, "requests": HAVE_REQUESTS}}


def write_reports(results: list, meta: dict, outdir: Path, name: str, formats: set) -> list:
    outdir.mkdir(parents=True, exist_ok=True)
    written = []
    if "json" in formats:
        p = outdir / f"{name}.json"
        write_json(results, meta, p)
        written.append(("JSON", str(p), ""))
    if "html" in formats:
        p = outdir / f"{name}.html"
        p.write_text(render_html(results, meta), encoding="utf-8")
        written.append(("HTML", str(p), ""))
    if "pdf" in formats:
        p = outdir / f"{name}.pdf"
        err = write_pdf(results, meta, p)
        written.append(("PDF", "" if err else str(p), err or ""))
    return written


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="phish_detector.py",
        description="Automated phishing email detector: parses EML/MBOX, checks SPF/DKIM/DMARC, looks up links in "
                    "threat intelligence, and scores phishing probability with per-feature explanations.",
        epilog="Examples:\n  python phish_detector.py suspicious.eml\n  python phish_detector.py inbox.mbox mails/ "
               "-o reports\n  python phish_detector.py --lab\n  python phish_detector.py --self-test",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="*", help=".eml or .mbox files, or folders containing them")
    ap.add_argument("-o", "--output", default="phish_reports", help="output folder (default: phish_reports)")
    ap.add_argument("--name", default="phish_report", help="base file name for the reports (default: phish_report)")
    ap.add_argument("--format", default="html,pdf,json", help="comma list of html, pdf, json (default: all)")
    ap.add_argument("--offline", action="store_true", help="no DNS, threat-feed downloads or VirusTotal lookups")
    ap.add_argument("--no-feeds", action="store_true", help="skip public threat-feed downloads")
    ap.add_argument("--feed-file", action="append", default=[], help="extra blocklist (URLs or domains, one per line)")
    ap.add_argument("--vt-key", default=None, help="VirusTotal API key (default: VT_API_KEY environment variable)")
    ap.add_argument("--vt-max-urls", type=int, default=4, help="VirusTotal URL lookups per email (default 4)")
    ap.add_argument("--vt-max-files", type=int, default=2, help="VirusTotal attachment lookups per email (default 2)")
    ap.add_argument("--vt-max-total", type=int, default=40, help="VirusTotal lookups per run (default 40)")
    ap.add_argument("--vt-interval", type=float, default=15.5, help="seconds between VirusTotal calls (free tier: 15.5)")
    ap.add_argument("--brand", action="append", default=[], metavar="NAME=dom1,dom2",
                    help="protect an extra brand, e.g. --brand \"My School=myschool.edu\"")
    ap.add_argument("--dns-server", action="append", default=[], help="use this DNS server (repeatable)")
    ap.add_argument("--dns-timeout", type=float, default=4.0, help="DNS timeout in seconds (default 4)")
    ap.add_argument("--max-messages", type=int, default=200, help="stop after this many messages (default 200)")
    ap.add_argument("--cache-dir", default=None, help="cache folder for feeds and VirusTotal results")
    ap.add_argument("--fail-threshold", type=float, default=None, metavar="P",
                    help="exit with code 3 if any message scores >= P (0-1), for automation")
    ap.add_argument("--lab", nargs="?", const="lab_samples", default=None, metavar="DIR",
                    help="write the built-in sample emails to DIR and analyze them offline")
    ap.add_argument("--make-samples", metavar="DIR", help="only write the sample emails to DIR")
    ap.add_argument("--self-test", action="store_true", help="run the offline self-test and exit")
    ap.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    ap.add_argument("--quiet", action="store_true", help="only print warnings and errors")
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return ap


def main(argv: Optional[list] = None) -> int:
    global CON
    _harden_stdio()
    ap = build_parser()
    args = ap.parse_args(argv)
    CON = Console(args.color, args.quiet)
    for spec in args.brand:
        if not add_custom_brand(spec):
            CON.warn(f"Ignoring --brand '{spec}' (expected NAME=domain1,domain2)")
    if args.self_test:
        return run_self_test()
    if args.make_samples:
        paths = write_samples(Path(args.make_samples))
        CON.ok(f"Wrote {len(paths)} sample files and {LAB_FEED_NAME} to {args.make_samples}")
        return 0
    inputs, feed_files, offline = list(args.inputs), list(args.feed_file), args.offline
    if args.lab is not None:
        folder = Path(args.lab)
        write_samples(folder)
        inputs, offline = [str(folder)], True
        feed_files.append(str(folder / LAB_FEED_NAME))
        CON.info(f"Lab mode: built-in sample emails written to {folder}/ and analyzed offline")
    if not inputs:
        ap.print_usage()
        CON.err("No input files. Give .eml/.mbox files or folders, or try --lab or --self-test.")
        return 2
    formats = {f.strip().lower() for f in args.format.split(",") if f.strip()} & {"html", "pdf", "json"}
    if not formats:
        CON.err("--format must include html, pdf and/or json")
        return 2
    vt_key = (args.vt_key if args.vt_key is not None else os.environ.get("VT_API_KEY", "")).strip()

    CON.out(CON.paint(f"{TOOL_NAME} {__version__} - automated phishing email detector", "bold"))
    analyzer = PhishAnalyzer(live=not offline, use_feeds=not args.no_feeds, feed_files=tuple(feed_files),
                             vt_key=vt_key, vt_max_urls=args.vt_max_urls, vt_max_files=args.vt_max_files,
                             vt_max_total=args.vt_max_total, vt_interval=args.vt_interval,
                             dns_timeout=args.dns_timeout, nameservers=args.dns_server or None,
                             cache_dir=args.cache_dir)
    if offline:
        CON.info("Offline mode: no DNS, internet feeds or VirusTotal")
    else:
        CON.info("DNS: " + ("live checks enabled" if analyzer.dns.enabled else "disabled") +
                 (f" - {analyzer.dns.note}" if analyzer.dns.note else ""))
    for fs in analyzer.feed_status:
        if fs["status"] == "loaded":
            CON.info(f"Threat feed: {fs['name']} - {fs['count']} entries ({fs['source']})")
        else:
            CON.warn(f"Threat feed unavailable: {fs['name']} ({fs.get('note', '')})")
    CON.info("VirusTotal: " + (f"on (up to {args.vt_max_urls} links + {args.vt_max_files} files per email, "
                               f"paced for the free tier)" if analyzer.vt else f"off - {analyzer.vt_note}"))
    CON.out("")
    results, warnings = analyze_inputs(inputs, analyzer, args.max_messages)
    if analyzer.vt:
        analyzer.vt.save_cache()
    for w in warnings:
        CON.warn(w)
    if not results:
        CON.err("No messages could be analyzed.")
        return 1
    meta = build_meta(analyzer, inputs, warnings, offline)
    written = write_reports(results, meta, Path(args.output), args.name, formats)
    counts = Counter(r.verdict for r in results)
    CON.out("")
    CON.ok(f"{len(results)} message(s): " + ", ".join(f"{n} {v.lower()}" for v, n in counts.most_common()))
    for kind, path, err in written:
        if err:
            CON.warn(f"{kind} report skipped: {err}")
        else:
            CON.ok(f"{kind} report: {path}")
    if args.fail_threshold is not None and any(r.probability >= args.fail_threshold for r in results):
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
