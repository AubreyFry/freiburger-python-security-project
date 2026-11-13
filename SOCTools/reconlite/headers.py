"""headers.py - Fetch HTTP response headers and evaluate them.

Enhancement: missing security headers and weak (present but unsafe)
settings are flagged separately.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from util import SafeClient, normalize_url

# Security headers we expect, with the fix to recommend when one is missing.
SECURITY_HEADERS = {
    "Content-Security-Policy":
        "Add a Content-Security-Policy that limits where scripts, styles, and frames can load from.",
    "Strict-Transport-Security":
        "Serve the site over HTTPS and enable HSTS (Strict-Transport-Security) so browsers refuse plain HTTP.",
    "X-Frame-Options":
        "Set X-Frame-Options: DENY or SAMEORIGIN (or CSP frame-ancestors) to block clickjacking.",
    "X-Content-Type-Options":
        "Set X-Content-Type-Options: nosniff so browsers don't guess file types.",
    "Referrer-Policy":
        "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter) so full URLs don't leak to other sites.",
    "Permissions-Policy":
        "Set a Permissions-Policy that turns off browser features the site doesn't use (camera, microphone, geolocation).",
}

# Headers that reveal what software (and sometimes which version) is running.
LEAKY_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator")

HSTS_MIN_MAX_AGE = 15552000  # 180 days


def _weak(header: str, value: str, reason: str, recommendation: str) -> dict:
    return {"header": header, "value": value, "reason": reason, "recommendation": recommendation}


def _check_xfo(v: str):
    if v.strip().upper() not in ("DENY", "SAMEORIGIN"):
        return ("Only DENY or SAMEORIGIN protect against clickjacking; values like ALLOWALL or ALLOW-FROM do not.",
                "Change X-Frame-Options to DENY or SAMEORIGIN.")


def _check_xcto(v: str):
    if v.strip().lower() != "nosniff":
        return ("The only valid value is 'nosniff'.", "Change X-Content-Type-Options to nosniff.")


def _check_hsts(v: str):
    m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.I)
    if not m:
        return ("No max-age is set, so the policy has no effect.",
                f"Set Strict-Transport-Security with max-age of at least {HSTS_MIN_MAX_AGE}.")
    if int(m.group(1)) < HSTS_MIN_MAX_AGE:
        return (f"max-age is {m.group(1)} seconds, shorter than the recommended 180 days.",
                f"Raise the HSTS max-age to at least {HSTS_MIN_MAX_AGE}.")


def _check_csp(v: str):
    low = v.lower()
    problems = []
    if "'unsafe-inline'" in low:
        problems.append("allows inline scripts/styles ('unsafe-inline')")
    if "'unsafe-eval'" in low:
        problems.append("allows eval() ('unsafe-eval')")
    for directive in low.split(";"):
        parts = directive.split()
        if parts and parts[0] in ("default-src", "script-src") and "*" in parts[1:]:
            problems.append(f"{parts[0]} allows any source ('*')")
    if "default-src" not in low and "script-src" not in low:
        problems.append("has no default-src or script-src, so scripts are not restricted")
    if problems:
        return ("The policy " + "; ".join(problems) + ".",
                "Tighten the CSP: remove 'unsafe-inline', 'unsafe-eval', and '*' and list only trusted sources.")


def _check_referrer(v: str):
    last = v.split(",")[-1].strip().lower()
    if last in ("unsafe-url", "no-referrer-when-downgrade"):
        return (f"'{last}' sends full URLs (including paths and query strings) to other sites.",
                "Change Referrer-Policy to strict-origin-when-cross-origin or no-referrer.")


WEAK_CHECKS = {
    "X-Frame-Options": _check_xfo,
    "X-Content-Type-Options": _check_xcto,
    "Strict-Transport-Security": _check_hsts,
    "Content-Security-Policy": _check_csp,
    "Referrer-Policy": _check_referrer,
}


def evaluate(headers: dict, url: str) -> dict:
    """Pure analysis of a header dict (no network)."""
    lower = {k.lower(): (k, v) for k, v in headers.items()}
    missing, weak, info_leaks, notes = [], [], [], []

    for name, rec in SECURITY_HEADERS.items():
        if name.lower() not in lower:
            missing.append({"header": name, "recommendation": rec})
            continue
        check = WEAK_CHECKS.get(name)
        value = lower[name.lower()][1]
        result = check(value) if check else None
        if result:
            weak.append(_weak(name, value, *result))

    # Extra weak-setting checks for headers that aren't in the "required" list.
    acao = lower.get("access-control-allow-origin")
    if acao and acao[1].strip() == "*":
        weak.append(_weak("Access-Control-Allow-Origin", acao[1],
                          "CORS is open to every website ('*').",
                          "Limit Access-Control-Allow-Origin to the specific origins that need it."))
    fp = lower.get("feature-policy")
    if fp and "permissions-policy" not in lower:
        weak.append(_weak("Feature-Policy", fp[1],
                          "Feature-Policy is the old, deprecated name and modern browsers ignore it.",
                          "Replace Feature-Policy with Permissions-Policy."))

    for name in LEAKY_HEADERS:
        if name.lower() in lower:
            value = lower[name.lower()][1]
            info_leaks.append({"header": name, "value": value,
                               "reveals_version": bool(re.search(r"\d", value))})

    if urlparse(url).scheme == "http":
        notes.append("Target uses plain HTTP; browsers ignore HSTS over HTTP, so HSTS only matters once HTTPS is enabled.")

    return {"missing": missing, "weak": weak, "info_leaks": info_leaks, "notes": notes}


def analyze(client: SafeClient, url: str) -> dict:
    url = normalize_url(url)
    resp = client.get(url)
    headers = dict(resp.headers)
    result = {"url": url, "status": resp.status_code, "headers": headers}
    result.update(evaluate(headers, url))
    return result
